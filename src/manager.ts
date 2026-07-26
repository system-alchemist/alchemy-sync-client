/**
 * SyncManager — the client hub that connects an app's local stores to the E2E
 * sync server. It owns the unlocked SyncEngine, runs the reconcile loop, and
 * bridges both directions:
 *   local store change  → diff vs last snapshot → engine.set/remove → push
 *   remote change (pull) → engine → applyItem() back into the store
 *
 * Offline-first: with no account the manager is inert and every store behaves
 * exactly as before. Sign-in unlocks the MEK (client-side) and starts syncing.
 *
 * FRAMEWORK-AGNOSTIC ON PURPOSE. Several apps share one account so that reading
 * across them lands in one library, and cross-app tracking through a
 * zero-knowledge store only works if every app derives the same item keys from
 * the same master key — a second implementation would drift and silently stop
 * seeing the first one's data. So this module imports no framework: state is
 * exposed as Signals (Svelte-store shaped, trivially bound in React), and
 * anything host-specific — the API base, the device id, where the session is
 * kept — is injected. See stores/sync.ts for the SvelteKit binding.
 *
 * Session persistence: the token and the master key (a non-extractable
 * CryptoKey) go to the injected SessionStore, IndexedDB by default, so a
 * session survives closing the tab and ends at sign-out.
 */
import { SyncEngine, type RemoteChange } from './engine';
import { HttpSyncTransport } from './transport';
import {
	registerAccount,
	loginAccount,
	recoverAccount,
	changeAccountPassword,
	regenerateRecoveryPhrase
} from './account';
import { importMasterKey, type Argon2Params } from './crypto';
import { Signal, readStore } from './signal';
import {
	indexedDbSessionStore,
	type SessionStore
} from './session-store';

/** How a store maps to/from per-entity sync items. */
export interface SyncDescriptor<T> {
	type: string;
	/** Split the whole store value into per-entity items. */
	toItems: (value: T) => Array<{ key: string; data: unknown }>;
	/** Merge one decrypted remote item back into the store value (LWW already
	 *  decided upstream by the engine's HLC compare). */
	applyItem: (value: T, change: { key: string; data: unknown; deleted: boolean }) => T;
}

export type AuthState =
	| { status: 'signed-out' }
	| { status: 'signing-in' }
	| { status: 'signed-in'; email: string }
	| { status: 'error'; message: string };

export type SyncStatus = 'idle' | 'syncing' | 'error';

interface Registration {
	type: string;
	descriptor: SyncDescriptor<unknown>;
	read: () => unknown;
	update: (fn: (v: unknown) => unknown) => void;
	/** key -> JSON(data) at last push, to diff local changes cheaply. */
	snapshot: Map<string, string>;
}

const SYNC_INTERVAL_MS = 60_000;
const DEBOUNCE_MS = 800;

export interface SyncManagerOptions {
	/** Origin/prefix the /api/sync/* routes live under. '' for same-origin root. */
	apiBase: string;
	/**
	 * Stable id for this device, the HLC tiebreaker. It must survive restarts: a
	 * device that reinvented its id could lose a tie it previously won and flip
	 * an already-settled conflict. Not secret — it rides inside the encrypted
	 * item blob and never leaves in the clear.
	 */
	deviceId: string;
	/** Defaults to IndexedDB. */
	sessionStore?: SessionStore;
	/** Client PDK cost. Defaults to the strong production profile; tests pass a
	 *  cheap one so the memory-hard KDF stays fast. */
	argon2Params?: Argon2Params;
}

function itemsToMap(items: Array<{ key: string; data: unknown }>): Map<string, string> {
	const map = new Map<string, string>();
	for (const { key, data } of items) map.set(key, JSON.stringify(data));
	return map;
}

function errorMessage(e: unknown): string {
	return e instanceof Error ? e.message : 'Something went wrong';
}

export class SyncManager {
	readonly auth = new Signal<AuthState>({ status: 'signed-out' });
	readonly status = new Signal<SyncStatus>('idle');
	readonly lastSyncedAt = new Signal<number | null>(null);

	private readonly apiBase: string;
	private readonly deviceId: string;
	private readonly session: SessionStore;
	private readonly argon2Params?: Argon2Params;

	constructor(options: SyncManagerOptions) {
		this.apiBase = options.apiBase;
		this.deviceId = options.deviceId;
		this.session = options.sessionStore ?? indexedDbSessionStore;
		this.argon2Params = options.argon2Params;
	}

	private engine: SyncEngine | null = null;
	private readonly regs: Registration[] = [];
	/** True while applying a remote change, so the store update it causes isn't
	 *  echoed straight back to the server. */
	private applying = false;
	private syncing = false;
	private debounce: ReturnType<typeof setTimeout> | null = null;
	private interval: ReturnType<typeof setInterval> | null = null;

	/** A syncable store registers itself (called from persistedWritable). */
	register<T>(
		descriptor: SyncDescriptor<T>,
		store: {
			subscribe: (fn: (v: T) => void) => () => void;
			update: (fn: (v: T) => T) => void;
		}
	): void {
		const d = descriptor as SyncDescriptor<unknown>;
		const reg: Registration = {
			type: descriptor.type,
			descriptor: d,
			read: () => readStore(store as { subscribe: (fn: (v: unknown) => void) => () => void }),
			update: store.update as (fn: (v: unknown) => unknown) => void,
			snapshot: new Map()
		};
		this.regs.push(reg);
		reg.snapshot = itemsToMap(d.toItems(reg.read()));
		// Stores register when their module is first imported, which for
		// route-scoped stores (bookmarks, progress) happens AFTER sign-in. Reconcile
		// immediately so items already pulled aren't stranded in the engine.
		if (this.engine) this.reconcile(reg);
		// Subscribe fires immediately with the current value; onLocalChange no-ops
		// while signed out (engine === null), just keeping the snapshot fresh.
		store.subscribe(() => this.onLocalChange(reg));
	}

	/**
	 * Two-way reconcile of one registration against the engine: pull anything the
	 * engine already knows into the store, then seed genuinely local-only entities
	 * back into the engine. Used both at sign-in (engine empty → pure seed) and on
	 * late registration (engine populated → replay then seed).
	 */
	private reconcile(reg: Registration): void {
		if (!this.engine) return;
		// 1. Engine → store, for everything already pulled.
		this.applying = true;
		try {
			for (const { key, data } of this.engine.list(reg.type)) {
				reg.update((v) => reg.descriptor.applyItem(v, { key, data, deleted: false }));
			}
		} finally {
			this.applying = false;
		}
		// 2. Store → engine, but only for entities the engine has never seen, so a
		//    fresh local write can't clobber a remote record's HLC (or resurrect
		//    something deleted on another device).
		let seeded = false;
		for (const { key, data } of reg.descriptor.toItems(reg.read())) {
			if (!this.engine.has(reg.type, key)) {
				this.engine.set(reg.type, key, data);
				seeded = true;
			}
		}
		reg.snapshot = itemsToMap(reg.descriptor.toItems(reg.read()));
		if (seeded) this.scheduleSync();
	}

	private onLocalChange(reg: Registration): void {
		const next = itemsToMap(reg.descriptor.toItems(reg.read()));
		if (this.applying || !this.engine) {
			reg.snapshot = next; // remote-applied or signed out — don't push
			return;
		}
		let changed = false;
		for (const [key, json] of next) {
			if (reg.snapshot.get(key) !== json) {
				this.engine.set(reg.type, key, JSON.parse(json));
				changed = true;
			}
		}
		for (const key of reg.snapshot.keys()) {
			if (!next.has(key)) {
				this.engine.remove(reg.type, key);
				changed = true;
			}
		}
		reg.snapshot = next;
		if (changed) this.scheduleSync();
	}

	private applyRemote(change: RemoteChange): void {
		const reg = this.regs.find((r) => r.type === change.type);
		if (!reg) return;
		this.applying = true;
		try {
			reg.update((v) =>
				reg.descriptor.applyItem(v, {
					key: change.key,
					data: change.data,
					deleted: change.deleted
				})
			);
		} finally {
			this.applying = false;
		}
		// The store's merge has the final say (reading progress, for one, keeps the
		// furthest position rather than the newest write). When it kept something
		// other than what the server sent, push ours back so the other device
		// converges on it — otherwise our copy would be silently overwritten by the
		// engine's plain last-writer-wins on the next round.
		const items = itemsToMap(reg.descriptor.toItems(reg.read()));
		const ours = items.get(change.key);
		const theirs = change.deleted ? undefined : JSON.stringify(change.data);
		if (ours !== undefined && ours !== theirs) {
			this.engine?.set(reg.type, change.key, JSON.parse(ours));
			this.scheduleSync();
		}
		reg.snapshot = items;
	}

	// --- account lifecycle ---

	async signUp(email: string, password: string): Promise<{ mnemonic: string }> {
		this.auth.set({ status: 'signing-in' });
		try {
			const { token, mek, mnemonic } = await registerAccount(this.apiBase, email, password, {
				params: this.argon2Params
			});
			await this.start(token, mek, email);
			return { mnemonic };
		} catch (e) {
			this.auth.set({ status: 'error', message: errorMessage(e) });
			throw e;
		}
	}

	async signIn(email: string, password: string): Promise<void> {
		this.auth.set({ status: 'signing-in' });
		try {
			const { token, mek } = await loginAccount(this.apiBase, email, password, {
				params: this.argon2Params
			});
			await this.start(token, mek, email);
		} catch (e) {
			this.auth.set({ status: 'error', message: errorMessage(e) });
			throw e;
		}
	}

	/**
	 * Reset a forgotten password with the recovery phrase and sign in. All synced
	 * data stays readable: the master key is unchanged, only its wrapping is.
	 */
	async recover(email: string, mnemonic: string, newPassword: string): Promise<void> {
		this.auth.set({ status: 'signing-in' });
		try {
			const { token, mek } = await recoverAccount(this.apiBase, email, mnemonic, newPassword, {
				params: this.argon2Params
			});
			await this.start(token, mek, email);
		} catch (e) {
			this.auth.set({ status: 'error', message: errorMessage(e) });
			throw e;
		}
	}

	/**
	 * Change the password of the signed-in account. Other devices are signed out
	 * by the server; this one keeps syncing on a fresh session.
	 */
	async changePassword(currentPassword: string, newPassword: string): Promise<void> {
		const state = this.auth.get();
		if (state.status !== 'signed-in') throw new Error('You need to be signed in.');
		const { token, mek } = await changeAccountPassword(
			this.apiBase,
			state.email,
			currentPassword,
			newPassword,
			{ params: this.argon2Params }
		);
		// Re-key the live session in place; the engine's data is untouched.
		this.stopTriggers();
		this.engine = null;
		await this.start(token, mek, state.email);
	}

	/**
	 * Issue a new recovery phrase and return it to show once. The old phrase
	 * stops working; synced data is unaffected.
	 */
	async newRecoveryPhrase(currentPassword: string): Promise<string> {
		const state = this.auth.get();
		if (state.status !== 'signed-in') throw new Error('You need to be signed in.');
		const { token, mek, mnemonic } = await regenerateRecoveryPhrase(
			this.apiBase,
			state.email,
			currentPassword,
			{ params: this.argon2Params }
		);
		// loginAccount opened a fresh session; adopt it so the stored token stays valid.
		this.stopTriggers();
		this.engine = null;
		await this.start(token, mek, state.email);
		return mnemonic;
	}

	signOut(): void {
		this.stopTriggers();
		if (this.debounce) {
			clearTimeout(this.debounce);
			this.debounce = null;
		}
		this.engine = null;
		void this.session.clear();
		this.status.set('idle');
		this.auth.set({ status: 'signed-out' });
		// Local data is intentionally left in place (offline-first). Signing back
		// in re-seeds from local and merges with the server.
	}

	/** Restore the session persisted in IndexedDB (survives closing the tab). */
	async init(): Promise<void> {
		if (this.engine) return;
		const session = await this.session.load();
		if (!session) return;
		try {
			await this.start(session.token, session.masterKey, session.email);
		} catch {
			this.signOut();
		}
	}

	/**
	 * Bring up the engine for a signed-in account. `master` is the raw MEK on a
	 * fresh sign-in and the non-extractable CryptoKey on resume; either way only
	 * the CryptoKey form is persisted, so the raw bytes exist for one page life
	 * at most.
	 */
	private async start(token: string, master: Uint8Array | CryptoKey, email: string): Promise<void> {
		const masterKey = master instanceof Uint8Array ? await importMasterKey(master) : master;
		this.engine = await SyncEngine.create(masterKey, new HttpSyncTransport(this.apiBase, token), {
			node: this.deviceId,
			onRemoteChange: (c) => this.applyRemote(c)
		});
		// Seed the engine with every current local entity so the first sync pushes
		// what this device already has. The engine is fresh here, so reconcile()
		// has nothing to replay and reduces to a pure seed.
		for (const reg of this.regs) this.reconcile(reg);
		await this.session.save({ token, email, masterKey });
		this.auth.set({ status: 'signed-in', email });
		await this.sync();
		this.startTriggers();
	}

	// --- the sync loop ---

	async sync(): Promise<void> {
		if (!this.engine || this.syncing) return;
		this.syncing = true;
		this.status.set('syncing');
		try {
			await this.engine.sync();
			this.lastSyncedAt.set(Date.now());
			this.status.set('idle');
		} catch {
			this.status.set('error');
		} finally {
			this.syncing = false;
		}
	}

	private scheduleSync(): void {
		if (this.debounce) return;
		this.debounce = setTimeout(() => {
			this.debounce = null;
			void this.sync();
		}, DEBOUNCE_MS);
	}

	private startTriggers(): void {
		this.stopTriggers();
		this.interval = setInterval(() => void this.sync(), SYNC_INTERVAL_MS);
		// Present in browsers and Electron renderers, absent in Node hosts, which
		// still get the interval.
		if (typeof window !== 'undefined') window.addEventListener('online', this.onOnline);
		if (typeof document !== 'undefined')
			document.addEventListener('visibilitychange', this.onVisible);
	}

	private stopTriggers(): void {
		if (this.interval) clearInterval(this.interval);
		this.interval = null;
		if (typeof window !== 'undefined') window.removeEventListener('online', this.onOnline);
		if (typeof document !== 'undefined')
			document.removeEventListener('visibilitychange', this.onVisible);
	}

	private onOnline = () => void this.sync();
	private onVisible = () => {
		if (typeof document === 'undefined' || document.visibilityState === 'visible') void this.sync();
	};
}
