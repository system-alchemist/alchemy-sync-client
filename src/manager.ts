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
 *
 * Session lifetime: tokens expire (the hub decides how fast) and are rotated
 * here — proactively when a third of the lifetime remains, and once more if a
 * sync is refused with a 401 in between. A refused refresh means the hub has
 * ended the session (expiry, revocation, a password change elsewhere): the
 * manager signs out and reports `auth = { status: 'error', message }` so the
 * host can say "sign in again" rather than show a red word. A hub without the
 * refresh endpoint yet answers 404, which is ignored; sessions then simply
 * last as long as the hub's tokens do.
 */
import { SyncEngine, type RemoteChange } from './engine.js';
import { HttpSyncTransport, SyncAuthError } from './transport.js';
import {
	registerAccount,
	loginAccount,
	recoverAccount,
	changeAccountPassword,
	regenerateRecoveryPhrase,
	refreshSession,
	endSession
} from './account.js';
import { importMasterKey, type Argon2Params } from './crypto.js';
import { Signal, readStore } from './signal.js';
import {
	indexedDbSessionStore,
	type SessionStore
} from './session-store.js';

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
/** Refresh once this fraction of the token's lifetime remains. */
const REFRESH_AT_REMAINING = 1 / 3;
/** When the lifetime is unknown (a session resumed from an older store), refresh this far ahead. */
const REFRESH_AHEAD_MS = 7 * 24 * 60 * 60_000;
/** With no expiry at all (older hubs omit it), try this often; a 404 is ignored. */
const REFRESH_UNKNOWN_EVERY_MS = 24 * 60 * 60_000;
/** Between attempts once a refresh is due but failing (offline, hub down). */
const REFRESH_RETRY_MS = 5 * 60_000;

export const SESSION_EXPIRED_MESSAGE = 'Your session has expired — sign in again.';

type FetchFn = typeof globalThis.fetch;

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
	/** Every request goes through this; defaults to the global fetch. Tests
	 *  inject a fake hub, hosts with a patched fetch may pass it explicitly. */
	fetchFn?: FetchFn;
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
	private readonly fetchFn: FetchFn;

	constructor(options: SyncManagerOptions) {
		this.apiBase = options.apiBase;
		this.deviceId = options.deviceId;
		this.session = options.sessionStore ?? indexedDbSessionStore;
		this.argon2Params = options.argon2Params;
		this.fetchFn = options.fetchFn ?? globalThis.fetch;
	}

	private engine: SyncEngine | null = null;
	private readonly regs: Registration[] = [];
	/** True while applying a remote change, so the store update it causes isn't
	 *  echoed straight back to the server. */
	private applying = false;
	private syncing = false;
	private debounce: ReturnType<typeof setTimeout> | null = null;
	private interval: ReturnType<typeof setInterval> | null = null;

	// The live session. The transport reads the token through a getter, so a
	// refresh swaps it without rebuilding the engine.
	private token: string | null = null;
	private email: string | null = null;
	private masterKey: CryptoKey | null = null;
	private expiresAt: number | null = null;
	/** When the current token was obtained; null on resume (lifetime unknown). */
	private issuedAt: number | null = null;
	private lastRefreshAttempt = 0;
	private refreshing: Promise<boolean> | null = null;

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
			const { token, mek, mnemonic, expiresAt } = await registerAccount(this.apiBase, email, password, {
				params: this.argon2Params,
				fetchFn: this.fetchFn
			});
			await this.start(token, mek, email, expiresAt ?? null);
			return { mnemonic };
		} catch (e) {
			this.auth.set({ status: 'error', message: errorMessage(e) });
			throw e;
		}
	}

	async signIn(email: string, password: string): Promise<void> {
		this.auth.set({ status: 'signing-in' });
		try {
			const { token, mek, expiresAt } = await loginAccount(this.apiBase, email, password, {
				params: this.argon2Params,
				fetchFn: this.fetchFn
			});
			await this.start(token, mek, email, expiresAt ?? null);
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
			const { token, mek, expiresAt } = await recoverAccount(this.apiBase, email, mnemonic, newPassword, {
				params: this.argon2Params,
				fetchFn: this.fetchFn
			});
			await this.start(token, mek, email, expiresAt ?? null);
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
		const { token, mek, expiresAt } = await changeAccountPassword(
			this.apiBase,
			state.email,
			currentPassword,
			newPassword,
			{ params: this.argon2Params, fetchFn: this.fetchFn }
		);
		// Re-key the live session in place; the engine's data is untouched.
		this.stopTriggers();
		this.engine = null;
		await this.start(token, mek, state.email, expiresAt ?? null);
	}

	/**
	 * Issue a new recovery phrase and return it to show once. The old phrase
	 * stops working; synced data is unaffected.
	 */
	async newRecoveryPhrase(currentPassword: string): Promise<string> {
		const state = this.auth.get();
		if (state.status !== 'signed-in') throw new Error('You need to be signed in.');
		const { token, mek, mnemonic, expiresAt } = await regenerateRecoveryPhrase(
			this.apiBase,
			state.email,
			currentPassword,
			{ params: this.argon2Params, fetchFn: this.fetchFn }
		);
		// loginAccount opened a fresh session; adopt it so the stored token stays valid.
		this.stopTriggers();
		this.engine = null;
		await this.start(token, mek, state.email, expiresAt ?? null);
		return mnemonic;
	}

	signOut(): void {
		this.teardown(true);
		this.auth.set({ status: 'signed-out' });
		// Local data is intentionally left in place (offline-first). Signing back
		// in re-seeds from local and merges with the server.
	}

	/** Drop the live session. `revoke` also tells the hub (best effort) — not
	 *  when the hub has already refused the token. */
	private teardown(revoke: boolean): void {
		this.stopTriggers();
		if (this.debounce) {
			clearTimeout(this.debounce);
			this.debounce = null;
		}
		const token = this.token;
		this.engine = null;
		this.token = null;
		this.email = null;
		this.masterKey = null;
		this.expiresAt = null;
		this.issuedAt = null;
		void this.session.clear();
		if (revoke && token) void endSession(this.apiBase, token, { fetchFn: this.fetchFn });
		this.status.set('idle');
	}

	/** The hub has ended this session: sign out and say why. */
	private expire(): void {
		this.teardown(false);
		this.auth.set({ status: 'error', message: SESSION_EXPIRED_MESSAGE });
	}

	/** Restore the session persisted in IndexedDB (survives closing the tab). */
	async init(): Promise<void> {
		if (this.engine) return;
		const session = await this.session.load();
		if (!session) return;
		// Past its expiry: no need to ask the hub what it will say.
		if (session.expiresAt !== undefined && session.expiresAt <= Date.now()) {
			await this.session.clear();
			this.auth.set({ status: 'error', message: SESSION_EXPIRED_MESSAGE });
			return;
		}
		try {
			await this.start(session.token, session.masterKey, session.email, session.expiresAt ?? null, false);
		} catch {
			this.signOut();
		}
	}

	/**
	 * Bring up the engine for a signed-in account. `master` is the raw MEK on a
	 * fresh sign-in and the non-extractable CryptoKey on resume; either way only
	 * the CryptoKey form is persisted, so the raw bytes exist for one page life
	 * at most. `fresh` marks a token minted just now (its lifetime is then known).
	 */
	private async start(
		token: string,
		master: Uint8Array | CryptoKey,
		email: string,
		expiresAt: number | null,
		fresh = true
	): Promise<void> {
		const masterKey = master instanceof Uint8Array ? await importMasterKey(master) : master;
		this.token = token;
		this.email = email;
		this.masterKey = masterKey;
		this.expiresAt = expiresAt;
		this.issuedAt = fresh ? Date.now() : null;
		this.lastRefreshAttempt = 0;
		this.engine = await SyncEngine.create(
			masterKey,
			new HttpSyncTransport(this.apiBase, () => this.token ?? '', this.fetchFn),
			{
				node: this.deviceId,
				onRemoteChange: (c) => this.applyRemote(c)
			}
		);
		// Seed the engine with every current local entity so the first sync pushes
		// what this device already has. The engine is fresh here, so reconcile()
		// has nothing to replay and reduces to a pure seed.
		for (const reg of this.regs) this.reconcile(reg);
		await this.persist();
		this.auth.set({ status: 'signed-in', email });
		await this.sync();
		this.startTriggers();
	}

	private async persist(): Promise<void> {
		if (!this.token || !this.email || !this.masterKey) return;
		await this.session.save({
			token: this.token,
			email: this.email,
			masterKey: this.masterKey,
			...(this.expiresAt !== null ? { expiresAt: this.expiresAt } : {})
		});
	}

	// --- session lifetime ---

	private refreshDue(now = Date.now()): boolean {
		if (!this.token) return false;
		if (this.expiresAt === null) return now - this.lastRefreshAttempt >= REFRESH_UNKNOWN_EVERY_MS;
		const remaining = this.expiresAt - now;
		const threshold =
			this.issuedAt !== null ? (this.expiresAt - this.issuedAt) * REFRESH_AT_REMAINING : REFRESH_AHEAD_MS;
		return remaining < threshold && now - this.lastRefreshAttempt >= REFRESH_RETRY_MS;
	}

	/**
	 * Rotate the token. Resolves true while the session is usable (refreshed, or
	 * the hub could not be asked / has no refresh yet), false when the hub
	 * refused it — in which case the session has already been ended here.
	 */
	private refresh(): Promise<boolean> {
		if (this.refreshing) return this.refreshing;
		this.refreshing = (async () => {
			const token = this.token;
			if (!token) return false;
			this.lastRefreshAttempt = Date.now();
			try {
				const next = await refreshSession(this.apiBase, token, { fetchFn: this.fetchFn });
				if (this.token !== token) return this.token !== null; // signed out or re-keyed meanwhile
				this.token = next.token;
				this.expiresAt = next.expiresAt ?? null;
				this.issuedAt = Date.now();
				await this.persist();
				return true;
			} catch (e) {
				if (e instanceof SyncAuthError) {
					this.expire();
					return false;
				}
				return true; // offline, hub down, or no refresh endpoint yet: carry on with the token we have
			} finally {
				this.refreshing = null;
			}
		})();
		return this.refreshing;
	}

	// --- the sync loop ---

	async sync(): Promise<void> {
		if (!this.engine || this.syncing) return;
		this.syncing = true;
		this.status.set('syncing');
		try {
			if (this.refreshDue() && !(await this.refresh())) return; // expired: teardown already reset the status
			const engine = this.engine;
			if (!engine) return;
			try {
				await engine.sync();
			} catch (e) {
				if (!(e instanceof SyncAuthError)) throw e;
				// The token died between checks: one refresh, one retry.
				if (!(await this.refresh()) || !this.engine) return;
				await this.engine.sync();
			}
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
