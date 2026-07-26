/**
 * SyncEngine — the transport-agnostic core of E2E sync. It holds the unlocked
 * MEK, encrypts/decrypts items, and reconciles local and remote state with
 * per-item last-writer-wins keyed by a Hybrid Logical Clock.
 *
 * It talks to a `SyncTransport` (a dumb encrypted-blob store), so it can be
 * unit-tested against an in-memory transport with no server. The server only
 * ever sees `{ id, seq, blob }` — opaque ids and ciphertext.
 */
import {
	importMasterKey,
	deriveItemKeys,
	deterministicItemId,
	encryptItem,
	decryptItem,
	type ItemKeys
} from './crypto';
import { HLC, type HLCTimestamp } from './hlc';

/** Server-visible record. `seq` is a per-account monotonic counter (the sync
 *  cursor); `blob` is the encrypted item. Nothing else is exposed. */
export interface RemoteItem {
	id: string;
	seq: number;
	blob: Uint8Array;
}
export interface OutgoingItem {
	id: string;
	blob: Uint8Array;
}

export interface SyncTransport {
	/** Items with seq > sinceSeq, ascending. */
	pull(sinceSeq: number): Promise<RemoteItem[]>;
	/** Upsert; returns the server-assigned seq per id. */
	push(items: OutgoingItem[]): Promise<Array<{ id: string; seq: number }>>;
}

/** What lives inside an encrypted blob — never leaves the device in the clear. */
interface ItemPlaintext {
	type: string;
	key: string;
	data: unknown;
	hlc: HLCTimestamp;
	deleted: boolean;
}

interface LocalRecord extends ItemPlaintext {
	dirty: boolean;
}

export interface RemoteChange {
	type: string;
	key: string;
	data: unknown; // undefined when deleted
	deleted: boolean;
}

export interface SyncEngineOptions {
	now?: () => number;
	/** Stable per-device id; breaks same-millisecond ties between devices. */
	node?: string;
	onRemoteChange?: (change: RemoteChange) => void;
}

export class SyncEngine {
	private readonly hlc: HLC;
	/**
	 * Keyed by a local `type\0key` composite, NOT the server's opaque id. The
	 * opaque id is a keyed HMAC and computing it is async, so keying on it would
	 * force set/remove/get to be async too. Identity on pull comes from the
	 * decrypted plaintext, which also means a server that renamed ids couldn't
	 * confuse us.
	 */
	private readonly records = new Map<string, LocalRecord>();
	private cursor = 0;
	private onRemoteChange?: (change: RemoteChange) => void;

	private constructor(
		private readonly keys: ItemKeys,
		private readonly transport: SyncTransport,
		opts: SyncEngineOptions = {}
	) {
		this.hlc = new HLC(opts.now, opts.node);
		this.onRemoteChange = opts.onRemoteChange;
	}

	/**
	 * Build an engine from either the raw MEK or an already-imported master key.
	 * Async because subkey derivation is WebCrypto; pass the CryptoKey form to
	 * keep the master key non-extractable end to end.
	 */
	static async create(
		master: Uint8Array | CryptoKey,
		transport: SyncTransport,
		opts: SyncEngineOptions = {}
	): Promise<SyncEngine> {
		const baseKey = master instanceof Uint8Array ? await importMasterKey(master) : master;
		return new SyncEngine(await deriveItemKeys(baseKey), transport, opts);
	}

	private static localKey(type: string, key: string): string {
		return `${type}${String.fromCharCode(0)}${key}`;
	}

	private idFor(type: string, key: string): string {
		return SyncEngine.localKey(type, key);
	}

	/** Create or update a local entity and mark it for the next push. */
	set(type: string, key: string, data: unknown): void {
		this.records.set(this.idFor(type, key), {
			type,
			key,
			data,
			hlc: this.hlc.send(),
			deleted: false,
			dirty: true
		});
	}

	/** Tombstone a local entity (propagates the delete on the next push). */
	remove(type: string, key: string): void {
		this.records.set(this.idFor(type, key), {
			type,
			key,
			data: undefined,
			hlc: this.hlc.send(),
			deleted: true,
			dirty: true
		});
	}

	get(type: string, key: string): unknown {
		const r = this.records.get(this.idFor(type, key));
		return r && !r.deleted ? r.data : undefined;
	}

	/** True when a record exists for this entity, tombstones included. Lets a
	 *  caller tell "never seen" from "seen and deleted". */
	has(type: string, key: string): boolean {
		return this.records.has(this.idFor(type, key));
	}

	list(type: string): Array<{ key: string; data: unknown }> {
		return [...this.records.values()]
			.filter((r) => r.type === type && !r.deleted)
			.map((r) => ({ key: r.key, data: r.data }));
	}

	/** One reconcile cycle: pull remote changes, merge (LWW), push local changes. */
	async sync(): Promise<void> {
		// PULL + merge. Identity comes from the decrypted plaintext, not remote.id.
		for (const remote of await this.transport.pull(this.cursor)) {
			this.cursor = Math.max(this.cursor, remote.seq);
			const item = await decryptItem<ItemPlaintext>(this.keys.itemKey, remote.blob);
			this.hlc.receive(item.hlc);
			const lk = SyncEngine.localKey(item.type, item.key);
			const local = this.records.get(lk);
			if (!local || HLC.compare(item.hlc, local.hlc) > 0) {
				this.records.set(lk, { ...item, dirty: false });
				this.onRemoteChange?.({
					type: item.type,
					key: item.key,
					data: item.deleted ? undefined : item.data,
					deleted: item.deleted
				});
			}
		}

		// PUSH dirty. The opaque server id is derived here (async HMAC) so the
		// synchronous set/remove path never has to await.
		const dirty = [...this.records.entries()].filter(([, r]) => r.dirty);
		if (dirty.length === 0) return;
		const outgoing: OutgoingItem[] = [];
		const localKeyById = new Map<string, string>();
		for (const [lk, r] of dirty) {
			const id = await deterministicItemId(this.keys.itemIdKey, r.type, r.key);
			localKeyById.set(id, lk);
			const blob = await encryptItem(this.keys.itemKey, {
				type: r.type,
				key: r.key,
				data: r.data,
				hlc: r.hlc,
				deleted: r.deleted
			} satisfies ItemPlaintext);
			outgoing.push({ id, blob });
		}
		for (const ack of await this.transport.push(outgoing)) {
			this.cursor = Math.max(this.cursor, ack.seq);
			const r = this.records.get(localKeyById.get(ack.id) ?? '');
			if (r) r.dirty = false;
		}
	}
}

/**
 * In-memory transport standing in for the real encrypted-blob server. Backing
 * store is shared by reference across engines to simulate multiple devices on
 * one account. Exposes `rows` so tests can assert the server holds only opaque
 * ciphertext.
 */
export class MemoryTransport implements SyncTransport {
	readonly rows = new Map<string, { seq: number; blob: Uint8Array }>();
	private nextSeq = 1;

	async pull(sinceSeq: number): Promise<RemoteItem[]> {
		return [...this.rows.entries()]
			.filter(([, r]) => r.seq > sinceSeq)
			.sort((a, b) => a[1].seq - b[1].seq)
			.map(([id, r]) => ({ id, seq: r.seq, blob: r.blob }));
	}

	async push(items: OutgoingItem[]): Promise<Array<{ id: string; seq: number }>> {
		return items.map(({ id, blob }) => {
			const seq = this.nextSeq++;
			this.rows.set(id, { seq, blob });
			return { id, seq };
		});
	}
}
