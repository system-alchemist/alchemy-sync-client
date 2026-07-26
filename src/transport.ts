/**
 * SyncTransport over the /api/sync/* HTTP endpoints — the real backend behind
 * the SyncEngine (MemoryTransport is its test double). Blobs travel base64 in
 * JSON; a bearer token authenticates every call. `fetchFn` is injectable so the
 * engine↔transport↔server round-trip can be tested without a live server.
 */
import type { SyncTransport, RemoteItem, OutgoingItem } from './engine.js';
import { bytesToBase64, base64ToBytes } from './base64.js';

type FetchFn = typeof globalThis.fetch;

export class HttpSyncTransport implements SyncTransport {
	constructor(
		private readonly apiBase: string,
		private readonly token: string,
		private readonly fetchFn: FetchFn = globalThis.fetch
	) {}

	private headers(extra?: Record<string, string>): Record<string, string> {
		return { authorization: `Bearer ${this.token}`, ...extra };
	}

	async pull(sinceSeq: number): Promise<RemoteItem[]> {
		const res = await this.fetchFn(`${this.apiBase}/api/sync/items?since=${sinceSeq}`, {
			headers: this.headers()
		});
		if (!res.ok) throw new Error(`sync pull failed (${res.status})`);
		const { items } = (await res.json()) as {
			items: Array<{ id: string; seq: number; blob: string }>;
		};
		return items.map((it) => ({ id: it.id, seq: it.seq, blob: base64ToBytes(it.blob) }));
	}

	async push(items: OutgoingItem[]): Promise<Array<{ id: string; seq: number }>> {
		const res = await this.fetchFn(`${this.apiBase}/api/sync/items`, {
			method: 'POST',
			headers: this.headers({ 'content-type': 'application/json' }),
			body: JSON.stringify({
				items: items.map((it) => ({ id: it.id, blob: bytesToBase64(it.blob) }))
			})
		});
		if (!res.ok) throw new Error(`sync push failed (${res.status})`);
		const { acks } = (await res.json()) as { acks: Array<{ id: string; seq: number }> };
		return acks;
	}
}
