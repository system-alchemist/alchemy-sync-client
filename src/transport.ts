/**
 * SyncTransport over the /api/sync/* HTTP endpoints — the real backend behind
 * the SyncEngine (MemoryTransport is its test double). Blobs travel base64 in
 * JSON; a bearer token authenticates every call. `fetchFn` is injectable so the
 * engine↔transport↔server round-trip can be tested without a live server.
 *
 * The token is read through a getter on every call: the manager rotates it
 * (see SyncManager's refresh) without rebuilding the engine.
 */
import type { SyncTransport, RemoteItem, OutgoingItem } from './engine.js';
import { bytesToBase64, base64ToBytes } from './base64.js';

type FetchFn = typeof globalThis.fetch;

/** The server refused the bearer token (401/403): expired, revoked, or never
 *  valid. Distinct from every other failure so the manager can try one refresh
 *  and, failing that, end the session instead of retrying forever. */
export class SyncAuthError extends Error {
	constructor(
		readonly status: number,
		message = `not authorised (${status})`
	) {
		super(message);
		this.name = 'SyncAuthError';
	}
}

function fail(what: string, res: Response): never {
	if (res.status === 401 || res.status === 403) {
		throw new SyncAuthError(res.status, `sync ${what} rejected (${res.status})`);
	}
	throw new Error(`sync ${what} failed (${res.status})`);
}

export class HttpSyncTransport implements SyncTransport {
	private readonly getToken: () => string;

	constructor(
		private readonly apiBase: string,
		token: string | (() => string),
		private readonly fetchFn: FetchFn = globalThis.fetch
	) {
		this.getToken = typeof token === 'function' ? token : () => token;
	}

	private headers(extra?: Record<string, string>): Record<string, string> {
		return { authorization: `Bearer ${this.getToken()}`, ...extra };
	}

	async pull(sinceSeq: number): Promise<RemoteItem[]> {
		const res = await this.fetchFn(`${this.apiBase}/api/sync/items?since=${sinceSeq}`, {
			headers: this.headers()
		});
		if (!res.ok) fail('pull', res);
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
		if (!res.ok) fail('push', res);
		const { acks } = (await res.json()) as { acks: Array<{ id: string; seq: number }> };
		return acks;
	}
}
