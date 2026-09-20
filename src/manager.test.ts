import { describe, it, expect } from 'vitest';
import { SyncManager, SESSION_EXPIRED_MESSAGE } from './manager.js';
import { memorySessionStore } from './session-store.js';
import { generateMEK, importMasterKey } from './crypto.js';

/**
 * A hub with just enough of /api/sync to exercise the session's lifetime:
 * `valid` tokens may sync, `refreshable` tokens may be rotated (the two sets
 * differ when a token has been superseded), and `refresh` decides what a
 * rotation returns. Everything else is a 404, like a hub that predates it.
 */
function fakeHub(opts: {
	valid: Set<string>;
	refreshable?: Set<string>;
	refresh?: (token: string) => { token: string; expiresAt?: number } | 'expired' | 'missing';
}) {
	const refreshable = opts.refreshable ?? opts.valid;
	const calls: string[] = [];
	const json = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
	const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = String(input).replace(/^https?:\/\/[^/]+/, '');
		const method = init?.method ?? 'GET';
		const token = (new Headers(init?.headers).get('authorization') ?? '').replace('Bearer ', '');
		calls.push(`${method} ${url} ${token}`);
		if (url === '/api/sync/session/refresh') {
			const r = opts.refresh?.(token) ?? 'missing';
			if (r === 'missing') return json(404, { message: 'no such route' });
			if (r === 'expired' || !refreshable.has(token)) return json(401, { message: 'session expired' });
			opts.valid.delete(token);
			opts.valid.add(r.token);
			refreshable.add(r.token);
			return json(200, r);
		}
		if (url === '/api/sync/session' && method === 'DELETE') {
			opts.valid.delete(token);
			return json(204, {});
		}
		if (url.startsWith('/api/sync/items')) {
			if (!opts.valid.has(token)) return json(401, { message: 'session expired' });
			return method === 'POST' ? json(200, { acks: [] }) : json(200, { items: [] });
		}
		return json(404, { message: 'no such route' });
	}) as typeof fetch;
	return { fetchFn, calls };
}

const DAY = 24 * 60 * 60_000;

/** A manager resuming a persisted session (what every app launch does). */
async function resumed(hub: ReturnType<typeof fakeHub>, session: { token: string; expiresAt?: number }) {
	const store = memorySessionStore();
	await store.save({
		token: session.token,
		email: 'reader@example.test',
		masterKey: await importMasterKey(generateMEK()),
		...(session.expiresAt !== undefined ? { expiresAt: session.expiresAt } : {})
	});
	const m = new SyncManager({ apiBase: 'https://hub.test', deviceId: 'dev-1', sessionStore: store, fetchFn: hub.fetchFn });
	await m.init();
	return { m, store };
}

describe('SyncManager — session lifetime', () => {
	it('rotates a token that is close to expiry and persists the new one', async () => {
		const hub = fakeHub({
			valid: new Set(['t1']),
			refresh: () => ({ token: 't2', expiresAt: Date.now() + 30 * DAY })
		});
		// Resumed with a day left: under the 7-day horizon a resumed session refreshes at.
		const { m, store } = await resumed(hub, { token: 't1', expiresAt: Date.now() + DAY });

		expect(m.auth.get()).toEqual({ status: 'signed-in', email: 'reader@example.test' });
		expect(m.status.get()).toBe('idle');
		const saved = await store.load();
		expect(saved?.token).toBe('t2');
		expect(saved?.expiresAt).toBeGreaterThan(Date.now() + 29 * DAY);
		expect(hub.calls).toContain('POST /api/sync/session/refresh t1');
		// The sync that followed used the rotated token.
		expect(hub.calls.at(-1)).toBe('GET /api/sync/items?since=0 t2');
		m.signOut();
	});

	it('leaves a healthy token alone', async () => {
		const hub = fakeHub({ valid: new Set(['t1']), refresh: () => ({ token: 'never' }) });
		const { m, store } = await resumed(hub, { token: 't1', expiresAt: Date.now() + 30 * DAY });
		expect((await store.load())?.token).toBe('t1');
		expect(hub.calls.some((c) => c.includes('/session/refresh'))).toBe(false);
		m.signOut();
	});

	it('keeps working against a hub that has no refresh yet', async () => {
		// No expiry known → the first sync tries a refresh, gets a 404, and carries on.
		const hub = fakeHub({ valid: new Set(['t1']) });
		const { m, store } = await resumed(hub, { token: 't1' });
		expect(hub.calls).toContain('POST /api/sync/session/refresh t1');
		expect(m.status.get()).toBe('idle');
		expect(m.auth.get().status).toBe('signed-in');
		expect((await store.load())?.token).toBe('t1');
		m.signOut();
	});

	it('recovers from a 401 mid-session with one refresh and a retry', async () => {
		// t1 has been superseded server-side (no longer valid for items) but may still be rotated.
		const hub = fakeHub({
			valid: new Set(),
			refreshable: new Set(['t1']),
			refresh: () => ({ token: 't2', expiresAt: Date.now() + 30 * DAY })
		});
		const { m, store } = await resumed(hub, { token: 't1', expiresAt: Date.now() + 30 * DAY });
		expect(m.status.get()).toBe('idle');
		expect(m.lastSyncedAt.get()).not.toBeNull();
		expect((await store.load())?.token).toBe('t2');
		expect(hub.calls).toEqual([
			'GET /api/sync/items?since=0 t1',
			'POST /api/sync/session/refresh t1',
			'GET /api/sync/items?since=0 t2'
		]);
		m.signOut();
	});

	it('ends the session when the hub refuses to refresh, and says so', async () => {
		const hub = fakeHub({ valid: new Set(), refreshable: new Set(), refresh: () => 'expired' });
		const { m, store } = await resumed(hub, { token: 't1', expiresAt: Date.now() + 30 * DAY });
		expect(m.auth.get()).toEqual({ status: 'error', message: SESSION_EXPIRED_MESSAGE });
		expect(m.status.get()).toBe('idle');
		expect(await store.load()).toBeNull();
		// A dead token is not "revoked" back to the hub.
		expect(hub.calls.some((c) => c.startsWith('DELETE'))).toBe(false);
	});

	it('does not even ask about a session whose expiry has passed', async () => {
		const hub = fakeHub({ valid: new Set(['t1']) });
		const { m, store } = await resumed(hub, { token: 't1', expiresAt: Date.now() - 1 });
		expect(m.auth.get()).toEqual({ status: 'error', message: SESSION_EXPIRED_MESSAGE });
		expect(await store.load()).toBeNull();
		expect(hub.calls).toEqual([]);
	});

	it('tells the hub on sign-out', async () => {
		const hub = fakeHub({ valid: new Set(['t1']) });
		const { m } = await resumed(hub, { token: 't1', expiresAt: Date.now() + 30 * DAY });
		m.signOut();
		await new Promise((r) => setTimeout(r, 0));
		expect(hub.calls.at(-1)).toBe('DELETE /api/sync/session t1');
		expect(m.auth.get()).toEqual({ status: 'signed-out' });
	});
});
