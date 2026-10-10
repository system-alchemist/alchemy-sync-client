import { describe, it, expect } from 'vitest';
import { SyncManager } from './manager.js';
import { memorySessionStore } from './session-store.js';
import { base64ToBytes, bytesToBase64 } from './base64.js';
import {
	generateMEK,
	importMasterKey,
	deriveItemKeys,
	deterministicItemId,
	encryptItem,
	decryptItem
} from './crypto.js';
import { HLC } from './hlc.js';

/**
 * A session ends while its sync is still in flight (2026-10-09): the reader
 * signs out of one account and into another before the first account's pull
 * comes back. The hub holds that pull open until the test lets it go, records
 * every request's token, and keeps each account's items apart.
 */
function heldHub() {
	const json = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
	const requests: Array<{ method: string; token: string }> = [];
	const pushes: Array<{ token: string; blobs: string[] }> = [];
	let hold: { release: (items: unknown[]) => void } | null = null;
	let holdNext = false;
	let sawHeld: () => void = () => {};
	const held = new Promise<void>((r) => (sawHeld = r));
	const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(String(input), 'https://hub.test');
		const method = init?.method ?? 'GET';
		const token = (new Headers(init?.headers).get('authorization') ?? '').replace('Bearer ', '');
		requests.push({ method, token });
		if (url.pathname === '/api/sync/items' && method === 'POST') {
			const body = JSON.parse(String(init?.body)) as { items: Array<{ id: string; blob: string }> };
			pushes.push({ token, blobs: body.items.map((it) => it.blob) });
			return json(200, { acks: body.items.map((it, i) => ({ id: it.id, seq: 100 + i })) });
		}
		if (url.pathname === '/api/sync/items') {
			if (holdNext) {
				holdNext = false;
				const items = await new Promise<unknown[]>((release) => {
					hold = { release };
					sawHeld();
				});
				return json(200, { items });
			}
			return json(200, { items: [] });
		}
		if (url.pathname === '/api/sync/session' && method === 'DELETE') return json(204, {});
		return json(404, { message: 'no such route' });
	}) as typeof fetch;
	return {
		fetchFn,
		requests,
		pushes,
		holdNextPull: () => (holdNext = true),
		held,
		release: (items: unknown[]) => hold?.release(items)
	};
}

/** A minimal writable store of { key → data } with the SyncDescriptor shape. */
function mapStore(initial: Record<string, unknown>) {
	let value: Record<string, unknown> = { ...initial };
	const subs = new Set<(v: Record<string, unknown>) => void>();
	const store = {
		subscribe(fn: (v: Record<string, unknown>) => void) {
			subs.add(fn);
			fn(value);
			return () => subs.delete(fn);
		},
		update(fn: (v: Record<string, unknown>) => Record<string, unknown>) {
			value = fn(value);
			for (const s of subs) s(value);
		}
	};
	const descriptor = {
		type: 'progress',
		toItems: (v: Record<string, unknown>) => Object.entries(v).map(([key, data]) => ({ key, data })),
		applyItem: (
			v: Record<string, unknown>,
			it: { key: string; data: unknown; deleted: boolean }
		): Record<string, unknown> => {
			const next = { ...v };
			if (it.deleted) delete next[it.key];
			else next[it.key] = it.data;
			return next;
		}
	};
	return { store, descriptor, value: () => value };
}

const settle = () => new Promise((r) => setTimeout(r, 50));

describe('SyncManager — a session that ends mid-sync', () => {
	it("keeps the old account's sync out of the new account", async () => {
		const hub = heldHub();
		const sessions = memorySessionStore();
		const mekA = generateMEK();
		const mekB = generateMEK();
		const keysA = await deriveItemKeys(await importMasterKey(mekA));
		const keysB = await deriveItemKeys(await importMasterKey(mekB));
		await sessions.save({ token: 'token-a', email: 'a@example.test', masterKey: await importMasterKey(mekA) });

		const m = new SyncManager({ apiBase: 'https://hub.test', deviceId: 'dev-1', sessionStore: sessions, fetchFn: hub.fetchFn });
		const library = mapStore({ 'on-this-device': { read: true } });
		m.register(library.descriptor, library.store);

		// Account A resumes; its first pull is held at the hub.
		hub.holdNextPull();
		const first = m.init();
		await hub.held;

		// The reader signs out of A and into B before A's pull comes back.
		m.signOut();
		await sessions.save({ token: 'token-b', email: 'b@example.test', masterKey: await importMasterKey(mekB) });
		await m.init();
		expect(m.auth.get()).toEqual({ status: 'signed-in', email: 'b@example.test' });
		// B's own first sync ran, not skipped behind A's.
		expect(hub.requests.some((r) => r.method === 'GET' && r.token === 'token-b')).toBe(true);

		// A's pull comes back now, with an item only A's account holds.
		const hlc = new HLC(() => Date.now(), 'another-device').send();
		const blob = await encryptItem(keysA.itemKey, { type: 'progress', key: 'only-in-a', data: { read: true }, hlc, deleted: false });
		hub.release([{ id: await deterministicItemId(keysA.itemIdKey, 'progress', 'only-in-a'), seq: 1, blob: bytesToBase64(blob) }]);
		await first.catch(() => {});
		await settle();

		// Nothing of A's reached this device's library after the sign-out...
		expect(library.value()['only-in-a']).toBeUndefined();
		// ...and every item pushed under B's token is sealed with B's key.
		for (const push of hub.pushes.filter((p) => p.token === 'token-b')) {
			for (const b of push.blobs) {
				await expect(decryptItem(keysB.itemKey, base64ToBytes(b))).resolves.toBeTruthy();
			}
		}
		// A's session sent nothing at all once it ended.
		const afterSignOut = hub.requests.slice(hub.requests.findIndex((r) => r.token === 'token-b'));
		expect(afterSignOut.some((r) => r.token === 'token-a' && r.method !== 'DELETE')).toBe(false);
		expect(m.status.get()).toBe('idle');
		m.signOut();
	});

	it('a refresh still reaches the live session', async () => {
		const hub = heldHub();
		const sessions = memorySessionStore();
		await sessions.save({ token: 'token-a', email: 'a@example.test', masterKey: await importMasterKey(generateMEK()) });
		const m = new SyncManager({ apiBase: 'https://hub.test', deviceId: 'dev-1', sessionStore: sessions, fetchFn: hub.fetchFn });
		await m.init();
		const before = hub.requests.length;
		await m.sync();
		// The live session keeps syncing with its own token.
		expect(hub.requests.slice(before).every((r) => r.token === 'token-a')).toBe(true);
		m.signOut();
	});
});
