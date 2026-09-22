import { describe, it, expect } from 'vitest';
import { SyncManager } from './manager.js';
import { memorySessionStore } from './session-store.js';
import { generateMEK, importMasterKey } from './crypto.js';

/**
 * A hub that actually stores items: POST assigns a per-account seq, GET returns
 * everything after `since`. Two managers sharing one master key stand in for
 * two devices on one account.
 */
function itemHub() {
	const items: Array<{ id: string; seq: number; blob: string }> = [];
	let seq = 0;
	const json = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
	const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(String(input), 'https://hub.test');
		const method = init?.method ?? 'GET';
		if (url.pathname === '/api/sync/items' && method === 'POST') {
			const body = JSON.parse(String(init?.body)) as { items: Array<{ id: string; blob: string }> };
			const acks = body.items.map((it) => {
				const existing = items.find((x) => x.id === it.id);
				seq += 1;
				if (existing) {
					existing.seq = seq;
					existing.blob = it.blob;
				} else items.push({ id: it.id, seq, blob: it.blob });
				return { id: it.id, seq };
			});
			return json(200, { acks });
		}
		if (url.pathname === '/api/sync/items') {
			const since = Number(url.searchParams.get('since') ?? '0');
			return json(200, { items: items.filter((it) => it.seq > since).sort((a, b) => a.seq - b.seq) });
		}
		return json(404, { message: 'no such route' });
	}) as typeof fetch;
	return { fetchFn, items };
}

/** A minimal writable store of { key → data } with the SyncDescriptor shape. */
function mapStore(initial: Record<string, unknown>) {
	let value: Record<string, unknown> = { ...initial };
	const subs = new Set<(v: Record<string, unknown>) => void>();
	let toItemsCalls = 0;
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
		toItems: (v: Record<string, unknown>) => {
			toItemsCalls += 1;
			return Object.entries(v).map(([key, data]) => ({ key, data }));
		},
		applyItem: (v: Record<string, unknown>, c: { key: string; data: unknown; deleted: boolean }) => {
			const next = { ...v };
			if (c.deleted) delete next[c.key];
			else next[c.key] = c.data;
			return next;
		}
	};
	return { store, descriptor, get value() { return value; }, get toItemsCalls() { return toItemsCalls; }, resetCount() { toItemsCalls = 0; } };
}

async function device(hub: ReturnType<typeof itemHub>, mek: Uint8Array, id: string) {
	const session = memorySessionStore();
	await session.save({ token: `tok-${id}`, email: 'reader@example.test', masterKey: await importMasterKey(mek) });
	const m = new SyncManager({ apiBase: 'https://hub.test', deviceId: id, sessionStore: session, fetchFn: hub.fetchFn });
	return m;
}

describe('SyncManager — a first pull is settled once per store, not once per item', () => {
	it('lands 1,000 remote items with a handful of snapshot rebuilds', async () => {
		const hub = itemHub();
		const mek = generateMEK();
		const N = 1000;

		// Device A: a library of N entries, pushed to the hub.
		const a = mapStore(Object.fromEntries(Array.from({ length: N }, (_, i) => [`scp:item-${i}`, { read: true, scroll: i }])));
		const A = await device(hub, mek, 'A');
		A.register(a.descriptor, a.store);
		await A.init();
		await A.sync();
		expect(hub.items).toHaveLength(N);

		// Device B: fresh, empty store, counts how often the manager re-reads it.
		const b = mapStore({});
		const B = await device(hub, mek, 'B');
		B.register(b.descriptor, b.store);
		await B.init();
		b.resetCount();
		await B.sync();

		expect(Object.keys(b.value)).toHaveLength(N);
		expect(b.value['scp:item-999']).toEqual({ read: true, scroll: 999 });
		// Before batching this was ~3N (one full snapshot per applied item).
		expect(b.toItemsCalls).toBeLessThan(10);
		expect(B.status.get()).toBe('idle');
	});

	it('still pushes back what a store merge kept over the server value', async () => {
		const hub = itemHub();
		const mek = generateMEK();
		const a = mapStore({ 'scp:x': { scroll: 10 } });
		const A = await device(hub, mek, 'A');
		A.register(a.descriptor, a.store);
		await A.init();
		await A.sync();

		// Device B's merge keeps the furthest scroll, so the server's 10 loses to a local 50.
		const b = mapStore({});
		b.descriptor.applyItem = (v, c) => ({ ...v, [c.key]: { scroll: Math.max(50, (c.data as { scroll: number }).scroll) } });
		const B = await device(hub, mek, 'B');
		B.register(b.descriptor, b.store);
		await B.init();
		await B.sync();
		expect(b.value['scp:x']).toEqual({ scroll: 50 });
		// The push-back is scheduled (debounced); a second sync carries it up.
		await new Promise((r) => setTimeout(r, 50));
		await B.sync();
		const before = hub.items.length;
		await A.sync();
		expect(hub.items).toHaveLength(before);
		expect(a.value['scp:x']).toEqual({ scroll: 50 });
	});
});
