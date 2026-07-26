import { describe, it, expect } from 'vitest';
import { SyncEngine, MemoryTransport } from './engine.js';
import { generateMEK } from './crypto.js';

/** A device on `server`, driven by a clock the test controls. */
function device(mek: Uint8Array, server: MemoryTransport, clock: () => number) {
	return SyncEngine.create(mek, server, { now: clock });
}

describe('SyncEngine — local', () => {
	it('set/get/list/remove', async () => {
		const e = await device(generateMEK(), new MemoryTransport(), () => 1);
		e.set('bookmark', 'b1', { title: 'A' });
		e.set('bookmark', 'b2', { title: 'B' });
		expect(e.get('bookmark', 'b1')).toEqual({ title: 'A' });
		expect(e.list('bookmark')).toHaveLength(2);
		e.remove('bookmark', 'b1');
		expect(e.get('bookmark', 'b1')).toBeUndefined();
		expect(e.list('bookmark')).toHaveLength(1);
	});
});

describe('SyncEngine — two devices on one account', () => {
	it('propagates a change from A to B', async () => {
		const mek = generateMEK();
		const server = new MemoryTransport();
		const A = await device(mek, server, () => 1000);
		const B = await device(mek, server, () => 1000);

		A.set('progress', 'w1', { pct: 42 });
		await A.sync();
		await B.sync();
		expect(B.get('progress', 'w1')).toEqual({ pct: 42 });
	});

	it('resolves a conflict by last-writer-wins (later HLC)', async () => {
		const mek = generateMEK();
		const server = new MemoryTransport();
		let ta = 1000;
		let tb = 1000;
		const A = await device(mek, server, () => ta);
		const B = await device(mek, server, () => tb);

		A.set('progress', 'w1', { pct: 10 });
		await A.sync();

		tb = 2000; // B writes later
		B.set('progress', 'w1', { pct: 90 });
		await B.sync(); // pulls A's (older), keeps its own, pushes
		await A.sync(); // pulls B's (newer), adopts

		expect(A.get('progress', 'w1')).toEqual({ pct: 90 });
		expect(B.get('progress', 'w1')).toEqual({ pct: 90 });
	});

	it('converges to ONE item when both create the same entity offline', async () => {
		const mek = generateMEK();
		const server = new MemoryTransport();
		let tb = 2000;
		const A = await device(mek, server, () => 1000);
		const B = await device(mek, server, () => tb);

		A.set('progress', 'w1', { pct: 10 }); // both, offline, same logical key
		B.set('progress', 'w1', { pct: 20 });
		await A.sync();
		await B.sync();
		await A.sync();

		expect(server.rows.size).toBe(1); // deterministic id -> no duplicate
		expect(A.get('progress', 'w1')).toEqual(B.get('progress', 'w1'));
	});

	it('propagates deletes', async () => {
		const mek = generateMEK();
		const server = new MemoryTransport();
		let t = 1000;
		const A = await device(mek, server, () => t);
		const B = await device(mek, server, () => t);

		A.set('bookmark', 'b1', { title: 'A' });
		await A.sync();
		await B.sync();
		expect(B.get('bookmark', 'b1')).toBeTruthy();

		t = 2000;
		A.remove('bookmark', 'b1');
		await A.sync();
		await B.sync();
		expect(B.get('bookmark', 'b1')).toBeUndefined();
	});
});

describe('zero-knowledge', () => {
	it('the server stores only opaque ciphertext', async () => {
		const server = new MemoryTransport();
		const A = await device(generateMEK(), server, () => 1);
		// The entity key must not be hex-compatible: ids are 32 hex chars over a
		// random per-account key, so "not.toContain('b1')" matches by chance ~11%
		// of runs. A key with non-hex characters makes the assertion meaningful.
		const ENTITY_KEY = 'zkmarker-work-42';
		A.set('bookmark', ENTITY_KEY, { title: 'ZKMARKER_TITLE_9x7', workId: 'ZKMARKER_WORK' });
		await A.sync();

		expect(server.rows.size).toBe(1);
		for (const [id, row] of server.rows) {
			const asText = Buffer.from(row.blob).toString('latin1');
			expect(asText).not.toContain('ZKMARKER'); // plaintext never present
			expect(asText).not.toContain('bookmark'); // type not leaked
			expect(id).toMatch(/^[0-9a-f]{32}$/); // id is an opaque HMAC...
			expect(id).not.toContain('bookmark'); // ...of neither the type...
			expect(id).not.toContain(ENTITY_KEY); // ...nor the entity key
		}
	});

	it("a different account's key cannot decrypt the blobs", async () => {
		const server = new MemoryTransport();
		const A = await device(generateMEK(), server, () => 1);
		A.set('progress', 'w1', { pct: 1 });
		await A.sync();

		const attacker = await device(generateMEK(), server, () => 1); // wrong MEK
		await expect(attacker.sync()).rejects.toThrow();
	});
});
