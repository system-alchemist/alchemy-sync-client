import { describe, it, expect } from 'vitest';
import { HLC } from './hlc';

describe('HLC', () => {
	it('is monotonic within a frozen clock (counter advances)', () => {
		let t = 1000;
		const c = new HLC(() => t);
		const a = c.send();
		const b = c.send();
		expect(HLC.compare(b, a)).toBeGreaterThan(0);
		expect(a.wall).toBe(b.wall);
		expect(b.counter).toBe(a.counter + 1);
	});

	it('resets counter when wall advances', () => {
		let t = 1000;
		const c = new HLC(() => t, 'node-a');
		c.send();
		c.send();
		t = 2000;
		expect(c.send()).toEqual({ wall: 2000, counter: 0, node: 'node-a' });
	});

	it('receive() orders after a remote stamp even with a lagging clock', () => {
		// Local clock is behind the remote's wall time.
		const local = new HLC(() => 500, 'node-a');
		const remote = { wall: 9000, counter: 4, node: 'node-b' };
		const after = local.receive(remote);
		expect(HLC.compare(after, remote)).toBeGreaterThan(0);
		// A subsequent local send still follows.
		expect(HLC.compare(local.send(), after)).toBeGreaterThan(0);
	});

	it('pack() is lexicographically ordered and reversible', () => {
		const a = { wall: 1000, counter: 5, node: 'n1' };
		const b = { wall: 1000, counter: 12, node: 'n1' };
		const d = { wall: 2000, counter: 0, node: 'n1' };
		expect(HLC.pack(a) < HLC.pack(b)).toBe(true);
		expect(HLC.pack(b) < HLC.pack(d)).toBe(true);
		expect(HLC.unpack(HLC.pack(b))).toEqual(b);
	});

	it('breaks same-instant ties between devices deterministically', () => {
		// Two devices stamping the same entity in the same millisecond. Without a
		// node tiebreaker these compare equal, each device keeps its own value,
		// and they never converge.
		const a = new HLC(() => 1000, 'aaa');
		const b = new HLC(() => 1000, 'bbb');
		const ta = a.send();
		const tb = b.send();
		expect(HLC.compare(ta, tb)).not.toBe(0);
		// Every device draws the same conclusion, whichever side it is asked from.
		expect(Math.sign(HLC.compare(ta, tb))).toBe(-Math.sign(HLC.compare(tb, ta)));
	});

	it('still orders timestamps written before node ids existed', () => {
		const legacy = { wall: 1000, counter: 1 };
		const current = { wall: 1000, counter: 2, node: 'n1' };
		expect(HLC.compare(current, legacy)).toBeGreaterThan(0);
		expect(HLC.compare(legacy, legacy)).toBe(0);
	});
});
