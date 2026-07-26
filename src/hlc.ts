/**
 * Hybrid Logical Clock — a timestamp that stays monotonic and total-orderable
 * even when device wall clocks disagree, so last-writer-wins across devices is
 * robust to clock skew. (wall, counter, node): counter breaks ties within the
 * same millisecond and lets a laggy device still order after what it just saw;
 * node breaks ties between *different* devices.
 *
 * The node id matters for convergence, not just neatness: without it, two
 * devices writing the same entity in the same millisecond compare as equal, each
 * keeps its own value, and they stay diverged forever. Comparing node ids last
 * gives every device the same deterministic winner.
 */
export interface HLCTimestamp {
	wall: number;
	counter: number;
	/** Per-device id. Optional for items written before node ids existed. */
	node?: string;
}

function randomNode(): string {
	const bytes = globalThis.crypto.getRandomValues(new Uint8Array(8));
	let s = '';
	for (const b of bytes) s += b.toString(16).padStart(2, '0');
	return s;
}

export class HLC {
	private wall = 0;
	private counter = 0;
	readonly node: string;

	constructor(
		private now: () => number = () => Date.now(),
		node?: string
	) {
		this.node = node ?? randomNode();
	}

	/** Stamp a local mutation. */
	send(): HLCTimestamp {
		const w = this.now();
		if (w > this.wall) {
			this.wall = w;
			this.counter = 0;
		} else {
			this.counter++;
		}
		return { wall: this.wall, counter: this.counter, node: this.node };
	}

	/** Advance past a timestamp seen from another device. */
	receive(remote: HLCTimestamp): HLCTimestamp {
		const w = this.now();
		const maxWall = Math.max(this.wall, remote.wall, w);
		if (maxWall === this.wall && maxWall === remote.wall) {
			this.counter = Math.max(this.counter, remote.counter) + 1;
		} else if (maxWall === this.wall) {
			this.counter = this.counter + 1;
		} else if (maxWall === remote.wall) {
			this.counter = remote.counter + 1;
		} else {
			this.counter = 0;
		}
		this.wall = maxWall;
		return { wall: this.wall, counter: this.counter, node: this.node };
	}

	/** <0 if a precedes b, >0 if a follows b, 0 only for the same device's write. */
	static compare(a: HLCTimestamp, b: HLCTimestamp): number {
		if (a.wall !== b.wall) return a.wall - b.wall;
		if (a.counter !== b.counter) return a.counter - b.counter;
		// Same instant on two devices: order by node id so every device agrees.
		return (a.node ?? '').localeCompare(b.node ?? '');
	}

	/** Lexicographically-sortable string form. */
	static pack(t: HLCTimestamp): string {
		return `${t.wall.toString().padStart(15, '0')}:${t.counter.toString().padStart(6, '0')}:${t.node ?? ''}`;
	}
	static unpack(s: string): HLCTimestamp {
		const [w, c, node] = s.split(':');
		return { wall: Number(w), counter: Number(c), node: node || undefined };
	}
}
