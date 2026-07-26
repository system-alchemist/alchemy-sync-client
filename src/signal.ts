/**
 * A minimal observable, deliberately shaped like a Svelte readable store:
 * `subscribe(fn)` calls `fn` immediately with the current value and returns an
 * unsubscribe function.
 *
 * That shape is why the sync client needs no framework. Svelte can consume a
 * Signal directly with `$signal`; React binds one with `useSyncExternalStore`;
 * a plain Node consumer just calls `get()`. Depending on `svelte/store` here
 * would have made the whole client unusable to the React/Electron app that also
 * needs it.
 */
export type Subscriber<T> = (value: T) => void;
export type Unsubscriber = () => void;

export class Signal<T> {
	private subscribers = new Set<Subscriber<T>>();

	constructor(private value: T) {}

	get(): T {
		return this.value;
	}

	set(value: T): void {
		this.value = value;
		// Copy first: a subscriber that unsubscribes while being notified would
		// otherwise mutate the set mid-iteration.
		for (const subscriber of [...this.subscribers]) subscriber(value);
	}

	subscribe(run: Subscriber<T>): Unsubscriber {
		this.subscribers.add(run);
		run(this.value);
		return () => {
			this.subscribers.delete(run);
		};
	}
}

/** Read a store's current value without holding a subscription. Works for any
 *  store following the subscribe contract, Signal and Svelte's alike. */
export function readStore<T>(store: { subscribe: (fn: Subscriber<T>) => Unsubscriber }): T {
	let value!: T;
	store.subscribe((v) => {
		value = v;
	})();
	return value;
}
