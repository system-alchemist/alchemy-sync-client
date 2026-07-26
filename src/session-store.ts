/**
 * Where a signed-in sync session lives between page loads.
 *
 * The master key is persisted as a **non-extractable CryptoKey**, not as bytes:
 * IndexedDB stores CryptoKey objects via structured clone, and a key imported
 * with `extractable: false` can be *used* by script but never read back out. So
 * script — including anything that slips in through an XSS hole — can decrypt
 * while the session is live, but cannot copy the key off the device. Raw bytes
 * in localStorage/sessionStorage offer no such protection.
 *
 * Sessions therefore survive closing the tab, and end at sign-out.
 */
const DB_NAME = 'alcove-sync';
const DB_VERSION = 1;
const STORE = 'session';
const RECORD_KEY = 'current';

/**
 * Where a signed-in session is kept between page loads. Injectable so a host
 * without IndexedDB (an Electron main process, a Node service) can supply its
 * own; browser and Electron-renderer consumers use indexedDbSessionStore.
 */
export interface SessionStore {
	load(): Promise<PersistedSession | null>;
	/** False when the session could not be persisted; sync still works for this
	 *  page, it just will not resume. */
	save(session: PersistedSession): Promise<boolean>;
	clear(): Promise<void>;
}

export interface PersistedSession {
	token: string;
	email: string;
	/** Non-extractable HKDF master key (see crypto.importMasterKey). */
	masterKey: CryptoKey;
}

function openDb(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, DB_VERSION);
		req.onupgradeneeded = () => {
			if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}

function tx<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
	return openDb().then(
		(db) =>
			new Promise<T>((resolve, reject) => {
				const request = run(db.transaction(STORE, mode).objectStore(STORE));
				request.onsuccess = () => resolve(request.result);
				request.onerror = () => reject(request.error);
				db.onclose = () => reject(new Error('database closed'));
			})
	);
}

/**
 * Best-effort: where IndexedDB is unavailable or refuses to store a CryptoKey
 * (private-browsing modes do both), the session simply doesn't outlive the page.
 * Sync still works for this page load, so a storage failure must not break it.
 */
export async function saveSession(session: PersistedSession): Promise<boolean> {
	try {
		await tx('readwrite', (store) => store.put(session, RECORD_KEY));
		return true;
	} catch {
		return false;
	}
}

/** The stored session, or null when signed out (or storage is unavailable —
 *  private-mode browsers can reject IndexedDB, which must not break the app). */
export async function loadSession(): Promise<PersistedSession | null> {
	try {
		const value = await tx<PersistedSession | undefined>('readonly', (store) =>
			store.get(RECORD_KEY)
		);
		return value ?? null;
	} catch {
		return null;
	}
}

export async function clearSession(): Promise<void> {
	try {
		await tx('readwrite', (store) => store.delete(RECORD_KEY));
	} catch {
		// Nothing usable to clear.
	}
}

/** IndexedDB-backed store: the default for browsers and Electron renderers. */
export const indexedDbSessionStore: SessionStore = {
	load: loadSession,
	save: saveSession,
	clear: clearSession
};

/** In-memory fallback for hosts with no IndexedDB. The session then lasts only
 *  as long as the process, which is the honest behaviour for a CLI or server. */
export function memorySessionStore(): SessionStore {
	let current: PersistedSession | null = null;
	return {
		async load() {
			return current;
		},
		async save(session) {
			current = session;
			return true;
		},
		async clear() {
			current = null;
		}
	};
}
