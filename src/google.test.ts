import { describe, it, expect } from 'vitest';
import {
	driveSecret,
	DriveError,
	DRIVE_KEY_FILE,
	unwrapWithGoogle
} from './google.js';
import {
	signInWithGoogle,
	loginWithGoogle,
	recoverAccount,
	NoGoogleAccountError,
	DRIVE_KEY_MISMATCH_MESSAGE
} from './account.js';
import { SyncManager } from './manager.js';
import { memorySessionStore } from './session-store.js';
import { bytesToBase64, base64ToBytes } from './base64.js';

// Cheap Argon2 for the recovery re-wrap (the Google path itself has no KDF).
const CHEAP = { m: 256, t: 1, p: 1 };
const DAY = 24 * 60 * 60_000;

/**
 * One fetch that plays both Google Drive (the app-data folder) and the hub's
 * Google routes. Fake ID tokens are `google:<sub>:<email>`; anything else is
 * refused the way the hub refuses a token it cannot verify.
 */
function fakeWorld() {
	const drive = new Map<string, string>(); // fileId -> content
	const accounts = new Map<string, { email: string; wrappedByGoogle: string; wrappedByRecovery: string }>();
	const sessions = new Map<string, string>(); // token -> sub
	let nextId = 1;
	const calls: string[] = [];
	const json = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

	const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(String(input), 'https://hub.test');
		const method = init?.method ?? 'GET';
		const headers = new Headers(init?.headers);
		const bearer = (headers.get('authorization') ?? '').replace('Bearer ', '');
		calls.push(`${method} ${url.host}${url.pathname}`);

		// --- Google Drive ---
		if (url.host === 'www.googleapis.com') {
			if (bearer !== 'drive-token') return json(403, { error: { message: 'insufficient scope' } });
			if (url.pathname === '/drive/v3/files' && method === 'GET') {
				expect(url.searchParams.get('spaces')).toBe('appDataFolder');
				expect(url.searchParams.get('q')).toContain(DRIVE_KEY_FILE);
				return json(200, { files: [...drive.keys()].map((id) => ({ id, name: DRIVE_KEY_FILE })) });
			}
			if (url.pathname.startsWith('/drive/v3/files/') && url.searchParams.get('alt') === 'media') {
				const content = drive.get(url.pathname.split('/').pop()!);
				return content === undefined ? json(404, {}) : new Response(content, { status: 200 });
			}
			if (url.pathname === '/upload/drive/v3/files' && method === 'POST') {
				const ct = headers.get('content-type') ?? '';
				const boundary = /boundary=(.+)$/.exec(ct)?.[1];
				expect(boundary).toBeTruthy();
				const parts = String(init?.body).split(`--${boundary}`);
				const meta = JSON.parse(parts[1].split('\r\n\r\n')[1]);
				expect(meta.parents).toEqual(['appDataFolder']);
				expect(meta.name).toBe(DRIVE_KEY_FILE);
				const content = parts[2].split('\r\n\r\n')[1].trim();
				const id = `file-${nextId++}`;
				drive.set(id, content);
				return json(200, { id });
			}
			return json(404, {});
		}

		// --- the hub ---
		const body = init?.body ? JSON.parse(String(init.body)) : {};
		const identity = (idToken: string) => {
			const m = /^google:([^:]+):(.+)$/.exec(idToken ?? '');
			return m ? { sub: m[1], email: m[2] } : null;
		};
		if (url.pathname === '/api/sync/google/session' && method === 'POST') {
			const id = identity(body.idToken);
			if (!id) return json(401, { message: 'Google did not accept that sign-in' });
			const acct = accounts.get(id.sub);
			if (!acct) return json(404, { message: 'no account for this Google identity' });
			const token = `t-${nextId++}`;
			sessions.set(token, id.sub);
			return json(200, { token, expiresAt: Date.now() + 30 * DAY, email: acct.email, wrappedByGoogle: acct.wrappedByGoogle });
		}
		if (url.pathname === '/api/sync/google/register' && method === 'POST') {
			const id = identity(body.idToken);
			if (!id) return json(401, { message: 'Google did not accept that sign-in' });
			if (accounts.has(id.sub)) return json(409, { message: 'this Google account is already registered' });
			accounts.set(id.sub, { email: id.email, wrappedByGoogle: body.wrappedByGoogle, wrappedByRecovery: body.wrappedByRecovery });
			const token = `t-${nextId++}`;
			sessions.set(token, id.sub);
			return json(200, { token, expiresAt: Date.now() + 30 * DAY, email: id.email });
		}
		if (url.pathname === '/api/sync/recovery-material' && method === 'POST') {
			const acct = [...accounts.values()].find((a) => a.email === body.email);
			return json(200, { wrappedByRecovery: acct?.wrappedByRecovery ?? bytesToBase64(new Uint8Array(60)) });
		}
		if (url.pathname === '/api/sync/recover' && method === 'POST') {
			const entry = [...accounts.entries()].find(([, a]) => a.email === body.email);
			if (!entry) return json(401, { message: 'that recovery phrase does not match this account' });
			if (body.wrappedByGoogle) entry[1].wrappedByGoogle = body.wrappedByGoogle;
			const token = `t-${nextId++}`;
			sessions.set(token, entry[0]);
			return json(200, { token, expiresAt: Date.now() + 30 * DAY });
		}
		if (url.pathname.startsWith('/api/sync/items')) {
			if (!sessions.has(bearer)) return json(401, { message: 'invalid or expired session' });
			return method === 'POST' ? json(200, { acks: [] }) : json(200, { items: [] });
		}
		if (url.pathname === '/api/sync/session/refresh') return json(404, { message: 'no such route' });
		return json(404, { message: 'not found' });
	}) as typeof fetch;

	return { fetchFn, drive, accounts, calls };
}

const ALIX = 'google:sub-123:alix@example.test';

describe('sign in with Google', () => {
	it('first sign-in creates the Drive key file and the account; a second device reuses both', async () => {
		const world = fakeWorld();
		const { fetchFn } = world;

		// Device A: no key file yet → one is written, and the hub knows no account → registered.
		const a = await driveSecret('drive-token', { fetchFn });
		expect(a.created).toBe(true);
		expect(world.drive.size).toBe(1);
		const sessionA = await signInWithGoogle('', { idToken: ALIX, driveSecret: a.secret }, { fetchFn });
		expect(sessionA.mnemonic?.split(' ')).toHaveLength(24);
		expect(sessionA.email).toBe('alix@example.test');
		expect(sessionA.expiresAt).toBeGreaterThan(Date.now());

		// Device B: the same Google account reads the same file and signs in — no new phrase.
		const b = await driveSecret('drive-token', { fetchFn });
		expect(b.created).toBe(false);
		expect([...b.secret]).toEqual([...a.secret]);
		const sessionB = await signInWithGoogle('', { idToken: ALIX, driveSecret: b.secret }, { fetchFn });
		expect(sessionB.mnemonic).toBeUndefined();
		expect([...sessionB.mek]).toEqual([...sessionA.mek]);

		// The hub holds a wrapped key that only the Drive secret opens.
		const stored = base64ToBytes(world.accounts.get('sub-123')!.wrappedByGoogle);
		expect(bytesToBase64(stored)).not.toContain(bytesToBase64(sessionA.mek));
		await expect(unwrapWithGoogle(new Uint8Array(32), stored)).rejects.toThrow();
		expect([...(await unwrapWithGoogle(a.secret, stored))]).toEqual([...sessionA.mek]);
	});

	it('a replaced Drive key file cannot unlock the account, and says how to repair it', async () => {
		const world = fakeWorld();
		const { fetchFn } = world;
		const first = await driveSecret('drive-token', { fetchFn });
		const created = await signInWithGoogle('', { idToken: ALIX, driveSecret: first.secret }, { fetchFn });

		// The user cleared the app's Drive data; the next sign-in makes a fresh file.
		world.drive.clear();
		const replaced = await driveSecret('drive-token', { fetchFn });
		expect(replaced.created).toBe(true);
		await expect(
			signInWithGoogle('', { idToken: ALIX, driveSecret: replaced.secret }, { fetchFn })
		).rejects.toThrow(DRIVE_KEY_MISMATCH_MESSAGE);

		// Recovery with the phrase, passing the current Drive secret, re-wraps the key…
		const recovered = await recoverAccount('', 'alix@example.test', created.mnemonic!, 'a-new-password', {
			fetchFn,
			params: CHEAP,
			driveSecret: replaced.secret
		});
		expect([...recovered.mek]).toEqual([...created.mek]);
		// …and Google sign-in works again, with the same master key.
		const again = await loginWithGoogle('', { idToken: ALIX, driveSecret: replaced.secret }, { fetchFn });
		expect([...again.mek]).toEqual([...created.mek]);
	});

	it('an unknown identity is a NoGoogleAccountError from loginWithGoogle; a bad token is the hub message', async () => {
		const { fetchFn } = fakeWorld();
		const secret = new Uint8Array(32);
		await expect(loginWithGoogle('', { idToken: ALIX, driveSecret: secret }, { fetchFn })).rejects.toBeInstanceOf(
			NoGoogleAccountError
		);
		await expect(
			signInWithGoogle('', { idToken: 'not-a-google-token', driveSecret: secret }, { fetchFn })
		).rejects.toThrow('Google did not accept that sign-in');
	});

	it('a token without the app-data scope is refused by Drive with a message that says so', async () => {
		const { fetchFn } = fakeWorld();
		const err = await driveSecret('token-without-scope', { fetchFn }).catch((e) => e);
		expect(err).toBeInstanceOf(DriveError);
		expect((err as DriveError).status).toBe(403);
		expect((err as DriveError).message).toMatch(/app-data folder/);
	});

	it('the manager signs in with Google, persists the session and syncs', async () => {
		const { fetchFn } = fakeWorld();
		const store = memorySessionStore();
		const m = new SyncManager({ apiBase: '', deviceId: 'dev-1', sessionStore: store, fetchFn });
		const { secret } = await driveSecret('drive-token', { fetchFn });
		const { mnemonic } = await m.signInWithGoogle({ idToken: ALIX, driveSecret: secret });
		expect(mnemonic?.split(' ')).toHaveLength(24);
		expect(m.auth.get()).toEqual({ status: 'signed-in', email: 'alix@example.test' });
		await m.sync();
		expect(m.status.get()).toBe('idle');
		expect((await store.load())?.email).toBe('alix@example.test');
		m.signOut();
	});
});
