import { describe, it, expect } from 'vitest';
import {
	linkGoogle,
	accountInfo,
	deleteAccount,
	GoogleOnOtherAccountError
} from './account.js';
import { unwrapWithGoogle } from './google.js';
import { base64ToBytes } from './base64.js';

const DAY = 24 * 60 * 60_000;

/**
 * A hub with accounts keyed by session token: `t-pw` is a password account
 * (alix@example.test), `t-g` a Google-only account that the identity
 * `google:sub-1:x@gmail.test` opens, holding 3 items.
 */
function fakeHub() {
	const accounts = new Map<string, { email: string; googleSub: string | null; wrappedByGoogle: string | null; hasPassword: boolean; items: number }>([
		['pw', { email: 'alix@example.test', googleSub: null, wrappedByGoogle: null, hasPassword: true, items: 10 }],
		['g', { email: 'x@gmail.test', googleSub: 'sub-1', wrappedByGoogle: 'old-wrap', hasPassword: false, items: 3 }]
	]);
	const sessions = new Map([['t-pw', 'pw'], ['t-g', 'g']]);
	const calls: string[] = [];
	const json = (status: number, body: unknown) =>
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

	const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = new URL(String(input), 'https://hub.test');
		const method = init?.method ?? 'GET';
		const token = (new Headers(init?.headers).get('authorization') ?? '').replace('Bearer ', '');
		const body = init?.body ? JSON.parse(String(init.body)) : {};
		calls.push(`${method} ${url.pathname} ${token}`);
		const id = sessions.get(token);
		if (!id) return json(401, { message: 'invalid or expired session' });
		const me = accounts.get(id)!;

		if (url.pathname === '/api/sync/account' && method === 'GET') {
			return json(200, { email: me.email, googleLinked: !!me.googleSub, hasPassword: me.hasPassword });
		}
		if (url.pathname === '/api/sync/account' && method === 'DELETE') {
			if (body.email !== me.email) return json(400, { message: 'that is not this account’s email' });
			accounts.delete(id);
			for (const [t, a] of sessions) if (a === id) sessions.delete(t);
			return new Response(null, { status: 204 });
		}
		if (url.pathname === '/api/sync/google/link' && method === 'POST') {
			const m = /^google:([^:]+):(.+)$/.exec(body.idToken ?? '');
			if (!m) return json(401, { message: 'Google did not accept that sign-in' });
			const sub = m[1];
			const holder = [...accounts.entries()].find(([, a]) => a.googleSub === sub);
			if (holder && holder[0] !== id) {
				const [hid, other] = holder;
				if (!body.confirmMove) {
					return json(409, {
						code: 'google-on-other-account',
						message: 'that Google account already opens a different library',
						other: { email: other.email, items: other.items, googleOnly: !other.hasPassword }
					});
				}
				if (!other.hasPassword) accounts.delete(hid);
				else other.googleSub = null;
				me.googleSub = sub;
				me.wrappedByGoogle = body.wrappedByGoogle;
				return json(200, { linked: true, moved: { email: other.email, deleted: !other.hasPassword } });
			}
			const already = me.googleSub === sub;
			me.googleSub = sub;
			me.wrappedByGoogle = body.wrappedByGoogle;
			return json(200, { linked: true, already, moved: null });
		}
		return json(404, { message: 'not found' });
	}) as typeof fetch;
	return { fetchFn, accounts, sessions, calls };
}

const mek = new Uint8Array(32).fill(7);
const secret = new Uint8Array(32).fill(9);

describe('linking Google to an existing account', () => {
	it('reports the account, links a free identity, and the wrapping opens with the Drive secret', async () => {
		const hub = fakeHub();
		expect(await accountInfo('', 't-pw', { fetchFn: hub.fetchFn })).toEqual({
			email: 'alix@example.test',
			googleLinked: false,
			hasPassword: true
		});
		const r = await linkGoogle('', 't-pw', { idToken: 'google:sub-9:alix@example.test', driveSecret: secret, mek }, { fetchFn: hub.fetchFn });
		expect(r).toEqual({ linked: true, already: false, moved: null });
		const stored = hub.accounts.get('pw')!;
		expect(stored.googleSub).toBe('sub-9');
		expect([...(await unwrapWithGoogle(secret, base64ToBytes(stored.wrappedByGoogle!)))]).toEqual([...mek]);
		expect((await accountInfo('', 't-pw', { fetchFn: hub.fetchFn })).googleLinked).toBe(true);
		// Linking again is a refresh of the wrapping, not an error.
		expect((await linkGoogle('', 't-pw', { idToken: 'google:sub-9:alix@example.test', driveSecret: secret, mek }, { fetchFn: hub.fetchFn })).already).toBe(true);
	});

	it('refuses an identity that opens another account until the move is confirmed, then deletes the Google-only one', async () => {
		const hub = fakeHub();
		const creds = { idToken: 'google:sub-1:x@gmail.test', driveSecret: secret, mek };
		const err = await linkGoogle('', 't-pw', creds, { fetchFn: hub.fetchFn }).catch((e) => e);
		expect(err).toBeInstanceOf(GoogleOnOtherAccountError);
		expect((err as GoogleOnOtherAccountError).other).toEqual({ email: 'x@gmail.test', items: 3, googleOnly: true });
		expect(hub.accounts.has('g')).toBe(true); // nothing moved yet

		const r = await linkGoogle('', 't-pw', { ...creds, confirmMove: true }, { fetchFn: hub.fetchFn });
		expect(r).toEqual({ linked: true, already: false, moved: { email: 'x@gmail.test', deleted: true } });
		expect(hub.accounts.get('pw')!.googleSub).toBe('sub-1');
		expect(hub.accounts.has('g')).toBe(false);
	});

	it('deletes an account only with its own email, and its sessions die with it', async () => {
		const hub = fakeHub();
		await expect(deleteAccount('', 't-g', 'someone@else.test', { fetchFn: hub.fetchFn })).rejects.toThrow(/email/);
		await deleteAccount('', 't-g', 'x@gmail.test', { fetchFn: hub.fetchFn });
		expect(hub.accounts.has('g')).toBe(false);
		await expect(accountInfo('', 't-g', { fetchFn: hub.fetchFn })).rejects.toThrow(/invalid or expired session/);
	});
});
