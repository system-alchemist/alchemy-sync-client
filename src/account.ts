/**
 * Client-side account flows for sync. The zero-knowledge boundary lives here:
 * key material is generated and unwrapped on-device, and only *wrapped* keys +
 * salt ever cross the wire. The MEK and the password-derived key never leave.
 */
import {
	createAccountKeys,
	unlockWithPassword,
	unlockWithRecovery,
	recoveryAuthFromMnemonic,
	rewrapWithPassword,
	isValidMnemonic,
	generateRecoveryMnemonic,
	keyFromMnemonic,
	wrapKey,
	DEFAULT_ARGON2,
	type Argon2Params
} from './crypto.js';
import { generateMEK } from './crypto.js';
import { bytesToBase64, base64ToBytes } from './base64.js';
import { SyncAuthError } from './transport.js';
import { wrapWithGoogle, unwrapWithGoogle } from './google.js';

type FetchFn = typeof globalThis.fetch;

export interface AccountSession {
	token: string;
	mek: Uint8Array;
	/** When the hub will stop honouring `token` (ms since epoch). Hubs that
	 *  don't report it leave this undefined; the manager then refreshes blind. */
	expiresAt?: number;
}

/** `expiresAt` from a session response, if the hub sent a usable one. */
function expiryOf(data: { expiresAt?: unknown }): number | undefined {
	return typeof data.expiresAt === 'number' && Number.isFinite(data.expiresAt) ? data.expiresAt : undefined;
}

interface AccountOpts {
	fetchFn?: FetchFn;
	/** Client PDK cost; must match between register and login for an account.
	 *  Defaults to the production profile; tests pass a cheaper one. */
	params?: Argon2Params;
}

/** What "sign in with Google" hands the account flows: the ID token Google
 *  issued for this app, and the secret from the user's Drive app-data folder
 *  (see google.ts — `driveSecret()` reads or creates it). */
export interface GoogleCredentials {
	idToken: string;
	driveSecret: Uint8Array;
}

/** The hub knows no account for this Google identity yet: register one. */
export class NoGoogleAccountError extends Error {
	constructor() {
		super('no account for this Google identity yet');
		this.name = 'NoGoogleAccountError';
	}
}

/** The Drive key file does not unlock this account's wrapped key. The file was
 *  replaced or the account was registered from another Drive; the recovery
 *  phrase (with `recoverAccount`, passing the current Drive secret) repairs it. */
export const DRIVE_KEY_MISMATCH_MESSAGE =
	'The key in your Google Drive does not unlock this account. Recover it with your recovery phrase to repair the link.';

async function readError(res: Response): Promise<Error> {
	let message = `request failed (${res.status})`;
	try {
		const body = (await res.json()) as { message?: string };
		if (body?.message) message = body.message;
	} catch {
		/* non-JSON error body — keep the status message */
	}
	return new Error(message);
}

/** Register: generate key material locally, send only the salt + wrapped keys,
 *  and surface the recovery mnemonic exactly once (never stored server-side). */
export async function registerAccount(
	apiBase: string,
	email: string,
	password: string,
	opts: AccountOpts = {}
): Promise<AccountSession & { mnemonic: string }> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const { mek, material } = await createAccountKeys(password, opts.params ?? DEFAULT_ARGON2);
	const res = await fetchFn(`${apiBase}/api/sync/register`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			email,
			password,
			salt: bytesToBase64(material.salt),
			wrappedByPassword: bytesToBase64(material.wrappedByPassword),
			wrappedByRecovery: bytesToBase64(material.wrappedByRecovery),
			// Proof we can later present to reset the password. A different HKDF
			// branch from the wrapping key, so the server still can't unwrap.
			recoveryAuth: bytesToBase64(recoveryAuthFromMnemonic(material.mnemonic))
		})
	});
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as { token: string; expiresAt?: number };
	return { token: data.token, mek, mnemonic: material.mnemonic, expiresAt: expiryOf(data) };
}

/** Log in: the server returns salt + password-wrapped MEK; we derive the PDK
 *  locally and unwrap the MEK here. A wrong password fails as a GCM auth error. */
export async function loginAccount(
	apiBase: string,
	email: string,
	password: string,
	opts: AccountOpts = {}
): Promise<AccountSession> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const res = await fetchFn(`${apiBase}/api/sync/session`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as {
		token: string;
		salt: string;
		wrappedByPassword: string;
		expiresAt?: number;
	};
	const mek = await unlockWithPassword(
		password,
		base64ToBytes(data.salt),
		base64ToBytes(data.wrappedByPassword),
		opts.params ?? DEFAULT_ARGON2
	);
	return { token: data.token, mek, expiresAt: expiryOf(data) };
}

/**
 * Reset a forgotten password with the 24-word recovery phrase.
 *
 * The phrase unwraps the master key locally, then re-wraps it under the new
 * password; the server only ever sees ciphertext plus a proof-of-possession
 * derived from a separate HKDF branch. Because the master key itself is
 * unchanged, all existing synced data stays readable.
 */
export async function recoverAccount(
	apiBase: string,
	email: string,
	mnemonic: string,
	newPassword: string,
	opts: AccountOpts & {
		/** For an account that signs in with Google: re-wrap the key under this
		 *  device's Drive secret as well, so the Google path works again after
		 *  the Drive file was lost or replaced. */
		driveSecret?: Uint8Array;
	} = {}
): Promise<AccountSession> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const phrase = mnemonic.trim().replace(/\s+/g, ' ');
	if (!isValidMnemonic(phrase)) {
		throw new Error('That does not look like a valid 24-word recovery phrase.');
	}

	const materialRes = await fetchFn(`${apiBase}/api/sync/recovery-material`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ email })
	});
	if (!materialRes.ok) throw await readError(materialRes);
	const { wrappedByRecovery } = (await materialRes.json()) as { wrappedByRecovery: string };

	// Wrong phrase for this account => GCM auth failure here, before anything is sent.
	let mek: Uint8Array;
	try {
		mek = await unlockWithRecovery(phrase, base64ToBytes(wrappedByRecovery));
	} catch {
		throw new Error('That recovery phrase does not match this account.');
	}

	const rewrapped = await rewrapWithPassword(mek, newPassword, opts.params ?? DEFAULT_ARGON2);
	const res = await fetchFn(`${apiBase}/api/sync/recover`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			email,
			recoveryAuth: bytesToBase64(recoveryAuthFromMnemonic(phrase)),
			newPassword,
			salt: bytesToBase64(rewrapped.salt),
			wrappedByPassword: bytesToBase64(rewrapped.wrappedByPassword),
			...(opts.driveSecret
				? { wrappedByGoogle: bytesToBase64(await wrapWithGoogle(opts.driveSecret, mek)) }
				: {})
		})
	});
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as { token: string; expiresAt?: number };
	return { token: data.token, mek, expiresAt: expiryOf(data) };
}

/**
 * Change the password of a signed-in account.
 *
 * The current password is needed for more than authorisation: it is the only
 * way to recover the raw master key (the live session holds it as a
 * non-extractable CryptoKey by design), so it can be re-wrapped under the new
 * password. Signing in again is what yields those bytes. The recovery phrase
 * still works afterwards, since the master key is untouched.
 */
export async function changeAccountPassword(
	apiBase: string,
	email: string,
	currentPassword: string,
	newPassword: string,
	opts: AccountOpts = {}
): Promise<AccountSession> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const params = opts.params ?? DEFAULT_ARGON2;

	// Proves the current password and hands back the raw master key.
	const { token, mek, expiresAt } = await loginAccount(apiBase, email, currentPassword, opts);

	const rewrapped = await rewrapWithPassword(mek, newPassword, params);
	const res = await fetchFn(`${apiBase}/api/sync/password`, {
		method: 'POST',
		headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
		body: JSON.stringify({
			currentPassword,
			newPassword,
			salt: bytesToBase64(rewrapped.salt),
			wrappedByPassword: bytesToBase64(rewrapped.wrappedByPassword)
		})
	});
	if (!res.ok) throw await readError(res);
	// This session survives; the server drops the account's other sessions.
	return { token, mek, expiresAt };
}

/**
 * Issue a new recovery phrase, retiring the old one.
 *
 * Like a password change this needs the current password: it authorises the
 * change and is the only way back to the raw master key (the session holds it
 * as a non-extractable CryptoKey). The master key is re-wrapped under the new
 * phrase, so synced data is untouched — only the old phrase stops working.
 */
export async function regenerateRecoveryPhrase(
	apiBase: string,
	email: string,
	currentPassword: string,
	opts: AccountOpts = {}
): Promise<AccountSession & { mnemonic: string }> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;

	// Proves the current password and hands back the raw master key.
	const { token, mek, expiresAt } = await loginAccount(apiBase, email, currentPassword, opts);

	const mnemonic = generateRecoveryMnemonic();
	const wrappedByRecovery = await wrapKey(keyFromMnemonic(mnemonic), mek);
	const res = await fetchFn(`${apiBase}/api/sync/recovery-phrase`, {
		method: 'POST',
		headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
		body: JSON.stringify({
			currentPassword,
			wrappedByRecovery: bytesToBase64(wrappedByRecovery),
			recoveryAuth: bytesToBase64(recoveryAuthFromMnemonic(mnemonic))
		})
	});
	if (!res.ok) throw await readError(res);
	return { token, mek, mnemonic, expiresAt };
}

/**
 * Sign in to an existing account with Google. The hub verifies the ID token,
 * finds the account by Google's stable subject id, opens a session and returns
 * the Google-wrapped master key; the Drive secret unwraps it here. A hub that
 * knows no account for this identity answers 404 → NoGoogleAccountError, which
 * `signInWithGoogle` turns into a registration.
 */
export async function loginWithGoogle(
	apiBase: string,
	creds: GoogleCredentials,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<AccountSession & { email: string }> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const res = await fetchFn(`${apiBase}/api/sync/google/session`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ idToken: creds.idToken })
	});
	if (res.status === 404) throw new NoGoogleAccountError();
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as {
		token: string;
		email: string;
		wrappedByGoogle: string;
		expiresAt?: number;
	};
	let mek: Uint8Array;
	try {
		mek = await unwrapWithGoogle(creds.driveSecret, base64ToBytes(data.wrappedByGoogle));
	} catch {
		throw new Error(DRIVE_KEY_MISMATCH_MESSAGE);
	}
	return { token: data.token, mek, email: data.email, expiresAt: expiryOf(data) };
}

/**
 * Create an account for a Google identity. Key material is generated here as
 * for a password account — a fresh master key, wrapped under the Drive secret
 * and under a new recovery phrase — and only the wrapped forms travel. The
 * email comes from the verified ID token, not from the caller. Surface the
 * mnemonic exactly once.
 */
export async function registerWithGoogle(
	apiBase: string,
	creds: GoogleCredentials,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<AccountSession & { email: string; mnemonic: string }> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const mek = generateMEK();
	const mnemonic = generateRecoveryMnemonic();
	const res = await fetchFn(`${apiBase}/api/sync/google/register`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({
			idToken: creds.idToken,
			wrappedByGoogle: bytesToBase64(await wrapWithGoogle(creds.driveSecret, mek)),
			wrappedByRecovery: bytesToBase64(await wrapKey(keyFromMnemonic(mnemonic), mek)),
			recoveryAuth: bytesToBase64(recoveryAuthFromMnemonic(mnemonic))
		})
	});
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as { token: string; email: string; expiresAt?: number };
	return { token: data.token, mek, email: data.email, mnemonic, expiresAt: expiryOf(data) };
}

/**
 * The one call an app makes for its "Sign in with Google" button: sign in when
 * the account exists, create it when it does not. `mnemonic` is present only
 * when an account was just created — show it once, the way sign-up does.
 */
export async function signInWithGoogle(
	apiBase: string,
	creds: GoogleCredentials,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<AccountSession & { email: string; mnemonic?: string }> {
	try {
		return await loginWithGoogle(apiBase, creds, opts);
	} catch (e) {
		if (e instanceof NoGoogleAccountError) return registerWithGoogle(apiBase, creds, opts);
		throw e;
	}
}

/** What the hub knows about the signed-in account, for the settings UI. */
export interface AccountInfo {
	email: string;
	/** A Google identity opens this account (Sign in with Google lands here). */
	googleLinked: boolean;
	/** The account has a password (false for one created by Google sign-in). */
	hasPassword: boolean;
}

/** GET /api/sync/account with the session token. */
export async function accountInfo(
	apiBase: string,
	token: string,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<AccountInfo> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const res = await fetchFn(`${apiBase}/api/sync/account`, {
		headers: { authorization: `Bearer ${token}` }
	});
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as { email: string; googleLinked?: boolean; hasPassword?: boolean };
	return { email: data.email, googleLinked: data.googleLinked === true, hasPassword: data.hasPassword !== false };
}

/** The Google identity presented for linking already opens a different
 *  account. `other` says which, so the app can ask before moving it. */
export class GoogleOnOtherAccountError extends Error {
	constructor(readonly other: { email: string; items: number; googleOnly: boolean }) {
		super(`that Google account already opens a different library (${other.email})`);
		this.name = 'GoogleOnOtherAccountError';
	}
}

export interface LinkGoogleInput {
	idToken: string;
	driveSecret: Uint8Array;
	/** The account's raw master key — only a host that holds it at rest (or has
	 *  it fresh from a sign-in) can link, since the key must be re-wrapped
	 *  under the Drive secret. The manager's non-extractable key cannot. */
	mek: Uint8Array;
	/** The identity is on another account: yes, move it here. A Google-only
	 *  account left with no way in is deleted by the hub; one with a password
	 *  merely loses Google. */
	confirmMove?: boolean;
}

/**
 * Attach a Google identity to the signed-in account, so Sign in with Google
 * lands here on every device. Re-wraps the master key under the Drive secret
 * (the same wrapping a Google sign-up makes) and sends only that. Linking the
 * same identity again just refreshes the wrapping.
 */
export async function linkGoogle(
	apiBase: string,
	token: string,
	input: LinkGoogleInput,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<{ linked: true; already: boolean; moved: { email: string; deleted: boolean } | null }> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const res = await fetchFn(`${apiBase}/api/sync/google/link`, {
		method: 'POST',
		headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
		body: JSON.stringify({
			idToken: input.idToken,
			wrappedByGoogle: bytesToBase64(await wrapWithGoogle(input.driveSecret, input.mek)),
			...(input.confirmMove ? { confirmMove: true } : {})
		})
	});
	if (res.status === 409) {
		const body = (await res.json().catch(() => null)) as
			| { code?: string; message?: string; other?: { email: string; items: number; googleOnly: boolean } }
			| null;
		if (body?.code === 'google-on-other-account' && body.other) throw new GoogleOnOtherAccountError(body.other);
		throw new Error(body?.message ?? 'request failed (409)');
	}
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as { already?: boolean; moved?: { email: string; deleted: boolean } | null };
	return { linked: true, already: data.already === true, moved: data.moved ?? null };
}

/**
 * Delete the signed-in account and everything the hub holds for it: sessions,
 * every encrypted item, the wrapped keys. The email is required as a
 * deliberate second step; the hub refuses a mismatch. Irreversible.
 */
export async function deleteAccount(
	apiBase: string,
	token: string,
	email: string,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<void> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const res = await fetchFn(`${apiBase}/api/sync/account`, {
		method: 'DELETE',
		headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
		body: JSON.stringify({ email })
	});
	if (!res.ok && res.status !== 204) throw await readError(res);
}

/**
 * Rotate a session token before (or just after) it expires. The hub keeps the
 * presented token valid for a short grace so requests in flight complete.
 * 401/403 surface as SyncAuthError — a *candidate* for "the hub ended the
 * session"; the manager confirms it against the items endpoint before acting,
 * because a 403 can also be an edge or a framework guard (SvelteKit's CSRF
 * check answered a bodiless POST from a WebView with exactly that). Any other
 * failure — offline, hub down, or a hub without this endpoint yet (404) — is
 * an ordinary Error the caller may ignore and retry later.
 *
 * Always a JSON body: a mutating request without a content type looks like a
 * cross-site form post to the hub's CSRF protection and is refused before it
 * reaches any route.
 */
export async function refreshSession(
	apiBase: string,
	token: string,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<{ token: string; expiresAt?: number }> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const res = await fetchFn(`${apiBase}/api/sync/session/refresh`, {
		method: 'POST',
		headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
		body: '{}'
	});
	if (res.status === 401 || res.status === 403) {
		throw new SyncAuthError(res.status, (await readError(res)).message);
	}
	if (!res.ok) throw await readError(res);
	const data = (await res.json()) as { token: string; expiresAt?: number };
	if (typeof data.token !== 'string' || !data.token) throw new Error('refresh returned no token');
	return { token: data.token, expiresAt: expiryOf(data) };
}

/**
 * Is `token` still honoured? A plain read of the items endpoint, past every
 * sequence number, so nothing is transferred. Only the hub's own 401 says no;
 * anything else (offline, an edge's 403, a 5xx) leaves the question open.
 */
export async function tokenStillValid(
	apiBase: string,
	token: string,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<'valid' | 'invalid' | 'unknown'> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	try {
		const res = await fetchFn(`${apiBase}/api/sync/items?since=2147483647`, {
			headers: { authorization: `Bearer ${token}` }
		});
		if (res.status === 401) return 'invalid';
		return res.ok ? 'valid' : 'unknown';
	} catch {
		return 'unknown';
	}
}

/** Tell the hub this device is done with its token (sign-out). Best effort:
 *  the local session is gone either way. */
export async function endSession(
	apiBase: string,
	token: string,
	opts: Pick<AccountOpts, 'fetchFn'> = {}
): Promise<void> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	try {
		await fetchFn(`${apiBase}/api/sync/session`, {
			method: 'DELETE',
			headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
			body: '{}'
		});
	} catch {
		/* offline: the hub's copy expires on its own */
	}
}
