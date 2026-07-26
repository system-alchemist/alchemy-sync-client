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
} from './crypto';
import { bytesToBase64, base64ToBytes } from './base64';

type FetchFn = typeof globalThis.fetch;

export interface AccountSession {
	token: string;
	mek: Uint8Array;
}

interface AccountOpts {
	fetchFn?: FetchFn;
	/** Client PDK cost; must match between register and login for an account.
	 *  Defaults to the production profile; tests pass a cheaper one. */
	params?: Argon2Params;
}

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
	const { token } = (await res.json()) as { token: string };
	return { token, mek, mnemonic: material.mnemonic };
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
	const data = (await res.json()) as { token: string; salt: string; wrappedByPassword: string };
	const mek = await unlockWithPassword(
		password,
		base64ToBytes(data.salt),
		base64ToBytes(data.wrappedByPassword),
		opts.params ?? DEFAULT_ARGON2
	);
	return { token: data.token, mek };
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
	opts: AccountOpts = {}
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
			wrappedByPassword: bytesToBase64(rewrapped.wrappedByPassword)
		})
	});
	if (!res.ok) throw await readError(res);
	const { token } = (await res.json()) as { token: string };
	return { token, mek };
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
	const { token, mek } = await loginAccount(apiBase, email, currentPassword, opts);

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
	return { token, mek };
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
	const { token, mek } = await loginAccount(apiBase, email, currentPassword, opts);

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
	return { token, mek, mnemonic };
}
