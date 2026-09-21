/**
 * Sign in with Google — identity from Google, the key from the user's own Drive.
 *
 * Google proves who the user is (an OIDC ID token) but hands over no secret, so
 * it cannot replace the password in the key model on its own. What replaces it
 * is a random 32-byte secret kept in the user's Drive *app-data folder*: a
 * hidden, per-app space that only this app's OAuth client can read, tied to the
 * user's Google account. The master key is wrapped under a key derived from
 * that secret and stored on the hub, exactly like the password wrapping.
 *
 * Trust, honestly: the hub still holds only ciphertext and cannot unwrap
 * anything; Google holds the Drive secret but never sees the hub's ciphertext.
 * Either party alone cannot read the library; both together could. That is the
 * trade "sign in with Google" makes, and the privacy copy in every app says so.
 * The recovery phrase works unchanged and is the way back if the Drive file is
 * ever lost.
 *
 * Needs an OAuth access token carrying the `drive.appdata` scope
 * (https://www.googleapis.com/auth/drive.appdata) — the app obtains it
 * however its platform does (a native sign-in on the phone, the auth-code flow
 * on the web) and passes it here; this module never talks to Google's sign-in.
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, wrapKey, unwrapKey } from './crypto.js';
import { bytesToBase64, base64ToBytes } from './base64.js';

type FetchFn = typeof globalThis.fetch;

const DRIVE_API = 'https://www.googleapis.com/drive/v3';
const DRIVE_UPLOAD = 'https://www.googleapis.com/upload/drive/v3';
/** The one file this app keeps in the user's Drive app-data folder. */
export const DRIVE_KEY_FILE = 'alchemylab-sync-key.json';
/** The OAuth scope the access token must carry. */
export const DRIVE_APPDATA_SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
const SECRET_LEN = 32;
const utf8 = new TextEncoder();

/** The wrapping key for Google accounts: HKDF over the Drive secret. A distinct
 *  label from every other branch, so the secret never doubles as anything else. */
export function googleWrappingKey(driveSecret: Uint8Array): Uint8Array {
	return hkdf(sha256, driveSecret, undefined, utf8.encode('alchemylab-google-wrap'), 32);
}
export const wrapWithGoogle = (driveSecret: Uint8Array, mek: Uint8Array): Promise<Uint8Array> =>
	wrapKey(googleWrappingKey(driveSecret), mek);
export const unwrapWithGoogle = (driveSecret: Uint8Array, wrapped: Uint8Array): Promise<Uint8Array> =>
	unwrapKey(googleWrappingKey(driveSecret), wrapped);

export interface DriveSecret {
	secret: Uint8Array;
	/** True when no key file existed and one was just written: a first sign-in
	 *  on this Google account (or the file had been deleted). */
	created: boolean;
	fileId: string;
}

/** Google's Drive API said no. `status` is the HTTP status it answered with. */
export class DriveError extends Error {
	constructor(
		readonly status: number,
		message: string
	) {
		super(message);
		this.name = 'DriveError';
	}
}

async function driveFail(what: string, res: Response): Promise<DriveError> {
	let detail = '';
	try {
		const body = (await res.json()) as { error?: { message?: string } };
		if (body?.error?.message) detail = `: ${body.error.message}`;
	} catch {
		/* not JSON */
	}
	if (res.status === 401 || res.status === 403) {
		return new DriveError(res.status, `Google Drive refused to ${what} the key file${detail} — the sign-in must grant this app its own app-data folder`);
	}
	return new DriveError(res.status, `Google Drive could not ${what} the key file (${res.status})${detail}`);
}

/**
 * The account's Drive secret: read from the app-data folder, or created there
 * when absent. Idempotent for one user across devices — every device that
 * signs in with the same Google account reads the same file.
 *
 * Two devices signing in for the very first time within the same second could
 * each create a file; the hub accepts only one registration, so the loser then
 * fails to unwrap and is told to recover. Rare enough to leave to the phrase.
 */
export async function driveSecret(
	accessToken: string,
	opts: { fetchFn?: FetchFn } = {}
): Promise<DriveSecret> {
	const fetchFn = opts.fetchFn ?? globalThis.fetch;
	const auth = { authorization: `Bearer ${accessToken}` };

	const q = encodeURIComponent(`name = '${DRIVE_KEY_FILE}' and trashed = false`);
	const list = await fetchFn(`${DRIVE_API}/files?spaces=appDataFolder&fields=files(id,name)&q=${q}`, {
		headers: auth
	});
	if (!list.ok) throw await driveFail('list', list);
	const { files } = (await list.json()) as { files?: Array<{ id: string; name: string }> };
	const existing = files?.[0];

	if (existing) {
		const res = await fetchFn(`${DRIVE_API}/files/${existing.id}?alt=media`, { headers: auth });
		if (!res.ok) throw await driveFail('read', res);
		const body = (await res.json().catch(() => null)) as { v?: unknown; secret?: unknown } | null;
		if (body?.v !== 1 || typeof body.secret !== 'string') {
			throw new DriveError(res.status, 'the key file in Google Drive is not in a form this app understands');
		}
		const secret = base64ToBytes(body.secret);
		if (secret.length !== SECRET_LEN) {
			throw new DriveError(res.status, 'the key file in Google Drive is damaged');
		}
		return { secret, created: false, fileId: existing.id };
	}

	const secret = randomBytes(SECRET_LEN);
	const boundary = `alchemylab-${Date.now().toString(36)}-${bytesToBase64(randomBytes(6)).replace(/[^a-z0-9]/gi, '')}`;
	const metadata = JSON.stringify({
		name: DRIVE_KEY_FILE,
		parents: ['appDataFolder'],
		mimeType: 'application/json'
	});
	const content = JSON.stringify({ v: 1, secret: bytesToBase64(secret), createdAt: new Date().toISOString() });
	const body =
		`--${boundary}\r\ncontent-type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n` +
		`--${boundary}\r\ncontent-type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
	const res = await fetchFn(`${DRIVE_UPLOAD}/files?uploadType=multipart&fields=id`, {
		method: 'POST',
		headers: { ...auth, 'content-type': `multipart/related; boundary=${boundary}` },
		body
	});
	if (!res.ok) throw await driveFail('create', res);
	const { id } = (await res.json()) as { id: string };
	return { secret, created: true, fileId: id };
}
