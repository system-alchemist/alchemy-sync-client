/**
 * Zero-knowledge crypto for E2E sync. WebCrypto for AES-GCM; audited @noble /
 * @scure for Argon2id, HKDF, HMAC, and the BIP39 recovery mnemonic.
 *
 * Key model (see docs/e2e-sync-design.md):
 *   password + salt --Argon2id--> PDK
 *   MEK = random 32 bytes; wrapped by PDK and by a recovery key.
 *   MEK --HKDF--> item-encryption key, item-id key.
 * The server only ever sees wrapped keys and encrypted item blobs.
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const utf8dec = new TextDecoder();

const KEY_LEN = 32; // AES-256
const NONCE_LEN = 12; // AES-GCM 96-bit
const SALT_LEN = 16;

/** Argon2id cost. `m` is memory in KiB. Production default is memory-hard;
 *  tests pass a cheaper profile so they stay fast. */
export interface Argon2Params {
	m: number;
	t: number;
	p: number;
}
export const DEFAULT_ARGON2: Argon2Params = { m: 65536, t: 3, p: 1 }; // 64 MiB, 3 passes

export function randomBytes(n: number): Uint8Array {
	return globalThis.crypto.getRandomValues(new Uint8Array(n));
}
export const generateSalt = () => randomBytes(SALT_LEN);
export const generateMEK = () => randomBytes(KEY_LEN);

function toHex(b: Uint8Array): string {
	let s = '';
	for (const x of b) s += x.toString(16).padStart(2, '0');
	return s;
}

/** Password + salt -> 32-byte password-derived key (Argon2id, memory-hard). */
export function deriveKeyFromPassword(
	password: string,
	salt: Uint8Array,
	params: Argon2Params = DEFAULT_ARGON2
): Uint8Array {
	return argon2id(utf8.encode(password), salt, { ...params, dkLen: KEY_LEN });
}

/**
 * The engine's two per-purpose keys, as **non-extractable** CryptoKeys: script
 * can use them but cannot read their bytes back, so an XSS foothold can't
 * exfiltrate the keys themselves. See importMasterKey.
 */
export interface ItemKeys {
	/** AES-GCM; encrypts item blobs. */
	itemKey: CryptoKey;
	/** HMAC-SHA256; derives opaque item ids. */
	itemIdKey: CryptoKey;
}

/**
 * Import the MEK as an HKDF base key. WebCrypto requires HKDF keys to be
 * non-extractable, so once the caller drops the raw bytes the master key can no
 * longer be read by script — only used. That is what lets a session resume from
 * IndexedDB without the master key ever being readable again.
 */
export function importMasterKey(mek: Uint8Array): Promise<CryptoKey> {
	return subtle.importKey('raw', ab(mek), 'HKDF', false, ['deriveKey']);
}

// An empty salt and noble's absent salt both reduce to HMAC's zero-padded block,
// so these derive byte-identical keys to the previous noble implementation —
// items written before this change stay readable.
const hkdfParams = (info: string): HkdfParams => ({
	name: 'HKDF',
	hash: 'SHA-256',
	salt: new Uint8Array(0),
	info: ab(utf8.encode(info))
});

/** Per-purpose subkeys from the master key (HKDF domain separation). */
export async function deriveItemKeys(master: CryptoKey): Promise<ItemKeys> {
	const [itemKey, itemIdKey] = await Promise.all([
		subtle.deriveKey(hkdfParams('item-enc'), master, { name: 'AES-GCM', length: 256 }, false, [
			'encrypt',
			'decrypt'
		]),
		subtle.deriveKey(
			hkdfParams('item-id'),
			master,
			{ name: 'HMAC', hash: 'SHA-256', length: 256 },
			false,
			['sign']
		)
	]);
	return { itemKey, itemIdKey };
}

/** NUL: cannot occur in a type or key, so the pairing is unambiguous. */
const ID_SEPARATOR = String.fromCharCode(0);

/**
 * Stable item id for a logical entity, so two devices that independently touch
 * the same (type,key) converge on ONE server item (no duplicates). Opaque to
 * the server (keyed HMAC), so it leaks neither the type nor the key.
 */
export async function deterministicItemId(
	itemIdKey: CryptoKey,
	type: string,
	key: string
): Promise<string> {
	const sig = await subtle.sign('HMAC', itemIdKey, ab(utf8.encode(`${type}${ID_SEPARATOR}${key}`)));
	return toHex(new Uint8Array(sig)).slice(0, 32);
}

// WebCrypto's BufferSource requires ArrayBuffer-backed views (not
// SharedArrayBuffer); noble/TextEncoder return Uint8Array<ArrayBufferLike>, so
// copy into a fresh ArrayBuffer-backed array at the boundary. Sizes are tiny.
function ab(x: Uint8Array): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(x.length);
	out.set(x);
	return out;
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
	return subtle.importKey('raw', ab(raw), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** AES-256-GCM. Output is nonce(12) || ciphertext; a fresh random nonce per call. */
export async function aesEncrypt(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
	const nonce = randomBytes(NONCE_LEN);
	const ck = await importAesKey(key);
	const ct = new Uint8Array(
		await subtle.encrypt({ name: 'AES-GCM', iv: ab(nonce) }, ck, ab(plaintext))
	);
	const out = new Uint8Array(NONCE_LEN + ct.length);
	out.set(nonce, 0);
	out.set(ct, NONCE_LEN);
	return out;
}

/** Reverse of aesEncrypt. Throws if the key is wrong or the blob was tampered. */
export async function aesDecrypt(key: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
	const nonce = blob.subarray(0, NONCE_LEN);
	const ct = blob.subarray(NONCE_LEN);
	const ck = await importAesKey(key);
	return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: ab(nonce) }, ck, ab(ct)));
}

/** Wrap/unwrap a key by encrypting it under a wrapping key (AES-GCM). */
export const wrapKey = (wrappingKey: Uint8Array, keyToWrap: Uint8Array) =>
	aesEncrypt(wrappingKey, keyToWrap);
export const unwrapKey = (wrappingKey: Uint8Array, wrapped: Uint8Array) =>
	aesDecrypt(wrappingKey, wrapped);

/** Encrypt/decrypt a JSON item under the non-extractable item key. */
export async function encryptItem(itemKey: CryptoKey, obj: unknown): Promise<Uint8Array> {
	const nonce = randomBytes(NONCE_LEN);
	const ct = new Uint8Array(
		await subtle.encrypt({ name: 'AES-GCM', iv: ab(nonce) }, itemKey, ab(utf8.encode(JSON.stringify(obj))))
	);
	const out = new Uint8Array(NONCE_LEN + ct.length);
	out.set(nonce, 0);
	out.set(ct, NONCE_LEN);
	return out;
}
export async function decryptItem<T>(itemKey: CryptoKey, blob: Uint8Array): Promise<T> {
	const plain = await subtle.decrypt(
		{ name: 'AES-GCM', iv: ab(blob.subarray(0, NONCE_LEN)) },
		itemKey,
		ab(blob.subarray(NONCE_LEN))
	);
	return JSON.parse(utf8dec.decode(new Uint8Array(plain))) as T;
}

// --- Recovery mnemonic (BIP39) ---
export const generateRecoveryMnemonic = () => generateMnemonic(wordlist, 256); // 24 words
export const isValidMnemonic = (m: string) => validateMnemonic(m.trim(), wordlist);
/** Derive a 32-byte recovery key from the mnemonic (HKDF over the BIP39 seed). */
export function keyFromMnemonic(mnemonic: string): Uint8Array {
	const seed = mnemonicToSeedSync(mnemonic.trim());
	return hkdf(sha256, seed, undefined, utf8.encode('alcove-recovery-key'), KEY_LEN);
}

/**
 * Proof-of-possession for the recovery phrase, sent to the server so it can
 * authorise a password reset.
 *
 * This is a SEPARATE HKDF branch from keyFromMnemonic: the server sees only
 * this value (and stores just an Argon2 hash of it), and cannot work back to
 * the wrapping key, so it still can't unwrap the master key. Guessing the
 * phrase is out of reach at 256 bits of BIP39 entropy.
 */
export function recoveryAuthFromMnemonic(mnemonic: string): Uint8Array {
	const seed = mnemonicToSeedSync(mnemonic.trim());
	return hkdf(sha256, seed, undefined, utf8.encode('alcove-recovery-auth'), KEY_LEN);
}

// --- Account-level helpers ---
export interface AccountKeyMaterial {
	salt: Uint8Array;
	wrappedByPassword: Uint8Array;
	wrappedByRecovery: Uint8Array;
	mnemonic: string; // show once, never stored server-side
}

/** Create a new account's key material. Persist salt + both wrapped keys
 *  server-side; surface the mnemonic to the user exactly once. */
export async function createAccountKeys(
	password: string,
	params: Argon2Params = DEFAULT_ARGON2
): Promise<{ mek: Uint8Array; material: AccountKeyMaterial }> {
	const salt = generateSalt();
	const mek = generateMEK();
	const mnemonic = generateRecoveryMnemonic();
	const pdk = deriveKeyFromPassword(password, salt, params);
	const recoveryKey = keyFromMnemonic(mnemonic);
	return {
		mek,
		material: {
			salt,
			wrappedByPassword: await wrapKey(pdk, mek),
			wrappedByRecovery: await wrapKey(recoveryKey, mek),
			mnemonic
		}
	};
}

/** Unlock the MEK with the password. Throws on a wrong password (GCM auth fail). */
export async function unlockWithPassword(
	password: string,
	salt: Uint8Array,
	wrappedByPassword: Uint8Array,
	params: Argon2Params = DEFAULT_ARGON2
): Promise<Uint8Array> {
	const pdk = deriveKeyFromPassword(password, salt, params);
	return unwrapKey(pdk, wrappedByPassword);
}

/** Unlock the MEK with the recovery mnemonic. */
export async function unlockWithRecovery(
	mnemonic: string,
	wrappedByRecovery: Uint8Array
): Promise<Uint8Array> {
	return unwrapKey(keyFromMnemonic(mnemonic), wrappedByRecovery);
}

/**
 * Re-wrap an existing MEK under a new password (fresh salt). Used by password
 * change and recovery: the master key itself never changes, so nothing has to
 * be re-encrypted and the recovery phrase keeps working.
 */
export async function rewrapWithPassword(
	mek: Uint8Array,
	newPassword: string,
	params: Argon2Params = DEFAULT_ARGON2
): Promise<{ salt: Uint8Array; wrappedByPassword: Uint8Array }> {
	const salt = generateSalt();
	const pdk = deriveKeyFromPassword(newPassword, salt, params);
	return { salt, wrappedByPassword: await wrapKey(pdk, mek) };
}
