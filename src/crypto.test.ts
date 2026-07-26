import { describe, it, expect } from 'vitest';
import {
	createAccountKeys,
	unlockWithPassword,
	unlockWithRecovery,
	encryptItem,
	decryptItem,
	importMasterKey,
	deriveItemKeys,
	deterministicItemId,
	generateMEK,
	isValidMnemonic,
	type Argon2Params
} from './crypto.js';

// Cheap Argon2 so tests stay fast; production uses the memory-hard default.
const FAST: Argon2Params = { m: 8192, t: 1, p: 1 };

/** The engine's key pair, derived the way SyncEngine does. */
async function itemKeys(mek = generateMEK()) {
	return deriveItemKeys(await importMasterKey(mek));
}

describe('item encryption', () => {
	it('round-trips a JSON item', async () => {
		const { itemKey } = await itemKeys();
		const obj = { a: 1, b: 'héllo', nested: { x: [1, 2, 3] } };
		const blob = await encryptItem(itemKey, obj);
		expect(await decryptItem(itemKey, blob)).toEqual(obj);
	});

	it('fails to decrypt with the wrong key', async () => {
		const mine = await itemKeys();
		const theirs = await itemKeys();
		const blob = await encryptItem(mine.itemKey, { secret: true });
		await expect(decryptItem(theirs.itemKey, blob)).rejects.toThrow();
	});

	it('uses a fresh nonce (same plaintext -> different ciphertext)', async () => {
		const { itemKey } = await itemKeys();
		const a = await encryptItem(itemKey, { x: 1 });
		const b = await encryptItem(itemKey, { x: 1 });
		expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
	});
});

describe('subkeys and item ids', () => {
	it('derives purpose-separated subkeys that cannot be exported', async () => {
		const mek = generateMEK();
		const { itemKey, itemIdKey } = await itemKeys(mek);
		expect(itemKey.extractable).toBe(false);
		expect(itemIdKey.extractable).toBe(false);
		// Purpose separation: the encryption key can't sign, the id key can't decrypt.
		expect(itemKey.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));
		expect(itemIdKey.usages).toEqual(['sign']);
		await expect(globalThis.crypto.subtle.exportKey('raw', itemKey)).rejects.toThrow();
	});

	it('item id is stable per (type,key) and varies otherwise', async () => {
		const { itemIdKey: k } = await itemKeys();
		expect(await deterministicItemId(k, 'progress', 'w1')).toBe(
			await deterministicItemId(k, 'progress', 'w1')
		);
		expect(await deterministicItemId(k, 'progress', 'w1')).not.toBe(
			await deterministicItemId(k, 'progress', 'w2')
		);
		expect(await deterministicItemId(k, 'progress', 'w1')).not.toBe(
			await deterministicItemId(k, 'bookmark', 'w1')
		);
	});

	it('gives different accounts different ids for the same entity', async () => {
		const one = await itemKeys();
		const two = await itemKeys();
		expect(await deterministicItemId(one.itemIdKey, 'progress', 'w1')).not.toBe(
			await deterministicItemId(two.itemIdKey, 'progress', 'w1')
		);
	});
});

describe('account key material', () => {
	it('unlocks the same MEK with the right password', async () => {
		const { mek, material } = await createAccountKeys('correct horse', FAST);
		const unlocked = await unlockWithPassword('correct horse', material.salt, material.wrappedByPassword, FAST);
		expect(Buffer.from(unlocked).equals(Buffer.from(mek))).toBe(true);
	});

	it('rejects a wrong password', async () => {
		const { material } = await createAccountKeys('correct horse', FAST);
		await expect(
			unlockWithPassword('wrong', material.salt, material.wrappedByPassword, FAST)
		).rejects.toThrow();
	});

	it('recovers the same MEK from the mnemonic', async () => {
		const { mek, material } = await createAccountKeys('pw', FAST);
		expect(isValidMnemonic(material.mnemonic)).toBe(true);
		expect(material.mnemonic.split(' ')).toHaveLength(24);
		const unlocked = await unlockWithRecovery(material.mnemonic, material.wrappedByRecovery);
		expect(Buffer.from(unlocked).equals(Buffer.from(mek))).toBe(true);
	});
});
