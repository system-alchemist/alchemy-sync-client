/**
 * Portable base64 for the sync wire format — blobs are Uint8Array on both sides
 * but JSON can only carry strings. Uses btoa/atob (global in browsers and Node
 * 24), so the same helpers work in the client transport and in server routes.
 * Items are small (a bookmark, a progress record), so the byte-at-a-time loop is
 * fine; don't reach for this on large media.
 */
export function bytesToBase64(bytes: Uint8Array): string {
	let binary = '';
	for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
	return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
	const binary = atob(b64);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
	return out;
}
