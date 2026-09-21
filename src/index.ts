/**
 * Public surface of the shared sync client.
 *
 * This directory is the whole client: crypto, the merge engine, the transport,
 * the account flows and the manager, with no framework imports. It is consumed
 * by Alcove through a small SvelteKit binding ($lib/stores/sync.ts) and is
 * intended to be consumed by SCP Ultimate (React/Electron) the same way through
 * a binding of its own — see PORTING.md.
 *
 * Sharing the code rather than reimplementing it is not tidiness: cross-app
 * reading history lives in one zero-knowledge store, so every app must derive
 * byte-identical item keys from the same master key. Two implementations would
 * drift — a different HKDF label or id separator is enough — and each app would
 * silently stop seeing the other's data.
 */

// Account lifecycle: register, sign in, recover, change password, new phrase,
// and the session's own lifetime (refresh, end).
export {
	registerAccount,
	loginAccount,
	recoverAccount,
	changeAccountPassword,
	regenerateRecoveryPhrase,
	regenerateRecoveryPhraseWithGoogle,
	refreshSession,
	endSession,
	tokenStillValid,
	loginWithGoogle,
	registerWithGoogle,
	signInWithGoogle,
	NoGoogleAccountError,
	DRIVE_KEY_MISMATCH_MESSAGE,
	accountInfo,
	linkGoogle,
	deleteAccount,
	GoogleOnOtherAccountError,
	type AccountSession,
	type AccountInfo,
	type GoogleCredentials,
	type LinkGoogleInput
} from './account.js';

// Sign in with Google: the key lives in the user's Drive app-data folder.
export {
	driveSecret,
	DriveError,
	DRIVE_KEY_FILE,
	DRIVE_APPDATA_SCOPE,
	type DriveSecret
} from './google.js';

// The manager: owns the engine, bridges app stores, runs the sync loop.
export {
	SyncManager,
	SESSION_EXPIRED_MESSAGE,
	type SyncManagerOptions,
	type SyncDescriptor,
	type AuthState,
	type SyncStatus
} from './manager.js';

// Session persistence (IndexedDB by default; swap for other hosts).
export {
	indexedDbSessionStore,
	memorySessionStore,
	type SessionStore,
	type PersistedSession
} from './session-store.js';

// Reactive primitive the manager exposes state through.
export { Signal, readStore, type Subscriber, type Unsubscriber } from './signal.js';

// Lower level, for anything driving the engine directly.
export { SyncEngine, MemoryTransport, type SyncTransport, type RemoteChange } from './engine.js';
export { HttpSyncTransport, SyncAuthError } from './transport.js';
export { HLC, type HLCTimestamp } from './hlc.js';
export { bytesToBase64, base64ToBytes } from './base64.js';
export {
	DEFAULT_ARGON2,
	isValidMnemonic,
	generateRecoveryMnemonic,
	type Argon2Params
} from './crypto.js';
