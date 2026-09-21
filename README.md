# @alchemylab/sync-client

A framework-free client for the Alchemy Lab zero-knowledge sync service. Alcove
(SvelteKit) and SCP Ultimate (React/Electron) both depend on it, so that a
reader's library spans every app.

```bash
npm install github:system-alchemist/alchemy-sync-client#v0.1.0
```

Installing from a git URL runs the package's `prepare` script, which builds
`dist/` — no registry needed. Pin a tag: consumers must move deliberately,
because a change to the crypto has to land in every app at once (see below).

```ts
import { SyncManager } from '@alchemylab/sync-client';
```

## Why share the code instead of reimplementing it

The store is zero-knowledge: the server holds ciphertext and opaque ids and can
tell you nothing about what it is storing. Item ids are `HMAC(itemIdKey, type ‖
NUL ‖ key)`, and the keys are HKDF branches of the account's master key. So two
apps see each other's data **only if they derive byte-identical keys**. A second
implementation that used a different HKDF label, a different id separator, or a
different JSON shape would produce a disjoint set of ids and each app would
quietly behave as though the other had never written anything — no error, just
an empty library. Hence: one implementation, imported twice.

## Dependencies

`@noble/hashes`, `@scure/bip39`, plus WebCrypto (`globalThis.crypto.subtle`) and
`fetch`. All present in browsers, Electron renderers and Node 18+.

## What a host has to provide

| Provide | Why |
|---|---|
| `apiBase` | Where `/api/sync/*` lives — `''` for same-origin, else the service origin |
| `deviceId` | Stable per-device string; the clock tiebreaker. Must survive restarts |
| `sessionStore` | Defaults to IndexedDB; supply your own in a Node/Electron-main host |
| A store per synced type | Anything with `subscribe`/`update`, plus a `SyncDescriptor` |

## Binding it in React (SCP Ultimate)

The manager exposes state as `Signal`s — `subscribe(fn)` calls `fn` immediately
and returns an unsubscribe — which is exactly `useSyncExternalStore`'s contract:

```ts
import { useSyncExternalStore } from 'react';
import { SyncManager, type Signal } from './sync';

export const sync = new SyncManager({
  apiBase: 'https://alcove.alchemylab.sh',
  deviceId: stableDeviceId()   // persist this once per install
});

export function useSignal<T>(signal: Signal<T>): T {
  return useSyncExternalStore(
    (cb) => signal.subscribe(cb),
    () => signal.get()
  );
}

// In a component:
const auth = useSignal(sync.auth);
```

Registering a zustand store is the same shape as a Svelte one — `subscribe` and
`update`. zustand's `subscribe` takes `(state) => void` and its `setState`
accepts an updater, so a thin wrapper is enough:

```ts
sync.register(
  {
    type: 'progress',
    toItems: (s) => Object.values(s.progress).map((p) => ({
      key: `scp:${p.articleId}`,          // namespace by source, always
      data: p
    })),
    applyItem: (s, change) => ({ ...s, progress: mergeOne(s.progress, change) })
  },
  {
    subscribe: (fn) => useStore.subscribe(fn),
    update: (fn) => useStore.setState((state) => fn(state))
  }
);
```

## Electron: sync from main, or add CORS

Decide this before writing the binding, because it changes which process owns
the client.

**From the main process (recommended).** Node's fetch does not enforce CORS, so
it talks to the sync API with no server change, and the same code path works in
a headless build. IndexedDB is not available there, so pass a `sessionStore` of
your own — persist `{token, email, masterKey}` however the app already stores
state. `masterKey` is a non-extractable `CryptoKey`; `structuredClone` keeps it
intact, a JSON round-trip destroys it. The renderer then talks to main over IPC.

**From the renderer.** Requests are cross-origin and the sync server currently
sends no CORS headers at all — a preflight returns 405. That needs an allowlist
adding to `/api/sync/*` on the Alcove side first; ask before building against
it. Packaged Electron renderers send `Origin: null` or a custom scheme, which
is awkward to allowlist safely, so this path costs more than it looks.

## Session lifetime (v0.1.3+)

Tokens expire; the manager keeps a session alive by rotating them. The hub
contract (see SCP's `docs/hub-integration-spec.md` §7.2 for the full text):

- every session response (`register`, `session`, `recover`) carries
  `expiresAt` (ms since epoch); without it the manager refreshes blind, daily;
- `POST /api/sync/session/refresh` with the bearer token → `{ token, expiresAt }`
  (the old token keeps a 60 s grace); `401` means the hub ended the session;
- `DELETE /api/sync/session` on sign-out (best effort).

The manager refreshes when a third of the lifetime remains, and once more if a
sync is refused with a 401 in between. A refused refresh (401/403) is treated
as a claim, not a verdict (v0.1.4+): the manager confirms it with a plain
`GET /api/sync/items` using the same token, and only the hub's own 401 there
ends the session — a 403 from an edge or a framework guard (SvelteKit's CSRF
check refuses any mutating request without a JSON content type) must never
sign a working device out. An ended session sets
`auth = { status: 'error', message: SESSION_EXPIRED_MESSAGE }` so the host can
say "sign in again". A hub without the endpoint answers 404, which is ignored
— adopt this version before the hub implements the contract, not after.
Every mutating call the client makes carries `content-type: application/json`
and a JSON body, refresh and sign-out included. Custom `SessionStore`s should
carry `expiresAt` through `save()`/`load()`. `SyncManagerOptions.fetchFn`
injects fetch (tests drive a fake hub with it); `tokenStillValid()` is exported
for hosts that want the same probe.

## Sign in with Google (v0.2.0+)

Google proves *who* the user is; it hands over no secret, so it cannot replace
the password in the key model by itself. The client keeps the account
zero-knowledge to the hub by putting the secret in the user's own Google Drive
**app-data folder** (a hidden per-app space, scope
`https://www.googleapis.com/auth/drive.appdata`): `driveSecret(accessToken)`
reads the app's key file there or creates it (32 random bytes), and the master
key is wrapped under HKDF(secret) and stored on the hub as `wrappedByGoogle`,
next to the password and recovery wrappings. The hub still holds only
ciphertext; Google holds a secret but never the ciphertext. Either alone
cannot read the library — the app's privacy copy must say so.

The app gets an ID token plus a Drive-scoped access token however its platform
does (native sign-in on the phone, the auth-code flow on the web), then:

```ts
const { secret, created } = await driveSecret(accessToken);
const s = await manager.signInWithGoogle({ idToken, driveSecret: secret });
if (s.mnemonic) showOnce(s.mnemonic); // an account was just created
```

`signInWithGoogle` signs in when the hub knows the identity and registers
otherwise (`loginWithGoogle` / `registerWithGoogle` are the halves). A Drive
file that no longer unlocks the account fails with `DRIVE_KEY_MISMATCH_MESSAGE`;
`recoverAccount(..., { driveSecret })` re-wraps the key under the current file
while setting a password. Hub contract: `POST /api/sync/google/session`
`{ idToken }` → `{ token, expiresAt, email, wrappedByGoogle }` (404 when the
identity has no account); `POST /api/sync/google/register` `{ idToken,
wrappedByGoogle, wrappedByRecovery, recoveryAuth }` → `{ token, expiresAt,
email }` (409 when the identity or the email is already registered); the hub
verifies the ID token against its configured OAuth client ids.

**Linking (v0.3.0+).** An existing password account can take on a Google
identity so that Sign in with Google lands in the same library everywhere:
`linkGoogle(apiBase, token, { idToken, driveSecret, mek })` re-wraps the
master key under the Drive secret and posts only the wrapping to
`POST /api/sync/google/link`. It needs the *raw* master key, so it is for
hosts that hold the key at rest (SCP's server and phone do) or have it fresh
from a sign-in — the manager's non-extractable key cannot do it. If the
identity already opens a different account the hub answers 409 with the
details and the client throws `GoogleOnOtherAccountError`; ask, then call
again with `confirmMove: true`: a Google-only account left with no way in is
deleted, one with a password merely loses Google. `accountInfo(apiBase,
token)` reports `{ email, googleLinked, hasPassword }` for the settings UI,
and `deleteAccount(apiBase, token, email)` is the irreversible
`DELETE /api/sync/account` (sessions, items and keys go with it).

## Rules that keep the apps compatible

1. **Namespace every key by source** — `scp:173`, `ao3:12345`. Ids are only
   unique within a source, and one library holds them all.
2. **Match the item `type` strings** across apps (`progress`, `bookmark`,
   `preferences`, `credential`) or each app will write into its own silo.
3. **Never fork the crypto.** Change it here and update both consumers, or the
   two stop seeing each other.
4. `applyItem` decides the merge and is authoritative — the manager pushes your
   value back when you keep it (that's how "furthest reading position wins"
   converges rather than ping-ponging).

## Releasing

```bash
npm run check && npm test && npm run build
git tag v0.2.0 && git push --tags
```

Then bump the `#v0.x.y` ref in each consumer. Consumers pin tags rather than
tracking `main` so that a crypto change can never reach one app before another —
which would leave them briefly unable to read each other's data.

## Repo layout

- `src/` — the client. No framework imports; `tsc` builds it standalone.
- `src/*.test.ts` — the pure tests (crypto, HLC, engine).
- Integration tests that need a server live in the Alcove repo, which owns the
  reference implementation of `/api/sync/*`.
