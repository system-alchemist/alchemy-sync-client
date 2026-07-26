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
