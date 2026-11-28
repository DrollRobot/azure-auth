# Token cache

| `cache=` | Behaviour |
|---|---|
| `"memory"` (default) | Tokens are kept in memory, and lost when the process exits. |
| `"disk"` | Tokens are kept in an encrypted file: DPAPI on Windows, Keychain on macOS, libsecret on Linux. |

```python
auth = AuthContext("contoso.com", username="admin@contoso.com", cache="disk")
```

A disk cache is most useful for [interactive sign-in](interactive-sign-in.md) and
[GDAP](gdap.md): it saves the refresh token, so later runs sign in without a prompt. An app
sign-in can get a new token at any time without a user, so a disk cache only saves one
request. A managed identity gets nothing from it: its endpoint is on the host.

There is no unencrypted disk cache. If the platform can't encrypt the file, such as Linux
without libsecret, `cache="disk"` raises `CacheEncryptionUnavailable`. It never writes plain
text, and never switches to the memory cache without telling you.

## Where the file lives

By default, the file is in the user's cache folder. `cache_path=` sets another location.
Contexts in one process that use the same file share one cache, and their threads can use it at
the same time.

```python
from pathlib import Path

auth = AuthContext(
    "contoso.com",
    username="admin@contoso.com",
    cache="disk",
    cache_path=Path.home() / ".cache" / "my-tool" / "msal.bin",
)
```

## When the file is written

New tokens go into the cache in memory. The file is written only by `flush_cache()`, by
`await auth.aio.close()`, and when the process exits. Each write encrypts the whole file, and a
run across many tenants changes the cache thousands of times, so writing on every change would
be slow.

If the process could be killed before it exits normally, call `flush_cache()` after anything
you don't want to lose, such as a browser sign-in or each batch of work:

```python
async with GraphClient(auth, scopes=["User.Read.All"]) as graph:
    await graph.login()
auth.flush_cache()

for batch in batches:
    await process(batch)
    await auth.aio.flush_cache()  # the same, from async code
```

Contexts from `get_tenant_context()` share the cache, so one call writes every tenant's tokens.
A killed process loses only the tokens since the last write. The next run gets them again
without a prompt, using the refresh token in the file.

On Windows, each write creates a new file next to the old one, then renames it over the old
one. A process stopped in the middle of a write leaves the old file intact. An older azure-auth
could leave an empty cache file in that case; an empty file raises `CacheFileEmpty` with its
path. Delete the file and sign in again.

## A reminder shortcut (Windows)

The disk cache holds a refresh token, in a folder you rarely open, so it is easy to forget.
`cache_reminder=` puts a shortcut to that folder somewhere you will see it:

```python
auth = AuthContext(
    "contoso.com", username="admin@contoso.com", cache="disk", cache_reminder="~/Desktop"
)
```

A path ending in `.url` is used as the shortcut's file name. Any other path is treated as a
folder, and the shortcut is saved in it as `AZURE-AUTH_MSAL_CACHE_DELETEME.url`. Missing
folders are created. The shortcut is written again each time a context is created, so it
always points at the current cache. The shortcut holds only a path, so it is safe in a synced
folder such as a Desktop; the cache file itself is not.

## Deleting the cache (Windows)

When you no longer need the sign-in, `delete_cache()` deletes the cache:

```python
from azure_auth import delete_cache

delete_cache()  # the default cache
delete_cache(cache_path)  # a cache_path= cache
```

It empties the file before deleting it, so no token is left even if the delete fails. It also
removes the cache's tokens from contexts in this process, so none of them writes the tokens
back. It does not cover:

- Another process using the cache. That process writes its tokens back at its next write. Stop
  it first.
- Access tokens a context already has in memory. The context keeps them until they expire.

The reminder and `delete_cache()` are Windows only, because only on Windows does the file hold
the tokens. On macOS and Linux the tokens are in the Keychain or libsecret, not in the folder.
There, `cache_reminder=` raises `ValueError` and `delete_cache()` raises `NotImplementedError`.
