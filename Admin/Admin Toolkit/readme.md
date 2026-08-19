# admin_toolkit.cpp

A menu-driven Windows local-account administration utility built entirely on
COM/ADSI. No shelling out to `net.exe`, `powershell.exe`, or any other
process — every action goes through the ADSI **WinNT provider**
(`IADsContainer`, `IADsUser`, `IADsGroup`).

## Features

**User Management**

| # | Action | Notes |
|---|--------|-------|
| 1 | Create a new local user | Password: admin-typed or randomly generated (choice offered). Optional immediate grant to local Administrators. |
| 2 | Add a user to Administrators | Existing account only; bind-checked first. |
| 3 | Remove a user from Administrators | Hard-blocks self-removal and removing the last remaining administrator — no override. |
| 4 | Disable a user | Sets `UF_ACCOUNTDISABLE`. |
| 5 | Enable a user | Clears `UF_ACCOUNTDISABLE`. |
| 6 | Reset a user's password | Admin-typed or randomly generated (choice offered). |
| 7 | Unlock a user | Clears account lockout (`IsAccountLocked`), separate mechanism from disable/enable. |
| 8 | Delete a user | Destructive — requires retyping the username to confirm. |

Random passwords are generated via `BCryptGenRandom` (Windows CNG), never
`rand()`, and are guaranteed at least one lowercase, uppercase, digit, and
symbol character. Generated passwords are displayed exactly once and are
never logged or persisted by the tool.

## Requirements

- Windows only (uses WinNT ADSI provider — local SAM).
- Must be run **elevated** (as Administrator) for any action that creates,
  modifies, or deletes accounts, or changes group membership.
- Scope is local machine only; not written for domain/AD account management.

## Building

### MSVC

```
cl /EHsc /W4 admin_toolkit.cpp activeds.lib adsiid.lib ole32.lib oleaut32.lib bcrypt.lib
```

### MinGW-w64

```
x86_64-w64-mingw32-g++ admin_toolkit.cpp -static-libstdc++ -static-libgcc -static \
   -Wall -municode -o admin_toolkit.exe -lactiveds -ladsiid -lole32 -loleaut32 -lbcrypt
```

Notes on the flags:

- `-municode` — **required**. The program uses `wmain()` (wide-char entry
  point); without this flag MinGW's default CRT startup looks for
  `WinMain`/`main` and linking fails with `undefined reference to WinMain`.
- `-static` — statically links the MinGW runtime (`libgcc_s_seh`,
  `libstdc++`, `libwinpthread`) so the resulting `.exe` has no MinGW DLL
  dependencies on the target machine. Without it you'll need to ship
  `libgcc_s_seh-1.dll`, `libstdc++-6.dll`, and `libwinpthread-1.dll`
  alongside the binary, or the `.exe` will fail at launch with a
  "code execution cannot proceed" error.
- `-lbcrypt` — required for the CNG-based random password generator.

Cross-compiling from Linux is fine for a syntax/link check, but the
resulting `.exe` must be run **on Windows**, since it calls real ADSI/COM.

## Usage

```
admin_toolkit.exe
```

Navigate the numbered menus; `0` goes back/exits at any level.

## Known WinNT-provider quirks (already handled in code)

These are documented here in case the code is extended further — worth
knowing before adding new ADSI calls.

- **Password must be set before the first `SetInfo()`.** Calling
  `SetInfo()` to commit a newly created account before calling
  `SetPassword()` commits the account with a *blank* password first,
  which local password policy can reject with `0x800708C5`
  ("password does not meet policy requirements") — misleadingly, since
  the blank password is what's being evaluated, not the real one.
  Fix: call `SetPassword()` on the still-uncommitted object, then a
  single `SetInfo()`.
- **`Put(L"Password", ...)` is invalid on the WinNT provider.** Unlike
  LDAP/AD, `"Password"` isn't a generic settable schema property here;
  attempting it fails with `E_ADS_SCHEMA_VIOLATION` (`0x8000500F`). Use
  the dedicated `SetPassword()` method instead.
- **`"WinNT://."` does not work for `IADsGroup::Add`/`Remove`.** It works
  fine for ordinary binds (`ADsGetObject`, `IADsContainer::Create`), but
  `Add`/`Remove` delegate to `NetLocalGroupAddMembers`/
  `NetLocalGroupDelMembers`, which resolve the member name via
  `LookupAccountName` — and `"."` isn't valid input there. This fails
  with `ERROR_NO_SUCH_MEMBER` (`0x8007056B`, "the member does not
  exist") even though the account genuinely exists, and is **not** a
  timing issue — it fails identically on a retry minutes later. Fix:
  use the real NetBIOS computer name (`GetComputerNameW`) for group
  membership paths specifically.
- **Post-creation group-add timing lag (a real, separate issue).**
  Immediately after `NetUserAdd`-style account creation, there can be a
  brief window where the new account isn't yet resolvable by the SAM/LSA
  path `NetLocalGroupAddMembers` uses, even though the account is fully
  committed. `AddUserToAdministratorsWithRetry()` retries a few times
  with a short delay, but *only* for `ERROR_NO_SUCH_MEMBER` immediately
  following creation — not used for group operations on pre-existing
  accounts, where this race doesn't apply.

## Design notes

- `BindExistingUser()` is the single shared entry point for every action
  that operates on an already-existing account (add/remove-admin,
  disable, enable, reset, unlock, delete) — keeps "no such user" handling
  consistent everywhere.
- Disable/Enable share one helper (`SetAccountDisabled`) since they're the
  same `UserFlags` bit with the opposite boolean. Unlock is a *different*
  ADSI mechanism (`IsAccountLocked`, not a `UserFlags` bit) and has its
  own helper (`SetAccountLocked`).
- Removing a user from Administrators has two hard-block guards, no
  override: refuses to remove the account currently running the program,
  and refuses to remove the last remaining administrator.

