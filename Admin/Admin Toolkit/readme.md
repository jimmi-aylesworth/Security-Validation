# Admin Toolkit

---

Windows local-account administration tooling built entirely on COM/ADSI
(`IADsContainer`, `IADsUser`, `IADsGroup` via the WinNT provider). No
shelling out to `net.exe`, `powershell.exe`, or any other process — every
action goes through COM.

This project ships two independent artifacts:

| Artifact | Source | Description |
|---|---|---|
| `admin_toolkit.exe` | `admin_toolkit.cpp` | Interactive, menu-driven console tool for day-to-day local account administration. Safety rails included. |
| `admin_toolkit.dll` | `admin_toolkit_dll.cpp` + `admin_toolkit_dll.def` | `rundll32`-loadable, fully non-interactive DLL for exercising Windows Security-log account-management event IDs in a **lab environment** for detection-rule validation. No safety rails. |

The two artifacts are **fully standalone** and do not share compiled code,
by explicit design decision. Bug fixes and core ADSI patterns are
duplicated intentionally so each can be built and deployed independently.

---

## admin_toolkit.exe — Console Tool

### Features

**User Management submenu:**

| # | Action | Notes |
|---|--------|-------|
| 1 | Create a new local user | Password: admin-typed or randomly generated (choice offered). Optional immediate grant to local Administrators. |
| 2 | Add a user to Administrators | Existing account only; existence verified via bind before attempting group add. |
| 3 | Remove a user from Administrators | Hard-blocks self-removal and removing the last remaining administrator — no override. |
| 4 | Disable a user | Sets `UF_ACCOUNTDISABLE`. |
| 5 | Enable a user | Clears `UF_ACCOUNTDISABLE`. |
| 6 | Reset a user's password | Admin-typed or randomly generated (choice offered). |
| 7 | Unlock a user | Clears account lockout via `IsAccountLocked` — distinct ADSI property from `UserFlags`. |
| 8 | Delete a user | Destructive and permanent (SID is gone). Requires retyping the username to confirm before proceeding. |

Random passwords are generated via `BCryptGenRandom` (Windows CNG), never
`rand()`, and are guaranteed to contain at least one lowercase letter,
uppercase letter, digit, and symbol character. Generated passwords are
shown exactly once and are never logged or persisted by the tool.

### Requirements

- Windows only.
- Must be run **elevated** (as Administrator) for any mutating action.
- Scope: local machine only. Not written for domain/AD account management.

### Building

**MSVC:**
```
cl /EHsc /W4 admin_toolkit.cpp activeds.lib adsiid.lib ole32.lib oleaut32.lib bcrypt.lib
```

**MinGW-w64 (cross-compiled from Linux, but must run on Windows):**
```
x86_64-w64-mingw32-g++ admin_toolkit.cpp -static-libstdc++ -static-libgcc -static \
   -Wall -municode -o admin_toolkit.exe \
   -lactiveds -ladsiid -lole32 -loleaut32 -lbcrypt
```

**Flag notes:**

- `-municode` — required. The program uses `wmain()` (wide-char entry
  point). Without it, MinGW's default CRT startup looks for `WinMain`/
  `main` and linking fails with `undefined reference to WinMain`.
- `-static` — statically links the MinGW runtime (`libgcc_s_seh`,
  `libstdc++`, `libwinpthread`) so the `.exe` has no MinGW DLL
  dependencies on the target machine. Without it, the binary will fail
  to launch on a machine without the MinGW runtime installed
  (`libgcc_s_seh-1.dll was not found`).
- `-lbcrypt` — required for `BCryptGenRandom`-based random password
  generation.

### Usage

```
admin_toolkit.exe
```

Navigate numbered menus. `0` goes back or exits at any menu level.

---

## admin_toolkit.dll — rundll32-Loadable Detection Harness

### Purpose

**LAB USE ONLY.** Designed to exercise native Windows Security-log
account-management event IDs for detection-rule validation before
promoting rules to production. Produces normal, native Windows audit
events (4720, 4722, 4724, 4725, 4726, 4732, 4733, 4738, 4740, etc.)
with no custom event log writes, no suppression of, and no interference
with the normal Windows auditing pipeline.

The DLL is fully silent by design — no console output, no `MessageBoxW`,
no `OutputDebugStringW`, no custom Event Log writes of any kind. Failures
are swallowed and the export simply returns. This mirrors how the real
technique actually behaves, which is the point of using this as a
detection-validation harness.

The self-removal and last-remaining-administrator guards from the console
tool are **deliberately absent** here — the DLL emulates the raw technique
for detection testing, not a safety-railed admin tool.

### Exports and Invocation

Each export follows the mandatory `rundll32` entry-point signature:
```
void CALLBACK Name(HWND, HINSTANCE, LPSTR lpszCmdLine, int)
```

Arguments are **colon-delimited** within `lpszCmdLine`.

| Export | Arguments | Example |
|---|---|---|
| `CreateUser` | `username:password` or `username:password:1` | `rundll32 admin_toolkit.dll,CreateUser labuser:P@ssw0rd!:1` |
| `AddAdmin` | `username` | `rundll32 admin_toolkit.dll,AddAdmin labuser` |
| `RemoveAdmin` | `username` | `rundll32 admin_toolkit.dll,RemoveAdmin labuser` |
| `DisableUser` | `username` | `rundll32 admin_toolkit.dll,DisableUser labuser` |
| `EnableUser` | `username` | `rundll32 admin_toolkit.dll,EnableUser labuser` |
| `ResetPassword` | `username:password` | `rundll32 admin_toolkit.dll,ResetPassword labuser:N3wP@ss!` |
| `UnlockUser` | `username` | `rundll32 admin_toolkit.dll,UnlockUser labuser` |
| `DeleteUser` | `username` | `rundll32 admin_toolkit.dll,DeleteUser labuser` |

**`CreateUser` note:** the optional trailing `:1` grants local
Administrators immediately after account creation. Omitting it (or
passing `:0`) creates the account only. No random-password path — the
caller always supplies a password as part of the argument string.

### Requirements

- Windows only.
- Must be run **elevated**, or invoked from an elevated `rundll32` process.
- Scope: local machine only.
- Lab/range environment only. Do not run outside a controlled environment
  built for detection-rule validation.

### Building

**Required files:**
- `admin_toolkit_dll.cpp`
- `admin_toolkit_dll.def` — **mandatory** module-definition file.
  Without it, `__stdcall` (CALLBACK) exports get name-decorated
  (`_CreateUser@16`) and `rundll32` cannot find them by the plain names
  given on the command line.

**MSVC:**
```
cl /EHsc /LD admin_toolkit_dll.cpp admin_toolkit_dll.def ^
   activeds.lib adsiid.lib ole32.lib oleaut32.lib ^
   /Fe:admin_toolkit.dll
```

**MinGW-w64:**
```
x86_64-w64-mingw32-g++ -std=c++17 -Wall -shared \
   -static-libstdc++ -static-libgcc -static \
   admin_toolkit_dll.cpp admin_toolkit_dll.def \
   -o admin_toolkit.dll \
   -lactiveds -ladsiid -lole32 -loleaut32
```

Note: `-lbcrypt` is **not** required for the DLL — there is no random
password generation path.

---

## WinNT Provider — Known Quirks (Documented)

These quirks affected development of both artifacts and are documented
here for reference when extending either further.

**Password must be set before the first `SetInfo()`.**  
Calling `SetInfo()` to commit a new account before `SetPassword()` commits
the account with a blank password first. On a machine enforcing password
policy, the blank password is rejected with `0x800708C5`
(`ERROR_PASSWORD_RESTRICTION`) — misleadingly, since it's the blank
password being evaluated, not the real one. Fix: call `SetPassword()` on
the still-uncommitted object, then a single `SetInfo()`.

**`Put(L"Password", ...)` is invalid on the WinNT provider.**  
Unlike LDAP/AD, `"Password"` isn't a generic settable schema property on
the WinNT provider. Attempting it fails with `E_ADS_SCHEMA_VIOLATION`
(`0x8000500F`). Use the dedicated `IADsUser::SetPassword()` method.

**`"WinNT://."` does not work for `IADsGroup::Add`/`Remove`.**  
`"."` works correctly for ordinary object binds (`ADsGetObject`,
`IADsContainer::Create`) but not for group-membership operations.
`IADsGroup::Add`/`Remove` delegate internally to
`NetLocalGroupAddMembers`/`NetLocalGroupDelMembers`, which resolve the
member name via `LookupAccountName` — and `"."` is not valid input to that
resolution path. Fails with `ERROR_NO_SUCH_MEMBER` (`0x8007056B`, "the
member does not exist") even though the account genuinely exists, and is
**not** a timing issue — fails identically on a retry minutes later. Fix:
use the real NetBIOS computer name (`GetComputerNameW`) for all
group-membership paths.

**Post-creation group-add timing lag (separate from the above).**  
Immediately after account creation, there can be a brief window where the
new account isn't yet resolvable by the SAM/LSA path
`NetLocalGroupAddMembers` uses, even though the account is fully committed.
Both artifacts include a retry wrapper (`AddUserToAdministratorsWithRetry`)
that retries a few times with a 300ms delay, but only on
`ERROR_NO_SUCH_MEMBER` and only for the creation-time admin-grant step.
Group operations on pre-existing accounts do not use this wrapper.

**`IsAccountLocked` is not a `UserFlags` bit.**  
Account lockout is exposed by the WinNT provider as its own boolean ADSI
property (`IADsUser::put_IsAccountLocked`), not as a bit inside
`UserFlags`. Disable/enable manipulate `UF_ACCOUNTDISABLE` inside
`UserFlags`; unlock clears `IsAccountLocked` via its own dedicated method.
The two mechanisms are unrelated.
