// File:
//   admin_toolkit.cpp
//
// Author:
//    Jimmi Aylesworth
//
// Date:
//    August 19, 2026
//
// Menu-driven Windows administration utility built entirely on COM/ADSI.
// No shelling out to net.exe, powershell.exe, or any other process.
//
// Current functionality (User Management submenu):
//   1) Create a new local user account (optionally grant local Admin rights)
//   2) Add an existing user to the local Administrators group
//   3) Remove a user from the local Administrators group (hard-blocks
//      self-removal and removing the last remaining administrator)
//   4) Disable a user
//   5) Enable a user
//   6) Reset a user's password (admin-typed or randomly generated)
//   7) Unlock a user (clear account lockout)
//   8) Delete a user (type-to-confirm required)
//
// Design notes:
//   - Uses the ADSI "WinNT" provider, which talks to the local SAM
//     (or a domain, if you point it at a DC) purely through COM.
//   - IADsContainer::Create + IADsUser gives you account creation and
//     property manipulation without touching NetUserAdd or any CLI tool.
//   - IADsGroup::Add adds a user ADsPath to a group (e.g. Administrators)
//     the same way, again purely via COM.
//   - BindExistingUser() is the single shared entry point every
//     "operate on an existing account" action uses to resolve a
//     username to a live IADsUser* via ADsGetObject. Keeping this in
//     one place means bind-failure handling (e.g. "no such user") is
//     consistent across disable/enable/reset/unlock/delete.
//   - Disable/Enable manipulate the UF_ACCOUNTDISABLE bit inside the
//     UserFlags property. Unlock is a *different* mechanism - ADSI
//     exposes account lockout as its own IADsUser::IsAccountLocked
//     boolean property, not a UserFlags bit, so it has its own
//     dedicated helper (SetAccountLocked) rather than reusing the
//     UserFlags helper (SetAccountDisabled).
//   - Password generation uses BCryptGenRandom (Windows CNG), not
//     rand()/srand(). rand() is a low-quality, predictable PRNG and
//     unsuitable for generating credentials, particularly for a tool
//     whose entire purpose is administrative account control.
//   - Delete is destructive and irreversible (the account's SID is
//     gone permanently; a recreated account with the same username
//     gets a brand new, unrelated SID). ActionDeleteUser requires the
//     admin to retype the username to confirm, mirroring the
//     type-to-confirm pattern common in cloud consoles for destructive
//     operations, rather than a single y/n keypress.
//
// Build (MSVC):
//   cl /EHsc /W4 admin_toolkit.cpp activeds.lib adsiid.lib ole32.lib oleaut32.lib bcrypt.lib
//
// Build (MinGW-w64, cross-compiled from Linux is fine for syntax checking,
// but this must run ON Windows since it calls real ADSI/COM):
//   x86_64-w64-mingw32-g++ admin_toolkit.cpp -static-libstdc++ -static-libgcc -static \
//      -Wall -municode -o admin_toolkit.exe -lactiveds -ladsiid -lole32 -loleaut32 -lbcrypt
//
// -static links the MinGW runtime (libgcc_s_seh, libstdc++, libwinpthread)
// statically so the resulting .exe has no MinGW DLL dependencies on the
// target machine.
//
// Must be run elevated (Administrator) to create, modify, or delete
// accounts, or to modify group membership.

#include <windows.h>
#include <activeds.h>
#include <comdef.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <limits>
#include <algorithm>

//Ignore below pragma line warnings if compiling on linux, MinGW builds rely on -l flags

#pragma comment(lib, "activeds.lib")
#pragma comment(lib, "adsiid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "bcrypt.lib")

// ---------------------------------------------------------------------
// Small RAII helper so we don't leak CoInitialize/CoUninitialize pairs
// if something throws or we add early returns later.
// ---------------------------------------------------------------------
struct ComInit {
    HRESULT hr;
    ComInit() : hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~ComInit() {
        if (SUCCEEDED(hr)) CoUninitialize();
    }
    bool ok() const { return SUCCEEDED(hr); }
};

// Print a human-readable error for a failed HRESULT.
static void PrintComError(const std::string& context, HRESULT hr) {
    _com_error err(hr);
    std::wcerr << L"[ERROR] " << context.c_str() << L" failed: "
               << err.ErrorMessage() << L" (0x" << std::hex << hr << L")\n"
               << std::dec;
}

// ---------------------------------------------------------------------
// Returns this machine's NetBIOS computer name.
//
// CONFIRMED ROOT CAUSE (Microsoft docs + multiple independent reports
// of the identical symptom): the "." placeholder works fine for the
// top-level ADsGetObject()/IADsContainer::Create() binds used
// elsewhere in this file (CreateLocalUser, BindExistingUser) - ADSI's
// own path parser handles those internally. But IADsGroup::Add() and
// IADsGroup::Remove() delegate to NetLocalGroupAddMembers/
// NetLocalGroupDelMembers, which resolve the member's account name
// via LookupAccountName - and "." is not valid input to that
// resolution path. Every Microsoft example for IADsGroup::Add uses a
// real NetBIOS computer name, never ".". Passing "." through
// consistently fails with ERROR_NO_SUCH_MEMBER (0x8007056B, "the
// member does not exist"), even though the account genuinely exists -
// confirmed both immediately after creation and on a separate, later,
// manual retry, which rules out this having been a timing issue.
// (The retry wrapper added earlier for a different, genuine timing
// concern - see AddUserToAdministratorsWithRetry's own comment -
// remains in place for that original purpose; it does not address
// this bug, which is a name-resolution issue, not a race condition.)
// ---------------------------------------------------------------------
static std::wstring GetLocalComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size)) {
        return std::wstring(buffer, size);
    }
    // Fallback only if GetComputerNameW itself fails (extremely
    // unlikely) - "." still works for every OTHER bind in this file,
    // just not group Add/Remove, so degrade rather than crash.
    return L".";
}

// ---------------------------------------------------------------------
// Creates a local user account via ADSI (WinNT provider) and returns
// a live IADsUser pointer to it (caller must Release()).
// ---------------------------------------------------------------------
static HRESULT CreateLocalUser(const std::wstring& username,
                                const std::wstring& password,
                                IADsUser** ppUser) {
    *ppUser = nullptr;

    // Bind to the local computer's account container.
    // "WinNT://." refers to the local machine; the "," format could
    // instead target a domain, e.g. "WinNT://MYDOMAIN".
    IADsContainer* pContainer = nullptr;
    HRESULT hr = ADsGetObject(L"WinNT://.",
                               IID_IADsContainer,
                               reinterpret_cast<void**>(&pContainer));
    if (FAILED(hr)) {
        PrintComError("ADsGetObject(WinNT://.)", hr);
        return hr;
    }

    IDispatch* pDispatch = nullptr;
    hr = pContainer->Create(_bstr_t(L"user"), _bstr_t(username.c_str()), &pDispatch);
    pContainer->Release();

    if (FAILED(hr)) {
        PrintComError("IADsContainer::Create", hr);
        return hr;
    }

    IADsUser* pUser = nullptr;
    hr = pDispatch->QueryInterface(IID_IADsUser, reinterpret_cast<void**>(&pUser));
    pDispatch->Release();

    if (FAILED(hr)) {
        PrintComError("QueryInterface(IID_IADsUser)", hr);
        return hr;
    }

    // Set the password BEFORE the first SetInfo().
    //
    // Two things had to be fixed here across two rounds:
    //
    // 1) Originally this called SetInfo() first (committing the
    //    account to the SAM with a BLANK password, since nothing had
    //    set one yet), then called SetPassword() afterward. Since
    //    ADSI evaluates the password against local policy at commit
    //    time, that first SetInfo() was rejected with 0x800708C5
    //    ("password does not meet policy requirements") because of
    //    the blank password - not because of anything wrong with the
    //    caller's actual password string, which was never even
    //    evaluated yet at that point.
    //
    // 2) The first attempted fix called Put(L"Password", ...) to
    //    stage the password as a generic property before SetInfo().
    //    That's invalid for the WinNT provider specifically -
    //    "Password" isn't a schema property you can Put() on a WinNT
    //    user object (that's an LDAP/AD-provider notion), so it fails
    //    with E_ADS_SCHEMA_VIOLATION (0x8000500F).
    //
    // The actually-correct WinNT pattern (matching Microsoft's own
    // ADSI samples) is to call the dedicated SetPassword() method on
    // the still-uncommitted object BEFORE the first SetInfo(). Called
    // in that order, the password stages correctly on the pending
    // object, and the single SetInfo() below commits the account and
    // its real password together - never passing through a blank- or
    // schema-invalid state.
    hr = pUser->SetPassword(_bstr_t(password.c_str()));
    if (FAILED(hr)) {
        PrintComError("IADsUser::SetPassword (pre-commit)", hr);
        pUser->Release();
        return hr;
    }

    hr = pUser->SetInfo(); // single commit: account + password together
    if (FAILED(hr)) {
        PrintComError("IADsUser::SetInfo (initial create)", hr);
        pUser->Release();
        return hr;
    }

    // Make sure the account isn't disabled. UF_ACCOUNTDISABLE is the
    // relevant UserFlag bit; clear it explicitly since new accounts
    // sometimes come up disabled depending on OS defaults.
    VARIANT var;
    VariantInit(&var);
    hr = pUser->Get(_bstr_t(L"UserFlags"), &var);
    if (SUCCEEDED(hr) && (var.vt == VT_I4)) {
        long flags = var.lVal;
        const long UF_ACCOUNTDISABLE = 0x0002;
        flags &= ~UF_ACCOUNTDISABLE;

        VARIANT newVar;
        VariantInit(&newVar);
        newVar.vt = VT_I4;
        newVar.lVal = flags;
        pUser->Put(_bstr_t(L"UserFlags"), newVar);
        VariantClear(&newVar);
    }
    VariantClear(&var);

    hr = pUser->SetInfo();
    if (FAILED(hr)) {
        PrintComError("IADsUser::SetInfo (post-password)", hr);
        pUser->Release();
        return hr;
    }

    *ppUser = pUser; // caller owns this now
    return S_OK;
}

// ---------------------------------------------------------------------
// Adds an existing user (identified by ADsPath) to the local
// Administrators group, purely via IADsGroup::Add.
// ---------------------------------------------------------------------
static HRESULT AddUserToAdministrators(const std::wstring& userAdsPath, bool quiet = false) {
    IADsGroup* pGroup = nullptr;
    std::wstring groupPath = L"WinNT://" + GetLocalComputerName() + L"/Administrators,group";
    HRESULT hr = ADsGetObject(groupPath.c_str(),
                               IID_IADsGroup,
                               reinterpret_cast<void**>(&pGroup));
    if (FAILED(hr)) {
        if (!quiet) PrintComError("ADsGetObject(Administrators group)", hr);
        return hr;
    }

    hr = pGroup->Add(_bstr_t(userAdsPath.c_str()));
    pGroup->Release();

    if (FAILED(hr)) {
        // ADS_E_MEMBEROFATTRIBUTEEXISTS / similar HRESULTs are common
        // if the user is already a member; treat as non-fatal.
        if (!quiet) PrintComError("IADsGroup::Add", hr);
        return hr;
    }

    return S_OK;
}

// ---------------------------------------------------------------------
// Retries AddUserToAdministrators() a few times with a short delay
// between attempts.
//
// This works around a documented Windows/ADSI timing quirk: right
// after a local account is created (NetUserAdd, which is what
// IADsContainer::Create + SetInfo call under the hood), there's a
// brief window where the account isn't yet resolvable by the
// SID-lookup path that NetLocalGroupAddMembers uses internally - even
// though the account is fully committed and tools like `net user` can
// see it an instant later. The symptom is ERROR_NO_SUCH_MEMBER
// (Win32 1387 / HRESULT 0x8007056B, "the member does not exist") on
// the very first group-add attempt immediately following creation,
// which then succeeds cleanly on retry a few hundred milliseconds on.
//
// Only ERROR_NO_SUCH_MEMBER is retried. Any other failure (bad path,
// real permissions problem, etc.) is returned immediately - retrying
// those wouldn't help, since they're not a timing issue and won't
// resolve themselves.
// ---------------------------------------------------------------------
static HRESULT AddUserToAdministratorsWithRetry(const std::wstring& userAdsPath,
                                                  int maxAttempts = 5,
                                                  DWORD delayMs = 300) {
    const HRESULT kNoSuchMember = HRESULT_FROM_WIN32(ERROR_NO_SUCH_MEMBER);

    HRESULT hr = E_FAIL;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        const bool isLastAttempt = (attempt == maxAttempts);

        // Stay quiet on intermediate attempts so a normal timing-lag
        // recovery doesn't spam the console with error text the admin
        // never actually needs to see; only the final, truly-failed
        // attempt (if we exhaust all retries) prints anything.
        hr = AddUserToAdministrators(userAdsPath, /*quiet=*/!isLastAttempt);

        if (SUCCEEDED(hr)) return hr;
        if (hr != kNoSuchMember) return hr; // not the timing issue - no point retrying
        if (!isLastAttempt) Sleep(delayMs);
    }
    return hr;
}

// ---------------------------------------------------------------------
// Removes an existing user (identified by ADsPath) from the local
// Administrators group, purely via IADsGroup::Remove. Mirror image of
// AddUserToAdministrators - no retry wrapper needed here, since the
// retry logic exists specifically to absorb the LSA/SAM resolution
// lag right after NEW account creation, which doesn't apply when
// removing an already-existing account from a group.
// ---------------------------------------------------------------------
static HRESULT RemoveUserFromAdministrators(const std::wstring& userAdsPath) {
    IADsGroup* pGroup = nullptr;
    std::wstring groupPath = L"WinNT://" + GetLocalComputerName() + L"/Administrators,group";
    HRESULT hr = ADsGetObject(groupPath.c_str(),
                               IID_IADsGroup,
                               reinterpret_cast<void**>(&pGroup));
    if (FAILED(hr)) {
        PrintComError("ADsGetObject(Administrators group)", hr);
        return hr;
    }

    hr = pGroup->Remove(_bstr_t(userAdsPath.c_str()));
    pGroup->Release();

    if (FAILED(hr)) {
        PrintComError("IADsGroup::Remove", hr);
        return hr;
    }

    return S_OK;
}

// ---------------------------------------------------------------------
// Returns the current member count of the local Administrators group
// via IADsGroup::Members()/IADsMembers::get_Count. Used by
// ActionRemoveUserFromAdministrators() to hard-block removing the
// last remaining administrator.
// ---------------------------------------------------------------------
static HRESULT GetAdministratorsMemberCount(long* pCount) {
    *pCount = 0;

    IADsGroup* pGroup = nullptr;
    std::wstring groupPath = L"WinNT://" + GetLocalComputerName() + L"/Administrators,group";
    HRESULT hr = ADsGetObject(groupPath.c_str(),
                               IID_IADsGroup,
                               reinterpret_cast<void**>(&pGroup));
    if (FAILED(hr)) return hr;

    IADsMembers* pMembers = nullptr;
    hr = pGroup->Members(&pMembers);
    pGroup->Release();
    if (FAILED(hr)) return hr;

    hr = pMembers->get_Count(pCount);
    pMembers->Release();
    return hr;
}

// ---------------------------------------------------------------------
// Binds to an existing local user account by name via the WinNT
// provider. This is the single shared entry point used by every
// action that operates on an already-existing account: disable,
// enable, reset password, unlock, and delete.
//
// On failure, hr carries the underlying ADSI/COM error (most commonly
// "no such user" when the account doesn't exist). This function
// intentionally does NOT special-case that error - it's left to
// bubble up so every caller reports it the same way, through
// PrintComError, with a context string identifying which action was
// attempting the bind.
// ---------------------------------------------------------------------
static HRESULT BindExistingUser(const std::wstring& username, IADsUser** ppUser) {
    *ppUser = nullptr;

    std::wstring path = L"WinNT://./" + username;
    IADsUser* pUser = nullptr;
    HRESULT hr = ADsGetObject(path.c_str(), IID_IADsUser, reinterpret_cast<void**>(&pUser));
    if (FAILED(hr)) {
        return hr;
    }

    *ppUser = pUser;
    return S_OK;
}

// ---------------------------------------------------------------------
// Sets or clears the UF_ACCOUNTDISABLE bit on an already-bound user's
// UserFlags property, then commits the change with SetInfo(). Shared
// by both the "Disable a user" and "Enable a user" menu actions -
// disabling and enabling are the same operation with the opposite
// boolean, so they share one implementation rather than duplicating
// the flag-manipulation logic.
// ---------------------------------------------------------------------
static HRESULT SetAccountDisabled(IADsUser* pUser, bool disabled) {
    const long UF_ACCOUNTDISABLE = 0x0002;

    VARIANT var;
    VariantInit(&var);
    HRESULT hr = pUser->Get(_bstr_t(L"UserFlags"), &var);
    if (FAILED(hr) || var.vt != VT_I4) {
        VariantClear(&var);
        return FAILED(hr) ? hr : E_FAIL;
    }

    long flags = var.lVal;
    VariantClear(&var);

    if (disabled) {
        flags |= UF_ACCOUNTDISABLE;
    } else {
        flags &= ~UF_ACCOUNTDISABLE;
    }

    VARIANT newVar;
    VariantInit(&newVar);
    newVar.vt = VT_I4;
    newVar.lVal = flags;
    hr = pUser->Put(_bstr_t(L"UserFlags"), newVar);
    VariantClear(&newVar);
    if (FAILED(hr)) return hr;

    return pUser->SetInfo();
}

// ---------------------------------------------------------------------
// Locks or unlocks an already-bound user account via the dedicated
// IADsUser::put_IsAccountLocked property.
//
// IMPORTANT: unlike disable/enable, account lockout is NOT a
// UserFlags bit under the WinNT provider - ADSI models it as its own
// boolean property. That's why this has its own helper instead of
// being folded into SetAccountDisabled() above; the two mechanisms
// are unrelated even though they sound similar.
// ---------------------------------------------------------------------
static HRESULT SetAccountLocked(IADsUser* pUser, bool locked) {
    HRESULT hr = pUser->put_IsAccountLocked(locked ? VARIANT_TRUE : VARIANT_FALSE);
    if (FAILED(hr)) return hr;
    return pUser->SetInfo();
}

// ---------------------------------------------------------------------
// Deletes a local user account outright via IADsContainer::Delete.
//
// This is destructive and irreversible: the account's SID is gone
// permanently, and a later account created with the same username
// gets a brand-new, unrelated SID with none of the original's
// permissions, ownership, or group-membership history.
//
// This function assumes the caller has ALREADY confirmed intent - the
// type-to-confirm UX flow lives in ActionDeleteUser(), not here, so
// this stays a plain "just do it" primitive that's easy to reason
// about and easy to unit-test independent of console I/O.
// ---------------------------------------------------------------------
static HRESULT DeleteLocalUser(const std::wstring& username) {
    IADsContainer* pContainer = nullptr;
    HRESULT hr = ADsGetObject(L"WinNT://.",
                               IID_IADsContainer,
                               reinterpret_cast<void**>(&pContainer));
    if (FAILED(hr)) return hr;

    hr = pContainer->Delete(_bstr_t(L"user"), _bstr_t(username.c_str()));
    pContainer->Release();
    return hr;
}

// ---------------------------------------------------------------------
// Case-insensitive comparison for two wide strings. Used by
// ActionRemoveUserFromAdministrators()'s self-removal guard to compare
// the typed username against the account this program is currently
// running as. Implemented with towlower() (already used elsewhere in
// this file, e.g. PromptYesNo) rather than the MSVC-specific
// _wcsicmp(), which isn't guaranteed available under MinGW.
// ---------------------------------------------------------------------
static bool EqualsCaseInsensitive(const std::wstring& a, const std::wstring& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (towlower(a[i]) != towlower(b[i])) return false;
    }
    return true;
}

// ---------------------------------------------------------------------
// Cryptographically-random password generation
// ---------------------------------------------------------------------
// Used by the "Reset a user's password" action when the admin chooses
// to generate a password rather than type one. Built on BCryptGenRandom
// (Windows CNG) rather than rand()/srand() - rand() is a low-quality,
// predictable PRNG, and using it to mint account credentials would be
// a real weakness in a tool explicitly built for administrative
// account control.
// ---------------------------------------------------------------------

// Fills `buffer` with `length` cryptographically-random bytes via CNG.
// Passing a null algorithm handle with BCRYPT_USE_SYSTEM_PREFERRED_RNG
// tells CNG to use the OS's preferred RNG without us having to open
// and manage an algorithm provider handle ourselves.
static bool GetRandomBytes(BYTE* buffer, ULONG length) {
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buffer,
        length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status);
}

// Returns a uniformly-distributed random index in [0, rangeExclusive)
// using rejection sampling against a random byte, rather than a naive
// `randomByte % rangeExclusive`, to avoid modulo bias for our (small)
// alphabet sizes. On the extremely unlikely event of an RNG failure,
// falls back to index 0 rather than throwing, since this is a
// best-effort convenience feature, not a security control in itself
// (the actual security boundary is SetPassword()/LSA policy).
static size_t RandomIndex(size_t rangeExclusive) {
    if (rangeExclusive <= 1) return 0;

    // Largest multiple of rangeExclusive that fits in a byte's range
    // (0-255); bytes at or above this are rejected and redrawn to
    // avoid modulo bias. Computed in unsigned int, NOT BYTE: when
    // rangeExclusive evenly divides 256 (e.g. 16, as used by the
    // default 16-character password length during Fisher-Yates
    // shuffling), the remainder is 0 and the "no rejection needed"
    // limit is literally 256 - which overflows a BYTE (max 255) to 0.
    // That previously made the loop's exit condition (b >= limit)
    // always true for every possible byte value, spinning forever.
    // Keeping the arithmetic in unsigned int avoids the overflow, and
    // the remainder == 0 case is handled explicitly below: when 256
    // divides evenly, every byte value is already uniform, so no
    // rejection is needed at all.
    const unsigned int remainder = 256u % static_cast<unsigned int>(rangeExclusive);
    const unsigned int limit = 256u - remainder;

    BYTE b = 0;
    do {
        if (!GetRandomBytes(&b, 1)) return 0;
    } while (remainder != 0 && static_cast<unsigned int>(b) >= limit);
    return static_cast<size_t>(b % rangeExclusive);
}

// Generates a random password guaranteed to contain at least one
// lowercase letter, one uppercase letter, one digit, and one symbol,
// padded to `length` (minimum enforced at 12) with random characters
// from the combined alphabet, then Fisher-Yates shuffled so the
// guaranteed characters aren't predictably sitting in positions 0-3.
static std::wstring GenerateRandomPassword(size_t length = 16) {
    static const std::wstring lower   = L"abcdefghijklmnopqrstuvwxyz";
    static const std::wstring upper   = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const std::wstring digits  = L"0123456789";
    static const std::wstring symbols = L"!@#$%^&*()-_=+[]{}";
    static const std::wstring all     = lower + upper + digits + symbols;

    if (length < 12) length = 12; // enforce a sane minimum length

    std::wstring password;
    password.reserve(length);

    password += lower[RandomIndex(lower.size())];
    password += upper[RandomIndex(upper.size())];
    password += digits[RandomIndex(digits.size())];
    password += symbols[RandomIndex(symbols.size())];

    while (password.size() < length) {
        password += all[RandomIndex(all.size())];
    }

    for (size_t i = password.size() - 1; i > 0; --i) {
        size_t j = RandomIndex(i + 1);
        std::swap(password[i], password[j]);
    }

    return password;
}

// ---------------------------------------------------------------------
// Console helpers
// ---------------------------------------------------------------------
static std::wstring PromptLine(const std::wstring& prompt) {
    std::wcout << prompt;
    std::wstring input;
    std::getline(std::wcin, input);
    return input;
}

static bool PromptYesNo(const std::wstring& prompt) {
    while (true) {
        std::wstring answer = PromptLine(prompt + L" [y/n]: ");
        if (!answer.empty()) {
            wchar_t c = towlower(answer[0]);
            if (c == L'y') return true;
            if (c == L'n') return false;
        }
        std::wcout << L"Please answer y or n.\n";
    }
}

// A minimal masked password prompt using the console API directly
// (still no shelling out — this is just raw Win32 console handling).
static std::wstring PromptPassword(const std::wstring& prompt) {
    std::wcout << prompt;
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);

    std::wstring password;
    std::getline(std::wcin, password);

    SetConsoleMode(hStdin, mode); // restore echo
    std::wcout << L"\n";
    return password;
}

// ---------------------------------------------------------------------
// Menu action: create user (+ optional admin grant)
//
// Offers the same generate-vs-type password sub-choice as
// ActionResetPassword(): a cryptographically-random password
// (displayed exactly once, never persisted) or an admin-typed one via
// the existing masked PromptPassword() flow.
// ---------------------------------------------------------------------
static void ActionCreateUser() {
    std::wstring username = PromptLine(L"New username: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    std::wcout << L"How should the password be set?\n"
               << L"  1) Generate a random password\n"
               << L"  2) Type a password\n"
               << L"Select an option: ";
    std::wstring choice;
    std::getline(std::wcin, choice);

    std::wstring password;
    bool generated = false;

    if (choice == L"1") {
        password = GenerateRandomPassword();
        generated = true;
    } else if (choice == L"2") {
        password = PromptPassword(L"Password for " + username + L": ");
        if (password.empty()) {
            std::wcout << L"Password cannot be empty.\n";
            return;
        }
    } else {
        std::wcout << L"Unrecognized option.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = CreateLocalUser(username, password, &pUser);
    if (FAILED(hr) || !pUser) {
        std::wcout << L"User creation failed. See error above.\n";
        return;
    }

    std::wcout << L"User '" << username << L"' created successfully.\n";
    if (generated) {
        // Shown exactly once - this tool does not log or persist
        // generated passwords anywhere. It's the admin's responsibility
        // to record it before moving on.
        std::wcout << L"Generated password (record this now, it will not be shown again): "
                   << password << L"\n";
    }

    bool makeAdmin = PromptYesNo(L"Grant this user administrative privileges?");
    if (makeAdmin) {
        // NOT using pUser->get_ADsPath() (avoids relying on a
        // creation-time object's path string) and NOT using the "."
        // placeholder (which resolves fine for ordinary binds but is
        // NOT valid input to the LookupAccountName-based resolution
        // that IADsGroup::Add performs internally - see
        // GetLocalComputerName()'s comment for the full explanation
        // and sourcing). Real computer name required here.
        std::wstring path = L"WinNT://" + GetLocalComputerName() + L"/" + username;

        hr = AddUserToAdministratorsWithRetry(path);
        if (SUCCEEDED(hr)) {
            std::wcout << L"'" << username
                       << L"' added to the local Administrators group.\n";
        } else {
            std::wcout << L"Failed to add '" << username
                       << L"' to Administrators. See error above.\n";
        }
    }

    pUser->Release();
}

// ---------------------------------------------------------------------
// Menu action: add an existing user to the local Administrators group
//
// Distinct from the admin-grant prompt inside ActionCreateUser: this
// targets a username the admin types in, for granting Administrators
// membership to an account that already exists (as opposed to one
// just created in the same flow).
//
// Binds via BindExistingUser first so a typo'd/nonexistent username
// produces a clean "no such user" error rather than a raw group-add
// failure. Uses the plain (non-retrying) AddUserToAdministrators -
// the retry wrapper exists specifically to absorb the LSA/SAM
// resolution lag immediately after NEW account creation; that race
// condition doesn't apply here, since the account already existed
// before this action ran.
// ---------------------------------------------------------------------
static void ActionAddUserToAdministrators() {
    std::wstring username = PromptLine(L"Username to add to Administrators: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUser(username, &pUser);
    if (FAILED(hr)) {
        PrintComError("BindExistingUser (add to Administrators)", hr);
        return;
    }
    pUser->Release(); // only needed the bind to confirm the account exists

    // Real computer name required for group Add() to resolve the
    // member correctly - see GetLocalComputerName()'s comment.
    std::wstring path = L"WinNT://" + GetLocalComputerName() + L"/" + username;
    hr = AddUserToAdministrators(path);

    if (SUCCEEDED(hr)) {
        std::wcout << L"'" << username
                   << L"' added to the local Administrators group.\n";
    } else {
        std::wcout << L"Failed to add '" << username
                   << L"' to Administrators. See error above.\n";
    }
}

// ---------------------------------------------------------------------
// Menu action: remove an existing user from the local Administrators
// group
//
// Two hard-block guards, no override, per explicit decision: it's too
// easy to shoot yourself in the foot otherwise.
//
//   1) Self-removal guard - refuses to remove the account this
//      program is CURRENTLY RUNNING AS, compared case-insensitively
//      via GetUserNameW(). Removing your own admin rights mid-session
//      is an easy, entirely avoidable mistake.
//   2) Last-admin guard - refuses if the target account is the only
//      (or only remaining) member of Administrators, via
//      GetAdministratorsMemberCount(). Doing so would leave the
//      machine with no local administrators at all.
//
// Binds via BindExistingUser first, same as the add action, so a
// typo'd/nonexistent username produces a clean error before either
// guard or the actual removal is attempted.
// ---------------------------------------------------------------------
static void ActionRemoveUserFromAdministrators() {
    std::wstring username = PromptLine(L"Username to remove from Administrators: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUser(username, &pUser);
    if (FAILED(hr)) {
        PrintComError("BindExistingUser (remove from Administrators)", hr);
        return;
    }
    pUser->Release(); // only needed the bind to confirm the account exists

    // Guard 1: self-removal.
    wchar_t currentUser[256];
    DWORD currentUserLen = 256;
    if (GetUserNameW(currentUser, &currentUserLen)) {
        if (EqualsCaseInsensitive(currentUser, username)) {
            std::wcout << L"Refusing to remove '" << username
                       << L"' from Administrators - this is the account "
                       << L"currently running this program.\n";
            return;
        }
    }

    // Guard 2: last remaining administrator.
    long memberCount = 0;
    hr = GetAdministratorsMemberCount(&memberCount);
    if (SUCCEEDED(hr) && memberCount <= 1) {
        std::wcout << L"Refusing to remove '" << username
                   << L"' - this would leave the local Administrators "
                   << L"group with no members.\n";
        return;
    }

    // Real computer name required for group Remove() to resolve the
    // member correctly - see GetLocalComputerName()'s comment.
    std::wstring path = L"WinNT://" + GetLocalComputerName() + L"/" + username;
    hr = RemoveUserFromAdministrators(path);

    if (SUCCEEDED(hr)) {
        std::wcout << L"'" << username
                   << L"' removed from the local Administrators group.\n";
    } else {
        std::wcout << L"Failed to remove '" << username
                   << L"' from Administrators. See error above.\n";
    }
}

// ---------------------------------------------------------------------
// Menu action: disable an existing user
// ---------------------------------------------------------------------
static void ActionDisableUser() {
    std::wstring username = PromptLine(L"Username to disable: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUser(username, &pUser);
    if (FAILED(hr)) {
        PrintComError("BindExistingUser (disable)", hr);
        return;
    }

    hr = SetAccountDisabled(pUser, true);
    pUser->Release();

    if (SUCCEEDED(hr)) {
        std::wcout << L"'" << username << L"' has been disabled.\n";
    } else {
        PrintComError("SetAccountDisabled(true)", hr);
    }
}

// ---------------------------------------------------------------------
// Menu action: enable an existing user
// ---------------------------------------------------------------------
static void ActionEnableUser() {
    std::wstring username = PromptLine(L"Username to enable: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUser(username, &pUser);
    if (FAILED(hr)) {
        PrintComError("BindExistingUser (enable)", hr);
        return;
    }

    hr = SetAccountDisabled(pUser, false);
    pUser->Release();

    if (SUCCEEDED(hr)) {
        std::wcout << L"'" << username << L"' has been enabled.\n";
    } else {
        PrintComError("SetAccountDisabled(false)", hr);
    }
}

// ---------------------------------------------------------------------
// Menu action: reset an existing user's password
//
// Offers a sub-choice: generate a cryptographically-random password
// (displayed exactly once, never persisted by this tool) or let the
// admin type a new one directly, matching the same masked-input flow
// used during account creation.
// ---------------------------------------------------------------------
static void ActionResetPassword() {
    std::wstring username = PromptLine(L"Username to reset password for: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUser(username, &pUser);
    if (FAILED(hr)) {
        PrintComError("BindExistingUser (reset password)", hr);
        return;
    }

    std::wcout << L"How should the new password be set?\n"
               << L"  1) Generate a random password\n"
               << L"  2) Type a new password\n"
               << L"Select an option: ";
    std::wstring choice;
    std::getline(std::wcin, choice);

    std::wstring newPassword;
    bool generated = false;

    if (choice == L"1") {
        newPassword = GenerateRandomPassword();
        generated = true;
    } else if (choice == L"2") {
        newPassword = PromptPassword(L"New password for " + username + L": ");
        if (newPassword.empty()) {
            std::wcout << L"Password cannot be empty.\n";
            pUser->Release();
            return;
        }
    } else {
        std::wcout << L"Unrecognized option.\n";
        pUser->Release();
        return;
    }

    hr = pUser->SetPassword(_bstr_t(newPassword.c_str()));
    if (SUCCEEDED(hr)) {
        hr = pUser->SetInfo();
    }
    pUser->Release();

    if (FAILED(hr)) {
        PrintComError("SetPassword/SetInfo (reset)", hr);
        return;
    }

    std::wcout << L"Password for '" << username << L"' has been reset.\n";
    if (generated) {
        // Shown exactly once - this tool does not log or persist
        // generated passwords anywhere. It's the admin's responsibility
        // to record it before moving on.
        std::wcout << L"Generated password (record this now, it will not be shown again): "
                   << newPassword << L"\n";
    }
}

// ---------------------------------------------------------------------
// Menu action: unlock an existing user (clear account lockout)
// ---------------------------------------------------------------------
static void ActionUnlockUser() {
    std::wstring username = PromptLine(L"Username to unlock: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUser(username, &pUser);
    if (FAILED(hr)) {
        PrintComError("BindExistingUser (unlock)", hr);
        return;
    }

    hr = SetAccountLocked(pUser, false);
    pUser->Release();

    if (SUCCEEDED(hr)) {
        std::wcout << L"'" << username << L"' has been unlocked.\n";
    } else {
        PrintComError("SetAccountLocked(false)", hr);
    }
}

// ---------------------------------------------------------------------
// Menu action: delete an existing user
//
// Destructive and irreversible - requires the admin to retype the
// exact username as a confirmation step, mirroring the "type the
// resource name to confirm" pattern common in cloud consoles for
// destructive actions. A single accidental y/n keypress is much
// easier to make by mistake than retyping a full username correctly.
// ---------------------------------------------------------------------
static void ActionDeleteUser() {
    std::wstring username = PromptLine(L"Username to delete: ");
    if (username.empty()) {
        std::wcout << L"Username cannot be empty.\n";
        return;
    }

    std::wcout << L"This will permanently delete the local account '" << username
               << L"'.\nThis cannot be undone - a recreated account with the same "
               << L"name will have a different SID.\n"
               << L"Type the username again to confirm deletion: ";
    std::wstring confirmation;
    std::getline(std::wcin, confirmation);

    if (confirmation != username) {
        std::wcout << L"Confirmation did not match. Deletion cancelled.\n";
        return;
    }

    HRESULT hr = DeleteLocalUser(username);
    if (SUCCEEDED(hr)) {
        std::wcout << L"'" << username << L"' has been deleted.\n";
    } else {
        PrintComError("DeleteLocalUser", hr);
    }
}

// ---------------------------------------------------------------------
// User Management submenu
// ---------------------------------------------------------------------
static void PrintUserManagementMenu() {
    std::wcout << L"\n--- User Management ---\n"
               << L"1) Create a new local user\n"
               << L"2) Add a user to Administrators\n"
               << L"3) Remove a user from Administrators\n"
               << L"4) Disable a user\n"
               << L"5) Enable a user\n"
               << L"6) Reset a user's password\n"
               << L"7) Unlock a user\n"
               << L"8) Delete a user\n"
               << L"0) Back\n"
               << L"Select an option: ";
}

static void RunUserManagementMenu() {
    while (true) {
        PrintUserManagementMenu();
        std::wstring choice;
        std::getline(std::wcin, choice);

        if (choice == L"1") {
            ActionCreateUser();
        } else if (choice == L"2") {
            ActionAddUserToAdministrators();
        } else if (choice == L"3") {
            ActionRemoveUserFromAdministrators();
        } else if (choice == L"4") {
            ActionDisableUser();
        } else if (choice == L"5") {
            ActionEnableUser();
        } else if (choice == L"6") {
            ActionResetPassword();
        } else if (choice == L"7") {
            ActionUnlockUser();
        } else if (choice == L"8") {
            ActionDeleteUser();
        } else if (choice == L"0") {
            break;
        } else {
            std::wcout << L"Unrecognized option.\n";
        }
    }
}

// ---------------------------------------------------------------------
// Main menu loop
// ---------------------------------------------------------------------
static void PrintMainMenu() {
    std::wcout << L"\n=== COM-Based Administration Toolkit ===\n"
               << L"1) User Management\n"
               << L"0) Exit\n"
               << L"Select an option: ";
}

int wmain() {
    ComInit com;
    if (!com.ok()) {
        PrintComError("CoInitializeEx", com.hr);
        return 1;
    }

    while (true) {
        PrintMainMenu();
        std::wstring choice;
        std::getline(std::wcin, choice);

        if (choice == L"1") {
            RunUserManagementMenu();
        } else if (choice == L"0") {
            break;
        } else {
            std::wcout << L"Unrecognized option.\n";
        }
    }

    return 0;
}
