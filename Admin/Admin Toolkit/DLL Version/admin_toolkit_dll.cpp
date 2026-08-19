// File:
// admin_toolkit_dll.cpp
//
// Author:
//    Jimmi Aylesworth
//
// Date:
//    August 19, 2026
//
// rundll32-loadable, fully self-contained COM/ADSI local-account 
// administration DLL, built for exercising Windows Security-log 
// detection rules (account creation/deletion/modification event IDs)
// in a LAB environment ONLY.
//
// Each exported function follows the mandatory rundll32 entry-point
// signature:
//   void CALLBACK Name(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
// LPSTR is ANSI, NOT wide, regardless of the rest of this file being
// Unicode internally - rundll32 always calls exports with an ANSI
// command line. lpszCmdLine is converted to wide immediately on entry.
//
// Invocation:
//   rundll32.exe admin_toolkit.dll,CreateUser username:password[:1]
//   rundll32.exe admin_toolkit.dll,AddAdmin username
//   rundll32.exe admin_toolkit.dll,RemoveAdmin username
//   rundll32.exe admin_toolkit.dll,DisableUser username
//   rundll32.exe admin_toolkit.dll,EnableUser username
//   rundll32.exe admin_toolkit.dll,ResetPassword username:password
//   rundll32.exe admin_toolkit.dll,UnlockUser username
//   rundll32.exe admin_toolkit.dll,DeleteUser username
//
// Arguments are colon-delimited. CreateUser's optional trailing ":1"
// grants local Administrators immediately after creation (":0" or
// omitted = no grant).
//
// DESIGN NOTES / EXPLICIT DEVIATIONS FROM admin_toolkit.cpp (atk.exe):
//   - Fully silent by design: no console (none is attached under
//     rundll32), no MessageBox, no OutputDebugStringW, no custom
//     Event Log writes of any kind. Failures are swallowed and the
//     export simply returns. This mirrors how the real-world
//     equivalent technique actually behaves, which is the point of
//     using this as a detection-validation harness.
//   - This DLL does NOT suppress, tamper with, or otherwise interfere
//     with native Windows Security auditing. The entire point is to
//     generate normal, native account-management event IDs (4720,
//     4722, 4724, 4725, 4726, 4732, 4733, 4738, 4740, etc.) for
//     detection rules to fire against. Nothing here touches audit
//     policy or the event log pipeline.
//   - No random password generation - the caller always supplies a
//     password as part of the colon-delimited argument string. This
//     keeps the DLL path fully non-interactive.
//   - The self-removal / last-remaining-administrator guards present
//     in admin_toolkit.cpp's ActionRemoveUserFromAdministrators are
//     DELIBERATELY NOT present here - this DLL emulates the raw
//     technique for detection testing, not a safety-railed admin tool.
//   - DeleteUser does not prompt for confirmation - there is no
//     console to confirm in under rundll32.
//   - Fully self-contained/standalone: none of this logic is shared
//     with or imported from admin_toolkit.cpp, by explicit design
//     decision, even though it duplicates logic already written and
//     tested there (CreateLocalUser's password-before-SetInfo fix,
//     the real-computer-name fix for group Add/Remove, etc. - see
//     admin_toolkit.cpp's README/comments for the full history of why
//     each of those matters).
//
// LAB USE ONLY. This DLL creates/deletes/modifies real local accounts
// and group membership with no confirmation, no guardrails, and no
// feedback of any kind. Do not run this outside a lab/range
// environment built for detection-rule validation.
//
// Build (MSVC):
//   cl /EHsc /LD admin_toolkit_dll.cpp admin_toolkit_dll.def ^
//      activeds.lib adsiid.lib ole32.lib oleaut32.lib ^
//      /Fe:admin_toolkit.dll
//
// Build (MinGW-w64):
//   x86_64-w64-mingw32-g++ -std=c++17 -Wall -shared -static-libstdc++ -static-libgcc -static \
//      admin_toolkit_dll.cpp admin_toolkit_dll.def -o admin_toolkit.dll \
//      -lactiveds -ladsiid -lole32 -loleaut32
//
// A .def file (admin_toolkit_dll.def) is REQUIRED alongside this
// source file for BOTH toolchains. Without it, the __stdcall
// (CALLBACK) exports get linker name-decorated (e.g. _CreateUser@16),
// and rundll32 - which looks up the EXACT undecorated name given on
// the command line - will fail to find the entry point.
//
// Must be run elevated (Administrator) to create, modify, or delete
// accounts, or to modify group membership - same requirement as the
// console version.

#include <windows.h>
#include <activeds.h>
#include <comdef.h>
#include <string>
#include <vector>

// ---------------------------------------------------------------------
// Small RAII helper so each export's CoInitialize/CoUninitialize pair
// is always balanced, scoped to that single rundll32 invocation. Each
// rundll32.exe call is its own fresh process, so - unlike the EXE,
// which initializes COM once in wmain() for the whole session - every
// export here must initialize and tear down COM independently.
// ---------------------------------------------------------------------
struct ComInit {
    HRESULT hr;
    ComInit() : hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~ComInit() {
        if (SUCCEEDED(hr)) CoUninitialize();
    }
    bool ok() const { return SUCCEEDED(hr); }
};

// ---------------------------------------------------------------------
// Converts rundll32's ANSI lpszCmdLine to a wide string. rundll32
// always invokes exports with an ANSI command line regardless of the
// rest of this file being Unicode internally (ADSI/BSTR requires wide
// strings throughout).
// ---------------------------------------------------------------------
static std::wstring AnsiToWide(LPSTR ansi) {
    if (!ansi || !*ansi) return std::wstring();
    int required = MultiByteToWideChar(CP_ACP, 0, ansi, -1, nullptr, 0);
    if (required <= 0) return std::wstring();
    std::wstring wide(static_cast<size_t>(required) - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, ansi, -1, &wide[0], required);
    return wide;
}

// ---------------------------------------------------------------------
// Splits a colon-delimited argument string into parts. Empty trailing
// segments are preserved (so "user:pass:" still yields 3 parts), but
// a wholly empty input yields zero parts.
// ---------------------------------------------------------------------
static std::vector<std::wstring> SplitColon(const std::wstring& s) {
    std::vector<std::wstring> parts;
    if (s.empty()) return parts;

    size_t start = 0;
    while (true) {
        size_t pos = s.find(L':', start);
        if (pos == std::wstring::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

// ---------------------------------------------------------------------
// Returns this machine's NetBIOS computer name. Required for
// IADsGroup::Add/Remove to resolve members correctly - the "."
// placeholder is only valid for ordinary ADsGetObject/
// IADsContainer::Create binds, not for group-membership operations,
// which resolve names via LookupAccountName internally. (Same root
// cause documented and fixed in admin_toolkit.cpp; duplicated here by
// design since this DLL is fully standalone.)
// ---------------------------------------------------------------------
static std::wstring GetLocalComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buffer, &size)) {
        return std::wstring(buffer, size);
    }
    return L".";
}

// ---------------------------------------------------------------------
// Creates a local user account via ADSI (WinNT provider). Password is
// set on the still-uncommitted object BEFORE the single SetInfo()
// call - committing first and setting the password after would commit
// a blank password, which local policy can reject with
// 0x800708C5 (ERROR_PASSWORD_RESTRICTION).
// ---------------------------------------------------------------------
static HRESULT CreateLocalUserInternal(const std::wstring& username,
                                        const std::wstring& password,
                                        IADsUser** ppUser) {
    *ppUser = nullptr;

    IADsContainer* pContainer = nullptr;
    HRESULT hr = ADsGetObject(L"WinNT://.",
                               IID_IADsContainer,
                               reinterpret_cast<void**>(&pContainer));
    if (FAILED(hr)) return hr;

    IDispatch* pDispatch = nullptr;
    hr = pContainer->Create(_bstr_t(L"user"), _bstr_t(username.c_str()), &pDispatch);
    pContainer->Release();
    if (FAILED(hr)) return hr;

    IADsUser* pUser = nullptr;
    hr = pDispatch->QueryInterface(IID_IADsUser, reinterpret_cast<void**>(&pUser));
    pDispatch->Release();
    if (FAILED(hr)) return hr;

    hr = pUser->SetPassword(_bstr_t(password.c_str()));
    if (FAILED(hr)) {
        pUser->Release();
        return hr;
    }

    hr = pUser->SetInfo();
    if (FAILED(hr)) {
        pUser->Release();
        return hr;
    }

    // Clear UF_ACCOUNTDISABLE in case the OS defaults a new account to
    // disabled. Best-effort: failures here are swallowed by design,
    // same as everywhere else in this file.
    VARIANT var;
    VariantInit(&var);
    hr = pUser->Get(_bstr_t(L"UserFlags"), &var);
    if (SUCCEEDED(hr) && var.vt == VT_I4) {
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

    pUser->SetInfo();

    *ppUser = pUser;
    return S_OK;
}

// ---------------------------------------------------------------------
// Binds to an existing local user account by name.
// ---------------------------------------------------------------------
static HRESULT BindExistingUserInternal(const std::wstring& username, IADsUser** ppUser) {
    *ppUser = nullptr;
    std::wstring path = L"WinNT://./" + username;
    return ADsGetObject(path.c_str(), IID_IADsUser, reinterpret_cast<void**>(ppUser));
}

// ---------------------------------------------------------------------
// Adds/removes a user to/from the local Administrators group. Both
// use the real NetBIOS computer name, never ".", since IADsGroup::Add/
// Remove resolve members via LookupAccountName internally and "."
// isn't valid input there (fails with ERROR_NO_SUCH_MEMBER /
// 0x8007056B otherwise, regardless of retries or delay - confirmed
// not a timing issue).
// ---------------------------------------------------------------------
static HRESULT AddUserToAdministratorsInternal(const std::wstring& username) {
    IADsGroup* pGroup = nullptr;
    std::wstring groupPath = L"WinNT://" + GetLocalComputerName() + L"/Administrators,group";
    HRESULT hr = ADsGetObject(groupPath.c_str(), IID_IADsGroup, reinterpret_cast<void**>(&pGroup));
    if (FAILED(hr)) return hr;

    std::wstring memberPath = L"WinNT://" + GetLocalComputerName() + L"/" + username;
    hr = pGroup->Add(_bstr_t(memberPath.c_str()));
    pGroup->Release();
    return hr;
}

static HRESULT RemoveUserFromAdministratorsInternal(const std::wstring& username) {
    IADsGroup* pGroup = nullptr;
    std::wstring groupPath = L"WinNT://" + GetLocalComputerName() + L"/Administrators,group";
    HRESULT hr = ADsGetObject(groupPath.c_str(), IID_IADsGroup, reinterpret_cast<void**>(&pGroup));
    if (FAILED(hr)) return hr;

    std::wstring memberPath = L"WinNT://" + GetLocalComputerName() + L"/" + username;
    hr = pGroup->Remove(_bstr_t(memberPath.c_str()));
    pGroup->Release();
    return hr;
}

// ---------------------------------------------------------------------
// Retries AddUserToAdministratorsInternal() a few times on
// ERROR_NO_SUCH_MEMBER, to absorb the brief SAM/LSA resolution lag
// immediately after NEW account creation. Only used by CreateUser's
// optional admin-grant step - AddAdmin (an existing-account action)
// does not need this, same reasoning as admin_toolkit.cpp.
// ---------------------------------------------------------------------
static HRESULT AddUserToAdministratorsWithRetry(const std::wstring& username,
                                                  int maxAttempts = 5,
                                                  DWORD delayMs = 300) {
    const HRESULT kNoSuchMember = HRESULT_FROM_WIN32(ERROR_NO_SUCH_MEMBER);
    HRESULT hr = E_FAIL;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        hr = AddUserToAdministratorsInternal(username);
        if (SUCCEEDED(hr)) return hr;
        if (hr != kNoSuchMember) return hr;
        if (attempt < maxAttempts) Sleep(delayMs);
    }
    return hr;
}

// ---------------------------------------------------------------------
// Sets/clears UF_ACCOUNTDISABLE on an already-bound user.
// ---------------------------------------------------------------------
static HRESULT SetAccountDisabledInternal(IADsUser* pUser, bool disabled) {
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
// Locks/unlocks an already-bound user via IsAccountLocked - a
// distinct ADSI property from UserFlags, not a UserFlags bit.
// ---------------------------------------------------------------------
static HRESULT SetAccountLockedInternal(IADsUser* pUser, bool locked) {
    HRESULT hr = pUser->put_IsAccountLocked(locked ? VARIANT_TRUE : VARIANT_FALSE);
    if (FAILED(hr)) return hr;
    return pUser->SetInfo();
}

// ---------------------------------------------------------------------
// Deletes a local user account outright. No confirmation - there is
// no console to confirm in under rundll32, and this DLL is designed
// to emulate the raw technique, not to be a safety-railed tool.
// ---------------------------------------------------------------------
static HRESULT DeleteLocalUserInternal(const std::wstring& username) {
    IADsContainer* pContainer = nullptr;
    HRESULT hr = ADsGetObject(L"WinNT://.", IID_IADsContainer, reinterpret_cast<void**>(&pContainer));
    if (FAILED(hr)) return hr;

    hr = pContainer->Delete(_bstr_t(L"user"), _bstr_t(username.c_str()));
    pContainer->Release();
    return hr;
}

// =======================================================================
// Exported entry points (rundll32-compatible signature)
//
// Every export: initializes COM, parses lpszCmdLine, performs the
// action, and returns - no output of any kind on success OR failure,
// by design. See file header "DESIGN NOTES" for the full rationale.
// =======================================================================

extern "C" __declspec(dllexport) void CALLBACK CreateUser(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.size() < 2 || args[0].empty() || args[1].empty()) return;

    const std::wstring& username = args[0];
    const std::wstring& password = args[1];
    bool grantAdmin = (args.size() >= 3 && args[2] == L"1");

    IADsUser* pUser = nullptr;
    HRESULT hr = CreateLocalUserInternal(username, password, &pUser);
    if (FAILED(hr) || !pUser) return;

    if (grantAdmin) {
        AddUserToAdministratorsWithRetry(username);
    }

    pUser->Release();
}

extern "C" __declspec(dllexport) void CALLBACK AddAdmin(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.empty() || args[0].empty()) return;

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUserInternal(args[0], &pUser);
    if (FAILED(hr)) return;
    pUser->Release();

    AddUserToAdministratorsInternal(args[0]);
}

extern "C" __declspec(dllexport) void CALLBACK RemoveAdmin(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.empty() || args[0].empty()) return;

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUserInternal(args[0], &pUser);
    if (FAILED(hr)) return;
    pUser->Release();

    // No self-removal / last-admin guard here - deliberate, see file
    // header. This export emulates the raw technique for detection
    // testing rather than being a safety-railed admin tool.
    RemoveUserFromAdministratorsInternal(args[0]);
}

extern "C" __declspec(dllexport) void CALLBACK DisableUser(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.empty() || args[0].empty()) return;

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUserInternal(args[0], &pUser);
    if (FAILED(hr)) return;

    SetAccountDisabledInternal(pUser, true);
    pUser->Release();
}

extern "C" __declspec(dllexport) void CALLBACK EnableUser(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.empty() || args[0].empty()) return;

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUserInternal(args[0], &pUser);
    if (FAILED(hr)) return;

    SetAccountDisabledInternal(pUser, false);
    pUser->Release();
}

extern "C" __declspec(dllexport) void CALLBACK ResetPassword(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.size() < 2 || args[0].empty() || args[1].empty()) return;

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUserInternal(args[0], &pUser);
    if (FAILED(hr)) return;

    hr = pUser->SetPassword(_bstr_t(args[1].c_str()));
    if (SUCCEEDED(hr)) {
        pUser->SetInfo();
    }
    pUser->Release();
}

extern "C" __declspec(dllexport) void CALLBACK UnlockUser(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.empty() || args[0].empty()) return;

    IADsUser* pUser = nullptr;
    HRESULT hr = BindExistingUserInternal(args[0], &pUser);
    if (FAILED(hr)) return;

    SetAccountLockedInternal(pUser, false);
    pUser->Release();
}

extern "C" __declspec(dllexport) void CALLBACK DeleteUser(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
    ComInit com;
    if (!com.ok()) return;

    std::vector<std::wstring> args = SplitColon(AnsiToWide(lpszCmdLine));
    if (args.empty() || args[0].empty()) return;

    DeleteLocalUserInternal(args[0]);
}

// ---------------------------------------------------------------------
// Standard DllMain. No per-thread/per-process setup needed beyond
// what each export already does for itself.
// ---------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}