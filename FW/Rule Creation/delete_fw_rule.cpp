// File:
//   delete_fw_rule.cpp
// 
// Author:
//    Jimmi Aylesworth
//
// Date:
//    August 18, 2026
//
// Purpose:
//   Removes a specific named Windows Firewall rule (via the INetFwPolicy2 
//   COM interface), created to block outbound telemetry for MsSense.exe.
//   Intended to be run as part of a cleanup step after testing has been
//   performed on a host.
//
// Behavior:
//   - Requires an elevated (administrator) process token, since firewall
//     policy modification requires admin rights.
//   - Looks up the target rule by exact display name and removes it if
//     present.
//   - Emits clear, distinct exit codes and stderr messages so it can be
//     scripted/orchestrated (e.g. from TriageMaster or a similar pipeline)
//     without needing to parse free-text output.
//
// Exit codes:
//   0  - Rule found and removed successfully
//   1  - Rule was not found (nothing to remove; not necessarily an error)
//   2  - Not running elevated
//   3  - COM initialization failure
//   4  - Failed to create INetFwPolicy2 instance
//   5  - Failed to retrieve INetFwRules collection
//   6  - Remove() failed for a reason other than "not found"
//
// Build:
//   $ x86_64-w64-mingw32-g++ delete_fw_rule.cpp -static-libstdc++ -static-libgcc -lole32 -loleaut32 -o delete_fw_rule.exe

#include <windows.h>
#include <netfw.h>
#include <comutil.h>
#include <comdef.h>   // _com_error, for decoding HRESULTs into readable text
#include <cstdio>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// Name of the firewall rule to remove.
static const wchar_t* TargetRuleName = L"AppBlocker-Outbound-MsSense";

// ---------------------------------------------------------------------
// Returns true if the current process is running with an elevated
// (administrator) token. Firewall policy writes require elevation; failing
// fast here with a clear message is more useful than letting COM calls
// fail deeper in the call stack with an opaque E_ACCESSDENIED.
// ---------------------------------------------------------------------
static bool IsProcessElevated()
{
    bool elevated = false;
    HANDLE token = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    TOKEN_ELEVATION elevation{};
    DWORD returnedSize = 0;

    if (GetTokenInformation(token, TokenElevation, &elevation,
                             sizeof(elevation), &returnedSize))
    {
        elevated = (elevation.TokenIsElevated != 0);
    }

    CloseHandle(token);
    return elevated;
}

// ---------------------------------------------------------------------
// Small helper to print an HRESULT with its decoded message, so failures
// are actionable from the console/log rather than just a hex code.
// ---------------------------------------------------------------------
static void PrintHResultError(const char* context, HRESULT hr)
{
    _com_error err(hr);
    fwprintf(stderr, L"[!] %hs failed: 0x%08X - %ls\n",
              context, hr, err.ErrorMessage());
}

int main()
{
    // --- Elevation check -------------------------------------------------
    if (!IsProcessElevated())
    {
        fwprintf(stderr,
            L"[!] This tool must be run elevated (Administrator) to modify "
            L"firewall policy.\n");
        return 2;
    }

    // --- COM initialization ----------------------------------------------
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        PrintHResultError("CoInitializeEx", hr);
        return 3;
    }

    int exitCode = 0;
    INetFwPolicy2* policy = nullptr;
    INetFwRules* rules = nullptr;

    // --- Create the firewall policy COM object ----------------------------
    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&policy));

    if (FAILED(hr))
    {
        PrintHResultError("CoCreateInstance(NetFwPolicy2)", hr);
        CoUninitialize();
        return 4;
    }

    // --- Retrieve the rule collection -------------------------------------
    hr = policy->get_Rules(&rules);
    if (FAILED(hr))
    {
        PrintHResultError("INetFwPolicy2::get_Rules", hr);
        policy->Release();
        CoUninitialize();
        return 5;
    }

    // --- Attempt removal ---------------------------------------------------
    // NOTE: INetFwRules::Remove() matches on exact display name. If the
    // artifact-planting mechanism ever randomizes the rule name (e.g.
    // appends a GUID/timestamp to dodge simple string-match cleanup),
    // this exact-match lookup will silently miss it. If that turns out to
    // matter operationally, replace this with an enumeration over `rules`
    // (via IEnumVARIANT / Item-by-index) and match on a name prefix
    // instead of full equality.
    hr = rules->Remove(_bstr_t(TargetRuleName));

    if (SUCCEEDED(hr))
    {
        wprintf(L"[+] Removed firewall rule: \"%ls\"\n", TargetRuleName);
        exitCode = 0;
    }
    else if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
    {
        // Rule didn't exist. Not treated as a hard failure -- on a clean
        // host, or if it was already remediated, this is expected.
        wprintf(L"[i] Rule \"%ls\" not found; nothing to remove.\n",
                TargetRuleName);
        exitCode = 1;
    }
    else
    {
        PrintHResultError("INetFwRules::Remove", hr);
        exitCode = 6;
    }

    // --- Cleanup -------------------------------------------------------
    rules->Release();
    policy->Release();
    CoUninitialize();

    return exitCode;
}