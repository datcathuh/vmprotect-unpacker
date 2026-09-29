#pragma once
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <cwchar>

#pragma comment(lib, "psapi.lib")

extern HANDLE g_hPipe;

inline void DbgLog(const std::string& msg) {
    std::string line = msg + "\n";
    OutputDebugStringA(line.c_str());
    if (g_hPipe && g_hPipe != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(g_hPipe, line.c_str(), (DWORD)line.size(), &written, nullptr);
    }
}

template <typename... Args>
inline void DbgLogF(const char* fmt, Args... args) {
    char buf[512];
    snprintf(buf, sizeof(buf), fmt, args...);
    DbgLog(std::string(buf));
}

inline bool IsDllTarget() {
    wchar_t target[MAX_PATH];
    return GetEnvironmentVariableW(L"VMPTARGET", target, MAX_PATH) > 0;
}

inline bool WPathEquals(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        if (towlower(*a) != towlower(*b)) return false;
        ++a; ++b;
    }
    return *a == *b;
}

// Resolves the module to unpack.
//  - DLL targets (VMPTARGET set): finds the loaded module that matches the path.
//  - EXE targets: returns the main module.
inline ULONGLONG FindTargetModuleBase() {
    wchar_t target[MAX_PATH] = L"";
    DWORD len = GetEnvironmentVariableW(L"VMPTARGET", target, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
        return (ULONGLONG)peb->Reserved3[1];
    }

    HMODULE hMods[1024];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
        return 0;
    DWORD count = cbNeeded / sizeof(HMODULE);

    // Exact full-path match first
    for (DWORD i = 0; i < count; ++i) {
        wchar_t modPath[MAX_PATH];
        if (!GetModuleFileNameExW(GetCurrentProcess(), hMods[i], modPath, MAX_PATH))
            continue;
        if (WPathEquals(modPath, target))
            return (ULONGLONG)hMods[i];
    }

    // Fallback: base-name match (loader may canonicalize paths differently)
    wchar_t* tbase = wcsrchr(target, L'\\');
    tbase = tbase ? tbase + 1 : target;
    for (DWORD i = 0; i < count; ++i) {
        wchar_t modPath[MAX_PATH];
        if (!GetModuleFileNameExW(GetCurrentProcess(), hMods[i], modPath, MAX_PATH))
            continue;
        wchar_t* mbase = wcsrchr(modPath, L'\\');
        mbase = mbase ? mbase + 1 : modPath;
        if (WPathEquals(mbase, tbase))
            return (ULONGLONG)hMods[i];
    }
    return 0;
}
