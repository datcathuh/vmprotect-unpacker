#pragma once
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <sstream>

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
