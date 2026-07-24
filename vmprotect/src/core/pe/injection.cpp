#include <common.h>
#include <random>
#include <ctime>
#include <fileapi.h>
#include <sstream>
#include <thread>

static std::string HexStr(uint64_t val) {
    std::ostringstream oss;
    oss << "0x" << std::hex << val;
    return oss.str();
}

static std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, out.data(), len, nullptr, nullptr);
    return out;
}

static std::wstring GetRandomTempPath() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring name = L"tmp_";
    std::mt19937 rng((unsigned)std::time(nullptr) + GetCurrentProcessId());
    std::uniform_int_distribution<int> dist(0, 35);
    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 8; ++i) name += charset[dist(rng)];
    name += L".dll";
    return std::wstring(tempPath) + name;
}

DllInjector::DllInjector()
    : m_dllLoaded(false) {
    LoadNtFunctions();
    LoadDllFromResource();
}

DllInjector::~DllInjector() {
}

bool DllInjector::LoadNtFunctions() {
    return true;
}

bool DllInjector::LoadDllFromResource() {
    if (m_dllLoaded) return true;

    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_UNPACKER_DLL), RT_RCDATA);
    if (!hRes) {
        Log("[!] FindResource failed for unpacker DLL");
        return LoadDllFromFile(L"vmprotect_dll.dll", m_dllData);
    }
    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) {
        Log("[!] LoadResource failed");
        return false;
    }
    DWORD size = SizeofResource(nullptr, hRes);
    if (size == 0) {
        Log("[!] Resource size is zero");
        return false;
    }
    const BYTE* pData = (const BYTE*)LockResource(hData);
    if (!pData) {
        Log("[!] LockResource failed");
        return false;
    }
    m_dllData.assign(pData, pData + size);
    m_dllLoaded = true;
    Log("[+] Unpacker DLL loaded from resource (" + std::to_string(size) + " bytes)");
    return true;
}

bool DllInjector::LoadDllFromFile(const std::wstring& filePath, std::vector<BYTE>& outData) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log("[!] Failed to open " + wstring_to_utf8(filePath));
        return false;
    }
    DWORD size = GetFileSize(hFile, nullptr);
    if (size == 0) {
        CloseHandle(hFile);
        return false;
    }
    outData.resize(size);
    DWORD read = 0;
    bool ok = ReadFile(hFile, outData.data(), size, &read, nullptr) && read == size;
    CloseHandle(hFile);
    if (ok) Log("[+] Loaded " + wstring_to_utf8(filePath) + " (" + std::to_string(size) + " bytes)");
    return ok;
}

bool DllInjector::InjectViaLdr(HANDLE hProcess, const std::vector<BYTE>& dllData, const std::wstring& pipeName) {
    std::wstring tempPath = GetRandomTempPath();
    Log("[*] Writing DLL to: " + wstring_to_utf8(tempPath));

    HANDLE hFile = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log("[!] Failed to create temp file, error: " + std::to_string(GetLastError()));
        return false;
    }
    DWORD written = 0;
    if (!WriteFile(hFile, dllData.data(), (DWORD)dllData.size(), &written, nullptr) || written != dllData.size()) {
        Log("[!] Failed to write DLL to temp file");
        CloseHandle(hFile);
        DeleteFileW(tempPath.c_str());
        return false;
    }
    CloseHandle(hFile);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        Log("[!] kernel32.dll not loaded");
        DeleteFileW(tempPath.c_str());
        return false;
    }
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        Log("[!] LoadLibraryW not found");
        DeleteFileW(tempPath.c_str());
        return false;
    }
    Log("[*] LoadLibraryW at " + HexStr((uint64_t)pLoadLibraryW));

    size_t pathBytes = (tempPath.size() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        Log("[!] VirtualAllocEx for path failed, error: " + std::to_string(GetLastError()));
        DeleteFileW(tempPath.c_str());
        return false;
    }

    if (!WriteProcessMemory(hProcess, remotePath, tempPath.c_str(), pathBytes, nullptr)) {
        Log("[!] WriteProcessMemory for path failed, error: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        DeleteFileW(tempPath.c_str());
        return false;
    }
    Log("[*] Remote path at " + HexStr((uint64_t)remotePath));

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
        remotePath, 0, nullptr);
    if (!hThread) {
        Log("[!] CreateRemoteThread failed, error: " + std::to_string(GetLastError()));
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        DeleteFileW(tempPath.c_str());
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);

    if (!DeleteFileW(tempPath.c_str())) {
        if (GetLastError() == ERROR_ACCESS_DENIED || GetLastError() == ERROR_SHARING_VIOLATION) {
            if (MoveFileExW(tempPath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
                Log("[*] Temp file will be deleted on reboot");
        }
    }

    if (exitCode == 0) {
        Log("[!] LoadLibraryW failed");
        return false;
    }

    Log("[+] DLL injected (handle: " + HexStr(exitCode) + ")");
    return true;
}

static bool PatchRemoteProcess(HANDLE hProcess) {
    // Get PEB address via NtQueryInformationProcess
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        Log("[!] Failed to get target PEB");
        return false;
    }
    Log("[*] Target PEB at " + HexStr((uint64_t)pbi.PebBaseAddress));

    // Read PEB from target
    BYTE pebBuf[0x200] = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &read) || read < 0x100) {
        Log("[!] Failed to read target PEB");
        return false;
    }

    // Patch BeingDebugged (PEB + 0x02)
    bool changed = false;
    if (pebBuf[0x02] != 0) {
        Log("[*] Target PEB BeingDebugged was 1, patching to 0");
        pebBuf[0x02] = 0;
        changed = true;
    }

    // Patch NtGlobalFlag (PEB + 0xBC on x64)
    DWORD* globalFlag = (DWORD*)(pebBuf + 0xBC);
    if (*globalFlag != 0) {
        LogF("[*] Target NtGlobalFlag was 0x%X, patching to 0", *globalFlag);
        *globalFlag = 0;
        changed = true;
    }

    // Read process heap pointer (PEB + 0x18 on x64)
    PVOID heapAddr = *(PVOID*)(pebBuf + 0x18);
    if (!heapAddr) {
        Log("[!] Failed to get target heap address");
    } else {
        Log("[*] Target heap at " + HexStr((uint64_t)heapAddr));

        BYTE heapBuf[0x100] = {};
        read = 0;
        if (ReadProcessMemory(hProcess, heapAddr, heapBuf, sizeof(heapBuf), &read) && read >= 0x80) {
            ULONG flags = *(ULONG*)(heapBuf + 0x70);
            ULONG forceFlags = *(ULONG*)(heapBuf + 0x74);
            const ULONG debugBits = 0x40000060;

            if ((flags & debugBits) || forceFlags) {
                LogF("[*] Target heap flags: Flags=0x%X ForceFlags=0x%X", flags, forceFlags);
                *(ULONG*)(heapBuf + 0x70) = flags & ~debugBits;
                *(ULONG*)(heapBuf + 0x74) = 0;

                SIZE_T written = 0;
                if (WriteProcessMemory(hProcess, heapAddr, heapBuf, sizeof(heapBuf), &written) && written >= 0x80) {
                    Log("[+] Target heap patched");
                    changed = true;
                } else {
                    Log("[!] Failed to write target heap");
                }
            } else {
                Log("[*] Target heap flags already clean");
            }
        } else {
            Log("[!] Failed to read target heap");
        }
    }

    if (!changed) {
        Log("[*] No anti-debug patches needed in target");
        return true;
    }

    // Write patched PEB back
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &written) || written < 0x100) {
        Log("[!] Failed to write patched PEB");
        return false;
    }

    Log("[+] Target process patched (BeingDebugged=0, NtGlobalFlag=0, Heap=clean)");
    return true;
}

bool DllInjector::Inject(const std::wstring& exePath) {
    if (!m_dllLoaded && !LoadDllFromResource()) {
        Log("[!] Failed to load Unpacker DLL");
        return false;
    }

    wchar_t pipeName[256];
    swprintf_s(pipeName, L"\\\\.\\pipe\\VMP_%u_%u", GetCurrentProcessId(), GetTickCount());
    SetEnvironmentVariableW(L"VMPIPE", pipeName);
    Log("[*] Pipe: " + wstring_to_utf8(pipeName));

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(exePath.c_str(), MAX_PATH, fullPath, nullptr)) {
        wcsncpy_s(fullPath, exePath.c_str(), MAX_PATH);
    }
    wchar_t outDir[MAX_PATH];
    wcsncpy_s(outDir, fullPath, MAX_PATH);
    wchar_t* slash = wcsrchr(outDir, L'\\');
    if (slash) *slash = 0;
    SetEnvironmentVariableW(L"VMPOUTDIR", outDir);

    HANDLE hPipe = CreateNamedPipeW(pipeName,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 0, 8192, 10000, nullptr);
    bool hasPipe = (hPipe != INVALID_HANDLE_VALUE);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exePath.c_str(), nullptr, nullptr, nullptr,
        FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        Log("[!] CreateProcess failed, error: " + std::to_string(GetLastError()));
        if (hasPipe) CloseHandle(hPipe);
        SetEnvironmentVariableW(L"VMPIPE", nullptr);
        return false;
    }
    Log("[*] Created PID " + std::to_string(pi.dwProcessId) + " (suspended)");

    SetEnvironmentVariableW(L"VMPIPE", nullptr);

    // Start pipe listener BEFORE injection so the DLL can connect during DllMain
    bool pipeDone = false;
    std::thread pipeThread;
    if (hasPipe) {
        pipeThread = std::thread([hPipe, &pi, &pipeDone]() {
            if (ConnectNamedPipe(hPipe, nullptr)) {
                CHAR buf[1024];
                DWORD read;
                while (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT) {
                    if (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
                        buf[read] = 0;
                        size_t len = strlen(buf);
                        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = 0;
                        if (len > 0) Log(std::string("[DLL] ") + buf);
                    } else {
                        DWORD err = GetLastError();
                        if (err == ERROR_BROKEN_PIPE) break;
                        Sleep(50);
                    }
                }
                pipeDone = true;
            }
        });
    }

    bool success = InjectViaLdr(pi.hProcess, m_dllData, pipeName);

    if (success) {
        PatchRemoteProcess(pi.hProcess);
        ResumeThread(pi.hThread);
        Log("[+] Process resumed, waiting for DLL...");

        WaitForSingleObject(pi.hProcess, 60000);
    } else {
        Log("[!] Injection failed, terminating process");
        TerminateProcess(pi.hProcess, 1);
    }

    if (hasPipe) {
        CloseHandle(hPipe);
        if (pipeThread.joinable()) pipeThread.join();
    }

    // Check for dump files
    wchar_t dumpCheck[MAX_PATH];
    swprintf_s(dumpCheck, L"dump_%d.exe", pi.dwProcessId);
    HANDLE hDump = CreateFileW(dumpCheck, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDump != INVALID_HANDLE_VALUE) {
        DWORD dumpSize = GetFileSize(hDump, nullptr);
        CloseHandle(hDump);
        Log("[+] Dump file: " + wstring_to_utf8(dumpCheck) + " (" + std::to_string(dumpSize) + " bytes)");
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return success;
}
