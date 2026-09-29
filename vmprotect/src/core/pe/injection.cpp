#include <common.h>
#include <random>
#include <ctime>
#include <fileapi.h>
#include <sstream>
#include <thread>
#include <psapi.h>
#include <winternl.h>

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

static std::wstring GetRandomTempPath(const wchar_t* ext) {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring name = L"tmp_";
    std::mt19937 rng((unsigned)std::time(nullptr) + GetCurrentProcessId());
    std::uniform_int_distribution<int> dist(0, 35);
    const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 8; ++i) name += charset[dist(rng)];
    name += ext;
    return std::wstring(tempPath) + name;
}

static std::wstring DirOf(const std::wstring& fullPath) {
    std::wstring out = fullPath;
    wchar_t* slash = wcsrchr(out.data(), L'\\');
    if (slash) *slash = 0;
    return out;
}

static bool TargetHasDllExtension(const std::wstring& path) {
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos || (path.size() - dot) != 4) return false;
    wchar_t c = path[dot + 1];
    return (c == L'd' || c == L'D') && (path[dot + 2] == L'l' || path[dot + 2] == L'L') &&
           (path[dot + 3] == L'l' || path[dot + 3] == L'L');
}

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static bool PatchRemoteProcess(HANDLE hProcess);

// Sets an environment variable in a remote process using an arch-specific thunk.
static bool SetRemoteEnv(HANDLE hProcess, const wchar_t* name, const wchar_t* value) {
    if (!name) return false;

    size_t nameBytes = (wcslen(name) + 1) * sizeof(wchar_t);
    LPVOID remoteName = VirtualAllocEx(hProcess, nullptr, nameBytes,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteName) return false;
    if (!WriteProcessMemory(hProcess, remoteName, name, nameBytes, nullptr)) {
        VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
        return false;
    }

    LPVOID remoteValue = nullptr;
    size_t valueBytes = 0;
    if (value) {
        valueBytes = (wcslen(value) + 1) * sizeof(wchar_t);
        remoteValue = VirtualAllocEx(hProcess, nullptr, valueBytes,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteValue) {
            VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
            return false;
        }
        if (!WriteProcessMemory(hProcess, remoteValue, value, valueBytes, nullptr)) {
            VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, remoteValue, 0, MEM_RELEASE);
            return false;
        }
    }

    // Parameter block: [namePtr, valuePtr]
    struct RemoteParams { const wchar_t* name; const wchar_t* value; };
    RemoteParams params = {};
    params.name = (const wchar_t*)remoteName;
    params.value = (const wchar_t*)remoteValue;
    LPVOID remoteParams = VirtualAllocEx(hProcess, nullptr, sizeof(params),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteParams) {
        VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
        if (remoteValue) VirtualFreeEx(hProcess, remoteValue, 0, MEM_RELEASE);
        return false;
    }
    WriteProcessMemory(hProcess, remoteParams, &params, sizeof(params), nullptr);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pSetEnv = GetProcAddress(hKernel32, "SetEnvironmentVariableW");
    if (!pSetEnv) { VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE); return false; }

    // Arch-specific thunk that unpacks the param block and calls SetEnvironmentVariableW.
    BYTE thunk[32] = {};
    SIZE_T thunkSize = 0;
#if defined(_M_AMD64)
    // param block in rcx: [name, value]
    // mov rdx, [rcx+8]    (value)
    // mov rcx, [rcx]      (name)
    // mov rax, <addr>     (SetEnvironmentVariableW)
    // jmp rax
    thunk[0]  = 0x48; thunk[1]  = 0x8B; thunk[2]  = 0x51; thunk[3]  = 0x08; // mov rdx,[rcx+8]
    thunk[4]  = 0x48; thunk[5]  = 0x8B; thunk[6]  = 0x09;                    // mov rcx,[rcx]
    thunk[7]  = 0x48; thunk[8]  = 0xB8;                                      // mov rax, imm64
    *(uint64_t*)&thunk[9] = (uint64_t)pSetEnv;
    thunk[17] = 0xFF; thunk[18] = 0xE0;                                       // jmp rax
    thunkSize = 19;
#else
    // stdcall: name via [esp+4], value via [esp+8] but we push them ourselves
    // eax = param block ptr
    // mov eax,[esp+4]      (param block)
    // mov edx,[eax+4]      (value)
    // push edx
    // mov edx,[eax]        (name)
    // push edx
    // mov eax,<addr>       (SetEnvironmentVariableW)
    // jmp eax              (stdcall — 2 args on stack; ret will clean stack)
    thunk[0]  = 0x8B; thunk[1]  = 0x44; thunk[2]  = 0x24; thunk[3]  = 0x04; // mov eax,[esp+4]
    thunk[4]  = 0x8B; thunk[5]  = 0x50; thunk[6]  = 0x04;                    // mov edx,[eax+4]
    thunk[7]  = 0x52;                                                          // push edx
    thunk[8]  = 0x8B; thunk[9]  = 0x10;                                       // mov edx,[eax]
    thunk[10] = 0x52;                                                          // push edx
    thunk[11] = 0xB8;                                                          // mov eax, imm32
    *(uint32_t*)&thunk[12] = (uint32_t)(uint64_t)pSetEnv;
    thunk[16] = 0xFF; thunk[17] = 0xE0;                                       // jmp eax
    thunkSize = 18;
#endif

    LPVOID remoteThunk = VirtualAllocEx(hProcess, nullptr, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteThunk) {
        VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
        if (remoteValue) VirtualFreeEx(hProcess, remoteValue, 0, MEM_RELEASE);
        return false;
    }
    WriteProcessMemory(hProcess, remoteThunk, thunk, thunkSize, nullptr);

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remoteThunk, remoteParams, 0, nullptr);
    bool ok = false;
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        ok = (exitCode != 0); // SetEnvironmentVariableW returns nonzero on success
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, remoteThunk, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteParams, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
    if (remoteValue) VirtualFreeEx(hProcess, remoteValue, 0, MEM_RELEASE);
    return ok;
}

bool DllInjector::AttachPid(DWORD pid, const std::wstring& modulePath) {
    if (!m_dllLoaded && !LoadDllFromResource()) {
        Log("[!] Failed to load Unpacker DLL");
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        Log("[!] Failed to open process " + std::to_string(pid) + " (error " +
            std::to_string(GetLastError()) + ")");
        if (GetLastError() == ERROR_ACCESS_DENIED)
            Log("[~] Tip: run as administrator for elevated targets");
        return false;
    }
    Log("[+] Opened process " + std::to_string(pid));

    wchar_t pipeName[256];
    swprintf_s(pipeName, L"\\\\.\\pipe\\VMP_%u_%u", GetCurrentProcessId(), GetTickCount());

    HANDLE hPipe = CreateNamedPipeW(pipeName,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 0, 8192, 10000, nullptr);
    bool hasPipe = (hPipe != INVALID_HANDLE_VALUE);
    Log("[*] Pipe: " + wstring_to_utf8(pipeName));

    wchar_t mainModulePath[MAX_PATH] = L"";
    GetModuleFileNameExW(hProcess, nullptr, mainModulePath, MAX_PATH);

    std::wstring targetModulePath = modulePath;
    if (targetModulePath.empty())
        targetModulePath = mainModulePath;

    std::wstring targetDir = DirOf(targetModulePath);
    bool isModuleDll = TargetHasDllExtension(targetModulePath);

    // Prove the remote process sees the pipe + target info via its own env block.
    Log("[*] Setting VMPIPE in remote process");
    SetRemoteEnv(hProcess, L"VMPIPE", pipeName);

    Log("[*] Setting VMPATTACH in remote process");
    SetRemoteEnv(hProcess, L"VMPATTACH", L"1");

    if (!modulePath.empty()) {
        Log("[*] Setting VMPTARGET in remote process: " + wstring_to_utf8(targetModulePath));
        SetRemoteEnv(hProcess, L"VMPTARGET", targetModulePath.c_str());
    }

    Log("[*] Setting VMPOUTDIR in remote process: " + wstring_to_utf8(targetDir));
    SetRemoteEnv(hProcess, L"VMPOUTDIR", targetDir.c_str());

    // Poll target for dump file
    wchar_t dumpExt[8];
    swprintf_s(dumpExt, L"%s", isModuleDll ? L"dll" : L"exe");

    wchar_t dumpCheck[MAX_PATH];
    if (!targetDir.empty())
        swprintf_s(dumpCheck, L"%s\\dump_%d.%s", targetDir.c_str(), pid, dumpExt);
    else
        swprintf_s(dumpCheck, L"dump_%d.%s", pid, dumpExt);

    bool pipeDone = false;
    std::thread pipeThread;
    if (hasPipe) {
        pipeThread = std::thread([hPipe, pid, &pipeDone]() {
            if (ConnectNamedPipe(hPipe, nullptr)) {
                CHAR buf[1024];
                DWORD read;
                while (true) {
                    if (ReadFile(hPipe, buf, sizeof(buf) - 1, &read, nullptr) && read > 0) {
                        buf[read] = 0;
                        size_t len = strlen(buf);
                        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) buf[--len] = 0;
                        if (len > 0) Log(std::string("[DLL] ") + buf);
                    } else {
                        break;
                    }
                }
                pipeDone = true;
            }
        });
    }

    Log("[*] Injecting unpacker DLL into target process...");
    bool success = InjectViaLdr(hProcess, m_dllData, pipeName);
    bool dumpFound = false;

    if (success) {
        PatchRemoteProcess(hProcess);
        Log("[+] Attached to process, waiting for dump...");

        // Poll for the dump file
        DWORD waited = 0;
        while (waited < 60000) {
            DWORD exitCode = 0;
            if (GetExitCodeProcess(hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                Log("[!] Target process exited (code " + std::to_string(exitCode) + ")");
                break;
            }
            HANDLE hCheck = CreateFileW(dumpCheck, GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hCheck != INVALID_HANDLE_VALUE) {
                DWORD dumpSize = GetFileSize(hCheck, nullptr);
                CloseHandle(hCheck);
                Log("[+] Dump file: " + wstring_to_utf8(dumpCheck) + " (" +
                    std::to_string(dumpSize) + " bytes)");
                dumpFound = true;
                break;
            }
            Sleep(500);
            waited += 500;
        }
    } else {
        Log("[!] Injection failed");
    }

    if (hasPipe) {
        CloseHandle(hPipe);
        if (pipeThread.joinable()) pipeThread.join();
    }

    if (!dumpFound && success)
        Log("[!] No dump file produced within 60s");

    CloseHandle(hProcess);
    return success;
}

static bool WriteFileBytes(const std::wstring& path, const std::vector<BYTE>& data) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    bool ok = WriteFile(hFile, data.data(), (DWORD)data.size(), &written, nullptr) && written == data.size();
    CloseHandle(hFile);
    return ok;
}

static bool DeleteFileSafe(const std::wstring& path) {
    if (DeleteFileW(path.c_str())) return true;
    DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
        if (MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
            Log("[*] Host file will be deleted on reboot");
        return true;
    }
    return false;
}

DllInjector::DllInjector()
    : m_dllLoaded(false), m_hostLoaded(false) {
    LoadNtFunctions();
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
        return LoadFileBytes(L"vmprotect_dll.dll", m_dllData);
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

bool DllInjector::LoadHostFromResource() {
    if (m_hostLoaded) return true;

    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_HOST_EXE), RT_RCDATA);
    if (!hRes) {
        Log("[!] FindResource failed for host exe");
        return LoadFileBytes(L"host.exe", m_hostData);
    }
    HGLOBAL hData = LoadResource(nullptr, hRes);
    if (!hData) {
        Log("[!] LoadResource for host failed");
        return false;
    }
    DWORD size = SizeofResource(nullptr, hRes);
    if (size == 0) {
        Log("[!] Host resource size is zero");
        return false;
    }
    const BYTE* pData = (const BYTE*)LockResource(hData);
    if (!pData) {
        Log("[!] LockResource for host failed");
        return false;
    }
    m_hostData.assign(pData, pData + size);
    m_hostLoaded = true;
    Log("[+] Host executable loaded from resource (" + std::to_string(size) + " bytes)");
    return true;
}

bool DllInjector::LoadFileBytes(const std::wstring& filePath, std::vector<BYTE>& outData) {
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
    std::wstring tempPath = GetRandomTempPath(L".dll");
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
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
        &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) {
        Log("[!] Failed to get target PEB");
        return false;
    }
    Log("[*] Target PEB at " + HexStr((uint64_t)pbi.PebBaseAddress));

    BYTE pebBuf[0x200] = {};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &read) || read < 0x100) {
        Log("[!] Failed to read target PEB");
        return false;
    }

    bool changed = false;
    if (pebBuf[0x02] != 0) {
        Log("[*] Target PEB BeingDebugged was 1, patching to 0");
        pebBuf[0x02] = 0;
        changed = true;
    }

    DWORD* globalFlag = (DWORD*)(pebBuf + 0xBC);
    if (*globalFlag != 0) {
        LogF("[*] Target NtGlobalFlag was 0x%X, patching to 0", *globalFlag);
        *globalFlag = 0;
        changed = true;
    }

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

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, sizeof(pebBuf), &written) || written < 0x100) {
        Log("[!] Failed to write patched PEB");
        return false;
    }

    Log("[+] Target process patched (BeingDebugged=0, NtGlobalFlag=0, Heap=clean)");
    return true;
}

// Shared core that runs a target process, injects the unpacker DLL, and waits for a dump.
// For EXE targets: exeToRun is the target .exe, commandLine may be null, targetDllPath is empty.
// For DLL targets: exeToRun is the host .exe, commandLine sets up the host + target, targetDllPath is set.
bool DllInjector::RunTarget(
    const std::wstring& exeToRun,
    const std::wstring& commandLine,
    const std::wstring& targetDir,
    const std::wstring& targetDllPath,
    const wchar_t* dumpExtension)
{
    if (!m_dllLoaded && !LoadDllFromResource()) {
        Log("[!] Failed to load Unpacker DLL");
        return false;
    }

    wchar_t pipeName[256];
    swprintf_s(pipeName, L"\\\\.\\pipe\\VMP_%u_%u", GetCurrentProcessId(), GetTickCount());
    SetEnvironmentVariableW(L"VMPIPE", pipeName);
    Log("[*] Pipe: " + wstring_to_utf8(pipeName));

    if (targetDllPath.empty())
        SetEnvironmentVariableW(L"VMPTARGET", nullptr);
    else
        SetEnvironmentVariableW(L"VMPTARGET", targetDllPath.c_str());

    SetEnvironmentVariableW(L"VMPOUTDIR", targetDir.empty() ? nullptr : targetDir.c_str());

    HANDLE hPipe = CreateNamedPipeW(pipeName,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 0, 8192, 10000, nullptr);
    bool hasPipe = (hPipe != INVALID_HANDLE_VALUE);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    std::wstring cmdCopy = commandLine;
    if (!CreateProcessW(exeToRun.c_str(), cmdCopy.empty() ? nullptr : cmdCopy.data(),
        nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        Log("[!] CreateProcess failed, error: " + std::to_string(GetLastError()));
        if (hasPipe) CloseHandle(hPipe);
        SetEnvironmentVariableW(L"VMPIPE", nullptr);
        return false;
    }
    Log("[*] Created PID " + std::to_string(pi.dwProcessId) + " (suspended)");
    SetEnvironmentVariableW(L"VMPIPE", nullptr);

    wchar_t dumpCheck[MAX_PATH];
    if (!targetDir.empty())
        swprintf_s(dumpCheck, L"%s\\dump_%d.%s", targetDir.c_str(), pi.dwProcessId, dumpExtension);
    else
        swprintf_s(dumpCheck, L"dump_%d.%s", pi.dwProcessId, dumpExtension);

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
    bool dumpFound = false;

    if (success) {
        PatchRemoteProcess(pi.hProcess);
        ResumeThread(pi.hThread);
        Log("[+] Process resumed, waiting for DLL...");

        // Poll for the dump file, and bail as soon as it appears (or the target exits).
        DWORD waited = 0;
        int prevTenth = 0;
        Log("[*] Polling for " + wstring_to_utf8(dumpCheck) + " (host pid " +
            std::to_string(pi.dwProcessId) + ")");
        while (waited < 60000) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
                Log("[!] Poll exit: host process already terminated");
                break;
            }
            HANDLE hCheck = CreateFileW(dumpCheck, GENERIC_READ, FILE_SHARE_READ,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hCheck != INVALID_HANDLE_VALUE) {
                DWORD ds = GetFileSize(hCheck, nullptr);
                CloseHandle(hCheck);
                Log("[+] Poll found dump: " + std::to_string(ds) + " bytes");
                dumpFound = true;
                break;
            }
            int tenth = (int)(waited / 10000);
            if (tenth != prevTenth) {
                prevTenth = tenth;
                Log("[*] Still waiting for dump... (" + std::to_string(waited / 1000) +
                    "s) checking " + wstring_to_utf8(dumpCheck));
            }
            Sleep(500);
            waited += 500;
        }
        Log("[*] Poll finished in " + std::to_string(waited) + "ms, found=" +
            std::to_string((int)dumpFound));
    } else {
        Log("[!] Injection failed, terminating process");
        TerminateProcess(pi.hProcess, 1);
    }

    // DLL flow runs through our host.exe; clean it up once the dump window is done.
    if (!targetDllPath.empty()) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 10000);
    }

    if (hasPipe) {
        CloseHandle(hPipe);
        if (pipeThread.joinable()) pipeThread.join();
    }

    // Report the dump
    HANDLE hDump = CreateFileW(dumpCheck, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDump != INVALID_HANDLE_VALUE) {
        DWORD dumpSize = GetFileSize(hDump, nullptr);
        CloseHandle(hDump);
        Log("[+] Dump file: " + wstring_to_utf8(dumpCheck) + " (" + std::to_string(dumpSize) + " bytes)");
    }
    if (!dumpFound && success)
        Log("[!] No dump file produced within 60s");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return success;
}

std::wstring DllInjector::WriteHostToTemp() {
    if (!m_hostLoaded && !LoadHostFromResource())
        return L"";

    std::wstring hostPath = GetRandomTempPath(L".exe");
    Log("[*] Writing host to: " + wstring_to_utf8(hostPath));
    if (!WriteFileBytes(hostPath, m_hostData)) {
        Log("[!] Failed to write host executable");
        return L"";
    }
    return hostPath;
}

bool DllInjector::Inject(const std::wstring& exePath) {
    if (!m_dllLoaded && !LoadDllFromResource()) {
        Log("[!] Failed to load Unpacker DLL");
        return false;
    }

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(exePath.c_str(), MAX_PATH, fullPath, nullptr))
        wcsncpy_s(fullPath, exePath.c_str(), MAX_PATH);

    std::wstring dir = DirOf(fullPath);
    std::wstring cmd = L"\"" + std::wstring(fullPath) + L"\"";
    return RunTarget(fullPath, cmd, dir, L"", L"exe");
}

bool DllInjector::InjectDll(const std::wstring& dllPath) {
    if (!m_hostLoaded && !LoadHostFromResource()) {
        Log("[!] Failed to load host executable");
        return false;
    }

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(dllPath.c_str(), MAX_PATH, fullPath, nullptr))
        wcsncpy_s(fullPath, dllPath.c_str(), MAX_PATH);

    std::wstring hostPath = WriteHostToTemp();
    if (hostPath.empty()) return false;

    std::wstring dir = DirOf(fullPath);
    std::wstring cmd = L"\"" + hostPath + L"\" \"" + std::wstring(fullPath) + L"\" 300";

    bool ok = RunTarget(hostPath, cmd, dir, std::wstring(fullPath), L"dll");
    DeleteFileSafe(hostPath);
    return ok;
}