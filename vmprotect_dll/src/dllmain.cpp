#include <Windows.h>
#include <excpt.h>
#include <tlhelp32.h>
#include "anti/antidebug.h"
#include "core/dump.h"
#include "utils.h"

HANDLE g_hPipe = INVALID_HANDLE_VALUE;

static const DWORD g_t0 = GetTickCount();
static void LogT(const char* msg) {
    DbgLogF("[T+%ums] %s", (unsigned)(GetTickCount() - g_t0), msg);
}

static bool ConnectToPipe() {
    wchar_t pipeName[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"VMPIPE", pipeName, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        DbgLog("[dll] no VMPIPE env var, skipping pipe");
        return false;
    }
    for (int i = 0; i < 50; ++i) {
        g_hPipe = CreateFileW(pipeName, GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            DbgLog("[dll] pipe connected");
            return true;
        }
        Sleep(100);
    }
    g_hPipe = INVALID_HANDLE_VALUE;
    DbgLog("[dll] pipe connection failed");
    return false;
}

static bool IsValidMemory(const void* addr, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    return VirtualQuery(addr, &mbi, sizeof(mbi)) &&
        mbi.State == MEM_COMMIT &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
}

static bool IsOepReady(ULONGLONG base) {
    BYTE buf[0x1000];
    if (!base) return false;

    if (!IsValidMemory((void*)base, sizeof(buf))) return false;
    memcpy(buf, (void*)base, sizeof(buf));

    if (*(WORD*)buf != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + ((IMAGE_DOS_HEADER*)buf)->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (nt->FileHeader.NumberOfSections == 0) return false;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    static int pollCount = 0;
    pollCount++;

    // Tier 1: Hash comparison of non-executable sections.
    // First call: snapshot and return false.
    // Subsequent calls: if any section hash differs, VMP decompressed.
    {
        static std::vector<DWORD> savedHashes;
        static bool firstCall = true;

        std::vector<DWORD> currentHashes;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) continue;
            DWORD rva = sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            if (rva == 0 || size == 0) continue;
            if (!IsValidMemory((void*)(base + rva), min(size, 4096u))) continue;

            BYTE sample[4096];
            DWORD readSize = min(size, (DWORD)sizeof(sample));
            memcpy(sample, (void*)(base + rva), readSize);

            DWORD h = 0;
            for (DWORD j = 0; j < readSize; ++j)
                h = h * 31 + sample[j];
            currentHashes.push_back(h);
        }

        if (firstCall) {
            savedHashes = currentHashes;
            firstCall = false;
            return false;
        }

        if (currentHashes.size() == savedHashes.size()) {
            for (size_t i = 0; i < currentHashes.size(); ++i) {
                if (currentHashes[i] != savedHashes[i])
                    return true;
            }
        }
    }

    // Tier 2: Check import directory for populated thunks.
    // After VMP resolves imports, the thunks contain address - key,
    // which looks like a valid pointer. Before resolution, thunks
    // contain ordinals (high bit set), zeros, or hint/name RVAs.
    {
        IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->VirtualAddress && importDir->Size > sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            ULONGLONG descAddr = base + importDir->VirtualAddress;
            if (!IsValidMemory((void*)descAddr, importDir->Size)) return false;
            IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)descAddr;

            for (int j = 0; desc[j].Characteristics != 0; ++j) {
                if (j > 50) break;
                DWORD thunkRva = desc[j].OriginalFirstThunk
                    ? desc[j].OriginalFirstThunk : desc[j].FirstThunk;
                if (!thunkRva || thunkRva >= 0x20000000) continue;
                if (!IsValidMemory((void*)(base + thunkRva), is64 ? 8 : 4)) continue;
                ULONGLONG thunkVal;
                if (is64)
                    thunkVal = *(ULONGLONG*)(base + thunkRva);
                else
                    thunkVal = *(DWORD*)(base + thunkRva);
                // Valid resolved function pointer: > 0x10000, not an ordinal
                if (thunkVal > 0x10000 && !(thunkVal & (1ULL << (is64 ? 63 : 31))))
                    return true;
            }
        }
    }

    // Tier 3: Fallback after 2+ seconds — check for at least 2 valid
    // non-empty sections (any name). This handles custom section names
    // and VMP-protected binaries where standard section names are missing.
    if (pollCount >= 10) {
        int n = 0;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (sec[i].Misc.VirtualSize > 0x200 && sec[i].VirtualAddress > 0x1000)
                n++;
        }
        if (n >= 2)
            return true;
    }

    return false;
}

static bool IsAttachMode() {
    wchar_t buf[16];
    DWORD len = GetEnvironmentVariableW(L"VMPATTACH", buf, 16);
    return len > 0 && wcscmp(buf, L"1") == 0;
}

static void SuspendOtherThreads() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    THREADENTRY32 te = { sizeof(THREADENTRY32) };

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
}

// Reverse of SuspendOtherThreads — needed when attaching to a live process
// (e.g. a running service) so we don't leave it frozen after dumping.
static void ResumeOtherThreads() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    THREADENTRY32 te = { sizeof(THREADENTRY32) };

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != tid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
}

static std::wstring DirOf(const std::wstring& fullPath) {
    std::wstring out = fullPath;
    wchar_t* slash = wcsrchr(out.data(), L'\\');
    if (slash) *slash = 0;
    return out;
}

// For DLL targets without VMPOUTDIR, dump next to the target DLL itself
// (never next to the host exe in %TEMP%).
static void ConfigureDumpPath(wchar_t* outDir, bool dllTarget) {
    if (GetEnvironmentVariableW(L"VMPOUTDIR", outDir, MAX_PATH) && outDir[0])
        return;

    if (dllTarget) {
        wchar_t target[MAX_PATH] = L"";
        if (GetEnvironmentVariableW(L"VMPTARGET", target, MAX_PATH) > 0 && target[0]) {
            std::wstring dir = DirOf(target);
            wcsncpy_s(outDir, MAX_PATH, dir.c_str(), dir.size());
            return;
        }
    }

    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        wchar_t* slash = wcsrchr(exePath, L'\\');
        if (slash) {
            *(slash + 1) = 0;
            wcsncpy_s(outDir, MAX_PATH, exePath, MAX_PATH);
            return;
        }
    }
    outDir[0] = 0;
}

static LONG OnReconstructFault(LPEXCEPTION_POINTERS ep) {
    DbgLogF("[!] reconstruction fault at 0x%p (code 0x%08X)", ep->ExceptionRecord->ExceptionAddress, ep->ExceptionRecord->ExceptionCode);
    return EXCEPTION_EXECUTE_HANDLER;
}

// Runs ReconstructPe behind SEH so a reconstruction fault cannot take down the
// whole host process (the raw dump is already on disk by this point).
static bool ReconstructPeGuarded(DumpContext& ctx, const std::wstring& outputPath) {
    bool ok = false;
    __try {
        ok = ReconstructPe(ctx, outputPath);
    } __except (OnReconstructFault(GetExceptionInformation())) {
        ok = false;
    }
    return ok;
}

static DWORD WINAPI DumpWorker(LPVOID) {
    DbgLog("[*] dump worker started");
    LogT("dump worker started");

    ConnectToPipe();
    LogT("pipe connected");
    bool attach = IsAttachMode();
    antidebug::PatchPeb();
    antidebug::ClearHardwareBreakpoints();
    antidebug::InstallVehHandler();
    if (!attach) {
        // Only relevant while VMP is unpacking at load time. Attaching to a
        // live process skips these to avoid destabilizing it.
        // The NtRaiseHardError hook is opt-in (VMPNTHOOK=1): patching ntdll
        // involves a VirtualProtect on its image which can hang the process on
        // some systems, so it is disabled unless explicitly requested.
        wchar_t noHook[8] = L"";
        GetEnvironmentVariableW(L"VMPNTHOOK", noHook, 8);
        if (wcscmp(noHook, L"1") == 0)
            antidebug::PatchNtRaiseHardError();
    }
    if (attach) DbgLog("[*] attach mode (live process)");

    bool dllTarget = IsDllTarget();
    ULONGLONG targetBase = 0;

    if (dllTarget) {
        // The host loads the target DLL after we're injected; wait for it to appear.
        DbgLog("[*] DLL target detected, waiting for module...");
        for (int i = 0; i < 300; ++i) {
            targetBase = FindTargetModuleBase();
            if (targetBase) break;
            Sleep(100);
        }
        if (!targetBase) {
            DbgLog("[!] timeout waiting for target module to load");
            antidebug::RemoveAll();
            return 1;
        }
        DbgLogF("[+] target module at 0x%llX", targetBase);
    } else {
        targetBase = FindTargetModuleBase();
        DbgLogF("[*] target module at 0x%llX", targetBase);
    }
    LogT("target module resolved");

    DbgLog("[*] waiting for VMP to finish unpacking...");
    DWORD waited = 0;
    bool ready = false;
    while (waited < 30000) {
        if (IsOepReady(targetBase)) {
            DbgLogF("[+] unpack detected after %ums", waited);
            ready = true;
            break;
        }
        if (waited > 0 && waited % 2000 == 0)
            DbgLogF("[~] still waiting... %ums", waited);
        Sleep(200);
        waited += 200;
    }

    if (!ready) {
        DbgLog("[!] timeout waiting for unpack");
        antidebug::RemoveAll();
        return 1;
    }
    LogT("oep ready");

    // Short extra delay to ensure VMP fully completes all post-unpack
    // operations (fixups, TLS callbacks, etc.) before we freeze the process.
    DbgLog("[*] waiting 1s for VMP to settle...");
    Sleep(1000);

    DbgLog("[*] suspending other threads...");
    SuspendOtherThreads();
    LogT("threads suspended");

    DbgLog("[*] dumping process memory...");
    DumpContext ctx = {};
    if (!DumpProcess(ctx)) {
        DbgLog("[!] DumpProcess failed");
        antidebug::RemoveAll();
        return 1;
    }
    LogT("dump snapshot taken");

    // Attached to a live process: unfreeze it now that the snapshot is taken.
    if (attach) {
        DbgLog("[*] resuming other threads...");
        ResumeOtherThreads();
    }

    wchar_t dumpPath[MAX_PATH];
    const wchar_t* ext = dllTarget ? L"dll" : L"exe";
    wchar_t outDir[MAX_PATH] = L"";
    ConfigureDumpPath(outDir, dllTarget);
    if (outDir[0])
        swprintf_s(dumpPath, L"%s\\dump_%d.%s", outDir, GetCurrentProcessId(), ext);
    else
        swprintf_s(dumpPath, L"dump_%d.%s", GetCurrentProcessId(), ext);
    DbgLogF("[*] writing raw dump to %S", dumpPath);
    HANDLE hRaw = CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hRaw != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hRaw, ctx.rawDump, (DWORD)ctx.rawSize, &written, nullptr);
        CloseHandle(hRaw);
        DbgLogF("[+] raw dump written: %u bytes", written);
    } else {
        DbgLog("[!] failed to create dump file");
    }
    LogT("raw dump written");

    DbgLogF("[*] reconstructing PE import table...");
    bool reconOk = ReconstructPeGuarded(ctx, dumpPath);
    if (reconOk) {
        DbgLogF("[+] PE dump saved to %S", dumpPath);
    }

    // Save VMP devirtualization disassembly if available
    if (ctx.vmpDetected && ctx.devirtCount > 0) {
            wchar_t disasmPath[MAX_PATH];
            wcsncpy_s(disasmPath, dumpPath, MAX_PATH);
            wchar_t* dot = wcsrchr(disasmPath, L'.');
            if (dot) wcscpy_s(dot, MAX_PATH - (dot - disasmPath), L"_devirt.txt");
            else wcscat_s(disasmPath, L"_devirt.txt");

            HANDLE hDisasm = CreateFileW(disasmPath, GENERIC_WRITE, 0, nullptr,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDisasm != INVALID_HANDLE_VALUE) {
                std::string header = "VMProtect Devirtualization Results\n";
                header += "---\n";
                header += "VMP Version: " + std::string(ctx.is64Bit ? "x64 " : "x86 ") +
                    std::to_string(ctx.devirtCount) + " entries devirtualized\n\n";

                for (auto& r : ctx.devirtResults) {
                    header += "--- Entry at RVA 0x" + std::to_string(r.outputRva) +
                        " (" + std::to_string(r.instrCount) + " instrs, " +
                        std::to_string(r.outputSize) + " bytes) ---\n";
                    header += r.disassembly + "\n\n";
                }

                DWORD written;
                WriteFile(hDisasm, header.c_str(), (DWORD)header.size(), &written, nullptr);
                CloseHandle(hDisasm);
                DbgLogF("[+] devirt disassembly saved to %S", disasmPath);
        }
    }

    FreeDump(ctx);
    antidebug::RemoveAll();
    DbgLog("[*] dump worker done");
    LogT("dump worker done");
    if (g_hPipe && g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(nullptr, 0, DumpWorker, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
