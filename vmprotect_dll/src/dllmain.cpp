#include <Windows.h>
#include <tlhelp32.h>
#include "anti/antidebug.h"
#include "core/dump.h"
#include "utils.h"

HANDLE g_hPipe = INVALID_HANDLE_VALUE;

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

static ULONGLONG FindImageBase() {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    return (ULONGLONG)peb->Reserved3[1];
}

static bool IsValidMemory(const void* addr, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    return VirtualQuery(addr, &mbi, sizeof(mbi)) &&
        mbi.State == MEM_COMMIT &&
        (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
}

static bool IsOepReady() {
    BYTE buf[0x1000];
    ULONGLONG base = FindImageBase();
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

    // Tier 3: Fallback after 2+ seconds — check standard section names.
    // This handles targets where VMP restored the original PE header
    // or non-packed targets where nothing changed (Tier 1 never fires).
    if (pollCount >= 10) {
        int n = 0;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            char name[9] = {};
            memcpy(name, sec[i].Name, 8);
            if (strcmp(name, ".text") == 0 || strcmp(name, ".rdata") == 0 ||
                strcmp(name, ".data") == 0 || strcmp(name, ".rsrc") == 0 ||
                strcmp(name, ".reloc") == 0 || strcmp(name, ".pdata") == 0 ||
                strcmp(name, ".idata") == 0)
                n++;
        }
        if (n >= 2)
            return true;
    }

    return false;
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

static DWORD WINAPI DumpWorker(LPVOID) {
    DbgLog("[*] dump worker started");

    ConnectToPipe();
    antidebug::PatchPeb();
    antidebug::ClearHardwareBreakpoints();
    antidebug::InstallVehHandler();
    antidebug::PatchNtRaiseHardError();

    DbgLog("[*] waiting for VMP to finish unpacking...");
    DWORD waited = 0;
    bool ready = false;
    while (waited < 30000) {
        if (IsOepReady()) {
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

    // Short extra delay to ensure VMP fully completes all post-unpack
    // operations (fixups, TLS callbacks, etc.) before we freeze the process.
    DbgLog("[*] waiting 1s for VMP to settle...");
    Sleep(1000);

    DbgLog("[*] suspending other threads...");
    SuspendOtherThreads();

    DbgLog("[*] dumping process memory...");
    DumpContext ctx = {};
    if (!DumpProcess(ctx)) {
        DbgLog("[!] DumpProcess failed");
        antidebug::RemoveAll();
        return 1;
    }

    wchar_t dumpPath[MAX_PATH];
    wchar_t outDir[MAX_PATH] = L"";
    if (GetEnvironmentVariableW(L"VMPOUTDIR", outDir, MAX_PATH) && outDir[0]) {
        swprintf_s(dumpPath, L"%s\\dump_%d.exe", outDir, GetCurrentProcessId());
    } else {
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
            wchar_t* slash = wcsrchr(exePath, L'\\');
            if (slash) {
                *(slash + 1) = 0;
                swprintf_s(dumpPath, L"%sdump_%d.exe", exePath, GetCurrentProcessId());
            } else {
                swprintf_s(dumpPath, L"dump_%d.exe", GetCurrentProcessId());
            }
        } else {
            swprintf_s(dumpPath, L"dump_%d.exe", GetCurrentProcessId());
        }
    }
    DbgLogF("[*] reconstructing PE -> %S", dumpPath);

    if (ReconstructPe(ctx, dumpPath)) {
        DbgLogF("[+] dump saved to %S", dumpPath);

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
    }

    FreeDump(ctx);
    antidebug::RemoveAll();
    DbgLog("[*] dump worker done");
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
