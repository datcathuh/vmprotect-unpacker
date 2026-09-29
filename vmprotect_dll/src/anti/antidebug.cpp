#include "antidebug.h"
#include "../utils.h"

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

extern "C" NTSTATUS NTAPI NtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength);

extern "C" NTSTATUS NTAPI NtClose(HANDLE Handle);

#ifndef ProcessDebugObjectHandle
#define ProcessDebugObjectHandle 0x1e
#endif
#ifndef ProcessDebugFlags
#define ProcessDebugFlags 0x1f
#endif
#ifndef STATUS_PORT_NOT_SET
#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)
#endif

static PVOID g_vehHandle = nullptr;

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((LONG)(LONG_PTR)&(((type*)0)->field))
#endif

namespace antidebug {

bool PatchPeb() {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb) {
        DbgLog("[!] Failed to get PEB");
        return false;
    }

    DbgLogF("[*] PEB at 0x%p, BeingDebugged=%d", peb, peb->BeingDebugged);

    peb->BeingDebugged = 0;

    // NtGlobalFlag is at offset 0xBC from PEB base
    *(PDWORD)((PBYTE)peb + 0xBC) = 0;

    DbgLog("[+] PEB patched (BeingDebugged=0, NtGlobalFlag=0)");
    return true;
}

/*
 * Clear debug heap flags. The debugger sets extra flags in the heap
 * structure (HEAP_TAIL_CHECKING, HEAP_FREE_CHECKING, HEAP_VALIDATE_PARAMS).
 * We clear only those bits to avoid breaking heap invariants.
 */
bool PatchHeapFlags() {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb) {
        DbgLog("[!] Failed to get PEB for heap patch");
        return false;
    }

    PVOID heap = *(PVOID*)((PBYTE)peb + 0x18);
    if (!heap) {
        DbgLog("[!] Failed to get process heap");
        return false;
    }

    ULONG flags = *(ULONG*)((PBYTE)heap + 0x70);
    ULONG forceFlags = *(ULONG*)((PBYTE)heap + 0x74);

    const ULONG debugBits = 0x40000060;
    if ((flags & debugBits) || forceFlags) {
        DbgLogF("[*] Heap flags before: Flags=0x%X ForceFlags=0x%X", flags, forceFlags);
        *(ULONG*)((PBYTE)heap + 0x70) &= ~debugBits;
        *(ULONG*)((PBYTE)heap + 0x74) = 0;
        DbgLog("[+] Heap flags restored to non-debugged values");
    } else {
        DbgLog("[*] Heap flags already clean");
    }
    return true;
}

/*
 * NtQueryInformationProcess hook with proper trampoline.
 * VMP uses direct syscalls for this function, so we must use a 12-byte
 * hook (mov rax, hookFn; jmp rax) to catch all callers.
 * The trampoline preserves the original bytes for chaining.
 */
static BYTE g_originalBytes[12] = {};
static PVOID g_trampoline = nullptr;

static NTSTATUS NTAPI NtQueryInformationProcessHook(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    auto realNtQueryInfo = (decltype(&NtQueryInformationProcess))g_trampoline;
    NTSTATUS status = realNtQueryInfo(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    if (status >= 0 && ProcessInformation) {
        if (ProcessInformationClass == (PROCESSINFOCLASS)ProcessDebugPort) {
            *(DWORD*)ProcessInformation = 0;
        }
        else if (ProcessInformationClass == (PROCESSINFOCLASS)ProcessDebugObjectHandle) {
            *(HANDLE*)ProcessInformation = nullptr;
            status = STATUS_PORT_NOT_SET;
        }
        else if (ProcessInformationClass == (PROCESSINFOCLASS)ProcessDebugFlags) {
            *(ULONG*)ProcessInformation = 1;
        }
    }
    return status;
}

bool PatchNtQueryInfo() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        DbgLog("[!] ntdll not found");
        return false;
    }

    FARPROC target = GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!target) {
        DbgLog("[!] NtQueryInformationProcess not found");
        return false;
    }

    DbgLogF("[*] NtQueryInformationProcess at 0x%p", target);

    BYTE* code = (BYTE*)target;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(code, &mbi, sizeof(mbi)) == 0) {
        DbgLog("[!] VirtualQuery failed");
        return false;
    }
    DWORD oldProtect;
    if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
        DbgLog("[!] VirtualProtect failed");
        return false;
    }

    if (code[0] == 0xE9) {
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
        return true;
    }

    const int hookSize = 12;

    // Save original bytes for trampoline
    memcpy(g_originalBytes, code, hookSize);

    // Allocate a trampoline: original bytes + jmp back to original + hookSize
    g_trampoline = VirtualAlloc(nullptr, hookSize + 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_trampoline) {
        DbgLog("[!] Failed to allocate trampoline");
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
        return false;
    }

    BYTE* tramp = (BYTE*)g_trampoline;
    memcpy(tramp, code, hookSize);
    BYTE jmpBack[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xE0
    };
    *(PVOID*)&jmpBack[2] = code + hookSize;
    memcpy(tramp + hookSize, jmpBack, sizeof(jmpBack));

    // Write 12-byte hook: mov rax, hookFn; jmp rax
    BYTE patch[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xE0
    };
    *(PVOID*)&patch[2] = NtQueryInformationProcessHook;
    memcpy(code, patch, hookSize);

    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);

    DbgLog("[+] NtQueryInformationProcess hooked (with trampoline)");
    return true;
}

/*
 * Hook NtRaiseHardError to suppress VMP's "debugger found" dialog.
 *
 * NOTE: We must NOT return quickly. The original dialog blocks VMP's
 * main thread, which gives our DumpWorker time to dump the process.
 * If we return immediately, VMP proceeds to call ExitProcess and kills
 * everything. We sleep here to match the dialog blocking behavior.
 */
static NTSTATUS NTAPI NtRaiseHardErrorHook(
    NTSTATUS ErrorStatus, ULONG NumberOfParameters,
    ULONG UnicodeStringParameterMask, PULONG_PTR Parameters,
    ULONG ValidResponseOptions, DWORD* Response)
{
    if (Response) *Response = 3;
    DbgLog("[*] NtRaiseHardError suppressed, blocking thread for 5s...");
    Sleep(5000);
    return 0;
}

bool PatchNtRaiseHardError() {
    DbgLog("[HOOK] PatchNtRaiseHardError enter");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { DbgLog("[HOOK] ntdll not found"); return false; }

    FARPROC target = GetProcAddress(ntdll, "NtRaiseHardError");
    if (!target) { DbgLog("[HOOK] NtRaiseHardError not found"); return false; }
    DbgLogF("[HOOK] NtRaiseHardError at %p", target);

    BYTE* code = (BYTE*)target;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(code, &mbi, sizeof(mbi)) == 0) { DbgLog("[HOOK] VirtualQuery failed"); return false; }
    DbgLogF("[HOOK] VirtualQuery base=%p prot=%X", mbi.BaseAddress, mbi.Protect);

    DWORD oldProtect;
    if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) {
        DbgLog("[HOOK] VirtualProtect failed");
        return false;
    }
    DbgLog("[HOOK] VirtualProtect PAGE_READWRITE ok");

    if (code[0] == 0xE9) {
        DbgLog("[HOOK] already hooked (E9), skipping");
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
        return true;
    }
    DbgLogF("[HOOK] code[0]=0x%02X", code[0]);

    // 5-byte jmp rel32 (safe for syscall stubs which are at least 8 bytes)
    INT_PTR offset = (INT_PTR)NtRaiseHardErrorHook - ((INT_PTR)code + 5);
    if (offset < -0x7FFFFFFF || offset > 0x7FFFFFFF) {
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
        DbgLog("[!] NtRaiseHardError hook target too far (>2GB)");
        return false;
    }
    BYTE patch[5] = { 0xE9 };
    *(INT32*)&patch[1] = (INT32)offset;

    DbgLog("[HOOK] writing 5-byte JMP patch...");
    memcpy(code, patch, sizeof(patch));
    DbgLog("[HOOK] memcpy done");

    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
    DbgLog("[+] NtRaiseHardError hooked (dialog suppressed)");
    return true;
}

/*
 * Hook NtTerminateProcess to prevent VMP from killing the process
 * after it detects a debugger.
 */
static NTSTATUS NTAPI NtTerminateProcessHook(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    if (ProcessHandle == NULL || ProcessHandle == GetCurrentProcess()) {
        DbgLog("[*] NtTerminateProcess(self) blocked");
        return 0;
    }
    DbgLog("[*] NtTerminateProcess(others) blocked");
    return 0;
}

bool PatchNtTerminateProcess() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        DbgLog("[!] ntdll not found for NtTerminateProcess hook");
        return false;
    }

    FARPROC target = GetProcAddress(ntdll, "NtTerminateProcess");
    if (!target) {
        target = GetProcAddress(ntdll, "ZwTerminateProcess");
        if (!target) {
            DbgLog("[!] NtTerminateProcess/ZwTerminateProcess not found in ntdll");
            return false;
        }
    }

    BYTE* code = (BYTE*)target;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(code, &mbi, sizeof(mbi)) == 0) return false;
    DWORD oldProtect;
    if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect)) return false;

    if (code[0] == 0xE9) {
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
        return true;
    }

    BYTE patch[] = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xE0
    };
    *(PVOID*)&patch[2] = NtTerminateProcessHook;
    memcpy(code, patch, sizeof(patch));

    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
    DbgLog("[+] NtTerminateProcess hooked (exit blocked)");
    return true;
}

/* Clear hardware breakpoints that VMP might have set */
bool ClearHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    if (!GetThreadContext(hThread, &ctx)) {
        DbgLog("[!] GetThreadContext failed");
        return false;
    }

    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        DbgLogF("[*] Clearing HW breakpoints: DR0=0x%p DR1=0x%p DR2=0x%p DR3=0x%p",
            (PVOID)ctx.Dr0, (PVOID)ctx.Dr1, (PVOID)ctx.Dr2, (PVOID)ctx.Dr3);
        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
        ctx.Dr6 = ctx.Dr7 = 0;
        SetThreadContext(hThread, &ctx);
        DbgLog("[+] Hardware breakpoints cleared");
    }

    return true;
}

/*
 * VEH handler catches INT3 breakpoints and single-step exceptions
 * that VMP uses for anti-debug and unpacking.
 */
static LONG CALLBACK VmpExceptionHandler(PEXCEPTION_POINTERS ep) {
    ULONG code = ep->ExceptionRecord->ExceptionCode;
    ULONG_PTR addr = (ULONG_PTR)ep->ExceptionRecord->ExceptionAddress;

    if (code == EXCEPTION_BREAKPOINT) {
        DbgLogF("[VEH] INT3 at 0x%p, skipping", (PVOID)addr);
#if defined(_M_AMD64)
        ep->ContextRecord->Rip++;
#else
        ep->ContextRecord->Eip++;
#endif
        ep->ContextRecord->EFlags |= 0x10000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        DbgLogF("[VEH] Single-step at 0x%p", (PVOID)addr);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

bool InstallVehHandler() {
    if (g_vehHandle) {
        DbgLog("[*] VEH already installed");
        return true;
    }
    g_vehHandle = AddVectoredExceptionHandler(1, VmpExceptionHandler);
    if (g_vehHandle) {
        DbgLog("[+] Vectored exception handler installed");
        return true;
    }
    DbgLog("[!] Failed to install VEH");
    return false;
}

bool RemoveVehHandler() {
    if (g_vehHandle) {
        if (RemoveVectoredExceptionHandler(g_vehHandle)) {
            g_vehHandle = nullptr;
            DbgLog("[+] VEH removed");
            return true;
        }
    }
    return false;
}

void RemoveAll() {
    RemoveVehHandler();
}

}
