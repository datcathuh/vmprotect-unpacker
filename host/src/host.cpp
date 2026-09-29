#include <windows.h>
#include <cstdio>
#include <cstdlib>

// Plain, non-packed loader host for dumping VMP-protected DLLs.
// vmprotect.exe spawns us suspended, injects vmprotect_dll.dll while suspended,
// then resumes us. We LoadLibrary the target DLL (which triggers its DllMain /
// unpacking) and then just idle so the unpacker can dump it.
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"usage: host.exe <dll_path> [sleep_seconds]\n");
        return 1;
    }

    wprintf(L"[host] loading %ls ...\n", argv[1]);

    // Don't let the OS raise dialogs that could stall VMP unpacking.
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    HMODULE hMod = LoadLibraryW(argv[1]);
    if (!hMod) {
        wprintf(L"[host] LoadLibraryW failed, error 0x%X\n", GetLastError());
        return 2;
    }
    wprintf(L"[host] loaded %ls at 0x%p\n", argv[1], (void*)hMod);

    DWORD sleepMs = 120000;
    if (argc >= 3)
        sleepMs = (DWORD)_wtoi(argv[2]) * 1000;

    Sleep(sleepMs);
    return 0;
}