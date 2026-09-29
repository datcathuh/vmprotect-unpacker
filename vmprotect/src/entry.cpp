#define _CRT_SECURE_NO_WARNINGS
#include <common.h>
#include <cstdlib>

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    std::string msg = "\n[!!!] EXCEPTION CAUGHT !!!\n";
    msg += "  ExceptionCode: 0x" + std::to_string(pExceptionInfo->ExceptionRecord->ExceptionCode) + "\n";
    msg += "  ExceptionAddress: 0x" + std::to_string((ULONG_PTR)pExceptionInfo->ExceptionRecord->ExceptionAddress) + "\n";
    msg += "  ExceptionFlags: 0x" + std::to_string(pExceptionInfo->ExceptionRecord->ExceptionFlags) + "\n";
    if (pExceptionInfo->ExceptionRecord->NumberParameters > 0) {
        msg += "  Parameters:\n";
        for (DWORD i = 0; i < pExceptionInfo->ExceptionRecord->NumberParameters; ++i) {
            msg += "    Param[" + std::to_string(i) + "] = 0x" +
                std::to_string(pExceptionInfo->ExceptionRecord->ExceptionInformation[i]) + "\n";
        }
    }
    Log(msg);
    return EXCEPTION_CONTINUE_SEARCH;
}

void print_banner()
{
    std::string banner[17];
    banner[0] = "⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣠⣤⣶⣶⣶⣤⣄⣀⣀⠄⠄⠄⠄⠄";
    banner[1] = "⠄⠄⠄⠄⠄⠄⠄⠄⣀⣤⣤⣶⣿⣿⣿⣿⣿⣿⣿⣟⢿⣿⣿⣿⣶⣤⡀⠄";
    banner[2] = "⠄⠄⠄⠄⠄⠄⢀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣜⠿⠿⣿⣿⣧⢓";
    banner[3] = "⠄⠄⠄⠄⠄⡠⢛⣿⣿⣿⡟⣿⣿⣽⣋⠻⢻⣿⣿⣿⣿⡻⣧⡠⣭⣭⣿⡧";
    banner[4] = "⠄⠄⠄⠄⠄⢠⣿⡟⣿⢻⠃⣻⣨⣻⠿⡀⣝⡿⣿⣿⣷⣜⣜⢿⣝⡿⡻⢔";
    banner[5] = "⠄⠄⠄⠄⠄⢸⡟⣷⢿⢈⣚⣓⡡⣻⣿⣶⣬⣛⣓⣉⡻⢿⣎⠢⠻⣴⡾⠫";
    banner[6] = "⠄⠄⠄⠄⠄⢸⠃⢹⡼⢸⣿⣿⣿⣦⣹⣿⣿⣿⠿⠿⠿⠷⣎⡼⠆⣿⠵⣫";
    banner[7] = "⠄⠄⠄⠄⠄⠈⠄⠸⡟⡜⣩⡄⠄⣿⣿⣿⣿⣶⢀⢀⣿⣷⣿⣿⡐⡇⡄⣿";
    banner[8] = "⠄⠄⠄⠄⠄⠄⠄⠄⠁⢶⢻⣧⣖⣿⣿⣿⣿⣿⣿⣿⣿⡏⣿⣇⡟⣇⣷⣿";
    banner[9] = "⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣆⣤⣽⣿⡿⠿⠿⣿⣿⣦⣴⡇⣿⢨⣾⣿⢹⢸";
    banner[10] = "⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⠊⡛⢿⣿⣿⣿⣿⡿⣫⢱⢺⡇⡏⣿⣿⣸⡼";
    banner[11] = "⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⡿⠄⣿⣷⣾⡍⣭⣶⣿⣿⡌⣼⣹⢱⠹⣿⣇⣧";
    banner[12] = "⠄⠄⠄⠄⠄⠄⠄⠄⠄⣼⠁⣤⣭⣭⡌⢁⣼⣿⣿⣿⢹⡇⣭⣤⣶⣤⡝⡼";
    banner[13] = "⠄⣀⠤⡀⠄⠄⠄⠄⠄⡏⣈⡻⡿⠃⢀⣾⣿⣿⣿⡿⡼⠁⣿⣿⣿⡿⢷⢸";
    banner[14] = "⢰⣷⡧⡢⠄⠄⠄⠄⠠⢠⡛⠿⠄⠠⠬⠿⣿⠭⠭⢱⣇⣀⣭⡅⠶⣾⣷⣶";
    banner[15] = "⠈⢿⣿⣧⠄⠄⠄⠄⢀⡛⠿⠄⠄⠄⠄⢠⠃⠄⠄⡜⠄⠄⣤⢀⣶⣮⡍⣴";
    banner[16] = "⠄⠈⣿⣿⡀⠄⠄⠄⢩⣝⠃⠄⠄⢀⡄⡎⠄⠄⠄⠇⠄⠄⠅⣴⣶⣶⠄⣶";

    for (int i = 0; i < 17; ++i) {
        std::cout << banner[i] << std::endl;
    }
    std::cout << "\n \n \n";
}

void init()
{
    SetConsoleTitleA("t.me/x3ghx / github.com/datcathuh/vmprotect-unpacker");
    SetConsoleOutputCP(CP_UTF8);
    print_banner();

    PVOID handler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    if (handler) {
        Log("[+] Vectored exception handler installed.");
    }
    else {
        Log("[!] Failed to install vectored exception handler.");
    }
}

static bool IsElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return true;
    TOKEN_ELEVATION te = {};
    DWORD size = 0;
    bool elevated = GetTokenInformation(hToken, TokenElevation, &te, sizeof(te), &size) && te.TokenIsElevated;
    CloseHandle(hToken);
    return elevated;
}

static bool HasDllExtension(const char* path) {
    size_t len = strlen(path);
    if (len < 4) return false;
    const char* ext = path + len - 4;
    return (ext[0] == '.') &&
           ((ext[1]=='d'||ext[1]=='D') && (ext[2]=='l'||ext[2]=='L') && (ext[3]=='l'||ext[3]=='L'));
}

int main(int argc, char* argv[]) {
    init();

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <target.exe|target.dll>\n";
        std::cout << "       " << argv[0] << " -pid <pid> [module.exe|module.dll]\n";
        return 1;
    }

    DllInjector injector;
    bool ok = false;

    if (strcmp(argv[1], "-pid") == 0) {
        if (argc < 3) {
            std::cout << "Usage: " << argv[0] << " -pid <pid> [module.exe|module.dll]\n";
            return 1;
        }
        DWORD pid = (DWORD)_atoi64(argv[2]);
        std::wstring modulePath;
        if (argc > 3) {
            modulePath = std::wstring(argv[3], argv[3] + strlen(argv[3]));
            wchar_t fullPath[MAX_PATH];
            if (GetFullPathNameW(modulePath.c_str(), MAX_PATH, fullPath, nullptr))
                modulePath = fullPath;
        }
        ok = injector.AttachPid(pid, modulePath);
    } else {
        std::wstring targetPath = std::wstring(argv[1], argv[1] + strlen(argv[1]));
        bool isDll = HasDllExtension(argv[1]);

        if (!IsElevated()) {
            Log("[~] Not running as admin — some targets may need elevation (run as admin if it fails)");
        }

        ok = isDll ? injector.InjectDll(targetPath) : injector.Inject(targetPath);
    }

    std::cout << "[~] Injection " << (ok ? "succeeded" : "failed") << std::endl;

    return -1337;
}