#define _CRT_SECURE_NO_WARNINGS
#include <common.h>

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
    SetConsoleTitleA(EC("t.me/x3ghx"));
    SetConsoleOutputCP(CP_UTF8);
    SPOOF_CALL(print_banner)();

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

int main(int argc, char* argv[]) {
    SPOOF_CALL(init)();

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <target.exe>\n";
        return 1;
    }

    std::wstring exePath = std::wstring(argv[1], argv[1] + strlen(argv[1]));

    if (!IsElevated()) {
        Log("[~] Not running as admin — some targets may need elevation (run as admin if it fails)");
    }

    DllInjector injector;
    bool ok = injector.Inject(exePath);
    std::cout << "[~] Injection " << (ok ? "succeeded" : "failed") << std::endl;

    return -1337;
}