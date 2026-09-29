#pragma once
#include <windows.h>
#include <string>
#include <vector>

class DllInjector {
public:
    DllInjector();
    ~DllInjector();

    bool Inject(const std::wstring& exePath);
    bool InjectDll(const std::wstring& dllPath);
    bool AttachPid(DWORD pid, const std::wstring& modulePath);

private:
    std::vector<BYTE> m_dllData;
    std::vector<BYTE> m_hostData;
    bool m_dllLoaded;
    bool m_hostLoaded;

    bool LoadNtFunctions();
    bool LoadDllFromResource();
    bool LoadHostFromResource();
    bool LoadFileBytes(const std::wstring& filePath, std::vector<BYTE>& outData);
    bool InjectViaLdr(HANDLE hProcess, const std::vector<BYTE>& dllData, const std::wstring& pipeName);
    bool RunTarget(const std::wstring& exeToRun,
                   const std::wstring& commandLine,
                   const std::wstring& targetDir,
                   const std::wstring& targetDllPath,
                   const wchar_t* dumpExtension);
    std::wstring WriteHostToTemp();
};