#pragma once
#include <windows.h>
#include <string>
#include <vector>

class DllInjector {
public:
    DllInjector();
    ~DllInjector();

    bool Inject(const std::wstring& exePath);

private:
    std::vector<BYTE> m_dllData;
    bool m_dllLoaded;

    bool LoadNtFunctions();
    bool LoadDllFromResource();
    bool LoadDllFromFile(const std::wstring& filePath, std::vector<BYTE>& outData);
    bool InjectViaLdr(HANDLE hProcess, const std::vector<BYTE>& dllData, const std::wstring& pipeName);
};
