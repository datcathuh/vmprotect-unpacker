#pragma once
#include <windows.h>
#include <string>
#include <vector>

class PEParser {
public:
    PEParser();
    ~PEParser();

    bool LoadFromFile(const std::wstring& filePath);
    bool LoadFromMemory(const void* data, size_t size);
    void Unload();

    bool IsValid() const;
    WORD GetMachine() const;
    DWORD GetEntryPointRVA() const;
    ULONGLONG GetImageBase() const;
    DWORD GetSizeOfImage() const;
    WORD GetSubsystem() const;
    bool Is64Bit() const;

    bool GetSection(const std::string& name, IMAGE_SECTION_HEADER* outHeader, BYTE** outData = nullptr) const;
    DWORD GetExportFunctionRVA(const std::string& funcName) const;

    const IMAGE_FILE_HEADER* GetFileHeader()       const { return m_fileHeader; }
    const IMAGE_OPTIONAL_HEADER* GetOptionalHeader()   const { return m_optHeader; }
    const IMAGE_SECTION_HEADER* GetSectionHeaders()   const { return m_sections; }
    int                            GetSectionCount()     const { return m_sectionCount; }

private:
    bool ParseHeaders();

    void* m_mappedData;
    size_t m_dataSize;
    bool m_isValid;
    IMAGE_DOS_HEADER* m_dosHeader;
    IMAGE_NT_HEADERS* m_ntHeaders;
    IMAGE_FILE_HEADER* m_fileHeader;
    IMAGE_OPTIONAL_HEADER* m_optHeader;
    IMAGE_SECTION_HEADER* m_sections;
    int m_sectionCount;
};