#include <common.h>

PEParser::PEParser() : m_mappedData(nullptr), m_dataSize(0), m_isValid(false),
m_dosHeader(nullptr), m_ntHeaders(nullptr), m_fileHeader(nullptr),
m_optHeader(nullptr), m_sections(nullptr), m_sectionCount(0) {
}

PEParser::~PEParser() {
    Unload();
}

bool PEParser::LoadFromFile(const std::wstring& filePath) {
    Unload();

    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size == 0)
        return false;

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size))
        return false;

    m_mappedData = malloc(size);
    if (!m_mappedData)
        return false;

    memcpy(m_mappedData, buffer.data(), size);
    m_dataSize = size;

    return ParseHeaders();
}

bool PEParser::LoadFromMemory(const void* data, size_t size) {
    Unload();

    if (!data || size == 0)
        return false;

    m_mappedData = malloc(size);
    if (!m_mappedData)
        return false;

    memcpy(m_mappedData, data, size);
    m_dataSize = size;

    return ParseHeaders();
}

void PEParser::Unload() {
    if (m_mappedData) {
        free(m_mappedData);
        m_mappedData = nullptr;
    }
    m_dataSize = 0;
    m_isValid = false;
    m_dosHeader = nullptr;
    m_ntHeaders = nullptr;
    m_fileHeader = nullptr;
    m_optHeader = nullptr;
    m_sections = nullptr;
    m_sectionCount = 0;
}

bool PEParser::ParseHeaders() {
    if (!m_mappedData || m_dataSize < sizeof(IMAGE_DOS_HEADER))
        return false;

    m_dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_mappedData);
    if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (m_dataSize < m_dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))
        return false;

    m_ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(m_mappedData) + m_dosHeader->e_lfanew);
    if (m_ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;

    m_fileHeader = &m_ntHeaders->FileHeader;
    m_optHeader = &m_ntHeaders->OptionalHeader;

    if (m_optHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        m_optHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;

    // Locate section headers
    m_sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<BYTE*>(m_ntHeaders) + sizeof(IMAGE_NT_HEADERS));
    m_sectionCount = m_fileHeader->NumberOfSections;

    m_isValid = true;
    return true;
}

bool PEParser::IsValid() const {
    return m_isValid;
}

WORD PEParser::GetMachine() const {
    return m_isValid ? m_fileHeader->Machine : 0;
}

DWORD PEParser::GetEntryPointRVA() const {
    return m_isValid ? m_optHeader->AddressOfEntryPoint : 0;
}

ULONGLONG PEParser::GetImageBase() const {
    if (!m_isValid) return 0;
    if (m_optHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return reinterpret_cast<IMAGE_NT_HEADERS64*>(m_ntHeaders)->OptionalHeader.ImageBase;
    else
        return reinterpret_cast<IMAGE_NT_HEADERS32*>(m_ntHeaders)->OptionalHeader.ImageBase;
}

DWORD PEParser::GetSizeOfImage() const {
    return m_isValid ? m_optHeader->SizeOfImage : 0;
}

WORD PEParser::GetSubsystem() const {
    return m_isValid ? m_optHeader->Subsystem : 0;
}

bool PEParser::Is64Bit() const {
    return m_isValid && (m_optHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

bool PEParser::GetSection(const std::string& name, IMAGE_SECTION_HEADER* outHeader, BYTE** outData) const {
    if (!m_isValid || !outHeader)
        return false;

    char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
    for (int i = 0; i < m_sectionCount; ++i) {
        const auto& sec = m_sections[i];
        memcpy(sectionName, sec.Name, IMAGE_SIZEOF_SHORT_NAME);
        sectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        if (name.compare(sectionName) == 0) {
            *outHeader = sec;
            if (outData) {
                *outData = reinterpret_cast<BYTE*>(m_mappedData) + sec.VirtualAddress;
            }
            return true;
        }
    }
    return false;
}

DWORD PEParser::GetExportFunctionRVA(const std::string& funcName) const {
    if (!m_isValid)
        return 0;

    // Locate export directory
    DWORD exportRVA = m_optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0)
        return 0;

    // Find the export section
    IMAGE_SECTION_HEADER exportSection;
    if (!GetSection(".edata", &exportSection))
        return 0;

    BYTE* exportBase = reinterpret_cast<BYTE*>(m_mappedData) + exportSection.VirtualAddress;
    // The export directory might be in .rdata, so we need to find the section containing exportRVA
    // For simplicity, we'll assume it's in .edata or we map by RVA.
    // Instead, we can directly use RVA by computing offset from section.
    // Better: we can use RVA to file offset conversion, but for simplicity we'll find section containing exportRVA.
    IMAGE_SECTION_HEADER* containingSec = nullptr;
    for (int i = 0; i < m_sectionCount; ++i) {
        DWORD start = m_sections[i].VirtualAddress;
        DWORD end = start + m_sections[i].Misc.VirtualSize;
        if (exportRVA >= start && exportRVA < end) {
            containingSec = &m_sections[i];
            break;
        }
    }
    if (!containingSec)
        return 0;

    IMAGE_EXPORT_DIRECTORY* exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<BYTE*>(m_mappedData) + containingSec->PointerToRawData +
        (exportRVA - containingSec->VirtualAddress));

    DWORD* names = reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(m_mappedData) + containingSec->PointerToRawData +
        (exportDir->AddressOfNames - containingSec->VirtualAddress));
    WORD* ordinals = reinterpret_cast<WORD*>(
        reinterpret_cast<BYTE*>(m_mappedData) + containingSec->PointerToRawData +
        (exportDir->AddressOfNameOrdinals - containingSec->VirtualAddress));
    DWORD* functions = reinterpret_cast<DWORD*>(
        reinterpret_cast<BYTE*>(m_mappedData) + containingSec->PointerToRawData +
        (exportDir->AddressOfFunctions - containingSec->VirtualAddress));

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        char* namePtr = reinterpret_cast<char*>(
            reinterpret_cast<BYTE*>(m_mappedData) + containingSec->PointerToRawData +
            (names[i] - containingSec->VirtualAddress));
        if (funcName.compare(namePtr) == 0) {
            WORD ordinal = ordinals[i];
            return functions[ordinal];
        }
    }
    return 0;
}