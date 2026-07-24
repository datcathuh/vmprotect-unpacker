#pragma once
#include <Windows.h>
#include <vector>
#include <string>

#include "../vmp/vmp_devirt.h"

struct DumpContext {
    ULONGLONG imageBase;
    DWORD sizeOfImage;
    DWORD oepRva;
    bool is64Bit;
    BYTE* rawDump;
    SIZE_T rawSize;

    DWORD sectionAlignment;
    DWORD fileAlignment;
    WORD sectionCount;
    std::vector<IMAGE_SECTION_HEADER> sections;

    // VMP devirtualization results
    bool vmpDetected;
    int vmpEntryCount;
    int devirtCount;
    std::vector<vmp::DevirtResult> devirtResults;

    DumpContext() : imageBase(0), sizeOfImage(0), oepRva(0), is64Bit(false),
        rawDump(nullptr), rawSize(0), sectionAlignment(0x1000), fileAlignment(0x200),
        sectionCount(0), vmpDetected(false), vmpEntryCount(0), devirtCount(0) {}
};

bool DumpProcess(DumpContext& ctx);
bool ReconstructPe(DumpContext& ctx, const std::wstring& outputPath);
void FreeDump(DumpContext& ctx);