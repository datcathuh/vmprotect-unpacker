#pragma once
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <cstring>
#include <algorithm>
#include "../utils.h"

#pragma comment(lib, "ntdll.lib")

namespace vmp {

// VM handler descriptor
struct VMHandler {
    DWORD rva;
    DWORD nextOpcodeRva;
    int opcodeValue;
    DWORD size;
    std::vector<BYTE> code;
    bool isEndHandler;
    DWORD extJmpTarget;
};

// A discovered VM entry point (push bytecode; call/jmp handler)
struct VMEntryPoint {
    DWORD rva;
    DWORD bytecodeRva;
    DWORD bytecodeSize;
    DWORD dispatcherRva;
};

/*
 * All VMP detection results: handler table, handlers, entry points,
 * loader section range, version info
 */
struct VMPDetectResult {
    bool detected;
    bool isV2;
    bool hasBytecodeEncryption;
    bool hasImportProtection;
    DWORD dispatcherRva;
    DWORD handlerTableRva;
    DWORD handlerTableSize;
    DWORD entryPoint;
    DWORD loaderRva;
    DWORD loaderSize;
    std::vector<VMHandler> handlers;
    std::vector<VMEntryPoint> entries;
    std::vector<DWORD> vmpSectionRvas;
    int vmEntryCount;
};

// VM instruction types
enum VMInstType : WORD {
    vmNop = 0, vmPush = 0x101, vmPop = 0x102, vmMov = 0x103,
    vmAdd = 0x104, vmSub = 0x105, vmAnd = 0x106, vmOr = 0x107,
    vmXor = 0x108, vmMul = 0x109, vmDiv = 0x10A,
    vmShl = 0x10B, vmShr = 0x10C, vmSar = 0x10D,
    vmRol = 0x10E, vmRor = 0x10F,
    vmNot = 0x110, vmNeg = 0x111, vmCmp = 0x112, vmTest = 0x113,
    vmInc = 0x114, vmDec = 0x115, vmCall = 0x116, vmJmp = 0x117,
    vmJcc = 0x118, vmRet = 0x119, vmPushf = 0x11A, vmPopf = 0x11B,
    vmLeave = 0x11C, vmBswap = 0x11D, vmCwde = 0x11E, vmCdq = 0x11F,
    vmCqo = 0x120, vmSetcc = 0x121, vmCmpxchg = 0x122, vmXadd = 0x123,
    vmMovzx = 0x124, vmMovsx = 0x125, vmLea = 0x126,
    vmPushMem = 0x127, vmPopMem = 0x128, vmCallExtern = 0x129,
    vmReadTls = 0x12A, vmReadGs = 0x12B, vmReadFs = 0x12C,
    vmRdtsc = 0x12D, vmCpuid = 0x12E, vmInvalid = 0xFFFF
};

enum VMOpSize : BYTE {
    vmSizeByte = 0, vmSizeWord = 1, vmSizeDword = 2, vmSizeQword = 3, vmSizeDefault = 4
};

// Quick sanity check: does this look like valid handler code?
static bool IsLikelyHandlerCode(const BYTE* code, DWORD size) {
    if (size < 8) return false;
    int nonzero = 0;
    for (DWORD i = 0; i < min(size, (DWORD)32); ++i)
        if (code[i] != 0 && code[i] != 0xFF) nonzero++;
    if (nonzero < 4) return false;
    int knownInstrs = 0;
    for (DWORD i = 0; i < min(size, (DWORD)64) - 1; ++i) {
        if (code[i] == 0x89 || code[i] == 0x8B ||
            code[i] == 0x03 || code[i] == 0x01 ||
            code[i] == 0x33 || code[i] == 0x31 ||
            code[i] == 0xFF ||
            code[i] == 0x0F) knownInstrs++;
    }
    return knownInstrs >= 2;
}

/*
 * Find VMP handler table by scanning for 256 consecutive code pointers.
 * Returns RVA of the table, or 0 if not found.
 */
static DWORD FindHandlerTable(const BYTE* dump, DWORD size,
    bool& outIsV2, DWORD& outTableSize) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;

    struct SectionInfo { DWORD start, end; };
    std::vector<SectionInfo> execSections;
    std::vector<SectionInfo> allSections;
    for (WORD i = 0; i < sc; ++i) {
        SectionInfo si = { sec[i].VirtualAddress, sec[i].VirtualAddress + sec[i].Misc.VirtualSize };
        allSections.push_back(si);
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            execSections.push_back(si);
    }

    auto isInExec = [&](DWORD rva) -> bool {
        for (auto& s : execSections)
            if (rva >= s.start && rva < s.end) return true;
        return false;
    };

    // Try V2 first (4-byte relative offsets)
    DWORD entrySize2 = 4;
    DWORD tableSize2 = 256 * entrySize2;

    for (auto& sect : allSections) {
        DWORD start = sect.start;
        DWORD end = min(sect.end, size - tableSize2);
        for (DWORD rva = start; rva < end; ++rva) {
            int32_t firstOff = *(int32_t*)(dump + rva);
            DWORD firstTarget = rva + firstOff;
            if (!isInExec(firstTarget)) continue;

            int validCount = 0;
            for (int k = 0; k < 8; ++k) {
                int idx = (k * 37) % 256;
                int32_t off = *(int32_t*)(dump + rva + idx * 4);
                DWORD target = rva + off;
                if (isInExec(target) && IsLikelyHandlerCode(dump + target, size - target))
                    validCount++;
            }
            int zeroCount = 0;
            for (int k = 0; k < 256; ++k) {
                int32_t off = *(int32_t*)(dump + rva + k * 4);
                if (off == 0 || off == -1) zeroCount++;
            }

            if (validCount >= 5 && zeroCount < 50) {
                outIsV2 = true;
                outTableSize = tableSize2;
                DbgLogF("[VMP] V2 handler table at 0x%X (%d valid entries)", rva, validCount);
                return rva;
            }
        }
    }

    // Try V1 (8-byte pointers)
    DWORD entrySize1 = 8;
    DWORD tableSize1 = 256 * entrySize1;

    for (auto& sect : allSections) {
        DWORD start = sect.start;
        DWORD end = min(sect.end, size - tableSize1);
        for (DWORD rva = start; rva < end; rva += 4) {
            ULONGLONG firstPtr = *(ULONGLONG*)(dump + rva);
            DWORD firstTarget = (DWORD)(firstPtr & 0xFFFFFFFF);
            if (firstPtr == 0 || firstPtr == (ULONGLONG)-1) continue;
            if (firstTarget > 0x100000 && firstTarget < size && isInExec(firstTarget)) {
                int validCount = 0;
                for (int k = 0; k < 8; ++k) {
                    int idx = (k * 37) % 256;
                    ULONGLONG ptr = *(ULONGLONG*)(dump + rva + idx * 8);
                    DWORD target = (DWORD)(ptr & 0xFFFFFFFF);
                    if (target > 0x10000 && target < size && isInExec(target) &&
                        IsLikelyHandlerCode(dump + target, size - target))
                        validCount++;
                }
                if (validCount >= 5) {
                    outIsV2 = false;
                    outTableSize = tableSize1;
                    DbgLogF("[VMP] V1 handler table at 0x%X (%d valid entries)", rva, validCount);
                    return rva;
                }
            }
        }
    }

    return 0;
}

/*
 * Extract handlers from a discovered handler table.
 */
static bool ExtractHandlers(const BYTE* dump, DWORD size, DWORD tableRva, DWORD tableSize,
    bool isV2, std::vector<VMHandler>& outHandlers) {
    outHandlers.clear();
    if (tableRva == 0 || tableRva >= size) return false;
    int entryCount = min(256, (int)(tableSize / (isV2 ? 4 : 8)));
    if (entryCount <= 0) return false;

    for (int i = 0; i < entryCount; ++i) {
        DWORD handlerRva;
        if (isV2) {
            if (tableRva + i * 4 + 4 > size) break;
            int32_t relOff = *(int32_t*)(dump + tableRva + i * 4);
            if (relOff == 0 || relOff == -1) continue;
            handlerRva = tableRva + relOff;
        } else {
            if (tableRva + i * 8 + 8 > size) break;
            ULONGLONG ptr = *(ULONGLONG*)(dump + tableRva + i * 8);
            handlerRva = (DWORD)(ptr & 0xFFFFFFFF);
            if (handlerRva == 0 || handlerRva >= size) continue;
        }
        if (handlerRva == 0 || handlerRva >= size) continue;

        VMHandler h;
        h.rva = handlerRva;
        h.opcodeValue = i;
        h.isEndHandler = false;
        h.extJmpTarget = 0;
        DWORD maxCodeSize = min((DWORD)512, size - handlerRva);
        h.code.assign(dump + handlerRva, dump + handlerRva + maxCodeSize);
        h.size = maxCodeSize;
        outHandlers.push_back(h);
    }
    return !outHandlers.empty();
}

/*
 * Find VM entry points by scanning executable sections for
 * patterns like "push bytecode; call handler" or "mov reg, bytecode; call handler".
 */
static void FindVmEntries(BYTE* dump, DWORD sizeOfImage, DWORD handlerTableRva,
    BOOL isV2, std::vector<VMEntryPoint>& outEntries) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;

    DWORD minBytecodeRva = handlerTableRva;
    DWORD maxBytecodeRva = minBytecodeRva + (isV2 ? 256 * 4 : 256 * 8);

    for (WORD si = 0; si < sc; ++si) {
        if (!(sec[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD secRva = sec[si].VirtualAddress;
        DWORD secSize = sec[si].Misc.VirtualSize;
        if (secRva + secSize > sizeOfImage) secSize = sizeOfImage - secRva;

        for (DWORD i = 0; i < secSize - 8; ++i) {
            DWORD bytecodeRva = 0;

            if (i + 10 <= secSize && dump[secRva + i] == 0x68 &&
                (dump[secRva + i + 5] == 0xE8 || dump[secRva + i + 5] == 0xE9)) {
                bytecodeRva = *(uint32_t*)(dump + secRva + i + 1);
            }
            if (i + 10 <= secSize && (dump[secRva + i] == 0xB9 || dump[secRva + i] == 0xBA) &&
                dump[secRva + i + 5] == 0xE8) {
                bytecodeRva = *(uint32_t*)(dump + secRva + i + 1);
            }
            if (i + 14 <= secSize && (dump[secRva + i] == 0x48 || dump[secRva + i] == 0x4C) &&
                (dump[secRva + i + 1] & 0xF8) == 0xB8 && dump[secRva + i + 9] == 0xE8) {
                bytecodeRva = (DWORD)(*(ULONGLONG*)(dump + secRva + i + 2));
            }
            if (i + 11 <= secSize && dump[secRva + i] == 0x68 &&
                dump[secRva + i + 5] == 0xFF && dump[secRva + i + 6] == 0x15) {
                bytecodeRva = *(uint32_t*)(dump + secRva + i + 1);
            }

            if (bytecodeRva > 0 && bytecodeRva < sizeOfImage &&
                bytecodeRva != handlerTableRva) {
                VMEntryPoint ep;
                ep.rva = secRva + i;
                ep.bytecodeRva = bytecodeRva;
                ep.bytecodeSize = min(sizeOfImage - bytecodeRva, (DWORD)0x10000);
                ep.dispatcherRva = 0;
                outEntries.push_back(ep);
            }
        }
    }
}

/* Detect bytecode encryption: check handlers for XOR instructions */
static bool HasBytecodeEncryption(const std::vector<VMHandler>& handlers) {
    int xorCount = 0;
    for (size_t hi = 0; hi < handlers.size(); ++hi) {
        auto& h = handlers[hi];
        for (DWORD bi = 0; bi < min(h.size, (DWORD)100) - 1; ++bi) {
            if (h.code[bi] == 0x35 || (h.code[bi] == 0x81 && h.code[bi + 1] == 0xF0) ||
                (h.code[bi] == 0x83 && h.code[bi + 1] == 0xF0) || h.code[bi] == 0x34 ||
                (h.code[bi] == 0x48 && h.code[bi + 1] == 0x35)) {
                xorCount++;
            }
        }
    }
    return xorCount > (int)handlers.size() * 2;
}

/*
 * Main detection function.
 * Scans the dumped image for VMP handler tables, extracts handlers,
 * finds entry points, and identifies the VMP code section.
 */
static bool DetectVMP(BYTE* dump, DWORD sizeOfImage, VMPDetectResult& out) {
    ZeroMemory(&out, sizeof(out));
    if (!dump || sizeOfImage < 0x1000) return false;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    out.entryPoint = nt->OptionalHeader.AddressOfEntryPoint;

    // Step 1: Find handler table
    bool isV2 = false;
    DWORD tableSize = 0;
    DWORD tableRva = FindHandlerTable(dump, sizeOfImage, isV2, tableSize);
    if (!tableRva) {
        DbgLog("[*] no VMP handler table found");
        return false;
    }

    out.isV2 = isV2;
    out.handlerTableRva = tableRva;
    out.handlerTableSize = tableSize;
    out.detected = true;

    // Step 2: Extract handlers
    ExtractHandlers(dump, sizeOfImage, tableRva, tableSize, isV2, out.handlers);
    DbgLogF("[VMP] extracted %zu handlers from table at 0x%X (V%d)", 
        out.handlers.size(), tableRva, isV2 ? 2 : 1);

    // Step 3: Detect bytecode encryption
    out.hasBytecodeEncryption = HasBytecodeEncryption(out.handlers);
    if (out.hasBytecodeEncryption) DbgLog("[VMP] bytecode encryption detected");

    // Step 4: Find VM entry points
    FindVmEntries(dump, sizeOfImage, tableRva, isV2, out.entries);
    out.vmEntryCount = (int)out.entries.size();

    // Deduplicate by bytecode RVA
    std::set<DWORD> seen;
    std::vector<VMEntryPoint> deduped;
    for (auto& ep : out.entries) {
        if (seen.find(ep.bytecodeRva) == seen.end()) {
            seen.insert(ep.bytecodeRva);
            deduped.push_back(ep);
        }
    }
    out.entries = deduped;
    out.vmEntryCount = (int)out.entries.size();

    DbgLogF("[VMP] found %d unique VM entry points", out.vmEntryCount);

    // Step 5: Find the VMP loader section
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < sc; ++i) {
        DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (tableRva >= sections[i].VirtualAddress && tableRva < end) {
            DWORD secEnd = end;
            out.loaderRva = sections[i].VirtualAddress;
            for (WORD j = i; j < sc; ++j) {
                DWORD jEnd = sections[j].VirtualAddress + sections[j].Misc.VirtualSize;
                if (jEnd > secEnd) secEnd = jEnd;
            }
            out.loaderSize = secEnd - out.loaderRva;
            if (out.loaderSize > sizeOfImage - out.loaderRva)
                out.loaderSize = sizeOfImage - out.loaderRva;
            DbgLogF("[VMP] VMP code area at RVA 0x%X (size 0x%X)", out.loaderRva, out.loaderSize);
            break;
        }
    }

    return true;
}

} // namespace vmp
