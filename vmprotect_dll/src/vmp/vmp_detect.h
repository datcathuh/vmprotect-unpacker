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

// A discovered VM entry point
struct VMEntryPoint {
    DWORD rva;
    DWORD bytecodeRva;
    DWORD bytecodeSize;
    DWORD dispatcherRva;
};

struct VMPDetectResult {
    bool detected;
    bool isV2;
    bool hasBytecodeEncryption;
    bool hasImportProtection;
    int version;  // 0=unknown, 1=VMP1, 2=VMP2, 3=VMP3
    DWORD dispatcherRva;
    DWORD handlerTableRva;
    DWORD handlerTableSize;
    DWORD handlerBlobRva;
    DWORD entryPoint;
    DWORD loaderRva;
    DWORD loaderSize;
    std::vector<VMHandler> handlers;
    std::vector<VMEntryPoint> entries;
    std::vector<DWORD> vmpSectionRvas;
    int vmEntryCount;
};

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

// Known handler code signatures for more robust identification
struct HandlerSig {
    VMInstType type;
    DWORD offset;
    std::vector<BYTE> pattern;
    BYTE mask;
};

static bool IsLikelyHandlerCode(const BYTE* code, DWORD size) {
    if (size < 8) return false;
    int nonzero = 0;
    for (DWORD i = 0; i < min(size, (DWORD)32); ++i)
        if (code[i] != 0 && code[i] != 0xFF) nonzero++;
    if (nonzero < 4) return false;
    int knownInstrs = 0;
    for (DWORD i = 0; i < min(size, (DWORD)64) - 1; ++i) {
        BYTE b0 = code[i];
        if (b0 == 0x89 || b0 == 0x8B || b0 == 0x03 || b0 == 0x01 ||
            b0 == 0x33 || b0 == 0x31 || b0 == 0xFF || b0 == 0x0F)
            knownInstrs++;
    }
    return knownInstrs >= 2;
}

// See if code at target contains known dispatch patterns
static bool IsLikelyDispatcherCode(const BYTE* code, DWORD size) {
    for (DWORD i = 0; i < min(size, (DWORD)100) - 4; ++i) {
        // jmp [reg*scale + base] dispatch pattern
        if (code[i] == 0xFF && (code[i+1] & 0xF8) == 0x20) return true;
        // jmp reg
        if (code[i] == 0xFF && (code[i+1] & 0xF8) == 0xE0) return true;
        // jmp rel32
        if (code[i] == 0xE9) return true;
        // jmp [disp32] — indirect jump via IAT
        if (code[i] == 0xFF && code[i+1] == 0x25) return true;
        // call/jmp with switch table — jmp [address_table + reg*4/8]
        if (code[i] == 0x41 || code[i] == 0x44 || code[i] == 0x4C) {
            if (i+1 < min(size, (DWORD)100) && code[i+1] == 0xFF) return true;
        }
        // ret (end of handler)
        if (code[i] == 0xC3 || code[i] == 0xC2) return true;
    }
    return false;
}

// Validate a potential handler table by checking N entries
template<typename T>
static int ValidateHandlerTable(const BYTE* dump, DWORD size, DWORD tableRva,
    int entryCount, const std::vector<DWORD>& testIndices)
{
    int valid = 0;
    for (size_t ki = 0; ki < testIndices.size(); ++ki) {
        int idx = testIndices[ki];
        T rawEntry;
        if (sizeof(T) == 4) {
            if (tableRva + idx * 4 + 4 > size) continue;
            rawEntry = *(T*)(dump + tableRva + idx * 4);
        } else {
            if (tableRva + idx * 8 + 8 > size) continue;
            rawEntry = *(T*)(dump + tableRva + idx * 8);
        }
        if (rawEntry == 0 || rawEntry == (T)-1) continue;
        DWORD target;
        if (sizeof(T) == 4)
            target = tableRva + (int32_t)rawEntry;
        else
            target = (DWORD)((ULONGLONG)rawEntry & 0xFFFFFFFF);
        if (target >= size) continue;
        if (!IsLikelyHandlerCode(dump + target, size - target)) continue;
        valid++;
    }
    return valid;
}

/*
 * Find VMP handler tables.
 * Tries multiple strategies:
 *   Strategy A: 256-entry table of 4-byte relative offsets (VMP v3 vtNormal)
 *   Strategy B: 256-entry table of 8-byte absolute pointers (VMP v2/v3 V1 compat)
 *   Strategy C: vtAdvanced handler blob
 */
static DWORD FindHandlerTable(const BYTE* dump, DWORD size,
    bool& outIsV2, DWORD& outTableSize, DWORD& outBlobRva) {
    outBlobRva = 0;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;

    struct SectionInfo { DWORD start, end; DWORD chars; };
    std::vector<SectionInfo> sections;
    for (WORD i = 0; i < sc; ++i) {
        DWORD end = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (end > size) end = size;
        sections.push_back({ sec[i].VirtualAddress, end, sec[i].Characteristics });
    }

    auto isInExec = [&](DWORD rva) -> bool {
        for (auto& s : sections)
            if (rva >= s.start && rva < s.end && (s.chars & IMAGE_SCN_MEM_EXECUTE))
                return true;
        return false;
    };

    auto isInWritable = [&](DWORD rva) -> bool {
        for (auto& s : sections)
            if (rva >= s.start && rva < s.end && (s.chars & IMAGE_SCN_MEM_WRITE))
                return true;
        return false;
    };

    // Generate test indices (deterministic sampling)
    std::vector<DWORD> testIdxs;
    for (int k = 0; k < 12; ++k)
        testIdxs.push_back((k * 37) % 256);

    // Get image base for VA→RVA conversion
    WORD magic = nt->OptionalHeader.Magic;
    ULONGLONG imageBase = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        imageBase = ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.ImageBase;
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        imageBase = ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.ImageBase;

    auto resolveAbs = [&](ULONGLONG val) -> DWORD {
        if (val == 0 || val == (ULONGLONG)-1) return 0;
        DWORD asRva = (DWORD)(val & 0xFFFFFFFF);
        if (asRva < size && isInExec(asRva)) return asRva;
        if (val > imageBase && val < imageBase + size) {
            DWORD asVa = (DWORD)(val - imageBase);
            if (asVa < size && isInExec(asVa)) return asVa;
        }
        return 0;
    };

    // Strategy A: V2 format (4-byte relative offsets)
    // Scan at 4-byte granularity in VMP-like sections (writable+executable or writable data)
    {
        DWORD tableBytes = 256 * 4;
        for (auto& sect : sections) {
            if (sect.end - sect.start < tableBytes) continue;
            DWORD end = min(sect.end, size - tableBytes);
            for (DWORD rva = sect.start; rva < end; rva += 4) {
                int32_t firstOff = *(int32_t*)(dump + rva);
                DWORD firstTarget = rva + firstOff;
                if (!isInExec(firstTarget)) continue;

                int validCount = 0;
                int zeroCount = 0;
                for (size_t ki = 0; ki < testIdxs.size(); ++ki) {
                    int idx = testIdxs[ki];
                    int32_t off = *(int32_t*)(dump + rva + idx * 4);
                    DWORD target = rva + off;
                    if (off == 0 || off == -1) { zeroCount++; continue; }
                    if (isInExec(target) && IsLikelyHandlerCode(dump + target, size - target))
                        validCount++;
                }
                if (validCount >= 5 && zeroCount < 10) {
                    outIsV2 = true;
                    outTableSize = tableBytes;
                    DbgLogF("[VMP] V2 handler table at 0x%X (%d/%d valid)", rva, validCount, (int)testIdxs.size());
                    return rva;
                }
            }
        }
    }

    // Strategy B: V1 format (8-byte absolute pointers)
    {
        DWORD tableBytes = 256 * 8;
        for (auto& sect : sections) {
            if (sect.end - sect.start < tableBytes) continue;
            DWORD end = min(sect.end, size - tableBytes);
            for (DWORD rva = sect.start; rva < end; rva += 8) {
                ULONGLONG firstVal = *(ULONGLONG*)(dump + rva);
                DWORD firstTarget = resolveAbs(firstVal);
                if (firstTarget == 0) continue;

                int validCount = 0;
                for (size_t ki = 0; ki < testIdxs.size(); ++ki) {
                    int idx = testIdxs[ki];
                    ULONGLONG val = *(ULONGLONG*)(dump + rva + idx * 8);
                    DWORD target = resolveAbs(val);
                    if (!target) continue;
                    if (IsLikelyHandlerCode(dump + target, size - target))
                        validCount++;
                }
                if (validCount >= 5) {
                    outIsV2 = false;
                    outTableSize = tableBytes;
                    DbgLogF("[VMP] V1 handler table at 0x%X (%d/%d valid)", rva, validCount, (int)testIdxs.size());
                    return rva;
                }
            }
        }
    }

    // Strategy C: vtAdvanced handler blob
    // In advanced mode, the handler table is a code blob pointed to by LEA reg, [rip+offset]
    // followed by dispatch: read dword, add to base, jmp reg
    // The blob itself contains 256 entry points (code that does push_all, read_bytecode, dispatch)
    {
        for (auto& sect : sections) {
            if (!(sect.chars & IMAGE_SCN_MEM_EXECUTE)) continue;
            DWORD end = min(sect.end, size - 32);
            for (DWORD rva = sect.start; rva < end; rva += 1) {
                // Look for LEA r64, [rip+disp32] or LEA r32, [disp32]
                // x64: 48 8D 05/0D/15/1D/25/2D/35/3D + rel32
                // x86: 8D 05/0D/15/1D/25/2D/35/3D + disp32 (absolute address, not RIP-relative)
                if (rva + 7 > size) break;
                DWORD leaRva = rva;
                DWORD blobRva = 0;
                bool is64 = (dump[rva] == 0x48 && dump[rva+1] == 0x8D && (dump[rva+2] & 0xC7) == 0x05);
                bool is32 = (dump[rva] == 0x8D && (dump[rva+1] & 0xC7) == 0x05);
                if (is64 && rva + 7 <= size) {
                    blobRva = rva + 7 + *(int32_t*)(dump + rva + 3);
                } else if (is32 && rva + 6 <= size) {
                    blobRva = *(uint32_t*)(dump + rva + 2);
                }
                if (blobRva == 0 || blobRva >= size || blobRva == rva) continue;
                // The blob should be in an executable section
                if (!isInExec(blobRva)) continue;
                // Check if the blob location looks like a handler entry array
                // Each entry should start with push/pushf style prologue
                int entryCount = 0;
                for (int ei = 0; ei < 256 && blobRva + ei * 32 + 8 <= size; ++ei) {
                    const BYTE* ec = dump + blobRva + ei * 32;
                    if (ec[0] == 0x9C || ec[0] == 0x50 || (ec[0] >= 0x50 && ec[0] <= 0x57) ||
                        (ec[0] == 0x41 && ec[1] >= 0x50 && ec[1] <= 0x57) ||
                        ec[0] == 0x68 || ec[0] == 0x6A)
                        entryCount++;
                    else if (ec[0] == 0x48 && ec[1] >= 0x50 && ec[1] <= 0x57)
                        entryCount++;
                    else
                        break;
                }
                if (entryCount >= 16) {
                    outIsV2 = true;  // vtAdvanced still uses 4-byte relative entries
                    outTableSize = 0;  // Special: no fixed table
                    outBlobRva = blobRva;
                    DbgLogF("[VMP] vtAdvanced handler blob at 0x%X (%d entries, LEA at 0x%X)",
                        blobRva, entryCount, leaRva);
                    return leaRva;
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

    ULONGLONG imageBase = 0;
    if (!isV2) {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
            WORD magic = nt->OptionalHeader.Magic;
            if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                imageBase = ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.ImageBase;
            else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
                imageBase = ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.ImageBase;
        }
    }

    int entryCount;
    if (tableSize == 0) return false;  // vtAdvanced blob — handled elsewhere
    entryCount = min(256, (int)(tableSize / (isV2 ? 4 : 8)));
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
            ULONGLONG val = *(ULONGLONG*)(dump + tableRva + i * 8);
            if (val == 0 || val == (ULONGLONG)-1) continue;
            handlerRva = (DWORD)(val & 0xFFFFFFFF);
            if (handlerRva >= size) handlerRva = 0;
            if (handlerRva == 0 && imageBase != 0 && val > imageBase)
                handlerRva = (DWORD)(val - imageBase);
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

// Extract handlers from vtAdvanced mode (sequential entry points in blob)
static bool ExtractAdvancedHandlers(const BYTE* dump, DWORD size, DWORD blobRva,
    std::vector<VMHandler>& outHandlers) {
    outHandlers.clear();
    if (blobRva == 0 || blobRva + 32 > size) return false;

    // In vtAdvanced mode, each entry is at blobRva + opcode * 32
    // (or some other fixed stride). VMP copies handler stubs here during init.
    // We scan forward finding valid handler-sized chunks.
    int entrySpacing = 32;  // Default spacing
    const int maxEntries = 256;
    const DWORD maxScan = min(size - blobRva, (DWORD)(maxEntries * 64));

    // Detect spacing by looking for push patterns at regular intervals
    int bestSpacing = 0;
    int bestCount = 0;
    for (int sp = 8; sp <= 64; sp += 4) {
        int cnt = 0;
        for (int i = 0; blobRva + i * sp + 4 <= size && i < maxEntries; ++i) {
            const BYTE* ec = dump + blobRva + i * sp;
            if (ec[0] == 0x9C || ec[0] == 0x50 || (ec[0] >= 0x50 && ec[0] <= 0x57) ||
                (ec[0] == 0x41 && ec[1] >= 0x50 && ec[1] <= 0x57) ||
                (ec[0] == 0x48 && ec[1] >= 0x50 && ec[1] <= 0x57))
                cnt++;
        }
        if (cnt > bestCount) { bestCount = cnt; bestSpacing = sp; }
    }
    if (bestCount < 8) return false;
    entrySpacing = bestSpacing;

    for (int i = 0; blobRva + i * entrySpacing + 8 <= size && i < maxEntries; ++i) {
        DWORD handlerRva = blobRva + i * entrySpacing;
        VMHandler h;
        h.rva = handlerRva;
        h.opcodeValue = i;
        h.isEndHandler = false;
        h.extJmpTarget = 0;
        DWORD maxCodeSize = min((DWORD)entrySpacing, size - handlerRva);
        h.code.assign(dump + handlerRva, dump + handlerRva + maxCodeSize);
        h.size = maxCodeSize;
        outHandlers.push_back(h);
    }
    DbgLogF("[VMP] vtAdvanced: extracted %zu handlers at spacing %d", outHandlers.size(), entrySpacing);
    return !outHandlers.empty();
}

/*
 * Find VM entry points.
 * Scans all executable sections for patterns that invoke VM:
 *   push bytecodeRva
 *   call/jmp dispatcher
 *
 * Also finds patterns where mov rN, bytecodeRva precedes the call.
 */
static void FindVmEntries(BYTE* dump, DWORD sizeOfImage, DWORD handlerTableRva,
    BOOL isV2, std::vector<VMEntryPoint>& outEntries) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;

    for (WORD si = 0; si < sc; ++si) {
        if (!(sec[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD secRva = sec[si].VirtualAddress;
        DWORD secSize = sec[si].Misc.VirtualSize;
        if (secRva + secSize > sizeOfImage) secSize = sizeOfImage - secRva;

        for (DWORD i = 0; i < secSize - 14; ++i) {
            DWORD bytecodeRva = 0;
            DWORD callRva = 0;

            // Pattern 1: push imm32; call/jmp rel32
            if (dump[secRva + i] == 0x68 &&
                (dump[secRva + i + 5] == 0xE8 || dump[secRva + i + 5] == 0xE9)) {
                bytecodeRva = *(uint32_t*)(dump + secRva + i + 1);
                callRva = secRva + i + 5;
            }
            // Pattern 2: push imm32; jmp [iat]
            if (bytecodeRva == 0 && i + 11 <= secSize &&
                dump[secRva + i] == 0x68 &&
                dump[secRva + i + 5] == 0xFF && dump[secRva + i + 6] == 0x15) {
                bytecodeRva = *(uint32_t*)(dump + secRva + i + 1);
                callRva = secRva + i + 5;
            }
            // Pattern 3: mov ecx/edx, imm32; call rel32 (x86)
            if (bytecodeRva == 0 && i + 10 <= secSize &&
                (dump[secRva + i] == 0xB9 || dump[secRva + i] == 0xBA) &&
                dump[secRva + i + 5] == 0xE8) {
                bytecodeRva = *(uint32_t*)(dump + secRva + i + 1);
                callRva = secRva + i + 5;
            }
            // Pattern 4: mov rN, imm64; call rel32 (x64)
            if (bytecodeRva == 0 && i + 14 <= secSize &&
                (dump[secRva + i] & 0xF8) == 0x48 &&
                (dump[secRva + i + 1] & 0xF8) == 0xB8 &&
                dump[secRva + i + 9] == 0xE8) {
                ULONGLONG imm64 = *(ULONGLONG*)(dump + secRva + i + 2);
                bytecodeRva = (DWORD)(imm64 & 0xFFFFFFFF);
                callRva = secRva + i + 9;
            }
            // Pattern 5: push imm8; call rel32
            if (bytecodeRva == 0 && i + 6 <= secSize &&
                dump[secRva + i] == 0x6A && dump[secRva + i + 2] == 0xE8) {
                bytecodeRva = (DWORD)(int32_t)(int8_t)dump[secRva + i + 1];
                callRva = secRva + i + 2;
            }
            // Pattern 6: call rel32 (entry point itself is the call target)
            // This handles x64 TLS callback VM entries
            if (bytecodeRva == 0 && dump[secRva + i] == 0xE8 &&
                i > 0 && dump[secRva + i - 1] >= 0x50 && dump[secRva + i - 1] <= 0x57) {
                // Preceded by push reg — this is a push-args-then-call-VM pattern
                int32_t callOff = *(int32_t*)(dump + secRva + i + 1);
                DWORD callTarget = secRva + i + 5 + callOff;
                // If the target is in a VMP section (non-original code), it might be a VM call
                // But we can't know the bytecodeRva from this pattern
                continue;
            }

            if (bytecodeRva > 0 && bytecodeRva < sizeOfImage &&
                bytecodeRva != handlerTableRva) {
                // Skip if bytecodeRva falls in the handler table range
                if (handlerTableRva > 0 && bytecodeRva >= handlerTableRva &&
                    bytecodeRva < handlerTableRva + (isV2 ? 256 * 4 : 256 * 8))
                    continue;

                VMEntryPoint ep;
                ep.rva = secRva + i;
                ep.bytecodeRva = bytecodeRva;
                ep.bytecodeSize = min(sizeOfImage - bytecodeRva, (DWORD)0x20000);
                ep.dispatcherRva = callRva;
                outEntries.push_back(ep);
            }
        }
    }
}

// Alternative entry point finder: scan for the VM dispatcher and trace back callers
static void FindVmEntriesViaDispatcher(BYTE* dump, DWORD sizeOfImage,
    DWORD dispatcherRva, std::vector<VMEntryPoint>& outEntries) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;

    // Scan for calls/jmps to dispatcherRva in executable sections
    for (WORD si = 0; si < sc; ++si) {
        if (!(sec[si].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        DWORD secRva = sec[si].VirtualAddress;
        DWORD secSize = sec[si].Misc.VirtualSize;
        if (secRva + secSize > sizeOfImage) secSize = sizeOfImage - secRva;

        for (DWORD i = 0; i < secSize - 5; ++i) {
            // call rel32
            if (dump[secRva + i] == 0xE8) {
                int32_t callOff = *(int32_t*)(dump + secRva + i + 1);
                DWORD target = secRva + i + 5 + callOff;
                if (target == dispatcherRva) {
                    // Found a call to the dispatcher — check if there's a preceding push
                    DWORD bytecodeRva = 0;
                    if (i >= 5 && dump[secRva + i - 5] == 0x68)
                        bytecodeRva = *(uint32_t*)(dump + secRva + i - 4);
                    if (bytecodeRva > 0 && bytecodeRva < sizeOfImage) {
                        VMEntryPoint ep;
                        ep.rva = secRva + i - 5;
                        ep.bytecodeRva = bytecodeRva;
                        ep.bytecodeSize = min(sizeOfImage - bytecodeRva, (DWORD)0x20000);
                        ep.dispatcherRva = dispatcherRva;
                        outEntries.push_back(ep);
                    }
                }
            }
            // jmp rel32
            if (dump[secRva + i] == 0xE9) {
                int32_t jmpOff = *(int32_t*)(dump + secRva + i + 1);
                DWORD target = secRva + i + 5 + jmpOff;
                if (target == dispatcherRva) {
                    DWORD bytecodeRva = 0;
                    if (i >= 5 && dump[secRva + i - 5] == 0x68)
                        bytecodeRva = *(uint32_t*)(dump + secRva + i - 4);
                    if (bytecodeRva > 0 && bytecodeRva < sizeOfImage) {
                        VMEntryPoint ep;
                        ep.rva = secRva + i - 5;
                        ep.bytecodeRva = bytecodeRva;
                        ep.bytecodeSize = min(sizeOfImage - bytecodeRva, (DWORD)0x20000);
                        ep.dispatcherRva = dispatcherRva;
                        outEntries.push_back(ep);
                    }
                }
            }
        }
    }
}

// Detect bytecode encryption by examining handler code for XOR/ADD decrypt patterns
static bool HasBytecodeEncryption(const std::vector<VMHandler>& handlers) {
    int decryptPatterns = 0;
    for (size_t hi = 0; hi < handlers.size(); ++hi) {
        auto& h = handlers[hi];
        for (DWORD bi = 0; bi < min(h.size, (DWORD)120) - 1; ++bi) {
            BYTE b0 = h.code[bi];
            BYTE b1 = h.code[bi + 1];
            if (b0 == 0x35 || (b0 == 0x81 && b1 == 0xF0) ||  // xor eax, imm32
                (b0 == 0x83 && b1 == 0xF0) ||                  // xor eax, imm8
                b0 == 0x34 ||                                  // xor al, imm8
                (b0 == 0x48 && b1 == 0x35) ||                  // xor rax, imm32 (sign-ext)
                (b0 == 0x48 && b1 == 0x83 && h.code[bi+2]==0xF0)) { // xor rax, imm8
                decryptPatterns++;
            }
            // ADD/SUB patterns used in OpcodeCryptor
            if ((b0 == 0x83 && (b1 & 0xF8) == 0xC0) ||  // add reg, imm8
                (b0 == 0x83 && (b1 & 0xF8) == 0xE8) ||  // sub reg, imm8
                b0 == 0x05 || b0 == 0x2D) decryptPatterns++;  // add/sub eax, imm32
        }
    }
    return decryptPatterns > (int)handlers.size() * 3;
}

// Detect import protection presence
static bool HasImportProtection(BYTE* dump, DWORD sizeOfImage) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);

    // Check if IAT directory points to a VMP section (large RVA)
    DWORD iatRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
    DWORD iatSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
    if (iatRva == 0) return false;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD sc = nt->FileHeader.NumberOfSections;

    // Find the last section — likely VMP section
    DWORD lastSecEnd = 0;
    DWORD lastSecStart = 0;
    for (WORD i = 0; i < sc; ++i) {
        DWORD end = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (end > lastSecEnd) {
            lastSecEnd = end;
            lastSecStart = sec[i].VirtualAddress;
        }
    }
    // If IAT is in the last section, it's been redirected there = import protection
    if (iatRva >= lastSecStart && iatRva < lastSecEnd) return true;

    // Check if import directory is missing or zeroed
    DWORD importRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRva == 0 && iatRva != 0) return true;  // imports gone but IAT present = protected

    // Check if import descriptors are zeroed
    if (importRva > 0 && importRva < sizeOfImage) {
        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(dump + importRva);
        if (desc->Name == 0 && desc->FirstThunk == 0) return true;
    }

    return false;
}

/*
 * Main detection function.
 */
static bool DetectVMP(BYTE* dump, DWORD sizeOfImage, VMPDetectResult& out) {
    ZeroMemory(&out, sizeof(out));
    if (!dump || sizeOfImage < 0x1000) return false;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    out.entryPoint = nt->OptionalHeader.AddressOfEntryPoint;

    // Detect import protection
    out.hasImportProtection = HasImportProtection(dump, sizeOfImage);
    if (out.hasImportProtection) DbgLog("[VMP] import protection detected");

    // Step 1: Find handler table
    bool isV2 = false;
    DWORD tableSize = 0;
    DWORD blobRva = 0;
    DWORD tableRva = FindHandlerTable(dump, sizeOfImage, isV2, tableSize, blobRva);

    if (!tableRva) {
        // Try alternate strategies if standard detection fails
        // Some VMP versions place the handler table after the image sections
        DbgLog("[*] no VMP handler table found via standard scan");
        return false;
    }

    out.isV2 = isV2;
    out.handlerTableRva = tableRva;
    out.handlerTableSize = tableSize;
    out.handlerBlobRva = blobRva;
    out.detected = true;

    // Step 2: Extract handlers
    if (blobRva > 0) {
        // vtAdvanced mode
        ExtractAdvancedHandlers(dump, sizeOfImage, blobRva, out.handlers);
    } else {
        ExtractHandlers(dump, sizeOfImage, tableRva, tableSize, isV2, out.handlers);
    }
    DbgLogF("[VMP] extracted %zu handlers (V%d)", out.handlers.size(), isV2 ? 2 : 1);

    // Step 3: Detect bytecode encryption
    out.hasBytecodeEncryption = HasBytecodeEncryption(out.handlers);
    if (out.hasBytecodeEncryption) DbgLog("[VMP] bytecode encryption detected");

    // Step 4: Find VM entry points
    FindVmEntries(dump, sizeOfImage, tableRva, isV2, out.entries);

    // Also try dispatcher-based search if we have a dispatcher
    if (out.entries.empty()) {
        DWORD dispatcherRva = 0;
        // Try to find dispatcher near the handler table
        // The dispatcher is typically at handlerTableRva - some_offset or in the same section
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        WORD sc = nt->FileHeader.NumberOfSections;
        for (WORD i = 0; i < sc; ++i) {
            DWORD secEnd = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
            if (tableRva >= sec[i].VirtualAddress && tableRva < secEnd) {
                dispatcherRva = sec[i].VirtualAddress;
                break;
            }
        }
        if (dispatcherRva > 0) {
            FindVmEntriesViaDispatcher(dump, sizeOfImage, dispatcherRva, out.entries);
        }
    }

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

    // Step 5: Find VMP loader section (section containing the handler table)
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD scount = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < scount; ++i) {
        DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (tableRva >= sections[i].VirtualAddress && tableRva < end) {
            DWORD secEnd = end;
            out.loaderRva = sections[i].VirtualAddress;
            for (WORD j = i; j < scount; ++j) {
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
