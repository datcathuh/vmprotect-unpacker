#include "dump.h"
#include "../utils.h"
#include "../vmp/vmp_detect.h"
#include "../vmp/vmp_bytecode.h"
#include "../vmp/vmp_devirt.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <map>
#include <set>
#include <algorithm>
#pragma comment(lib, "psapi.lib")

static bool IsValidPeHeader(const BYTE* data, SIZE_T size) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (size < (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS)) return false;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    WORD magic = nt->OptionalHeader.Magic;
    return magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
}

static DWORD ScanForOep(BYTE* dump, DWORD size, DWORD entryRva, bool allowCallCandidates) {
    DWORD searchEnd = min(entryRva + 0x200, size);

    for (DWORD i = entryRva; i < searchEnd - 7; ++i) {
        BYTE* p = dump + i;

        if (p[0] == 0xE8 && allowCallCandidates) {
            DWORD rel = *(int32_t*)(p + 1);
            DWORD target = (i + 5) + rel;
            if (target > 0x1000 && target < size) {
                DbgLogF("[*] possible OEP call target: 0x%X", target);
                return target;
            }
        }

        if (p[0] == 0xE9) {
            DWORD rel = *(int32_t*)(p + 1);
            DWORD target = (i + 5) + rel;
            if (target > 0x1000 && target < size) {
                DbgLogF("[*] possible OEP jmp target: 0x%X", target);
                return target;
            }
        }

        if (p[0] == 0x68 && p[5] == 0xC3) {
            DWORD val = *(uint32_t*)(p + 1);
            DbgLogF("[*] possible OEP push/ret: 0x%X", val);
            return val;
        }

        if (p[0] == 0x48 && p[1] == 0x68 && p[6] == 0xC3) {
            DWORD val = *(uint32_t*)(p + 2);
            DbgLogF("[*] possible OEP push/ret (x64): 0x%X", val);
            return val;
        }
    }

    return entryRva;
}

static void RvaToSectionInfo(const IMAGE_SECTION_HEADER* sections, WORD count,
    DWORD* rawDataStarts, DWORD* rawDataEnds)
{
    for (WORD i = 0; i < count; ++i) {
        rawDataStarts[i] = sections[i].PointerToRawData;
        rawDataEnds[i] = sections[i].PointerToRawData + sections[i].SizeOfRawData;
    }
}

// resolves a runtime address to module name + function name by scanning loaded modules
struct ImportResolve {
    std::string moduleName;
    std::string funcName;
    DWORD ordinal;
    bool byOrdinal;
};

struct ImportEntry {
    std::string dllName;
    std::string funcName;
    DWORD ordinal;
    bool byOrdinal;
    DWORD thunkRva;
};

static bool GetModuleNameFromAddress(HMODULE mod, char* outName, DWORD outSize) {
    wchar_t modPath[MAX_PATH];
    if (!GetModuleFileNameExW(GetCurrentProcess(), mod, modPath, MAX_PATH))
        return false;
    wchar_t* baseName = wcsrchr(modPath, L'\\');
    if (!baseName) baseName = modPath;
    else baseName++;
    size_t converted = 0;
    wcstombs_s(&converted, outName, outSize, baseName, outSize - 1);
    return converted > 0;
}

static bool ResolveImportAddress(void* addr, ImportResolve& out) {
    HMODULE hMods[256];
    DWORD cbNeeded;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
        return false;

    DWORD numMods = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < numMods; ++i) {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo)))
            continue;

        BYTE* base = (BYTE*)modInfo.lpBaseOfDll;
        BYTE* end = base + modInfo.SizeOfImage;

        BYTE* ptr = (BYTE*)addr;
        if (ptr < base || ptr >= end)
            continue;

        // found the module - get export name
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) continue;

        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exportRva);
        DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
        DWORD* names = (DWORD*)(base + exp->AddressOfNames);
        WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
        char* modName = (char*)(base + exp->Name);

        // find which function this address corresponds to
        for (DWORD j = 0; j < exp->NumberOfFunctions; ++j) {
            DWORD funcRva = funcs[j];
            BYTE* funcAddr = base + funcRva;
            if (funcAddr == ptr) {
                DWORD ordinal = exp->Base + j;
                // try to find name
                bool foundName = false;
                for (DWORD k = 0; k < exp->NumberOfNames; ++k) {
                    if (ordinals[k] == j) {
                        out.funcName = (char*)(base + names[k]);
                        foundName = true;
                        break;
                    }
                }
                out.ordinal = ordinal;
                out.byOrdinal = !foundName;
                GetModuleNameFromAddress(hMods[i], modName, MAX_PATH);
                out.moduleName = modName;
                return true;
            }
        }

        // if exact address not found, it might be a forwarded export or IAT entry
        // check if address is within the export range
        DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (ptr >= base + exportRva && ptr < base + exportRva + exportSize) {
            // forwarder
            const char* forwardStr = (const char*)ptr;
            const char* dot = strchr(forwardStr, '.');
            if (dot) {
                out.moduleName = std::string(forwardStr, dot - forwardStr);
                out.funcName = dot + 1;
                out.byOrdinal = false;
                return true;
            }
        }

        // address falls within module but not an export - could be import thunk
        // just return the module name with unknown function
        GetModuleNameFromAddress(hMods[i], modName, MAX_PATH);
        out.moduleName = modName;
        out.funcName = "unknown";
        out.byOrdinal = false;
        return true;
    }
    return false;
}

// VMP writes (real_address - key) to the IAT. This function tries to recover
// the real function by iterating all exports of all loaded modules and checking
// if (export_addr - thunk_value) is a small positive number (the key).
// To avoid false positives, we find the export with the smallest key (closest
// address above the thunk value), which is likeliest to be correct.
// If found, writes the real export_addr to dump[thunkRva] on success.
struct BruteMatch {
    ULONGLONG funcAddr;
    DWORD ordinal;
    DWORD nameIdx;
};
static bool BruteForceResolveThunk(BYTE* dump, DWORD thunkRva, ULONGLONG thunkVal, bool is64, ImportResolve& out) {
    HMODULE hMods[512];
    DWORD cbNeeded;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
        return false;
    DWORD numMods = cbNeeded / sizeof(HMODULE);

    BruteMatch bestMatch = {};
    ULONGLONG bestKey = (ULONGLONG)-1;
    char bestModName[MAX_PATH] = "";
    BYTE* bestBase = nullptr;
    DWORD* bestNames = nullptr;
    WORD* bestNameOrdinals = nullptr;

    for (DWORD m = 0; m < numMods; ++m) {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hMods[m], &modInfo, sizeof(modInfo)))
            continue;

        BYTE* base = (BYTE*)modInfo.lpBaseOfDll;
        ULONGLONG baseAddr = (ULONGLONG)base;
        ULONGLONG modEnd = baseAddr + modInfo.SizeOfImage;

        // No range limit - check all modules

        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRva) continue;

        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exportRva);
        DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
        DWORD* names = (DWORD*)(base + exp->AddressOfNames);
        WORD* nameOrdinals = (WORD*)(base + exp->AddressOfNameOrdinals);
        DWORD exportEndRva = exportRva + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        char modName[MAX_PATH] = "";
        GetModuleNameFromAddress(hMods[m], modName, MAX_PATH);

        __try {
            for (DWORD j = 0; j < exp->NumberOfFunctions; ++j) {
                DWORD funcRva = funcs[j];
                if (funcRva >= exportRva && funcRva < exportEndRva) continue;
                ULONGLONG funcAddr = baseAddr + funcRva;
                ULONGLONG key = (funcAddr > thunkVal) ? (funcAddr - thunkVal) : (thunkVal - funcAddr);
                if (key < bestKey) {
                    bestKey = key;
                    bestMatch.funcAddr = funcAddr;
                    bestMatch.ordinal = exp->Base + j;
                    bestMatch.nameIdx = j;
                    strncpy_s(bestModName, modName, _TRUNCATE);
                    bestBase = base;
                    bestNames = names;
                    bestNameOrdinals = nameOrdinals;
                    if (key == 0) break;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    if (bestKey == (ULONGLONG)-1) return false;

    // For VMP-protected targets, IAT values are module-internal pointers
    // that cannot match DLL exports. Brute-force on these will always
    // produce very large keys. The VMP descriptor linking step handles
    // these, so we can reject them here. For normal PEs, any large key
    // is almost certainly a false positive — real import thunks have
    // keys under ~0x10000 (64KB) since the resolved address IS the
    // export address (key=0) or very near it.
    // We raise the limit to 1GB to also cover edge cases (stripped
    // fixups, forwarded exports, etc.) while still rejecting the
    // obviously-wrong module-internal matches.
    if (bestKey > 0x40000000) {
        DbgLogF("[*] rejecting brute-force match %s!%s (key 0x%llX too large)", bestModName, out.funcName.c_str(), bestKey);
        return false;
    }

    out.moduleName = bestModName;
    out.ordinal = bestMatch.ordinal;
    out.byOrdinal = true;
    out.funcName = "unknown";
    if (bestNames && bestNameOrdinals) {
        for (DWORD k = 0; k < 10000; ++k) {
            // We need NumberOfNames — estimate from bestNames access via SEH
            DWORD nameRva;
            __try {
                nameRva = bestNames[k];
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                break;
            }
            if (nameRva == 0) break;
            if (bestNameOrdinals[k] == bestMatch.nameIdx) {
                __try {
                    out.funcName = (char*)(bestBase + nameRva);
                    out.byOrdinal = false;
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                }
                break;
            }
        }
    }

    DbgLogF("[*] brute-force matched: %s!%s (RVA 0x%X, key 0x%llX)",
        bestModName, out.funcName.c_str(), thunkRva, bestKey);
    if (is64)
        *(ULONGLONG*)(dump + thunkRva) = bestMatch.funcAddr;
    else
        *(DWORD*)(dump + thunkRva) = (DWORD)(ULONG_PTR)bestMatch.funcAddr;
    return true;
}

// SEH-safe wrapper for import resolution (separate function to avoid C2712)
static bool SafeResolveImport(BYTE* dump, DWORD rva, ULONGLONG addr, bool is64, ImportResolve& resolved) {
    bool ok = false;
    __try {
        ok = ResolveImportAddress((void*)(ULONG_PTR)addr, resolved);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        ok = false;
    }
    if (!ok) {
        __try {
            ok = BruteForceResolveThunk(dump, rva, addr, is64, resolved);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            ok = false;
        }
    }
    return ok;
}

// Scan import descriptors at importDirRva to extract function names from INT arrays
// and IAT values. This handles VMP-encrypted import descriptors (garbage DLL names
// but valid INT/IAT RVAs). DLL names are recovered by matching IAT values via
// ResolveImportAddress.
static void ScanImportDescriptors(BYTE* dump, DWORD size, DWORD importDirRva, bool is64,
    std::map<std::string, std::vector<ImportEntry>>& importMap) {
    if (!importDirRva || importDirRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) > size) return;
    int entrySize = is64 ? 8 : 4;
    int totalAdded = 0;

    IMAGE_IMPORT_DESCRIPTOR* descs = (IMAGE_IMPORT_DESCRIPTOR*)(dump + importDirRva);
    for (IMAGE_IMPORT_DESCRIPTOR* d = descs; ; ++d) {
        if ((BYTE*)d - dump + (int)sizeof(IMAGE_IMPORT_DESCRIPTOR) > (int)size) break;
        if (d->Name == 0 && d->OriginalFirstThunk == 0 && d->FirstThunk == 0) break;
        if (d->OriginalFirstThunk == 0 && d->FirstThunk == 0) continue;
        DWORD intRva = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
        DWORD iatRva = d->FirstThunk ? d->FirstThunk : d->OriginalFirstThunk;
        // Determine DLL name by matching IAT entries to loaded module exports
        std::string dllName = "unknown.dll";
        for (int probe = 0; probe < 5; ++probe) {
            DWORD probeRva = iatRva + probe * entrySize;
            if (probeRva + entrySize > size) break;
            ULONGLONG probeAddr = is64 ? *(ULONGLONG*)(dump + probeRva) : *(DWORD*)(dump + probeRva);
            if (probeAddr <= 0x10000) continue;
            ImportResolve probeRes;
            if (ResolveImportAddress((void*)(ULONG_PTR)probeAddr, probeRes)) {
                dllName = probeRes.moduleName;
                break;
            }
        }
        int idx = 0;
        while (true) {
            DWORD intRvaCur = intRva + idx * entrySize;
            if (intRvaCur + entrySize > size) break;
            ULONGLONG intVal = is64 ? *(ULONGLONG*)(dump + intRvaCur) : *(DWORD*)(dump + intRvaCur);
            if (intVal == 0) break;
            ULONGLONG iatVal = 0;
            DWORD iatRvaCur = iatRva + idx * entrySize;
            if (iatRvaCur + entrySize <= size)
                iatVal = is64 ? *(ULONGLONG*)(dump + iatRvaCur) : *(DWORD*)(dump + iatRvaCur);

            ImportEntry entry;
            entry.dllName = dllName;
            entry.thunkRva = iatRvaCur;
            entry.ordinal = 0;
            entry.byOrdinal = false;

            if (is64 ? (intVal & IMAGE_ORDINAL_FLAG64) : (intVal & IMAGE_ORDINAL_FLAG32)) {
                entry.ordinal = (DWORD)(intVal & 0xFFFF);
                entry.byOrdinal = true;
                entry.funcName = "ordinal_" + std::to_string(entry.ordinal);
            } else {
                DWORD hnRva = (DWORD)intVal;
                if (hnRva + sizeof(IMAGE_IMPORT_BY_NAME) < size) {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
                    char* fn = (char*)ibn->Name;
                    SIZE_T maxLen = size - hnRva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                    fn[maxLen - 1] = 0;
                    entry.funcName = fn;
                } else {
                    entry.funcName = "unknown_" + std::to_string(idx);
                }
                if (entry.funcName.empty() || entry.funcName.find_first_not_of(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@?.~-") != std::string::npos) {
                    if (iatVal > 0x10000) {
                        ImportResolve addrResolved;
                        if (ResolveImportAddress((void*)(ULONG_PTR)iatVal, addrResolved)) {
                            entry.funcName = addrResolved.funcName;
                            entry.dllName = addrResolved.moduleName;
                            entry.byOrdinal = addrResolved.byOrdinal;
                            entry.ordinal = addrResolved.ordinal;
                        }
                    }
                }
            }
            bool found = false;
            auto it = importMap.find(entry.dllName);
            if (it != importMap.end()) {
                for (auto& e : it->second) {
                    if (e.funcName == entry.funcName && e.ordinal == entry.ordinal) {
                        if (e.thunkRva == 0) e.thunkRva = entry.thunkRva;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                importMap[entry.dllName].push_back(entry);
                totalAdded++;
            }
            ++idx;
        }
    }
    if (totalAdded > 0)
        DbgLogF("[*] descriptor scan: added %d imports from %d descriptors", totalAdded, descs[0].Name ? 1 : 0);
}

// Parse VMP's own import table and merge entries into importMap.
// VMP stores the original program's imports in its own import table for
// virtualized calls (d3d9, USER32, SHELL32, etc.) that don't use FF 15/FF 25 patterns.
static void MergeVmpImportTable(BYTE* dump, DWORD sizeOfImage, DWORD vmpImportRva, bool is64,
    std::map<std::string, std::vector<ImportEntry>>& importMap) {
    if (!vmpImportRva || vmpImportRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) >= sizeOfImage) return;

    IMAGE_IMPORT_DESCRIPTOR* descs = (IMAGE_IMPORT_DESCRIPTOR*)(dump + vmpImportRva);
    if (descs->Name == 0 || descs->Name >= sizeOfImage) return;

    int totalResolved = 0;
    int totalDlls = 0;
    int entrySize = is64 ? 8 : 4;

    for (IMAGE_IMPORT_DESCRIPTOR* desc = descs; desc->Name != 0; ++desc) {
        if (desc->Name >= sizeOfImage) continue;
        if (desc->FirstThunk == 0 || desc->FirstThunk >= sizeOfImage) continue;
        if (desc->OriginalFirstThunk == 0 || desc->OriginalFirstThunk >= sizeOfImage) continue;

        char* dllName = (char*)(dump + desc->Name);
        if (!dllName[0]) continue;

        ++totalDlls;
        int idx = 0;

        while (true) {
            ULONGLONG intVal = is64
                ? *(ULONGLONG*)(dump + desc->OriginalFirstThunk + idx * entrySize)
                : *(DWORD*)(dump + desc->OriginalFirstThunk + idx * entrySize);
            if (intVal == 0) break;

            ULONGLONG resolvedAddr = is64
                ? *(ULONGLONG*)(dump + desc->FirstThunk + idx * entrySize)
                : *(DWORD*)(dump + desc->FirstThunk + idx * entrySize);
            if (resolvedAddr == 0) { ++idx; continue; }

            ImportEntry entry;
            entry.dllName = dllName;
            entry.ordinal = 0;
            entry.byOrdinal = false;
            entry.thunkRva = 0;

            if (is64 ? (intVal & IMAGE_ORDINAL_FLAG64) : (intVal & IMAGE_ORDINAL_FLAG32)) {
                entry.ordinal = (DWORD)(intVal & 0xFFFF);
                entry.byOrdinal = true;
                entry.funcName = "ordinal_" + std::to_string(entry.ordinal);
            } else {
                DWORD hintNameRva = (DWORD)intVal;
                if (hintNameRva + sizeof(IMAGE_IMPORT_BY_NAME) < sizeOfImage) {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hintNameRva);
                    char* fn = (char*)ibn->Name;
                    SIZE_T maxLen = sizeOfImage - hintNameRva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                    fn[maxLen - 1] = 0;
                    entry.funcName = fn;
                } else {
                    entry.funcName = "unknown";
                }

                // If name looks encrypted (non-printable) or is "unknown", try to
                // resolve the runtime address to get the real function name
                if (entry.funcName == "unknown" || entry.funcName.find_first_not_of(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@?.~-") != std::string::npos) {
                    ImportResolve addrResolved;
                    if (resolvedAddr > 0x10000 && ResolveImportAddress((void*)(ULONG_PTR)resolvedAddr, addrResolved)) {
                        entry.funcName = addrResolved.funcName;
                        entry.ordinal = addrResolved.ordinal;
                        entry.byOrdinal = addrResolved.byOrdinal;
                    }
                }
            }

            // Skip if already in importMap
            bool found = false;
            auto it = importMap.find(dllName);
            if (it != importMap.end()) {
                for (auto& e : it->second) {
                    if (e.funcName == entry.funcName && e.ordinal == entry.ordinal && e.byOrdinal == entry.byOrdinal) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                importMap[dllName].push_back(entry);
            }

            totalResolved++;
            ++idx;
        }
    }

    if (totalResolved > 0) {
        DbgLogF("[+] merged %d VMP imports from %d DLLs (0x%X)", totalResolved, totalDlls, vmpImportRva);
    }
}

static bool RebuildImportTableViaScan(BYTE* dump, DWORD size, DWORD imageBase, bool is64, DWORD vmpImportRva = 0) {
    // scan for call [rva] and jmp [rva] patterns, resolve against loaded modules
    // and build a new import table in the dump

    // collect all unique import addresses found via scanning
    struct ImportThunk {
        DWORD rva;
        ULONGLONG resolvedAddr;
    };
    std::vector<ImportThunk> foundThunks;

    DWORD searchEnd = size - 8;
    for (DWORD i = 0; i < searchEnd; ++i) {
        BYTE* p = dump + i;

        // call [rva]  - FF 15 XX XX XX XX
        if (p[0] == 0xFF && p[1] == 0x15) {
            // On x64: call qword ptr [rip+disp32]; disp is relative to next instruction
            // On x86: call dword ptr [abs_addr]
            DWORD rva;
            if (is64) {
                int32_t disp = *(int32_t*)(p + 2);
                rva = (DWORD)(i + 6 + disp);
            } else {
                rva = *(uint32_t*)(p + 2);
            }
            if (rva < size && rva + 8 <= size) {
                ULONGLONG targetAddr = *(ULONGLONG*)(dump + rva);
                if (targetAddr > 0x10000 && targetAddr < 0x7FFFFFFF0000ULL) {
                    ImportThunk thunk;
                    thunk.rva = rva;
                    thunk.resolvedAddr = targetAddr;
                    foundThunks.push_back(thunk);
                }
            }
        }

        // jmp [rva]  - FF 25 XX XX XX XX
        if (p[0] == 0xFF && p[1] == 0x25) {
            DWORD rva;
            if (is64) {
                int32_t disp = *(int32_t*)(p + 2);
                rva = (DWORD)(i + 6 + disp);
            } else {
                rva = *(uint32_t*)(p + 2);
            }
            if (rva < size && rva + 8 <= size) {
                ULONGLONG targetAddr = *(ULONGLONG*)(dump + rva);
                if (targetAddr > 0x10000 && targetAddr < 0x7FFFFFFF0000ULL) {
                    ImportThunk thunk;
                    thunk.rva = rva;
                    thunk.resolvedAddr = targetAddr;
                    foundThunks.push_back(thunk);
                }
            }
        }
    }

    // deduplicate by RVA
    // (keep last occurrence - it has the final resolved address)
    std::map<DWORD, ULONGLONG> uniqueThunks;
    for (auto& t : foundThunks)
        uniqueThunks[t.rva] = t.resolvedAddr;

    DbgLogF("[*] import scan found %zu unique thunk locations", uniqueThunks.size());

    if (uniqueThunks.empty()) {
        DbgLog("[*] no import thunks found via scanning");
        return false;
    }

    // resolve each unique address
    std::map<std::string, std::vector<ImportEntry>> importMap; // dllName -> entries

    int thunkIdx = 0;
    for (auto& [rva, addr] : uniqueThunks) {
        if (++thunkIdx <= 3)
            DbgLogF("[*] resolving thunk[%d] RVA 0x%X val 0x%llX", thunkIdx, rva, addr);
        ImportResolve resolved;
        bool ok = SafeResolveImport(dump, rva, addr, is64, resolved);
        if (ok) {
            ImportEntry entry;
            entry.dllName = resolved.moduleName;
            entry.funcName = resolved.funcName;
            entry.ordinal = resolved.ordinal;
            entry.byOrdinal = resolved.byOrdinal;
            entry.thunkRva = rva;
            importMap[resolved.moduleName].push_back(entry);
        }
    }

    // Merge VMP's import table entries (d3d9, USER32, SHELL32, etc.)
    if (vmpImportRva) {
        MergeVmpImportTable(dump, size, vmpImportRva, is64, importMap);
    }

    // --- Link thunk RVAs to VMP import descriptor entries ---
    // VMP's import descriptors define DLL+function for synthetic IAT ranges.
    // Match discovered FF 15/FF 25 thunk RVAs against each descriptor's
    // FirstThunk array to attach names to entries that failed brute-force.
    int entrySize = is64 ? 8 : 4;
    if (vmpImportRva && !uniqueThunks.empty()) {
        int linkedCount = 0;
        IMAGE_IMPORT_DESCRIPTOR* vmpDescs = (IMAGE_IMPORT_DESCRIPTOR*)(dump + vmpImportRva);
        for (IMAGE_IMPORT_DESCRIPTOR* d = vmpDescs; d->Name != 0; ++d) {
            if ((BYTE*)d - dump + sizeof(IMAGE_IMPORT_DESCRIPTOR) > (int)size) break;
            if (d->Name >= size) continue;
            if (d->FirstThunk == 0 || d->FirstThunk >= size) continue;
            if (d->OriginalFirstThunk == 0 || d->OriginalFirstThunk >= size) continue;

            char* dllName = (char*)(dump + d->Name);
            DWORD ftStart = d->FirstThunk;
            DWORD ftEnd = ftStart + 200 * entrySize;
            if (ftEnd > size) ftEnd = size;

            for (auto& [rva, addr] : uniqueThunks) {
                if (rva < ftStart || rva >= ftEnd) continue;
                DWORD idx = (rva - ftStart) / entrySize;

                ULONGLONG intVal = 0;
                DWORD intRva = d->OriginalFirstThunk + idx * entrySize;
                if (intRva + entrySize > size) continue;
                intVal = is64
                    ? *(ULONGLONG*)(dump + intRva)
                    : *(DWORD*)(dump + intRva);
                if (intVal == 0) continue;

                bool alreadyExists = false;
                auto it = importMap.find(dllName);
                if (it != importMap.end()) {
                    for (auto& e : it->second) {
                        if (e.thunkRva == rva) { alreadyExists = true; break; }
                    }
                    if (!alreadyExists) {
                        for (auto& e : it->second) {
                            if (e.thunkRva == 0) { e.thunkRva = rva; alreadyExists = true; break; }
                        }
                    }
                }
                if (alreadyExists) continue;

                ImportEntry entry;
                entry.dllName = dllName;
                entry.ordinal = 0;
                entry.byOrdinal = false;
                entry.thunkRva = rva;

                if (is64 ? (intVal & IMAGE_ORDINAL_FLAG64) : (intVal & IMAGE_ORDINAL_FLAG32)) {
                    entry.ordinal = (DWORD)(intVal & 0xFFFF);
                    entry.byOrdinal = true;
                    entry.funcName = "ordinal_" + std::to_string(entry.ordinal);
                } else {
                    DWORD hnRva = (DWORD)intVal;
                    if (hnRva + sizeof(IMAGE_IMPORT_BY_NAME) < size) {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
                        char* fn = (char*)ibn->Name;
                        SIZE_T maxLen = size - hnRva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                        fn[maxLen - 1] = 0;
                        entry.funcName = fn;
                    } else {
                        entry.funcName = "encrypted_" + std::to_string(rva);
                    }
                }
                importMap[dllName].push_back(entry);
                linkedCount++;
            }
        }
        if (linkedCount > 0)
            DbgLogF("[+] linked %d thunk RVAs to VMP import descriptors", linkedCount);
    }

    // If we found very few imports (likely VMP import protection), scan for
    // function pointers in all data sections and writable sections
    size_t totalBeforeScan = 0;
    for (auto& [dll, entries] : importMap) totalBeforeScan += entries.size();

    if (totalBeforeScan < 50) {
        DbgLogF("[*] only %zu imports from scan, trying function pointer scan...", totalBeforeScan);

        std::set<ULONGLONG> seenAddrs;
        int entrySize = is64 ? 8 : 4;
        int fpFound = 0;

        auto resolveFuncPtr = [&](DWORD rva, ULONGLONG addr) {
            if (addr <= 0x10000 || addr >= 0x7FFFFFFF0000ULL) return;
            if (seenAddrs.find(addr) != seenAddrs.end()) return;
            seenAddrs.insert(addr);
            ImportResolve resolved;
            if (!SafeResolveImport(dump, rva, addr, is64, resolved)) return;
            ImportEntry entry;
            entry.dllName = resolved.moduleName;
            entry.funcName = resolved.funcName;
            entry.ordinal = resolved.ordinal;
            entry.byOrdinal = resolved.byOrdinal;
            entry.thunkRva = rva;
            importMap[resolved.moduleName].push_back(entry);
            fpFound++;
            if (fpFound <= 5)
                DbgLogF("[*] func-ptr: %s!%s (RVA 0x%X)", resolved.moduleName.c_str(), resolved.funcName.c_str(), rva);
        };

        // Scan PE header's IAT directory
        DbgLog("[*] funcptr: scanning IAT directory...");
        {
            DWORD iatDirRva = 0, iatDirSize = 0;
            if (is64) {
                iatDirRva = ((IMAGE_NT_HEADERS64*)(dump + ((IMAGE_DOS_HEADER*)dump)->e_lfanew))
                    ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                iatDirSize = ((IMAGE_NT_HEADERS64*)(dump + ((IMAGE_DOS_HEADER*)dump)->e_lfanew))
                    ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            } else {
                iatDirRva = ((IMAGE_NT_HEADERS32*)(dump + ((IMAGE_DOS_HEADER*)dump)->e_lfanew))
                    ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
                iatDirSize = ((IMAGE_NT_HEADERS32*)(dump + ((IMAGE_DOS_HEADER*)dump)->e_lfanew))
                    ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            }
            if (iatDirRva && iatDirSize && iatDirRva + entrySize < size) {
                DWORD end = min(iatDirRva + iatDirSize, size);
                for (DWORD r = iatDirRva; r + entrySize <= end; r += entrySize) {
                    if (r + entrySize > size) break;
                    ULONGLONG a = is64 ? *(ULONGLONG*)(dump + r) : *(DWORD*)(dump + r);
                    resolveFuncPtr(r, a);
                }
            }
        }
        DbgLog("[*] funcptr: IAT dir scan done");

        // Scan VMP import table's FirstThunk range
        DbgLog("[*] funcptr: scanning VMP FT range...");
        if (vmpImportRva && vmpImportRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) < size) {
            IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(dump + vmpImportRva);
            for (; d->Name != 0; ++d) {
                if ((BYTE*)d - dump + (int)sizeof(IMAGE_IMPORT_DESCRIPTOR) > (int)size) break;
                if (d->FirstThunk == 0 || d->FirstThunk >= size) continue;
                DWORD end = min(d->FirstThunk + 200 * entrySize, size);
                for (DWORD r = d->FirstThunk; r + entrySize <= end; r += entrySize) {
                    if (r + entrySize > size) break;
                    ULONGLONG a = is64 ? *(ULONGLONG*)(dump + r) : *(DWORD*)(dump + r);
                    if (a == 0) break;
                    resolveFuncPtr(r, a);
                }
            }
        }
        DbgLog("[*] funcptr: VMP FT scan done");

        // Scan original import descriptors (the 4 descriptors found by
        // FindOriginalImportDirectory at the PE header's updated import dir).
        // These have valid INT/IAT arrays even though DLL names are encrypted.
        DbgLog("[*] funcptr: scanning original import descriptors...");
        {
            DWORD descRva = 0;
            if (is64)
                descRva = ((IMAGE_NT_HEADERS64*)(dump + ((IMAGE_DOS_HEADER*)dump)->e_lfanew))
                    ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            else
                descRva = ((IMAGE_NT_HEADERS32*)(dump + ((IMAGE_DOS_HEADER*)dump)->e_lfanew))
                    ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (descRva)
                ScanImportDescriptors(dump, size, descRva, is64, importMap);
        }
        DbgLog("[*] funcptr: descriptor scan done");

        if (fpFound > 0)
            DbgLogF("[+] function pointer scan found %d additional imports", fpFound);
    }

    if (importMap.empty()) {
        DbgLog("[!] could not resolve any import addresses");
        return false;
    }

    // We need a large free area in the dump to place the new import descriptors,
    // DLL name strings, and hint/name entries.
    // Strategy: find a gap at the end of the image, or append to the last section
    DWORD newDataRva = 0;
    DWORD newDataSize = 0;

    // calculate required size
    for (auto& [dll, entries] : importMap) {
        newDataSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        newDataSize += (DWORD)dll.size() + 1;
        for (auto& e : entries) {
            if (e.byOrdinal) {
                newDataSize += is64 ? 8 : 4;
            } else {
                // hint/name entry: word hint + name + null
                newDataSize += 2 + (DWORD)e.funcName.size() + 1;
                newDataSize += is64 ? 8 : 4; // thunk entry
            }
        }
    }
    newDataSize += sizeof(IMAGE_IMPORT_DESCRIPTOR); // null terminator
    newDataSize += 0x100; // safety padding

    // find a place for the new import data - scan for a gap in the dump
    // We'll place it after the last section's raw data
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD sectionCount = nt->FileHeader.NumberOfSections;

    // find the highest RVA used by sections
    DWORD highestRva = 0;
    DWORD highestEnd = 0;
    for (WORD i = 0; i < sectionCount; ++i) {
        DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (end > highestEnd) {
            highestEnd = end;
            highestRva = sections[i].VirtualAddress;
        }
    }

    // make sure we have room in the dump buffer
    if (highestEnd + newDataSize > size) {
        DbgLogF("[!] not enough space for new import data (need 0x%X, have 0x%zX)",
            highestEnd + newDataSize, size);
        return false;
    }

    newDataRva = highestEnd;

    // Build the new import descriptors
    // Format: import descriptors, followed by thunk data, followed by strings

    BYTE* importData = dump + newDataRva;
    DWORD offset = 0;

    // IMAGE_IMPORT_DESCRIPTOR array + null terminator
    DWORD descCount = (DWORD)importMap.size() + 1;
    IMAGE_IMPORT_DESCRIPTOR* descs = (IMAGE_IMPORT_DESCRIPTOR*)(importData + offset);
    offset += descCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    ZeroMemory(descs, descCount * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    DWORD nameOffset = offset;

    DWORD descIndex = 0;
    // thunkRva → new FirstThunk entry RVA (for code patching)
    std::map<DWORD, DWORD> iatSlotPatch;
    for (auto& [dll, entries] : importMap) {
        IMAGE_IMPORT_DESCRIPTOR& desc = descs[descIndex];

        // DLL name RVA
        desc.Name = newDataRva + nameOffset;
        strcpy_s((char*)(importData + nameOffset), (DWORD)dll.size() + 1, dll.c_str());
        nameOffset += (DWORD)dll.size() + 1;

        // Reserve contiguous space for the INT/IAT thunk array
        DWORD thunkArrayOffset = nameOffset;
        DWORD thunkArraySize = ((DWORD)entries.size() + 1) * (is64 ? 8 : 4);
        desc.OriginalFirstThunk = newDataRva + thunkArrayOffset;
        desc.FirstThunk = newDataRva + thunkArrayOffset;
        nameOffset += thunkArraySize;

        // Write hint/name struct data and fill in thunk entries
        DWORD hintOffset = nameOffset;
        for (size_t i = 0; i < entries.size(); i++) {
            auto& e = entries[i];
            DWORD newThunkRva = newDataRva + thunkArrayOffset + (DWORD)i * (is64 ? 8 : 4);
            if (e.byOrdinal) {
                if (is64)
                    *(ULONGLONG*)(importData + thunkArrayOffset + i * 8) = IMAGE_ORDINAL_FLAG64 | e.ordinal;
                else
                    *(DWORD*)(importData + thunkArrayOffset + i * 4) = IMAGE_ORDINAL_FLAG32 | e.ordinal;
            } else {
                DWORD hintNameRva = newDataRva + hintOffset;
                *(WORD*)(importData + hintOffset) = 0;
                hintOffset += 2;
                strcpy_s((char*)(importData + hintOffset), (DWORD)e.funcName.size() + 1, e.funcName.c_str());
                hintOffset += (DWORD)e.funcName.size() + 1;
                if (hintOffset % 2) { importData[hintOffset] = 0; hintOffset++; }

                if (is64)
                    *(ULONGLONG*)(importData + thunkArrayOffset + i * 8) = hintNameRva;
                else
                    *(DWORD*)(importData + thunkArrayOffset + i * 4) = hintNameRva;
            }
            if (e.thunkRva != 0)
                iatSlotPatch[e.thunkRva] = newThunkRva;
        }

        // null terminator for this DLL's thunk array
        if (is64)
            *(ULONGLONG*)(importData + thunkArrayOffset + entries.size() * 8) = 0;
        else
            *(DWORD*)(importData + thunkArrayOffset + entries.size() * 4) = 0;

        nameOffset = hintOffset;
        descIndex++;
    }

    // null terminator for import descriptors (already zeroed)

    // Patch code instructions to reference the new IAT entries
    {
        int patchedCount = 0;
        std::map<DWORD, std::vector<DWORD>> instRefs;
        for (DWORD i = 0; i < size - 8; ++i) {
            BYTE* p = dump + i;
            if ((p[0] == 0xFF && (p[1] == 0x15 || p[1] == 0x25))) {
                DWORD targetRva;
                if (is64) {
                    int32_t disp = *(int32_t*)(p + 2);
                    targetRva = (DWORD)(i + 6 + disp);
                } else {
                    targetRva = *(uint32_t*)(p + 2);
                }
                if (iatSlotPatch.find(targetRva) != iatSlotPatch.end())
                    instRefs[targetRva].push_back(i);
            }
        }
        for (auto& [thunkRva, instRvas] : instRefs) {
            auto it = iatSlotPatch.find(thunkRva);
            if (it == iatSlotPatch.end()) continue;
            DWORD newTargetRva = it->second;
            for (DWORD instRva : instRvas) {
                if (instRva + 6 > size) continue;
                BYTE* inst = dump + instRva;
                if (is64) {
                    int32_t newDisp = (int32_t)(newTargetRva - (instRva + 6));
                    *(int32_t*)(inst + 2) = newDisp;
                } else {
                    *(DWORD*)(inst + 2) = newTargetRva;
                }
                patchedCount++;
            }
        }
        if (patchedCount > 0)
            DbgLogF("[+] patched %d code references to new IAT", patchedCount);
    }

    // Update the import directory in the dumped PE
    offset = nameOffset; // total bytes used
    if (is64) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew);
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newDataRva;
        nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = offset;
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew);
        nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newDataRva;
        nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = offset;
    }

    size_t totalEntries = 0;
    for (auto& [dll, entries] : importMap) totalEntries += entries.size();
    DbgLogF("[+] import table rebuilt with %zu DLLs, %zu thunks at RVA 0x%X",
        importMap.size(), totalEntries, newDataRva);
    return true;
}

static void FixSectionHeaders(BYTE* dump, DWORD sizeOfImage) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;

    DWORD rawOffset = (nt->OptionalHeader.SizeOfHeaders + 0x1FF) & ~0x1FF;

    if (rawOffset > nt->OptionalHeader.SizeOfHeaders)
        ZeroMemory(dump + nt->OptionalHeader.SizeOfHeaders, rawOffset - nt->OptionalHeader.SizeOfHeaders);

    for (WORD i = 0; i < count; ++i, ++sec) {
        sec->PointerToRawData = rawOffset;
        DWORD rawSize = sec->Misc.VirtualSize;

        DWORD usableSize = 0;
        if (sec->VirtualAddress + sec->Misc.VirtualSize <= sizeOfImage) {
            BYTE* secData = dump + sec->VirtualAddress;
            for (DWORD j = sec->Misc.VirtualSize; j > 0; --j) {
                if (secData[j - 1] != 0) {
                    usableSize = j;
                    break;
                }
            }
        }

        if (usableSize > 0)
            rawSize = usableSize;
        if (rawSize > sec->Misc.VirtualSize)
            rawSize = sec->Misc.VirtualSize;

        if (usableSize > 0 && sec->VirtualAddress != rawOffset) {
            memmove(dump + rawOffset, dump + sec->VirtualAddress, usableSize);
            ZeroMemory(dump + sec->VirtualAddress, usableSize);
        }

        if (sec->SizeOfRawData == 0)
            rawSize = usableSize;

        sec->SizeOfRawData = (rawSize + 0x1FF) & ~0x1FF;
        rawOffset += sec->SizeOfRawData;

        if (sec->SizeOfRawData > 0 && !(sec->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA))) {
            sec->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        }
    }
}

// Bounds-checked PE header accessor for use on (possibly corrupted) raw dumps.
static bool PeHeaderIsUsable(BYTE* dump, DWORD size) {
    if (!dump || size < 0x1000) return false;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    DWORD lfanew = dos->e_lfanew;
    if (lfanew == 0 || lfanew + 0x400 > size) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    WORD count = nt->FileHeader.NumberOfSections;
    if (count == 0 || count > 96) return false;
    DWORD secEnd = lfanew + 4 + 20 + nt->FileHeader.SizeOfOptionalHeader +
        (DWORD)count * sizeof(IMAGE_SECTION_HEADER);
    if (secEnd > size) return false;
    return true;
}

static void PreserveResourceDirectory(BYTE* dump, DWORD sizeOfImage) {
    if (!PeHeaderIsUsable(dump, sizeOfImage)) {
        DbgLog("[!] PE header unusable, skipping resource preservation");
        return;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    DWORD rsrcRva = 0, rsrcSize = 0;
    if (is64) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew);
        rsrcRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        rsrcSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew);
        rsrcRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        rsrcSize = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
    }

    if (rsrcRva == 0 || rsrcSize == 0) {
        DbgLog("[*] no resource directory in headers");
        return;
    }

    // Check if .rsrc section exists in section headers
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;
    bool hasRsrcSection = false;

    for (WORD i = 0; i < count; ++i) {
        if (memcmp(sections[i].Name, ".rsrc", 6) == 0 ||
            memcmp(sections[i].Name, ".rsrc\0\0", 8) == 0) {
            hasRsrcSection = true;
            break;
        }
    }

    if (hasRsrcSection) {
        DbgLog("[+] .rsrc section already present, data will be preserved by section fixup");
        return;
    }

    // If no explicit .rsrc section, the resource data might be within another section
    // The section fixup will handle it if it's within VirtualAddress range
    DbgLogF("[*] resource directory at RVA 0x%X, size 0x%X (in existing sections)", rsrcRva, rsrcSize);
}

static void RebuildRelocationTable(BYTE* dump, DWORD sizeOfImage, DWORD imageBase) {
    if (!PeHeaderIsUsable(dump, sizeOfImage)) {
        DbgLog("[!] PE header unusable, skipping relocation rebuild");
        return;
    }
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    // check if .reloc section already exists
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < count; ++i) {
        if (memcmp(sections[i].Name, ".reloc", 7) == 0) {
            DbgLog("[+] .reloc section already present");
            return;
        }
    }

    // Check if there's already a base reloc directory
    DWORD relocRva = 0, relocSize = 0;
    if (is64) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew);
        relocRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew);
        relocRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }

    if (relocRva && relocSize) {
        DbgLog("[+] relocation directory valid in headers");
        // ensure the data is within a section
        bool inSection = false;
        for (WORD i = 0; i < count; ++i) {
            DWORD start = sections[i].VirtualAddress;
            DWORD end = start + sections[i].Misc.VirtualSize;
            if (relocRva >= start && relocRva + relocSize <= end) {
                inSection = true;
                break;
            }
        }
        if (!inSection) {
            DbgLog("[*] relocation data outside sections, marking as fixed");
            if (is64) {
                IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew);
                nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            } else {
                IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew);
                nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            }
        }
        return;
    }

    DbgLog("[*] no relocation table found - rebuilding is complex, marking as fixed-base");
    // Mark the image as having no relocations (EFileFlags &= ~RELOCS_STRIPPED doesn't help here)
    // The OS will assume it must be loaded at ImageBase
}

// Scan for VMP virtual-machine entry points in the dumped image.
// VMP replaces original code with patterns like:
//   push offset_into_vm_bytecode   (or mov reg, offset)
//   call/jmp vm_dispatcher
//
// We identify these by looking for call instructions that target
// the VM dispatcher region, and extract the bytecode handle.

static DWORD FindVmDispatcher(BYTE* dump, DWORD size) {
    DWORD textStart = 0, textEnd = 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            textStart = sec[i].VirtualAddress;
            textEnd = textStart + sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textStart || textEnd > size) return 0;

    // Look for a function that appears to be the VM dispatcher.
    // The dispatcher typically receives a bytecode offset as a parameter
    // and runs a dispatch loop. Pattern: repeated indirect calls through
    // a handler table, often with a distinctive prologue.
    //
    // For now, just identify any code that calls into the VM dispatch area.
    // The real approach would require dynamic analysis.

    // Search for common VM call pattern: push <value>; call <dispatcher>
    // where the dispatcher address is repeated many times throughout the code
    std::map<DWORD, int> callTargetCounts;

    for (DWORD i = textStart; i < textEnd - 5; ++i) {
        if (dump[i] == 0xE8) {
            DWORD rel = *(int32_t*)(dump + i + 1);
            DWORD target = (i + 5) + rel;
            if (target < size)
                callTargetCounts[target]++;
        }
    }

    // the VM dispatcher will be the most-called function in the image
    DWORD bestTarget = 0;
    int bestCount = 0;
    for (auto& [target, count] : callTargetCounts) {
        if (count > bestCount && count > 10) {
            // verify it's in an executable section
            bool inExec = false;
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    if (target >= sec[i].VirtualAddress &&
                        target < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
                        inExec = true;
                        break;
                    }
                }
            }
            if (inExec) {
                bestCount = count;
                bestTarget = target;
            }
        }
    }

    if (bestTarget) {
        DbgLogF("[+] possible VM dispatcher at 0x%X (%d call sites)", bestTarget, bestCount);
    }

    return bestTarget;
}

static void FindVmEntries(BYTE* dump, DWORD size, DWORD vmDispatcher) {
    if (!vmDispatcher) return;

    size_t count = 0;
    DWORD searchEnd = size - 8;

    // Pattern 1: push <bytecode_offset>; call <dispatcher>
    // (x86: 68 xx xx xx xx E8/FF 15)
    for (DWORD i = 0; i < searchEnd - 6; ++i) {
        BYTE* p = dump + i;

        // push imm32; call rel32
        if (p[0] == 0x68 && p[5] == 0xE8) {
            DWORD bytecodeRef = *(uint32_t*)(p + 1);
            DWORD callRel = *(int32_t*)(p + 6);
            DWORD target = (i + 10) + callRel;
            if (target == vmDispatcher) {
                DbgLogF("[VM] entry at 0x%X: bytecode=0x%X", i, bytecodeRef);
                count++;
            }
        }

        // push imm32; call [disp32]
        if (p[0] == 0x68 && p[5] == 0xFF && p[6] == 0x15) {
            DWORD bytecodeRef = *(uint32_t*)(p + 1);
            DWORD callTarget = *(uint32_t*)(p + 7);
            if (callTarget == vmDispatcher) {
                DbgLogF("[VM] entry at 0x%X: bytecode=0x%X (indirect call)", i, bytecodeRef);
                count++;
            }
        }

        // x64 pattern: mov ecx/edx, <bytecode_offset>; call <dispatcher>
        // B9 xx xx xx xx (mov ecx, imm32) / BA xx xx xx xx (mov edx, imm32)
        if (i < searchEnd - 10) {
            if ((p[0] == 0xB9 || p[0] == 0xBA) && p[5] == 0xE8) {
                DWORD bytecodeRef = *(uint32_t*)(p + 1);
                DWORD callRel = *(int32_t*)(p + 6);
                DWORD target = (i + 10) + callRel;
                if (target == vmDispatcher) {
                    DbgLogF("[VM] entry at 0x%X: bytecode=0x%X (mov reg)", i, bytecodeRef);
                    count++;
                }
            }
        }

        // push imm64; jmp [disp32] (x64 indirect thunk)
        // 68 xx xx xx xx FF 25 xx xx xx xx
        if (p[0] == 0x68 && p[5] == 0xFF && p[6] == 0x25) {
            DWORD bytecodeRef = *(uint32_t*)(p + 1);
            DWORD jmpTargetRva = *(uint32_t*)(p + 7);
            DbgLogF("[VM] possible entry at 0x%X: bytecode=0x%X (jmp through 0x%X)", i, bytecodeRef, jmpTargetRva);
            count++;
        }
    }

    DbgLogF("[VM] found %zu VM entry points (dispatcher at 0x%X)", count, vmDispatcher);
}

bool DumpProcess(DumpContext& ctx) {
    ULONGLONG baseAddr = FindTargetModuleBase();
    if (!baseAddr) {
        DbgLog("[!] could not find image base");
        return false;
    }
    ctx.imageBase = baseAddr;

    BYTE hdrBuf[0x1000];
    memcpy(hdrBuf, (void*)baseAddr, sizeof(hdrBuf));
    if (!IsValidPeHeader(hdrBuf, sizeof(hdrBuf))) {
        DbgLog("[!] no valid PE header at image base");
        return false;
    }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdrBuf;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hdrBuf + dos->e_lfanew);

    ctx.is64Bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    // save original sections before any modifications
    ctx.sectionCount = nt->FileHeader.NumberOfSections;
    ctx.sections.resize(ctx.sectionCount);
    IMAGE_SECTION_HEADER* srcSec = IMAGE_FIRST_SECTION(nt);
    memcpy(ctx.sections.data(), srcSec, ctx.sectionCount * sizeof(IMAGE_SECTION_HEADER));

    if (ctx.is64Bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(hdrBuf + dos->e_lfanew);
        ctx.oepRva = nt64->OptionalHeader.AddressOfEntryPoint;
        ctx.sizeOfImage = nt64->OptionalHeader.SizeOfImage;
        ctx.sectionAlignment = nt64->OptionalHeader.SectionAlignment;
        ctx.fileAlignment = nt64->OptionalHeader.FileAlignment;
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(hdrBuf + dos->e_lfanew);
        ctx.oepRva = nt32->OptionalHeader.AddressOfEntryPoint;
        ctx.sizeOfImage = nt32->OptionalHeader.SizeOfImage;
        ctx.sectionAlignment = nt32->OptionalHeader.SectionAlignment;
        ctx.fileAlignment = nt32->OptionalHeader.FileAlignment;
    }

    if (ctx.sizeOfImage == 0 || ctx.sizeOfImage > 0x20000000) {
        DbgLog("[!] invalid SizeOfImage");
        return false;
    }

    ctx.rawDump = (BYTE*)VirtualAlloc(nullptr, ctx.sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ctx.rawDump) {
        DbgLog("[!] failed to allocate dump buffer");
        return false;
    }
    ctx.rawSize = ctx.sizeOfImage;

    MEMORY_BASIC_INFORMATION mbi;
    ULONGLONG current = baseAddr;
    SIZE_T totalDumped = 0;

    while (current < baseAddr + ctx.sizeOfImage) {
        if (VirtualQuery((LPCVOID)current, &mbi, sizeof(mbi)) == 0) break;
        if (mbi.State == MEM_COMMIT) {
            SIZE_T offset = (ULONGLONG)mbi.BaseAddress - baseAddr;
            SIZE_T copySize = min(mbi.RegionSize, ctx.sizeOfImage - offset);
            memcpy(ctx.rawDump + offset, mbi.BaseAddress, copySize);
            totalDumped += copySize;
        }
        current += mbi.RegionSize;
    }

    DbgLogF("[+] dumped %zu bytes at base 0x%llX (size: 0x%X)", totalDumped, baseAddr, ctx.sizeOfImage);
    return true;
}

// Resolve import thunks by reading hint/name RVAs from thunk locations and
// resolving function names across all loaded modules. Works for VMP where
// the IAT contains hint/name RVAs instead of resolved addresses.
static bool RebuildImportTableViaNameScan(BYTE* dump, DWORD size, DWORD sizeOfImage, bool is64) {
    int entrySize = is64 ? 8 : 4;
    struct ThunkInfo {
        DWORD rva;
        DWORD hintNameRva;
    };
    std::vector<ThunkInfo> nameThunks;

    DWORD searchEnd = size - 8;
    for (DWORD i = 0; i < searchEnd; ++i) {
        BYTE* p = dump + i;
        for (int op = 0; op < 2; ++op) {
            if ((op == 0 && p[0] == 0xFF && p[1] == 0x15) ||
                (op == 1 && p[0] == 0xFF && p[1] == 0x25)) {
                DWORD rva;
                if (is64) {
                    int32_t disp = *(int32_t*)(p + 2);
                    rva = (DWORD)(i + 6 + disp);
                } else {
                    rva = *(uint32_t*)(p + 2);
                }
                if (rva >= size || rva + entrySize > size) continue;
                ULONGLONG val = is64 ? *(ULONGLONG*)(dump + rva) : *(DWORD*)(dump + rva);

                // Check for hint/name RVA (small value ≤ sizeOfImage, not an ordinal)
                if (val == 0) continue;
                if (is64 ? (val & IMAGE_ORDINAL_FLAG64) : (val & IMAGE_ORDINAL_FLAG32)) continue;
                if (val > sizeOfImage) continue; // skip resolved addresses (handled by scan)

                DWORD hnRva = (DWORD)val;
                if (hnRva + sizeof(IMAGE_IMPORT_BY_NAME) >= sizeOfImage) continue;

                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
                SIZE_T fnLen = strnlen((char*)ibn->Name, sizeOfImage - hnRva - 2);
                if (fnLen < 1 || fnLen > 256) continue;

                ThunkInfo ti;
                ti.rva = rva;
                ti.hintNameRva = hnRva;
                nameThunks.push_back(ti);
            }
        }
    }

    // deduplicate by RVA (keep first)
    std::map<DWORD, DWORD> unique;
    for (auto& t : nameThunks) {
        if (unique.find(t.rva) == unique.end())
            unique[t.rva] = t.hintNameRva;
    }

    DbgLogF("[*] name scan found %zu unique thunks with hint/name RVAs", unique.size());
    if (unique.empty()) return false;

    // Enumerate all loaded modules
    HMODULE hMods[512];
    DWORD cbNeeded;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        DbgLog("[!] EnumProcessModules failed");
        return false;
    }
    DWORD numMods = cbNeeded / sizeof(HMODULE);

    int resolved = 0;
    for (auto& [rva, hnRva] : unique) {
        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
        char* funcName = (char*)ibn->Name;
        SIZE_T maxLen = sizeOfImage - hnRva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
        funcName[maxLen - 1] = 0;

        FARPROC proc = nullptr;
        for (DWORD m = 0; m < numMods; ++m) {
            if (hMods[m] == GetModuleHandleW(nullptr)) continue; // skip EXE
            proc = GetProcAddress(hMods[m], funcName);
            if (proc) break;
        }

        if (proc) {
            if (is64)
                *(ULONGLONG*)(dump + rva) = (ULONGLONG)proc;
            else
                *(DWORD*)(dump + rva) = (DWORD)(ULONG_PTR)proc;
            ++resolved;
        }
    }

    if (resolved > 0) {
        DbgLogF("[+] name-based scan resolved %d/%zu imports", resolved, unique.size());
        return true;
    }
    DbgLog("[!] name-based scan could not resolve any imports");
    return false;
}

// Scan entire dump for the original import descriptor table.
// VMP replaces the PE header's import directory with its own small set,
// but the original import descriptors are decompressed into the data.
// We scan every 4-byte aligned position for valid IMAGE_IMPORT_DESCRIPTOR
// sequences with proper DLL names and INT/IAT arrays.
static DWORD FindOriginalImportDirectory(BYTE* dump, DWORD sizeOfImage, bool is64) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    int entrySize = is64 ? 8 : 4;

    // Get current import directory RVA (VMP's) to skip its region
    DWORD currentImportRva = 0;
    if (is64)
        currentImportRva = ((IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    else
        currentImportRva = ((IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // Build a set of known VMP import RVAs (Name pointers) to avoid false positives
    DbgLogF("[*] current import dir (VMP) at RVA 0x%X", currentImportRva);

    // Scan every 4-byte aligned position in non-PE-header regions
    DWORD scanStart = nt->OptionalHeader.SizeOfHeaders;
    scanStart = (scanStart + 3) & ~3;

    for (DWORD rva = scanStart; rva + sizeof(IMAGE_IMPORT_DESCRIPTOR) < sizeOfImage; rva += 4) {
        // Skip PE headers region and current import dir
        if (currentImportRva && rva >= currentImportRva && rva < currentImportRva + 0x300) { rva = currentImportRva + 0x300; if (rva + sizeof(IMAGE_IMPORT_DESCRIPTOR) >= sizeOfImage) break; }

        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(dump + rva);
        if (desc->Name == 0 || desc->Name >= sizeOfImage) continue;
        if (desc->Name < (DWORD)sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS)) continue;

        // Fast candidate check: first 4 bytes of descriptor should look sensible
        // OriginalFirstThunk should be non-zero and in a data section range
        DWORD candidateInt = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (candidateInt == 0) continue;
        if (candidateInt < scanStart || candidateInt >= sizeOfImage) continue;

        // Check DLL name (must end with .dll)
        char* dllName = (char*)(dump + desc->Name);
        SIZE_T nameLen = strnlen(dllName, sizeOfImage - desc->Name);
        if (nameLen < 4 || nameLen > 128) continue;
        char* ext = dllName + nameLen - 4;
        bool hasDllExt = (ext[0] == '.' && (ext[1] == 'd' || ext[1] == 'D') &&
            (ext[2] == 'l' || ext[2] == 'L') && (ext[3] == 'l' || ext[3] == 'L'));

        // Also accept .ocx, .sys, .drv extensions, or just any at least 5-char name
        if (!hasDllExt) {
            if (nameLen < 5) continue;
            if (ext[0] != '.' && nameLen < 8) continue;
        }

        // Check INT/IAT has valid entries
        bool hasValidEntries = false;
        bool hasNullTerm = false;
        int validCount = 0;

        for (int j = 0; j < 2000; ++j) {
            DWORD off = (DWORD)j * entrySize;
            if (candidateInt + off + entrySize > sizeOfImage) break;

            ULONGLONG val = is64
                ? *(ULONGLONG*)(dump + candidateInt + off)
                : *(DWORD*)(dump + candidateInt + off);

            if (val == 0) { hasNullTerm = true; break; }
            validCount++;

            if (is64 ? (val & IMAGE_ORDINAL_FLAG64) : (val & IMAGE_ORDINAL_FLAG32)) {
                hasValidEntries = true;
                continue;
            }

            DWORD hnRva = (DWORD)val;
            if (hnRva + sizeof(IMAGE_IMPORT_BY_NAME) < sizeOfImage && hnRva >= sizeof(IMAGE_DOS_HEADER)) {
                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
                if (ibn->Hint == 0xFFFF) continue; // unlikely valid hint
                SIZE_T fnLen = strnlen((char*)ibn->Name, sizeOfImage - hnRva - 2);
                if (fnLen > 0 && fnLen < 256) hasValidEntries = true;
            }
        }

        if (!hasValidEntries || !hasNullTerm) continue;
        if (validCount < 2) continue;

        // Check next descriptor is either null or also valid
        IMAGE_IMPORT_DESCRIPTOR* next = desc + 1;
        if (next->Name == 0) {
            DbgLogF("[+] found import table at RVA 0x%X (%s, %d DLLs)", rva, dllName, 1);
            return rva;
        }
        if (next->Name >= sizeOfImage) continue;

        // Count how many consecutive valid descriptors
        int dllCount = 1;
        for (int k = 1; k < 100; ++k) {
            IMAGE_IMPORT_DESCRIPTOR* d = desc + k;
            if (d->Name == 0) { dllCount = k; break; }
            if (d->Name >= sizeOfImage) break;
            SIZE_T nl = strnlen((char*)(dump + d->Name), sizeOfImage - d->Name);
            if (nl < 3) break;
            dllCount = k + 1;
        }

        if (dllCount >= 3) {
            DbgLogF("[+] found import table at RVA 0x%X (%d DLLs)", rva, dllCount);
            for (int di = 0; di < min(10, dllCount); ++di) {
                IMAGE_IMPORT_DESCRIPTOR* dd = desc + di;
                char* dn = (char*)(dump + dd->Name);
                SIZE_T dnl = strnlen(dn, 64);
                char dnb[65] = {}; strncpy_s(dnb, dn, min(dnl, 64));
                DbgLogF("[*]   [%d] %s (INT 0x%X, IAT 0x%X)", di, dnb, dd->OriginalFirstThunk, dd->FirstThunk);
            }
            return rva;
        }
    }
    DbgLog("[*] could not find original import table");
    return 0;
}

static bool ResolveImportsFromDescriptors(BYTE* dump, DWORD sizeOfImage, bool is64) {
    // Reads import descriptors from the dumped PE, walks INT entries (ordinal or
    // hint/name RVAs), and resolves each import via LoadLibrary/GetProcAddress.
    // Writes real resolved addresses to FirstThunk.
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    DWORD importRva = 0;
    if (is64) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew);
        importRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew);
        importRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }

    if (!importRva || importRva >= sizeOfImage) return false;

    IMAGE_IMPORT_DESCRIPTOR* descs = (IMAGE_IMPORT_DESCRIPTOR*)(dump + importRva);
    if (descs->Name == 0 || descs->Name >= sizeOfImage) return false;

    int totalResolved = 0;
    int totalDlls = 0;

    for (IMAGE_IMPORT_DESCRIPTOR* desc = descs; desc->Name != 0; ++desc) {
        if (desc->Name >= sizeOfImage) continue;
        if (desc->FirstThunk == 0 || desc->FirstThunk >= sizeOfImage) continue;
        DWORD intRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (intRva == 0 || intRva >= sizeOfImage) continue;

        char* dllName = (char*)(dump + desc->Name);
        HMODULE hMod = LoadLibraryA(dllName);
        if (!hMod) {
            DbgLogF("[!] could not load DLL: %s", dllName);
            continue;
        }

        ++totalDlls;
        int entrySize = is64 ? 8 : 4;
        int idx = 0;

        while (true) {
            ULONGLONG intVal = is64
                ? *(ULONGLONG*)(dump + intRva + idx * entrySize)
                : *(DWORD*)(dump + intRva + idx * entrySize);
            if (intVal == 0) break;

            FARPROC proc = nullptr;

            if (is64 ? (intVal & IMAGE_ORDINAL_FLAG64) : (intVal & IMAGE_ORDINAL_FLAG32)) {
                DWORD ordinal = (DWORD)(intVal & 0xFFFF);
                proc = GetProcAddress(hMod, (LPCSTR)MAKEINTRESOURCEA(ordinal));
            } else {
                DWORD hintNameRva = (DWORD)intVal;
                if (hintNameRva + sizeof(IMAGE_IMPORT_BY_NAME) < sizeOfImage) {
                    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hintNameRva);
                    char* funcName = (char*)ibn->Name;
                    // ensure name is null-terminated within bounds
                    SIZE_T maxLen = sizeOfImage - hintNameRva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                    funcName[maxLen - 1] = 0;
                    proc = GetProcAddress(hMod, funcName);
                }
            }

            if (proc) {
                if (is64)
                    *(ULONGLONG*)(dump + desc->FirstThunk + idx * 8) = (ULONGLONG)proc;
                else
                    *(DWORD*)(dump + desc->FirstThunk + idx * 4) = (DWORD)(ULONG_PTR)proc;
                ++totalResolved;
            }
            ++idx;
        }
    }

    if (totalResolved > 0) {
        DbgLogF("[+] resolved %d imports across %d DLLs via INT descriptors", totalResolved, totalDlls);
        return true;
    }
    return false;
}

// Extract IAT slot RVAs from code scan: finds all call/jmp [xxx] targets
// and returns the unique set of IAT slot RVAs.
// Uses section characteristics and value plausibility to filter false positives.
static std::set<DWORD> FindIatSlots(BYTE* dump, DWORD size, bool is64) {
    // Build section info for filtering
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    WORD sectionCount = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    std::vector<IMAGE_SECTION_HEADER> secList(sections, sections + sectionCount);

    auto isInDataSection = [&](DWORD rva) -> bool {
        for (auto& s : secList) {
            if (rva >= s.VirtualAddress &&
                rva < s.VirtualAddress + s.Misc.VirtualSize) {
                // Must NOT be an execute-only section (IAT slots are in data)
                if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    return false;
                return true;
            }
        }
        return false;
    };

    std::set<DWORD> slots;
    DWORD searchEnd = size - 8;
    for (DWORD i = 0; i < searchEnd; ++i) {
        BYTE* p = dump + i;
        for (int op = 0; op < 2; ++op) {
            if ((op == 0 && p[0] == 0xFF && p[1] == 0x15) ||
                (op == 1 && p[0] == 0xFF && p[1] == 0x25)) {
                DWORD rva;
                if (is64) {
                    int32_t disp = *(int32_t*)(p + 2);
                    rva = (DWORD)(i + 6 + disp);
                } else {
                    rva = *(uint32_t*)(p + 2);
                }
                if (rva >= size || rva + 8 > size) continue;

                // Filter: slot must be in a data section, not code
                if (!isInDataSection(rva)) continue;

                // Filter: value at slot must be a plausible pointer
                ULONGLONG targetAddr = *(ULONGLONG*)(dump + rva);
                if (targetAddr <= 0x10000 || targetAddr >= 0x7FFFFFFF0000ULL) continue;

                slots.insert(rva);
            }
        }
    }
    return slots;
}

// Scan for import descriptors using known IAT slot RVAs as anchors.
// The original import descriptors have FirstThunk pointing to the first IAT
// slot for that DLL. By matching FirstThunk against our known slot RVAs,
// we can identify the original descriptors even when VMP obfuscates the values.
static DWORD FindImportDescriptorsByIatSlots(BYTE* dump, DWORD sizeOfImage,
    const std::set<DWORD>& iatSlots, bool is64)
{
    if (iatSlots.empty()) return 0;

    DWORD scanStart = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS);
    scanStart = (scanStart + 3) & ~3;

    // Build a fast lookup for IAT slot RVAs
    std::set<DWORD> iatSlotSet(iatSlots.begin(), iatSlots.end());

    // Also compute the min/max to define the IAT extent
    DWORD iatMin = *iatSlots.begin();
    DWORD iatMax = *iatSlots.rbegin();

    DbgLogF("[*] IAT slot range: 0x%X - 0x%X (%d slots)", iatMin, iatMax, iatSlots.size());

    struct Candidate {
        DWORD rva;
        DWORD score;
    };
    std::vector<Candidate> candidates;

    for (DWORD rva = scanStart; rva + sizeof(IMAGE_IMPORT_DESCRIPTOR) < sizeOfImage; rva += 4) {
        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(dump + rva);
        if (desc->Name == 0 || desc->Name >= sizeOfImage) continue;
        if (desc->FirstThunk == 0 || desc->FirstThunk >= sizeOfImage) continue;

        // Check if FirstThunk is one of our IAT slots (strict match)
        bool exactMatch = (iatSlotSet.find(desc->FirstThunk) != iatSlotSet.end());
        bool nearMatch = false;
        if (!exactMatch && desc->FirstThunk < iatMin && iatMin - desc->FirstThunk <= 0x100)
            nearMatch = true;
        if (!exactMatch && !nearMatch) continue;

        // Validate DLL name: must end with .dll, .ocx, .sys, .drv
        char* dllName = (char*)(dump + desc->Name);
        SIZE_T nameLen = strnlen(dllName, sizeOfImage - desc->Name);
        if (nameLen < 4 || nameLen > 128) continue;
        char* ext = dllName + nameLen - 4;
        bool hasDllExt = (ext[0] == '.' && (ext[1] == 'd' || ext[1] == 'D') &&
            (ext[2] == 'l' || ext[2] == 'L') && (ext[3] == 'l' || ext[3] == 'L'));
        if (!hasDllExt) {
            if (nameLen < 5) continue;
            if (ext[0] != '.') continue;
        }

        // Check INT pointer
        DWORD intRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (intRva == 0 || intRva >= sizeOfImage) continue;

        // Score: how many IAT slots are in [FirstThunk, FirstThunk + reasonable range)?
        DWORD maxIatSize = min((DWORD)2000 * (is64 ? 8 : 4), sizeOfImage - desc->FirstThunk);
        DWORD score = 0;
        for (DWORD slot : iatSlots) {
            if (slot >= desc->FirstThunk && slot < desc->FirstThunk + maxIatSize)
                score++;
        }
        // Bonus for exact FirstThunk match
        if (exactMatch) score += 100;

        if (score > 0) {
            candidates.push_back({ rva, score });
        }
    }

    if (candidates.empty()) {
        DbgLog("[*] no import descriptors matched IAT slot RVAs");
        return 0;
    }

    // Sort by score descending, take the highest-scored descriptor
    std::sort(candidates.begin(), candidates.end(),
        [](const Candidate& a, const Candidate& b) { return a.score > b.score; });

    DWORD bestRva = candidates[0].rva;
    DbgLogF("[+] found import descriptor at 0x%X (score %d) matching IAT slots", bestRva, candidates[0].score);

    // Verify: walk the consecutive descriptors and log them
    IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*)(dump + bestRva);
    int dllCount = 0;
    for (int k = 0; k < 100; ++k) {
        if (desc[k].Name == 0) { dllCount = k; break; }
        if (desc[k].Name >= sizeOfImage) break;
        char* dn = (char*)(dump + desc[k].Name);
        SIZE_T dnl = strnlen(dn, sizeOfImage - desc[k].Name);
        if (dnl < 3) break;
        dllCount = k + 1;
    }
    DbgLogF("[+] %d consecutive import descriptors starting at 0x%X", dllCount, bestRva);
    for (int di = 0; di < min(10, dllCount); ++di) {
        char* dn = (char*)(dump + desc[di].Name);
        SIZE_T dnl = strnlen(dn, 64);
        char dnb[65] = {}; strncpy_s(dnb, dn, min(dnl, 64));
        DbgLogF("[*]   [%d] %s (INT 0x%X, IAT 0x%X)", di, dnb,
            desc[di].OriginalFirstThunk, desc[di].FirstThunk);
    }

    if (dllCount < 1) return 0;
    return bestRva;
}

// Validate a single INT entry (hint/name RVA or ordinal) at given RVA
static bool IsValidIntEntry(BYTE* dump, DWORD size, ULONGLONG val, bool is64) {
    if (val == 0) return false;
    bool isOrd = is64
        ? (val & IMAGE_ORDINAL_FLAG64)
        : (val & IMAGE_ORDINAL_FLAG32);
    if (isOrd) {
        DWORD ord = (DWORD)(val & 0xFFFF);
        return ord >= 1 && ord <= 0x4000;
    }
    DWORD hnRva = (DWORD)val;
    if (hnRva < 0x1000 || hnRva + sizeof(IMAGE_IMPORT_BY_NAME) >= size) return false;
    IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
    SIZE_T fnLen = strnlen((char*)ibn->Name, size - hnRva - 2);
    return fnLen >= 1 && fnLen <= 256;
}

// Scan for INT arrays near given IAT slot groups.
// Groups IAT slots by proximity (gap == entrySize), then scans before each group
// for a matching-size INT array.
// Returns map of IAT group start RVA -> { INT RVA, vector of entries }
static std::map<DWORD, std::pair<DWORD, std::vector<ULONGLONG>>> FindIntArraysByIatGroups(
    BYTE* dump, DWORD size, const std::set<DWORD>& iatSlots, bool is64)
{
    int entrySize = is64 ? 8 : 4;
    std::map<DWORD, std::pair<DWORD, std::vector<ULONGLONG>>> result;

    if (iatSlots.empty()) return result;

    // Sort IAT slots and group by proximity
    std::vector<DWORD> sorted(iatSlots.begin(), iatSlots.end());
    std::sort(sorted.begin(), sorted.end());

    struct IatGroup {
        DWORD start;
        size_t count;
    };
    std::vector<IatGroup> iatGroups;

    DWORD groupStart = sorted[0];
    size_t groupCount = 1;
    for (size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i] == sorted[i-1] + entrySize) {
            groupCount++;
        } else if (sorted[i] < sorted[i-1] + 0x100) {
            // Small gap within same DLL's IAT (some entries might be missing)
            groupCount++;
        } else {
            if (groupCount >= 2) {
                iatGroups.push_back({ groupStart, groupCount });
            }
            groupStart = sorted[i];
            groupCount = 1;
        }
    }
    if (groupCount >= 2) {
        iatGroups.push_back({ groupStart, groupCount });
    }

    DbgLogF("[*] IAT groups: %zu (%zu IAT slots not in groups)", iatGroups.size(), sorted.size());

    // For each IAT group, scan backwards for an INT array of matching size
    for (auto& grp : iatGroups) {
        DWORD searchStart = (grp.start > 0x20000) ? grp.start - 0x20000 : 0x1000;
        for (DWORD rva = grp.start - entrySize; rva >= searchStart && rva > 0x1000; rva -= entrySize) {
            // Read potential INT entries
            bool valid = true;
            std::vector<ULONGLONG> entries;
            for (size_t j = 0; j < grp.count + 4; ++j) {
                DWORD off = (DWORD)j * entrySize;
                if (rva + off + entrySize > size) { valid = false; break; }
                ULONGLONG val = is64
                    ? *(ULONGLONG*)(dump + rva + off)
                    : *(DWORD*)(dump + rva + off);
                if (val == 0) {
                    if (j >= grp.count) break; // null terminator after entries
                    if (j >= grp.count - 2) break; // allow 1-2 extra nulls
                    valid = false; break;
                }
                if (!IsValidIntEntry(dump, size, val, is64)) { valid = false; break; }
                entries.push_back(val);
            }
            // Accept if entry count is reasonable (within ±2 of group size)
            if (valid && entries.size() >= max((size_t)2, grp.count - 2) &&
                entries.size() <= grp.count + 4) {
                result[grp.start] = { rva, entries };
                DbgLogF("[+] INT array at 0x%X (%zu entries) → IAT group at 0x%X (%zu slots)",
                    rva, entries.size(), grp.start, grp.count);
                break;
            }
        }
        if (result.find(grp.start) == result.end()) {
            DbgLogF("[*] no INT array found for IAT group at 0x%X (%zu slots)", grp.start, grp.count);
        }
    }

    return result;
}

// Scan for DLL name strings near an INT array, in data sections.
// Returns the DLL name if found, empty string otherwise.
static std::string FindDllNameNearInt(BYTE* dump, DWORD size, DWORD intRva, DWORD iatStart) {
    // Scan within [intRva - 0x2000, intRva + 0x2000] for null-terminated .dll strings
    DWORD searchStart = (intRva > 0x2000) ? intRva - 0x2000 : 0x1000;
    DWORD searchEnd = min(intRva + 0x2000, size - 5);
    for (DWORD rva = searchStart; rva < searchEnd; ++rva) {
        char* s = (char*)(dump + rva);
        SIZE_T slen = strnlen(s, size - rva);
        if (slen < 5 || slen > 128) continue;
        if (slen >= 4) {
            char* ext = s + slen - 4;
            if (ext[0] == '.' && (ext[1] == 'd' || ext[1] == 'D') &&
                (ext[2] == 'l' || ext[2] == 'L') && (ext[3] == 'l' || ext[3] == 'L')) {
                return std::string(s, slen);
            }
        }
    }
    return "";
}

// Try to resolve a function name against ALL loaded modules
static FARPROC ResolveAcrossAllModules(const char* funcName, DWORD ordinal, bool isOrdinal) {
    HMODULE hMods[512];
    DWORD cbNeeded;
    if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
        return nullptr;
    DWORD numMods = cbNeeded / sizeof(HMODULE);
    HMODULE hSelf = GetModuleHandleW(nullptr);
    for (DWORD m = 0; m < numMods; ++m) {
        if (hMods[m] == hSelf) continue;
        FARPROC proc = isOrdinal
            ? GetProcAddress(hMods[m], (LPCSTR)MAKEINTRESOURCEA(ordinal))
            : GetProcAddress(hMods[m], funcName);
        if (proc) return proc;
    }
    return nullptr;
}

// Resolve IAT slots by matching INT arrays (found near IAT groups) against
// loaded modules. Returns true if any imports were resolved.
static bool ResolveFromIntArrays(BYTE* dump, DWORD sizeOfImage,
    const std::set<DWORD>& iatSlots,
    const std::map<DWORD, std::pair<DWORD, std::vector<ULONGLONG>>>& intArrays,
    bool is64)
{
    if (intArrays.empty()) return false;
    int entrySize = is64 ? 8 : 4;
    int totalResolved = 0;

    for (auto& [iatStart, info] : intArrays) {
        DWORD intRva = info.first;
        auto& entries = info.second;

        // Find DLL name near this INT array
        std::string dllName = FindDllNameNearInt(dump, sizeOfImage, intRva, iatStart);
        HMODULE hMod = nullptr;
        if (!dllName.empty()) {
            hMod = LoadLibraryA(dllName.c_str());
            if (hMod) {
                DbgLogF("[+] INT at 0x%X: loaded DLL '%s' for resolution", intRva, dllName.c_str());
            } else {
                DbgLogF("[!] INT at 0x%X: found DLL name '%s' but LoadLibrary failed", intRva, dllName.c_str());
            }
        }

        // Resolve each entry
        int groupResolved = 0;
        for (size_t j = 0; j < entries.size(); ++j) {
            DWORD iatSlotRva = iatStart + (DWORD)(j * entrySize);
            bool slotExists = (iatSlots.find(iatSlotRva) != iatSlots.end());

            ULONGLONG intVal = entries[j];
            FARPROC proc = nullptr;

            bool isOrd = is64
                ? (intVal & IMAGE_ORDINAL_FLAG64)
                : (intVal & IMAGE_ORDINAL_FLAG32);

            std::string funcNameStr;

            if (isOrd) {
                DWORD ordinal = (DWORD)(intVal & 0xFFFF);
                funcNameStr = "ordinal " + std::to_string(ordinal);
                if (hMod) {
                    proc = GetProcAddress(hMod, (LPCSTR)MAKEINTRESOURCEA(ordinal));
                }
                if (!proc) {
                    proc = ResolveAcrossAllModules(nullptr, ordinal, true);
                }
                if (slotExists) {
                    DbgLogF("[*]   INT[%zu] = ord %u -> %s (slot exists: %d)", j, ordinal,
                        proc ? "FOUND" : "not found", slotExists);
                }
            } else {
                DWORD hnRva = (DWORD)intVal;
                IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dump + hnRva);
                char* fn = (char*)ibn->Name;
                SIZE_T maxLen = sizeOfImage - hnRva - offsetof(IMAGE_IMPORT_BY_NAME, Name);
                fn[maxLen - 1] = 0;
                funcNameStr = fn;

                if (hMod) {
                    proc = GetProcAddress(hMod, fn);
                }
                if (!proc) {
                    proc = ResolveAcrossAllModules(fn, 0, false);
                }
                if (slotExists) {
                    DbgLogF("[*]   INT[%zu] = %s -> %s (slot exists: %d)", j, fn,
                        proc ? "FOUND" : "not found", slotExists);
                }
            }

            if (proc && slotExists) {
                if (is64)
                    *(ULONGLONG*)(dump + iatSlotRva) = (ULONGLONG)proc;
                else
                    *(DWORD*)(dump + iatSlotRva) = (DWORD)(ULONG_PTR)proc;
                totalResolved++;
                groupResolved++;
            }
        }
        if (groupResolved > 0) {
            DbgLogF("[+] resolved %d imports via INT at 0x%X (%s)", groupResolved, intRva, dllName.c_str());
        }
    }

    if (totalResolved > 0) {
        DbgLogF("[+] resolved %d imports via INT array scan", totalResolved);
        return true;
    }
    DbgLog("[*] INT array scan resolved nothing");
    return false;
}

// Core reconstruction logic (no SEH — use SafeReconstructCall wrapper for crash safety)
static bool ReconstructPeCore(DumpContext& ctx, const wchar_t* outputPath) {
    (void)outputPath; // unused in core — file write is done by wrapper
    BYTE* dump = ctx.rawDump;
    if (!dump) return false;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DbgLog("[!] invalid DOS signature");
        return false;
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DbgLog("[!] invalid NT signature");
        return false;
    }

    // Restore original sections saved during dump
    if (ctx.sectionCount > 0 && ctx.sectionCount == nt->FileHeader.NumberOfSections) {
        IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
        memcpy(sections, ctx.sections.data(), ctx.sectionCount * sizeof(IMAGE_SECTION_HEADER));
    }

    WORD sectionCount = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    // Find OEP. DLLs skip the E8-call heuristic: the entry points at the real
    // DllMain after unpack, and the first call inside its prologue is a false
    // positive. Only trampoline patterns (E9 jmp / push-ret) are trusted there.
    DWORD realOep = ScanForOep(dump, ctx.sizeOfImage, ctx.oepRva, !IsDllTarget());
    if (realOep != ctx.oepRva) {
        DbgLogF("[+] found real OEP: 0x%X (entry was 0x%X)", realOep, ctx.oepRva);
        ctx.oepRva = realOep;
    }

    if (ctx.is64Bit)
        ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.AddressOfEntryPoint = ctx.oepRva;
    else
        ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.AddressOfEntryPoint = ctx.oepRva;

    // Save VMP's import table RVA before any modifications
    DWORD vmpImportRva = 0;
    if (ctx.is64Bit)
        vmpImportRva = ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    else
        vmpImportRva = ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    // Find original import directory (VMP replaces PE header's import dir with
    // its own small set; the original descriptors are in decompressed data sections)
    DWORD originalImportRva = FindOriginalImportDirectory(dump, ctx.sizeOfImage, ctx.is64Bit);
    if (originalImportRva) {
        DbgLogF("[*] updating PE header import directory to RVA 0x%X", originalImportRva);
        if (ctx.is64Bit) {
            ((IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = originalImportRva;
        } else {
            ((IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = originalImportRva;
        }
    }

    // Compact SizeOfImage to match original section layout (strip VMP zero padding)
    {
        DWORD realSizeOfImage = nt->OptionalHeader.SizeOfHeaders;
        for (WORD i = 0; i < sectionCount; ++i) {
            DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
            if (end > realSizeOfImage) realSizeOfImage = end;
        }
        if (realSizeOfImage < ctx.sizeOfImage) {
            DbgLogF("[*] compacted SizeOfImage from 0x%X to 0x%X", ctx.sizeOfImage, realSizeOfImage);
            if (ctx.is64Bit)
                ((IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew))->OptionalHeader.SizeOfImage = realSizeOfImage;
            else
                ((IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew))->OptionalHeader.SizeOfImage = realSizeOfImage;
            ctx.sizeOfImage = realSizeOfImage;
        }
    }

    // Back up the (already-edited) MZ/NT headers. The import-fix strategies can
    // dereference corrupt descriptors whose thunk/IAT RVAs point back at low
    // offsets, writing over the header region and later crashing every phase
    // that re-reads it. The backup is restored after the strategies finish.
    std::vector<BYTE> hdrSave;
    DWORD hdrSize = nt->OptionalHeader.SizeOfHeaders;
    if (hdrSize >= 0x40 && hdrSize <= ctx.rawSize)
        hdrSave.assign(dump, dump + hdrSize);

    // Rebuild IAT using multi-strategy approach:
    // 0. Name-based thunk resolution (handles VMP with hint/name RVAs in IAT)
    // 1. Scylla-style: find IAT slots via code scan → find matching import descriptors → resolve via INT
    // 2. INT array scan (find INT arrays in data, match to IAT slots, resolve names)
    // 3. Brute-force (handle remaining thunks)
    // 4. Resolve from existing import descriptors
    // 5. INT→IAT copy (last resort)
    bool iatRebuilt = false;

    // Strategy 0: resolve thunks by reading hint/name RVAs from IAT entries
    {
        DbgLog("[*] trying name-based thunk resolution...");
        if (RebuildImportTableViaNameScan(dump, (DWORD)ctx.rawSize, ctx.sizeOfImage, ctx.is64Bit)) {
            iatRebuilt = true;
        }
    }

    // Strategy 1: Scylla-style IAT slot scan + import descriptor matching
    if (!iatRebuilt) {
        DbgLog("[*] scanning for IAT slots (Scylla-style)...");
        std::set<DWORD> iatSlots = FindIatSlots(dump, (DWORD)ctx.rawSize, ctx.is64Bit);
        DbgLogF("[*] found %zu unique IAT slot RVAs", iatSlots.size());

        if (!iatSlots.empty()) {
            // 1a. Try to find import descriptors by matching FirstThunk to IAT slots
            DWORD descRva = FindImportDescriptorsByIatSlots(dump, ctx.sizeOfImage, iatSlots, ctx.is64Bit);
            if (descRva) {
                DbgLogF("[*] updating PE header import directory to RVA 0x%X (via IAT slot match)", descRva);
                if (ctx.is64Bit)
                    ((IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = descRva;
                else
                    ((IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = descRva;

                DbgLog("[*] resolving imports from matched descriptors...");
                if (ResolveImportsFromDescriptors(dump, ctx.sizeOfImage, ctx.is64Bit)) {
                    iatRebuilt = true;
                }
            }

            // 1b. Try INT array scan: group IAT slots, find INT arrays near groups
            if (!iatRebuilt) {
                DbgLog("[*] scanning for INT arrays near IAT groups...");
                auto intArrays = FindIntArraysByIatGroups(dump, ctx.sizeOfImage, iatSlots, ctx.is64Bit);
                if (!intArrays.empty()) {
                    if (ResolveFromIntArrays(dump, ctx.sizeOfImage, iatSlots, intArrays, ctx.is64Bit)) {
                        iatRebuilt = true;
                    }
                }
            }
        }
    }

    // Strategy 2: scan for resolved import thunks (standard non-VMP PEs)
    if (!iatRebuilt) {
        DbgLog("[*] scanning for import thunks (brute-force)...");
        if (RebuildImportTableViaScan(dump, (DWORD)ctx.rawSize, (DWORD)ctx.imageBase, ctx.is64Bit, vmpImportRva)) {
            iatRebuilt = true;
        }
    }

    // Strategy 3: resolve imports from dump's import descriptors
    if (!iatRebuilt) {
        DbgLog("[*] resolving imports from INT descriptors...");
        if (ResolveImportsFromDescriptors(dump, ctx.sizeOfImage, ctx.is64Bit)) {
            iatRebuilt = true;
        }
    }

    // Strategy 4: INT→IAT copy as last resort
    if (!iatRebuilt) {
        DWORD importRva = 0;
        if (ctx.is64Bit) {
            importRva = ((IMAGE_NT_HEADERS64*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        } else {
            importRva = ((IMAGE_NT_HEADERS32*)(dump + dos->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        }
        if (importRva && importRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) < ctx.sizeOfImage) {
            IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(dump + importRva);
            if (imports->Name != 0) {
                DbgLog("[*] trying INT→IAT copy as last resort");
                for (; imports->Name != 0; ++imports) {
                    DWORD thunkRva = imports->OriginalFirstThunk ? imports->OriginalFirstThunk : imports->FirstThunk;
                    if (thunkRva == 0 || thunkRva >= ctx.sizeOfImage) continue;
                    if (imports->FirstThunk == 0 || imports->FirstThunk >= ctx.sizeOfImage) continue;

                    // Bound the null-terminator scan to the image and cap the
                    // copy length. A stray/one-shot descriptor (or corrupted
                    // thunks) used to walk past the buffer and heap-corrupt the
                    // dump, crashing the worker much later.
                    BYTE* stop = dump + ctx.sizeOfImage;
                    DWORD intBytes = 0;
                    if (ctx.is64Bit) {
                        ULONGLONG* p = (ULONGLONG*)(dump + thunkRva);
                        for (; (BYTE*)p + 8 <= stop; ++p) {
                            if (*p == 0) { intBytes = (DWORD)((BYTE*)p - (dump + thunkRva)) + 8; break; }
                        }
                    } else {
                        DWORD* p = (DWORD*)(dump + thunkRva);
                        for (; (BYTE*)p + 4 <= stop; ++p) {
                            if (*p == 0) { intBytes = (DWORD)((BYTE*)p - (dump + thunkRva)) + 4; break; }
                        }
                    }
                    if (intBytes == 0) continue;
                    if (intBytes > ctx.sizeOfImage - imports->FirstThunk)
                        intBytes = ctx.sizeOfImage - imports->FirstThunk;
                    memcpy(dump + imports->FirstThunk, dump + thunkRva, intBytes);
                }
                iatRebuilt = true;
                DbgLog("[+] IAT rebuilt via INT copy (last resort)");
            }
        }
    }

    // Ensure import data is covered by a section (extend last section if needed)
    // Preserve resources
    if (!hdrSave.empty())
        memcpy(dump, hdrSave.data(), hdrSave.size());
    PreserveResourceDirectory(dump, ctx.sizeOfImage);

    // Rebuild relocation table if needed
    RebuildRelocationTable(dump, ctx.sizeOfImage, (DWORD)ctx.imageBase);

    // Save full import data before FixSectionHeaders (which truncates past the null-terminator descriptor)
    std::vector<BYTE> savedImport;
    DWORD fullImportSize = 0;
    if (iatRebuilt) {
        DWORD importRva = ctx.is64Bit
            ? ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            : ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD importSize = ctx.is64Bit
            ? ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
            : ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (importRva && importSize && importRva < ctx.rawSize) {
            // Save everything from importRva to end of buffer (covers descriptors + thunks + names)
            fullImportSize = (DWORD)(ctx.rawSize - importRva);
            savedImport.assign(dump + importRva, dump + importRva + fullImportSize);
            // Extend section VirtualSize to cover the full import data
            DWORD importEnd = importRva + fullImportSize;
            bool covered = false;
            sections = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                DWORD secEnd = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
                if (importRva >= sections[i].VirtualAddress && importEnd <= secEnd) {
                    covered = true;
                    break;
                }
            }
            if (!covered) {
                sections[sectionCount - 1].Misc.VirtualSize = importEnd - sections[sectionCount - 1].VirtualAddress;
                DbgLogF("[*] extended last section VirtualSize to 0x%X to cover import data",
                    sections[sectionCount - 1].Misc.VirtualSize);
                if (importEnd > ctx.sizeOfImage) {
                    ctx.sizeOfImage = importEnd;
                    if (ctx.is64Bit)
                        ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfImage = importEnd;
                    else
                        ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfImage = importEnd;
                }
            }
            savedImport.assign(dump + importRva, dump + importRva + fullImportSize);
        }
    }

    // Fix section headers (will truncate import data past null-terminator)
    FixSectionHeaders(dump, ctx.sizeOfImage);

    // Restore full import data to the file offset after FixSectionHeaders
    if (iatRebuilt && fullImportSize) {
        DWORD importRva = ctx.is64Bit
            ? ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            : ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRva) {
            sections = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
                DWORD secEnd = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
                if (importRva >= sections[i].VirtualAddress && importRva < secEnd) {
                    DWORD rawEnd = sections[i].PointerToRawData + sections[i].SizeOfRawData;
                    DWORD rawFileOffset = sections[i].PointerToRawData + (importRva - sections[i].VirtualAddress);
                    DWORD neededEnd = rawFileOffset + fullImportSize;
                    if (neededEnd > rawEnd) {
                        DWORD neededRaw = (neededEnd - sections[i].PointerToRawData + 0x1FF) & ~0x1FF;
                        DbgLogF("[*] extending section %d SizeOfRawData 0x%X -> 0x%X to cover import data",
                            i, sections[i].SizeOfRawData, neededRaw);
                        sections[i].SizeOfRawData = neededRaw;
                    }
                    memcpy(dump + rawFileOffset, savedImport.data(), fullImportSize);
                    break;
                }
            }
        }
    }

    // VMP detection & devirtualization
    {
        vmp::VMPDetectResult detect;
        if (vmp::DetectVMP(dump, ctx.sizeOfImage, detect)) {
            ctx.vmpDetected = true;
            ctx.vmpEntryCount = detect.vmEntryCount;
            DbgLogF("[VMP] detected VMP v%d with %d entry points, %zu handlers",
                detect.isV2 ? 2 : 1, detect.vmEntryCount, detect.handlers.size());

            ctx.devirtResults = vmp::DevirtualizeAll(dump, ctx.sizeOfImage, detect, ctx.is64Bit);
            ctx.devirtCount = (int)ctx.devirtResults.size();

            int totalDevirt = 0;
            for (auto& r : ctx.devirtResults) totalDevirt += r.instrCount;
            DbgLogF("[VMP] devirtualized %d/%d entries (%d total instructions)",
                ctx.devirtCount, ctx.vmpEntryCount, totalDevirt);
        } else {
            DbgLog("[VMP] VMP not detected or detection failed");
        }
    }

    return true;
}

// Writes the final PE dump to disk. Can be called on any outcome.
// Uses raw wchar_t* to avoid C++ wstring (SEH-safe).
static bool WritePeFile(BYTE* dump, const wchar_t* outputPath) {
    if (!dump || !outputPath) return false;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        DbgLogF("[!] failed to create output, error: %u", GetLastError());
        return false;
    }

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    DWORD fileSize = nt->OptionalHeader.SizeOfHeaders;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD end = sections[i].PointerToRawData + sections[i].SizeOfRawData;
        if (end > fileSize) fileSize = end;
    }

    fileSize = (fileSize + 0x1FF) & ~0x1FF;

    DWORD written = 0;
    bool ok = WriteFile(hFile, dump, fileSize, &written, nullptr) && written == fileSize;
    CloseHandle(hFile);

    if (ok)
        DbgLogF("[+] PE written: %S (%u bytes)", outputPath, written);
    else
        DbgLog("[!] failed to write output");

    return ok;
}

bool ReconstructPe(DumpContext& ctx, const std::wstring& outputPath) {
    BYTE* dump = ctx.rawDump;
    if (!dump) return false;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        DbgLog("[!] invalid DOS signature");
        return false;
    }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        DbgLog("[!] invalid NT signature");
        return false;
    }

    // Run core reconstruction, then write the PE file
    if (!ReconstructPeCore(ctx, outputPath.c_str()))
        return false;
    return WritePeFile(ctx.rawDump, outputPath.c_str());
}

void FreeDump(DumpContext& ctx) {
    if (ctx.rawDump) {
        VirtualFree(ctx.rawDump, 0, MEM_RELEASE);
        ctx.rawDump = nullptr;
    }
    ctx.rawSize = 0;
    ctx.sections.clear();
    ctx.sectionCount = 0;
}
