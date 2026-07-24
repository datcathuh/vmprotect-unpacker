#pragma once
#include <Windows.h>
#include <intrin.h>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include "vmp_detect.h"
#include "../utils.h"

/*
 * VMP Bytecode Extraction, Decryption & Parsing
 */

namespace vmp {

static std::string to_hex(DWORD val);

// CRC-based bytecode decryption
struct BytecodeDecryptor {
    DWORD crc;
    DWORD keyHi;
    DWORD keyLo;
    int shift;
    bool isSimple;

    void Init(DWORD entryRva) {
        crc = entryRva;
        keyHi = 0;
        keyLo = 0;
        shift = 7;
        isSimple = true;
    }

    BYTE DecryptOpcodeV1(BYTE encrypted) {
        BYTE decrypted = (BYTE)(encrypted ^ (crc & 0xFF));
        crc = (crc ^ encrypted) & 0xFFFFFFFF;
        return decrypted;
    }

    DWORD DecryptOpcodeV2(DWORD encrypted) {
        DWORD decrypted = encrypted ^ crc;
        crc = (crc ^ encrypted) & 0xFFFFFFFF;
        return decrypted;
    }

    DWORD DecryptValue(DWORD encrypted, const std::vector<DWORD>& keys) {
        DWORD val = encrypted;
        for (size_t i = 0; i < keys.size(); ++i) {
            DWORD op = keys[i] & 0xFF;
            DWORD key = keys[i] >> 8;
            switch (op) {
            case 0: val += key; break;
            case 1: val -= key; break;
            case 2: val ^= key; break;
            case 3: val = _rotl(val, key & 0x1F); break;
            case 4: val = _rotr(val, key & 0x1F); break;
            case 5: {
                BYTE* b = (BYTE*)&val;
                std::swap(b[0], b[3]);
                std::swap(b[1], b[2]);
                break;
            }
            case 6: val = ~val; break;
            case 7: val++; break;
            case 8: val--; break;
            }
        }
        return val;
    }

    bool DecryptXaddValue(const DWORD crypted[4], DWORD& outValue) {
        DWORD tmp[4];
        for (int i = 0; i < 4; ++i) {
            tmp[i] = _rotr(crypted[i] - keyHi, shift) ^ keyLo;
        }
        outValue = tmp[0];
        return true;
    }
};

// Parsed VM instruction
struct VMInstruction {
    VMInstType type;
    DWORD rva;
    int regIndex;
    int regIndex2;
    ULONGLONG immediate;
    DWORD memAddr;
    int memReg;
    int memIndex;
    int memScale;
    int memDisplacement;
    VMOpSize size;
    bool isMemOp;
    bool isExtern;
    int jccType;
    std::vector<ULONGLONG> chainedValues;

    VMInstruction() : type(vmInvalid), rva(0), regIndex(-1), regIndex2(-1),
        immediate(0), memAddr(0), memReg(-1), memIndex(-1), memScale(0),
        memDisplacement(0), size(vmSizeDefault), isMemOp(false), isExtern(false),
        jccType(0) {}
};

// Trace of VM instructions
struct VMTrace {
    DWORD entryRva;
    DWORD bytecodeRva;
    std::vector<VMInstruction> instrs;
    bool success;
    std::string error;
    std::vector<ULONGLONG> stack;
    std::vector<ULONGLONG> regs;
    ULONGLONG flags;

    VMTrace() : entryRva(0), bytecodeRva(0), success(false), flags(0) {
        regs.resize(16, 0);
    }
};

static std::string to_hex(DWORD val) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%08X", val);
    return std::string(buf);
}

/* Identify handler type from native code */
static VMInstType IdentifyHandlerType(const BYTE* code, DWORD size) {
    if (!code || size < 4) return vmInvalid;

    int movCount = 0, addCount = 0, subCount = 0, xorCount = 0;
    int jmpCount = 0, callCount = 0, andCount = 0, orCount = 0;
    int mulCount = 0, divCount = 0, shlCount = 0, shrCount = 0, sarCount = 0;
    int notCount = 0, negCount = 0, cmpCount = 0, testCount = 0;
    int incCount = 0, decCount = 0, retCount = 0;
    int movzxCount = 0, movsxCount = 0, bswapCount = 0;
    int xaddCount = 0, cmpxchgCount = 0, setccCount = 0;

    for (DWORD i = 0; i < min(size, (DWORD)200) - 2; ++i) {
        BYTE b0 = code[i];
        BYTE b1 = code[i + 1];

        if (b0 == 0x89 || b0 == 0x8B) movCount++;
        if ((b0 == 0x48 || b0 == 0x4C || b0 == 0x44) && (b1 == 0x89 || b1 == 0x8B)) movCount++;
        if (b0 == 0x03 || b0 == 0x01) addCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xC0) addCount++;
        if (b0 == 0x2B || b0 == 0x29) subCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xE8) subCount++;
        if (b0 == 0x33 || b0 == 0x31) xorCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xF0) xorCount++;
        if (b0 == 0x81 && (b1 & 0xF8) == 0xF0) xorCount++;
        if (b0 == 0x23 || b0 == 0x21) andCount++;
        if (b0 == 0x0B || b0 == 0x09) orCount++;
        if (b0 == 0x0F && b1 == 0xAF) mulCount++;
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xE0) mulCount++;
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xF8) divCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xE0) shlCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xE8) shrCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xF8) sarCount++;
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xD0) notCount++;
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xD8) negCount++;
        if (b0 == 0x3B || b0 == 0x39) cmpCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xF8) cmpCount++;
        if (b0 == 0x85 || b0 == 0x84 || b0 == 0xA8 || b0 == 0xA9) testCount++;
        if (b0 == 0xFF && (b1 & 0xF8) == 0xC0) incCount++;
        if (b0 == 0xFF && (b1 & 0xF8) == 0xC8) decCount++;
        if (b0 == 0xC3 || b0 == 0xC2) retCount++;
        if (b0 == 0xE9 || b0 == 0xEB) jmpCount++;
        if (b0 == 0xFF && (b1 == 0x25 || (b1 & 0xF8) == 0x20 || (b1 & 0xF8) == 0xE0)) jmpCount++;
        if (b0 == 0xE8 || (b0 == 0xFF && (b1 & 0xF8) == 0xD0)) callCount++;
        if (b0 == 0x0F && (b1 >= 0x80 && b1 <= 0x8F)) jmpCount++;
        if (b0 >= 0x70 && b0 <= 0x7F) jmpCount++;
        if (b0 == 0x0F && (b1 == 0xB6 || b1 == 0xB7)) movzxCount++;
        if (b0 == 0x0F && (b1 == 0xBE || b1 == 0xBF)) movsxCount++;
        if (b0 == 0x63) movsxCount++;
        if (b0 == 0x0F && b1 >= 0xC8 && b1 <= 0xCF) bswapCount++;
        if (b0 == 0x0F && (b1 == 0xC0 || b1 == 0xC1)) xaddCount++;
        if (b0 == 0x0F && (b1 == 0xB0 || b1 == 0xB1)) cmpxchgCount++;
        if (b0 == 0x0F && b1 >= 0x90 && b1 <= 0x9F) setccCount++;
    }

    if (size >= 1 && code[0] == 0x98) return vmCwde;
    if (size >= 1 && code[0] == 0x99) return vmCdq;
    if (size >= 2 && code[0] == 0x48 && code[1] == 0x99) return vmCqo;
    if (size >= 1 && code[0] == 0xC9) return vmLeave;
    if (size >= 1 && code[0] == 0x9C) return vmPushf;
    if (size >= 1 && code[0] == 0x9D) return vmPopf;
    if (size >= 1 && code[0] == 0xC3 && callCount == 0 && jmpCount == 0) return vmRet;
    if (size >= 1 && code[0] == 0xC2) return vmRet;

    if (addCount > subCount && addCount > xorCount) return vmAdd;
    if (subCount > addCount && subCount > xorCount) return vmSub;
    if (xorCount > addCount && xorCount > subCount) return vmXor;
    if (andCount) return vmAnd;
    if (orCount) return vmOr;
    if (mulCount) return vmMul;
    if (divCount) return vmDiv;
    if (shlCount > shrCount && shlCount > sarCount) return vmShl;
    if (shrCount > shlCount && shrCount > sarCount) return vmShr;
    if (sarCount) return vmSar;
    if (notCount) return vmNot;
    if (negCount) return vmNeg;
    if (cmpCount) return vmCmp;
    if (testCount) return vmTest;
    if (incCount && decCount == 0) return vmInc;
    if (decCount && incCount == 0) return vmDec;
    if (callCount && jmpCount == 0) return vmCall;
    if (jmpCount && callCount == 0) return vmJmp;
    if (bswapCount) return vmBswap;
    if (xaddCount) return vmXadd;
    if (cmpxchgCount) return vmCmpxchg;
    if (setccCount) return vmSetcc;
    if (movzxCount > movCount / 2) return vmMovzx;
    if (movsxCount > movCount / 2) return vmMovsx;

    return vmMov;
}

/* Identify operand size from handler code patterns */
static VMOpSize IdentifyHandlerSize(const BYTE* code, DWORD size) {
    for (DWORD i = 0; i < min(size, (DWORD)100) - 2; ++i) {
        if (code[i] == 0x88 || code[i] == 0x8A || code[i] == 0x30 ||
            code[i] == 0x32 || code[i] == 0x00 || code[i] == 0x02 ||
            code[i] == 0x38 || code[i] == 0x3A) return vmSizeByte;
        if (code[i] == 0x66) {
            if (i + 1 < min(size, (DWORD)100)) {
                if (code[i + 1] == 0x89 || code[i + 1] == 0x8B ||
                    code[i + 1] == 0x31 || code[i + 1] == 0x33) return vmSizeWord;
            }
        }
        if (code[i] == 0x48 && i + 1 < min(size, (DWORD)100)) {
            if (code[i + 1] == 0x89 || code[i + 1] == 0x8B ||
                code[i + 1] == 0x03 || code[i + 1] == 0x2B ||
                code[i + 1] == 0x33 || code[i + 1] == 0x01) return vmSizeQword;
        }
    }
    return vmSizeDword;
}

/*
 * Decode V1 bytecode
 * V1 uses single-byte opcodes with CRC-based streaming decryption
 */
static bool DecodeBytecodeV1(const BYTE* bytecode, DWORD bytecodeSize,
    const std::vector<VMHandler>& handlers, VMTrace& trace) {
    BytecodeDecryptor decryptor;
    decryptor.Init(trace.bytecodeRva);

    DWORD offset = 0;
    DWORD entryRva = trace.bytecodeRva;

    while (offset < bytecodeSize) {
        BYTE opcodeByte = bytecode[offset];
        DWORD instrRva = entryRva + offset;

        BYTE decrypted = decryptor.DecryptOpcodeV1(opcodeByte);

        int foundIdx = -1;
        for (size_t hi = 0; hi < handlers.size(); ++hi) {
            if (handlers[hi].opcodeValue == decrypted) { foundIdx = (int)hi; break; }
        }
        if (foundIdx < 0) {
            for (size_t hi = 0; hi < handlers.size(); ++hi) {
                if (handlers[hi].opcodeValue == opcodeByte) { foundIdx = (int)hi; break; }
            }
        }
        if (foundIdx < 0) {
            trace.error = "Unknown opcode at offset " + std::to_string(offset);
            break;
        }

        offset++;

        VMInstruction instr;
        instr.rva = instrRva;
        instr.type = IdentifyHandlerType(handlers[foundIdx].code.data(), handlers[foundIdx].size);
        instr.size = IdentifyHandlerSize(handlers[foundIdx].code.data(), handlers[foundIdx].size);

        switch (instr.type) {
        case vmPush:
        case vmMov:
            if (offset < bytecodeSize) {
                int regByte = bytecode[offset];
                instr.regIndex = regByte & 0x0F;
                offset++;
                if ((regByte & 0x80) && offset + 4 <= bytecodeSize) {
                    instr.immediate = *(uint32_t*)(bytecode + offset);
                    offset += 4;
                }
            }
            break;
        case vmAdd: case vmSub: case vmXor: case vmAnd: case vmOr:
            if (offset + 2 <= bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                instr.regIndex2 = bytecode[offset + 1] & 0x0F;
                offset += 2;
                if ((bytecode[offset - 2] & 0x80) && offset + 4 <= bytecodeSize) {
                    instr.immediate = *(uint32_t*)(bytecode + offset);
                    offset += 4;
                }
            }
            break;
        case vmJmp: case vmCall:
            if (offset + 4 <= bytecodeSize) {
                DWORD targetOff = *(uint32_t*)(bytecode + offset);
                offset += 4;
                if (targetOff > 0x80000000) {
                    instr.isExtern = true;
                    instr.immediate = targetOff & 0x7FFFFFFF;
                } else {
                    instr.immediate = targetOff;
                }
            }
            break;
        case vmRet:
            break;
        default:
            if (instr.type == vmPushf || instr.type == vmPopf ||
                instr.type == vmLeave || instr.type == vmNop) {}
            break;
        }

        trace.instrs.push_back(instr);
        if (instr.type == vmRet || instr.type == vmJmp) break;
        if (trace.instrs.size() > 20000) {
            trace.error = "Too many instructions";
            break;
        }
    }

    trace.success = trace.instrs.size() > 0;
    return trace.success;
}

/*
 * Decode V2 bytecode
 * V2 uses 4-byte opcodes (encrypted offsets into handler table)
 */
static bool DecodeBytecodeV2(const BYTE* bytecode, DWORD bytecodeSize,
    const std::vector<VMHandler>& handlers, DWORD handlerTableRva, VMTrace& trace) {
    BytecodeDecryptor decryptor;
    decryptor.Init(trace.bytecodeRva);

    DWORD offset = 0;
    DWORD entryRva = trace.bytecodeRva;

    while (offset + 4 <= bytecodeSize) {
        DWORD encOffset = *(uint32_t*)(bytecode + offset);
        DWORD instrRva = entryRva + offset;

        DWORD decrypted = decryptor.DecryptOpcodeV2(encOffset);
        DWORD handlerRva = handlerTableRva + decrypted;

        int foundIdx = -1;
        for (size_t hi = 0; hi < handlers.size(); ++hi) {
            if (handlers[hi].rva == handlerRva || abs((int)(handlers[hi].rva - (int)handlerRva)) < 16) {
                foundIdx = (int)hi; break;
            }
        }
        if (foundIdx < 0) {
            DWORD rawHandlerRva = handlerTableRva + encOffset;
            for (size_t hi = 0; hi < handlers.size(); ++hi) {
                if (handlers[hi].rva == rawHandlerRva || abs((int)(handlers[hi].rva - (int)rawHandlerRva)) < 16) {
                    foundIdx = (int)hi; break;
                }
            }
        }
        if (foundIdx < 0) {
            trace.error = "Unknown handler at offset " + std::to_string(offset) +
                " (decrypted: 0x" + to_hex(decrypted) + ")";
            break;
        }

        offset += 4;

        VMInstruction instr;
        instr.rva = instrRva;
        instr.type = IdentifyHandlerType(handlers[foundIdx].code.data(), handlers[foundIdx].size);
        instr.size = IdentifyHandlerSize(handlers[foundIdx].code.data(), handlers[foundIdx].size);

        switch (instr.type) {
        case vmPush: case vmMov:
            if (offset < bytecodeSize) {
                int regByte = bytecode[offset];
                instr.regIndex = regByte & 0x0F;
                offset++;
                if (regByte & 0x80) {
                    switch (instr.size) {
                    case vmSizeByte: if (offset < bytecodeSize) { instr.immediate = bytecode[offset]; offset++; } break;
                    case vmSizeWord: if (offset + 2 <= bytecodeSize) { instr.immediate = *(WORD*)(bytecode + offset); offset += 2; } break;
                    case vmSizeDword: if (offset + 4 <= bytecodeSize) { instr.immediate = *(uint32_t*)(bytecode + offset); offset += 4; } break;
                    case vmSizeQword: if (offset + 8 <= bytecodeSize) { instr.immediate = *(uint64_t*)(bytecode + offset); offset += 8; } break;
                    }
                }
            }
            break;
        case vmAdd: case vmSub: case vmXor: case vmAnd: case vmOr:
        case vmShl: case vmShr: case vmSar: case vmCmp: case vmTest:
            if (offset + 2 <= bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                instr.regIndex2 = bytecode[offset + 1] & 0x0F;
                offset += 2;
                if ((bytecode[offset - 2] & 0x80) || (bytecode[offset - 1] & 0x80)) {
                    if (offset + 4 <= bytecodeSize) {
                        instr.immediate = *(uint32_t*)(bytecode + offset);
                        offset += 4;
                    }
                }
            }
            break;
        case vmJmp: case vmCall:
            if (offset + 4 <= bytecodeSize) {
                DWORD targetOff = *(uint32_t*)(bytecode + offset);
                offset += 4;
                if (targetOff > 0x80000000) {
                    instr.isExtern = true;
                    instr.immediate = targetOff & 0x7FFFFFFF;
                } else {
                    instr.immediate = targetOff;
                }
            }
            break;
        case vmRet:
            break;
        case vmJcc:
            if (offset < bytecodeSize) {
                instr.jccType = bytecode[offset] & 0x0F;
                offset++;
                if (offset + 4 <= bytecodeSize) {
                    instr.immediate = *(uint32_t*)(bytecode + offset);
                    offset += 4;
                }
            }
            break;
        }

        trace.instrs.push_back(instr);
        if (instr.type == vmRet || instr.type == vmJmp) break;
        if (trace.instrs.size() > 50000) {
            trace.error = "Too many instructions";
            break;
        }
    }

    trace.success = trace.instrs.size() > 0;
    return trace.success;
}

// Main entry point: dispatches to V1 or V2 decoder
static bool DecodeBytecode(const BYTE* dump, DWORD sizeOfImage,
    const VMEntryPoint& entry,
    const std::vector<VMHandler>& handlers,
    DWORD handlerTableRva, bool isV2,
    VMTrace& trace) {
    trace.entryRva = entry.rva;
    trace.bytecodeRva = entry.bytecodeRva;

    if (entry.bytecodeRva == 0 || entry.bytecodeRva >= sizeOfImage) {
        trace.error = "Invalid bytecode RVA";
        return false;
    }

    DWORD maxSize = min(sizeOfImage - entry.bytecodeRva, (DWORD)0x20000);
    const BYTE* bytecode = dump + entry.bytecodeRva;

    if (isV2) {
        return DecodeBytecodeV2(bytecode, maxSize, handlers, handlerTableRva, trace);
    } else {
        return DecodeBytecodeV1(bytecode, maxSize, handlers, trace);
    }
}

} // namespace vmp
