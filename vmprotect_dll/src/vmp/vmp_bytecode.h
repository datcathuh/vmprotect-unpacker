#pragma once
#include <Windows.h>
#include <intrin.h>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include "vmp_detect.h"
#include "../utils.h"

namespace vmp {

static std::string to_hex(DWORD val);

// Multi-algorithm bytecode decryptor
struct BytecodeDecryptor {
    DWORD crc;
    DWORD keyHi;
    DWORD keyLo;
    int shift;

    void Init(DWORD entryRva) {
        crc = entryRva + 0x12345678;
        keyHi = 0;
        keyLo = 0;
        shift = 7;
    }

    // Simple CRC-stream V1 (8-bit opcode)
    BYTE DecryptOpcode8(BYTE encrypted) {
        BYTE decrypted = (BYTE)(encrypted ^ (crc & 0xFF));
        crc = (crc ^ encrypted) & 0xFFFFFFFF;
        return decrypted;
    }

    // Simple CRC-stream V2 (32-bit opcode)
    DWORD DecryptOpcode32(DWORD encrypted) {
        DWORD decrypted = encrypted ^ crc;
        crc = (crc ^ encrypted) & 0xFFFFFFFF;
        return decrypted;
    }

    // Reverse OpcodeCryptor sequence (ADD/SUB/XOR/ROL/ROR)
    // The cryptor applies a series of operations; we apply inverse.
    // Since we may not know the exact cryptor, we try multiple strategies.
    DWORD DecryptWithCryptor(DWORD encrypted, const std::vector<DWORD>& keys) {
        DWORD val = encrypted;
        // Apply operations IN REVERSE
        for (int i = (int)keys.size() - 1; i >= 0; --i) {
            DWORD op = keys[i] & 0xFF;
            DWORD key = keys[i] >> 8;
            switch (op) {
            case 0: val -= key; break;     // Inverse of ADD
            case 1: val += key; break;     // Inverse of SUB
            case 2: val ^= key; break;     // XOR is self-inverse
            case 3: val = _rotr(val, key & 0x1F); break;  // Inverse of ROL
            case 4: val = _rotl(val, key & 0x1F); break;  // Inverse of ROR
            case 5: {                       // Byte swap (self-inverse)
                BYTE* b = (BYTE*)&val;
                std::swap(b[0], b[3]);
                std::swap(b[1], b[2]);
                break;
            }
            case 6: val = ~val; break;     // NOT is self-inverse
            case 7: val--; break;          // Inverse of INC
            case 8: val++; break;          // Inverse of DEC
            }
        }
        return val;
    }

    // XADD block decryption (EncryptBuffer inverse from VMP source)
    bool DecryptXaddBlock(const DWORD crypted[4], DWORD decrypted[4]) {
        for (int i = 0; i < 4; ++i)
            decrypted[i] = _rotr(crypted[i] - keyHi, (i == 0) ? 7 : (i == 1) ? 11 : (i == 2) ? 17 : 23) ^ keyLo;
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
        regs.resize(17, 0);
    }
};

static std::string to_hex(DWORD val) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%08X", val);
    return std::string(buf);
}

// Identify handler type from native code (improved)
static VMInstType IdentifyHandlerType(const BYTE* code, DWORD size) {
    if (!code || size < 4) return vmInvalid;

    int movCount = 0, addCount = 0, subCount = 0, xorCount = 0;
    int jmpCount = 0, callCount = 0, andCount = 0, orCount = 0;
    int mulCount = 0, divCount = 0, shlCount = 0, shrCount = 0, sarCount = 0;
    int notCount = 0, negCount = 0, cmpCount = 0, testCount = 0;
    int incCount = 0, decCount = 0, retCount = 0;
    int movzxCount = 0, movsxCount = 0, bswapCount = 0;
    int xaddCount = 0, cmpxchgCount = 0, setccCount = 0;
    int pushCount = 0, popCount = 0, leaCount = 0;
    int rolCount = 0, rorCount = 0;

    for (DWORD i = 0; i < min(size, (DWORD)200) - 2; ++i) {
        BYTE b0 = code[i];
        BYTE b1 = code[i + 1];
        BYTE b2 = (i + 2 < size) ? code[i + 2] : 0;

        if (b0 == 0x89 || b0 == 0x8B) movCount++;
        if ((b0 == 0x48 || b0 == 0x4C || b0 == 0x44) && (b1 == 0x89 || b1 == 0x8B)) movCount++;
        if (b0 == 0x03 || b0 == 0x01) addCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xC0) addCount++;
        if (b0 == 0x05) addCount++;
        if (b0 == 0x2B || b0 == 0x29) subCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xE8) subCount++;
        if (b0 == 0x2D) subCount++;
        if (b0 == 0x33 || b0 == 0x31) xorCount++;
        if (b0 == 0x83 && (b1 & 0xF8) == 0xF0) xorCount++;
        if (b0 == 0x81 && (b1 & 0xF8) == 0xF0) xorCount++;
        if (b0 == 0x35) xorCount++;
        if (b0 == 0x23 || b0 == 0x21) andCount++;
        if (b0 == 0x0B || b0 == 0x09) orCount++;
        if (b0 == 0x0F && b1 == 0xAF) mulCount++;
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xE0) mulCount++;
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xF8) divCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xE0) shlCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xE8) shrCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xF8) sarCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xC0) rolCount++;
        if ((b0 == 0xD3 || b0 == 0xD1 || b0 == 0xC1) && (b1 & 0xF8) == 0xC8) rorCount++;
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
        if ((b0 & 0xF8) == 0x50 && (b0 != 0x50 || b1 != 0xE8)) pushCount++; // push reg, not push+call
        if ((b0 & 0xF8) == 0x58) popCount++;
        if (b0 == 0x8D) leaCount++;
    }

    if (size >= 1 && code[0] == 0x98) return vmCwde;
    if (size >= 1 && code[0] == 0x99) return vmCdq;
    if (size >= 2 && code[0] == 0x48 && code[1] == 0x99) return vmCqo;
    if (size >= 1 && code[0] == 0xC9) return vmLeave;
    if (size >= 1 && code[0] == 0x9C) return vmPushf;
    if (size >= 1 && code[0] == 0x9D) return vmPopf;
    if (size >= 1 && code[0] == 0xC3 && callCount == 0 && jmpCount == 0) return vmRet;
    if (size >= 1 && code[0] == 0xC2) return vmRet;
    if (size >= 1 && code[0] == 0x0F && code[1] == 0x31) return vmRdtsc;
    if (size >= 2 && code[0] == 0x0F && code[1] == 0xA2) return vmCpuid;

    if (addCount > subCount && addCount > xorCount) return vmAdd;
    if (subCount > addCount && subCount > xorCount) return vmSub;
    if (xorCount > addCount && xorCount > subCount) return vmXor;
    if (rolCount > rorCount && rolCount > addCount) return vmRol;
    if (rorCount > rolCount && rorCount > addCount) return vmRor;
    if (andCount && andCount > orCount) return vmAnd;
    if (orCount && orCount > andCount) return vmOr;
    if (mulCount) return vmMul;
    if (divCount) return vmDiv;
    if (shlCount > shrCount && shlCount > sarCount) return vmShl;
    if (shrCount > shlCount && shrCount > sarCount) return vmShr;
    if (sarCount) return vmSar;
    if (notCount) return vmNot;
    if (negCount) return vmNeg;
    if (cmpCount && cmpCount > testCount) return vmCmp;
    if (testCount) return vmTest;
    if (incCount && decCount == 0) return vmInc;
    if (decCount && incCount == 0) return vmDec;
    if (leaCount > movCount / 2) return vmLea;
    if (pushCount > popCount * 2) return vmPush;
    if (popCount > pushCount * 2) return vmPop;
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

static VMOpSize IdentifyHandlerSize(const BYTE* code, DWORD size) {
    for (DWORD i = 0; i < min(size, (DWORD)120) - 2; ++i) {
        if (code[i] == 0x88 || code[i] == 0x8A || code[i] == 0x30 ||
            code[i] == 0x32 || code[i] == 0x00 || code[i] == 0x02 ||
            code[i] == 0x38 || code[i] == 0x3A) return vmSizeByte;
        if (code[i] == 0x66) {
            if (i + 1 < min(size, (DWORD)120) &&
                (code[i + 1] == 0x89 || code[i + 1] == 0x8B ||
                 code[i + 1] == 0x31 || code[i + 1] == 0x33))
                return vmSizeWord;
        }
        if (code[i] == 0x48 && i + 1 < min(size, (DWORD)120)) {
            if (code[i + 1] == 0x89 || code[i + 1] == 0x8B ||
                code[i + 1] == 0x03 || code[i + 1] == 0x2B ||
                code[i + 1] == 0x33 || code[i + 1] == 0x01 ||
                code[i + 1] == 0x05) return vmSizeQword;
        }
    }
    return vmSizeDword;
}

// Infer cryptor key sequence from handler code patterns
// Scans handlers for ADD/SUB/XOR/ROL/ROR with immediates to build the cryptor key sequence
static bool BuildCryptorKeys(const std::vector<VMHandler>& handlers, std::vector<DWORD>& outKeys) {
    outKeys.clear();
    // Find the handler that reads bytecode and has the cryptor (typically handler 0 or 1)
    for (size_t hi = 0; hi < min(handlers.size(), (size_t)4); ++hi) {
        auto& h = handlers[hi];
        for (DWORD bi = 0; bi < min(h.size, (DWORD)200) - 6; ++bi) {
            BYTE b0 = h.code[bi];
            BYTE b1 = h.code[bi + 1];
            if (b0 == 0x83 && (b1 & 0xF8) == 0xC0) {  // add reg, imm8
                outKeys.push_back(0 | (h.code[bi + 2] << 8));
            } else if (b0 == 0x83 && (b1 & 0xF8) == 0xE8) {  // sub reg, imm8
                outKeys.push_back(1 | (h.code[bi + 2] << 8));
            } else if (b0 == 0x83 && (b1 & 0xF8) == 0xF0) {  // xor reg, imm8
                outKeys.push_back(2 | (h.code[bi + 2] << 8));
            } else if (b0 == 0xD1 && (b1 & 0xF8) == 0xC0) {  // rol reg, 1 (or ror)
                outKeys.push_back(3 | (1 << 8));
            } else if (b0 == 0xD1 && (b1 & 0xF8) == 0xC8) {  // ror reg, 1
                outKeys.push_back(4 | (1 << 8));
            } else if (b0 == 0xC1 && (b1 & 0xF8) == 0xC0) {  // rol reg, imm8
                outKeys.push_back(3 | (h.code[bi + 2] << 8));
            } else if (b0 == 0xC1 && (b1 & 0xF8) == 0xC8) {  // ror reg, imm8
                outKeys.push_back(4 | (h.code[bi + 2] << 8));
            } else if (b0 == 0x05) {  // add eax, imm32
                DWORD imm = *(uint32_t*)(h.code.data() + bi + 1);
                outKeys.push_back(0 | (imm << 8));
                bi += 4;
            } else if (b0 == 0x2D) {  // sub eax, imm32
                DWORD imm = *(uint32_t*)(h.code.data() + bi + 1);
                outKeys.push_back(1 | (imm << 8));
                bi += 4;
            } else if (b0 == 0x35) {  // xor eax, imm32
                DWORD imm = *(uint32_t*)(h.code.data() + bi + 1);
                outKeys.push_back(2 | (imm << 8));
                bi += 4;
            }
        }
    }
    return !outKeys.empty();
}

/*
 * Decode V1 bytecode (single-byte opcodes, CRC-stream decryption)
 */
static bool DecodeBytecodeV1(const BYTE* bytecode, DWORD bytecodeSize,
    const std::vector<VMHandler>& handlers, VMTrace& trace) {
    BytecodeDecryptor decryptor;
    decryptor.Init(trace.bytecodeRva);
    DWORD offset = 0;
    DWORD entryRva = trace.bytecodeRva;

    // Try to build cryptor keys
    std::vector<DWORD> cryptKeys;
    BuildCryptorKeys(handlers, cryptKeys);

    while (offset < bytecodeSize) {
        BYTE opcodeByte = bytecode[offset];
        DWORD instrRva = entryRva + offset;

        BYTE decrypted;
        if (!cryptKeys.empty())
            decrypted = (BYTE)decryptor.DecryptWithCryptor(opcodeByte, cryptKeys);
        else
            decrypted = decryptor.DecryptOpcode8(opcodeByte);

        // Try to match decrypted value first, then raw
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
            // Try skipping this byte (error recovery)
            trace.error = "Unknown opcode at offset " + std::to_string(offset);
            offset++;
            if (offset >= bytecodeSize) break;
            continue;  // Skip unknown opcode and try next
        }

        offset++;
        VMInstruction instr;
        instr.rva = instrRva;
        instr.type = IdentifyHandlerType(handlers[foundIdx].code.data(), handlers[foundIdx].size);
        instr.size = IdentifyHandlerSize(handlers[foundIdx].code.data(), handlers[foundIdx].size);

        switch (instr.type) {
        case vmPush:
        case vmMov:
        case vmPushMem:
        case vmPopMem:
        case vmLea:
            if (offset < bytecodeSize) {
                int regByte = bytecode[offset];
                int regLo = regByte & 0x0F;
                int regHi = (regByte >> 4) & 0x0F;
                instr.regIndex = regLo;
                instr.regIndex2 = regHi;
                if (instr.regIndex2 == 0) instr.regIndex2 = -1;
                offset++;
                if (regByte & 0x80) {
                    if (offset + 4 <= bytecodeSize) {
                        instr.immediate = *(uint32_t*)(bytecode + offset);
                        offset += 4;
                    }
                }
            }
            break;
        case vmAdd: case vmSub: case vmXor: case vmAnd: case vmOr:
        case vmShl: case vmShr: case vmSar: case vmCmp: case vmTest:
        case vmRol: case vmRor:
            if (offset + 2 <= bytecodeSize) {
                int regByte = bytecode[offset];
                int regByte2 = bytecode[offset + 1];
                instr.regIndex = regByte & 0x0F;
                instr.regIndex2 = regByte2 & 0x0F;
                offset += 2;
                if ((regByte & 0x80) || (regByte2 & 0x80)) {
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
        case vmSetcc:
            if (offset < bytecodeSize) {
                instr.jccType = bytecode[offset] & 0x0F;
                offset++;
            }
            break;
        case vmRet: case vmPushf: case vmPopf: case vmLeave: case vmNop:
        case vmCwde: case vmCdq: case vmCqo:
            break;
        case vmBswap: case vmNot: case vmNeg: case vmInc: case vmDec:
        case vmMul: case vmDiv:
            if (offset < bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                offset++;
            }
            break;
        case vmMovzx: case vmMovsx:
            if (offset + 2 <= bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                instr.regIndex2 = bytecode[offset + 1] & 0x0F;
                offset += 2;
            }
            break;
        case vmXadd: case vmCmpxchg:
            if (offset + 2 <= bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                instr.regIndex2 = bytecode[offset + 1] & 0x0F;
                offset += 2;
            }
            break;
        case vmReadTls: case vmReadGs: case vmReadFs:
            if (offset < bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                offset++;
            }
            break;
        default:
            break;
        }

        trace.instrs.push_back(instr);
        if (instr.type == vmRet || instr.type == vmJmp) break;
        if (trace.instrs.size() > 50000) {
            trace.error = "Too many instructions";
            break;
        }
    }

    if (trace.instrs.empty()) {
        trace.error = "No instructions decoded";
        return false;
    }
    trace.success = true;
    return true;
}

/*
 * Decode V2 bytecode (4-byte opcodes)
 */
static bool DecodeBytecodeV2(const BYTE* bytecode, DWORD bytecodeSize,
    const std::vector<VMHandler>& handlers, DWORD handlerTableRva, VMTrace& trace,
    bool isAdvanced = false) {
    BytecodeDecryptor decryptor;
    decryptor.Init(trace.bytecodeRva);
    DWORD offset = 0;
    DWORD entryRva = trace.bytecodeRva;

    std::vector<DWORD> cryptKeys;
    BuildCryptorKeys(handlers, cryptKeys);

    bool useCryptKeys = !cryptKeys.empty();

    while (offset + 4 <= bytecodeSize) {
        DWORD encOffset = *(uint32_t*)(bytecode + offset);
        DWORD instrRva = entryRva + offset;

        // Decrypt the opcode
        DWORD decrypted;
        if (useCryptKeys)
            decrypted = decryptor.DecryptWithCryptor(encOffset, cryptKeys);
        else
            decrypted = decryptor.DecryptOpcode32(encOffset);

        DWORD handlerRva;
        if (isAdvanced) {
            // In advanced mode, the bytecode contains relative offsets from the blob base
            handlerRva = handlerTableRva + decrypted;
        } else {
            handlerRva = handlerTableRva + decrypted;
        }

        int foundIdx = -1;
        // Match decrypted handler first
        for (size_t hi = 0; hi < handlers.size(); ++hi) {
            DWORD delta = (handlers[hi].rva > handlerRva) ?
                handlers[hi].rva - handlerRva : handlerRva - handlers[hi].rva;
            if (delta < 32) { foundIdx = (int)hi; break; }
        }
        if (foundIdx < 0) {
            // Try raw encrypted offset
            DWORD rawHandlerRva = handlerTableRva + encOffset;
            for (size_t hi = 0; hi < handlers.size(); ++hi) {
                DWORD delta = (handlers[hi].rva > rawHandlerRva) ?
                    handlers[hi].rva - rawHandlerRva : rawHandlerRva - handlers[hi].rva;
                if (delta < 32) { foundIdx = (int)hi; break; }
            }
        }
        if (foundIdx < 0) {
            trace.error = "Unknown handler at offset " + std::to_string(offset);
            offset += 4;
            if (offset >= bytecodeSize) break;
            continue;
        }

        offset += 4;
        VMInstruction instr;
        instr.rva = instrRva;
        instr.type = IdentifyHandlerType(handlers[foundIdx].code.data(), handlers[foundIdx].size);
        instr.size = IdentifyHandlerSize(handlers[foundIdx].code.data(), handlers[foundIdx].size);

        // Parse operands
        switch (instr.type) {
        case vmPush:
        case vmMov:
        case vmPushMem:
        case vmPopMem:
        case vmLea:
            if (offset < bytecodeSize) {
                int regByte = bytecode[offset];
                int regLo = regByte & 0x0F;
                int regHi = (regByte >> 4) & 0x0F;
                instr.regIndex = regLo;
                instr.regIndex2 = (regHi != 0) ? regHi : -1;
                offset++;
                if (regByte & 0x80) {
                    switch (instr.size) {
                    case vmSizeByte: if (offset < bytecodeSize) { instr.immediate = bytecode[offset]; offset++; } break;
                    case vmSizeWord: if (offset + 2 <= bytecodeSize) { instr.immediate = *(WORD*)(bytecode + offset); offset += 2; } break;
                    case vmSizeDword: if (offset + 4 <= bytecodeSize) { instr.immediate = *(uint32_t*)(bytecode + offset); offset += 4; } break;
                    case vmSizeQword: if (offset + 8 <= bytecodeSize) { instr.immediate = *(uint64_t*)(bytecode + offset); offset += 8; } break;
                    default: if (offset + 4 <= bytecodeSize) { instr.immediate = *(uint32_t*)(bytecode + offset); offset += 4; } break;
                    }
                }
            }
            break;
        case vmAdd: case vmSub: case vmXor: case vmAnd: case vmOr:
        case vmShl: case vmShr: case vmSar: case vmCmp: case vmTest:
        case vmRol: case vmRor:
            if (offset + 2 <= bytecodeSize) {
                int regByte = bytecode[offset];
                int regByte2 = bytecode[offset + 1];
                instr.regIndex = regByte & 0x0F;
                instr.regIndex2 = regByte2 & 0x0F;
                offset += 2;
                if ((regByte & 0x80) || (regByte2 & 0x80)) {
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
        case vmSetcc:
            if (offset < bytecodeSize) {
                instr.jccType = bytecode[offset] & 0x0F;
                offset++;
            }
            break;
        case vmRet: case vmPushf: case vmPopf: case vmLeave: case vmNop:
        case vmCwde: case vmCdq: case vmCqo:
            break;
        case vmBswap: case vmNot: case vmNeg: case vmInc: case vmDec:
        case vmMul: case vmDiv:
            if (offset < bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                offset++;
            }
            break;
        case vmMovzx: case vmMovsx:
            if (offset + 2 <= bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                instr.regIndex2 = bytecode[offset + 1] & 0x0F;
                offset += 2;
            }
            break;
        case vmXadd: case vmCmpxchg:
            if (offset + 2 <= bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                instr.regIndex2 = bytecode[offset + 1] & 0x0F;
                offset += 2;
            }
            break;
        case vmReadTls: case vmReadGs: case vmReadFs:
            if (offset < bytecodeSize) {
                instr.regIndex = bytecode[offset] & 0x0F;
                offset++;
            }
            break;
        default:
            break;
        }

        trace.instrs.push_back(instr);
        if (instr.type == vmRet || instr.type == vmJmp || instr.type == vmCall) break;
        if (trace.instrs.size() > 100000) {
            trace.error = "Too many instructions";
            break;
        }
    }

    if (trace.instrs.empty()) {
        trace.error = "No instructions decoded";
        return false;
    }
    trace.success = true;
    return true;
}

// Main entry point
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

    DWORD maxSize = min(sizeOfImage - entry.bytecodeRva, (DWORD)0x40000);
    const BYTE* bytecode = dump + entry.bytecodeRva;

    if (isV2) {
        bool isAdvanced = (handlerTableRva > 0x100000);  // heuristic
        return DecodeBytecodeV2(bytecode, maxSize, handlers, handlerTableRva, trace, isAdvanced);
    } else {
        return DecodeBytecodeV1(bytecode, maxSize, handlers, trace);
    }
}

} // namespace vmp
