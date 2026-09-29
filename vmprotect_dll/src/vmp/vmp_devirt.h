#pragma once
#include <Windows.h>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <sstream>
#include <cstring>
#include <algorithm>
#include "vmp_bytecode.h"
#include "vmp_detect.h"
#include "../utils.h"

namespace vmp {

struct DevirtResult {
    bool success;
    std::vector<BYTE> outputCode;
    DWORD outputRva;
    DWORD outputSize;
    std::string disassembly;
    std::vector<std::string> asmLines;
    int instrCount;
    bool is64Bit;
    std::vector<std::pair<DWORD, DWORD>> relocSites; // offset, targetRVA

    DevirtResult() : success(false), outputRva(0), outputSize(0),
        instrCount(0), is64Bit(false) {}
};

static const char* GetRegName(int idx, bool is64) {
    static const char* x86Names[] = {"eflags", "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    static const char* x64Names[] = {"eflags", "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    if (is64) {
        if (idx >= 0 && idx < 17) return x64Names[idx];
    } else {
        if (idx >= 0 && idx < 9) return x86Names[idx];
    }
    return "???";
}

static const char* GetJccName(int type) {
    static const char* names[] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                    "s", "ns", "p", "np", "l", "ge", "le", "g"};
    if (type >= 0 && type <= 15) return names[type];
    return "???";
}

struct VMState {
    std::vector<ULONGLONG> regs;
    std::vector<ULONGLONG> stack;
    ULONGLONG flags;
    DWORD stackTop;
    bool is64Bit;
    std::map<DWORD, int> slotToReg;
    int nextSlot;

    VMState(bool is64 = false) : flags(0), stackTop(0), nextSlot(0), is64Bit(is64) {
        regs.resize(17, 0);
    }

    void Push(ULONGLONG val) { stack.push_back(val); stackTop++; }
    ULONGLONG Pop() {
        if (stack.empty()) return 0;
        ULONGLONG val = stack.back(); stack.pop_back(); stackTop--;
        return val;
    }
    ULONGLONG PeekReg(int regIdx) {
        if (regIdx >= 0 && regIdx < (int)regs.size()) return regs[regIdx];
        return 0;
    }
};

// Encode ModRM/SIB bytes for register+register or register+immediate addressing
static void EncodeModRM(BYTE mod, BYTE reg, BYTE rm, std::vector<BYTE>& out) {
    out.push_back((BYTE)((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
    if (mod == 1) { /* +disp8 handled by caller */ }
    if (mod == 2) { /* +disp32 handled by caller */ }
}

static void EmitRexIfNeeded(bool is64, int reg1, int reg2, int reg3, std::vector<BYTE>& out) {
    if (!is64) return;
    BYTE rex = 0x40;
    if (reg1 >= 8) rex |= 0x44;
    if (reg2 >= 8) rex |= 0x41;
    if (reg3 >= 8) rex |= 0x42;
    if (rex != 0x40) out.push_back(rex);
}

static BYTE GetRex(bool is64, int reg1, int reg2) {
    if (!is64) return 0;
    BYTE rex = 0x48;  // W=1 for 64-bit operand size by default
    if (reg1 >= 8) rex |= 0x44;
    if (reg2 >= 8) rex |= 0x41;
    // If no extension bits needed and we don't need W, return 0
    if (rex == 0x48) return rex;
    return rex;
}

/* Emit native x86/x64 machine code for a single VM instruction */
static std::vector<BYTE> EmitNative(const VMInstruction& instr, VMState& state) {
    std::vector<BYTE> result;
    int reg1 = instr.regIndex >= 0 ? instr.regIndex : 0;
    int reg2 = instr.regIndex2 >= 0 ? instr.regIndex2 : 0;
    bool is64 = state.is64Bit;

    auto rexW = [&]() -> BYTE {
        BYTE r = 0x48;
        if (reg1 >= 8) r |= 0x44;
        if (reg2 >= 8) r |= 0x41;
        if (r == 0x48) return r;
        return r;
    };

    auto emitImm = [&](ULONGLONG val, VMOpSize sz) {
        switch (sz) {
        case vmSizeByte: result.push_back((BYTE)(val & 0xFF)); break;
        case vmSizeWord: { WORD w = (WORD)(val & 0xFFFF); result.insert(result.end(), (BYTE*)&w, (BYTE*)&w + 2); break; }
        case vmSizeDword: { DWORD dw = (DWORD)(val & 0xFFFFFFFF); result.insert(result.end(), (BYTE*)&dw, (BYTE*)&dw + 4); break; }
        case vmSizeQword: result.insert(result.end(), (BYTE*)&val, (BYTE*)&val + 8); break;
        default: { DWORD dw = (DWORD)(val & 0xFFFFFFFF); result.insert(result.end(), (BYTE*)&dw, (BYTE*)&dw + 4); break; }
        }
    };

    switch (instr.type) {
    case vmNop:
        result.push_back(0x90);
        return result;

    case vmRet:
        result.push_back(0xC3);
        return result;

    case vmPushf:
        result.push_back(0x9C);
        return result;

    case vmPopf:
        result.push_back(0x9D);
        return result;

    case vmCwde:
        result.push_back(0x98);
        return result;

    case vmCdq:
        result.push_back(0x99);
        return result;

    case vmCqo:
        if (is64) { result.push_back(0x48); result.push_back(0x99); }
        else result.push_back(0x99);
        return result;

    case vmLeave:
        result.push_back(0xC9);
        return result;

    case vmRdtsc:
        result.push_back(0x0F); result.push_back(0x31);
        return result;

    case vmCpuid:
        result.push_back(0x0F); result.push_back(0xA2);
        return result;

    case vmPush:
        if (instr.immediate != 0 || (instr.regIndex < 0 && instr.regIndex2 < 0)) {
            if (instr.immediate <= 0x7F && instr.immediate >= -0x80) {
                result.push_back(0x6A);
                result.push_back((BYTE)(instr.immediate & 0xFF));
            } else {
                result.push_back(0x68);
                DWORD imm = (DWORD)(instr.immediate & 0xFFFFFFFF);
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        } else if (instr.regIndex >= 0) {
            BYTE r = 0;
            if (is64 && reg1 >= 8) { result.push_back(0x41); r = 0x50 | (reg1 & 7); }
            else r = 0x50 | (reg1 & 7);
            result.push_back(r);
        } else {
            result.push_back(0x6A); result.push_back(0x00);
        }
        return result;

    case vmPop:
        if (instr.regIndex >= 0) {
            BYTE r;
            if (is64 && reg1 >= 8) { result.push_back(0x41); r = 0x58 | (reg1 & 7); }
            else r = 0x58 | (reg1 & 7);
            result.push_back(r);
        } else {
            result.push_back(0x58);  // pop eax/rax
        }
        return result;

    case vmCall:
        if (instr.isExtern) {
            // External call via import: emit call [iat_address_placeholder]
            result.push_back(0xFF); result.push_back(0x15);
            DWORD placeholder = 0xDEADBEEF;
            result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4);
        } else if (instr.regIndex >= 0) {
            // call reg
            BYTE r = 0xD0 | (reg1 & 7);
            if (is64 && reg1 >= 8) { result.push_back(0x41); }
            result.push_back(0xFF); result.push_back(r);
        } else {
            // call rel32 (placeholder — will be patched)
            result.push_back(0xE8);
            DWORD placeholder = 0;
            result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4);
        }
        return result;

    case vmJmp:
        if (instr.regIndex >= 0) {
            // jmp reg
            BYTE r = 0xE0 | (reg1 & 7);
            if (is64 && reg1 >= 8) { result.push_back(0x41); }
            result.push_back(0xFF); result.push_back(r);
        } else {
            result.push_back(0xE9);
            DWORD placeholder = 0;
            result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4);
        }
        return result;

    case vmJcc:
        result.push_back(0x0F);
        result.push_back(0x80 | (instr.jccType & 0x0F));
        { DWORD placeholder = 0;
        result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4); }
        return result;

    case vmMov: {
        VMOpSize sz = instr.size;
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            // mov reg1, reg2
            BYTE rex = 0;
            if (is64) {
                rex = 0x48;
                if (reg1 >= 8) rex |= 0x44;
                if (reg2 >= 8) rex |= 0x41;
            }
            if (rex) result.push_back(rex);
            if (sz == vmSizeByte) {
                result.push_back(0x8A);
                result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
            } else {
                result.push_back(0x89);
                result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
            }
        } else if (instr.regIndex >= 0) {
            // mov reg1, imm
            BYTE rex = is64 ? 0x48 : 0;
            if (reg1 >= 8) rex |= 0x44;
            if (rex && rex != 0x48) result.push_back(rex);
            if (is64 && sz == vmSizeQword) {
                // mov rax, imm64
                if (rex == 0x48) result.push_back(rex);
                result.push_back(0xB8 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&instr.immediate, (BYTE*)&instr.immediate + 8);
            } else {
                if (rex == 0x48) result.push_back(rex);
                result.push_back(0xB8 | (reg1 & 7));
                DWORD imm = (DWORD)(instr.immediate & 0xFFFFFFFF);
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;
    }

    case vmLea:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            // lea reg1, [reg2 + disp]
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x8D);
            // modrm: mod=01 (disp8) or mod=10 (disp32)
            if (instr.immediate != 0 && (int32_t)instr.immediate >= -128 && (int32_t)instr.immediate <= 127) {
                result.push_back(0x40 | ((reg1 & 7) << 3) | (reg2 & 7));
                result.push_back((BYTE)(instr.immediate & 0xFF));
            } else {
                result.push_back(0x80 | ((reg1 & 7) << 3) | (reg2 & 7));
                DWORD disp = (DWORD)(instr.immediate & 0xFFFFFFFF);
                result.insert(result.end(), (BYTE*)&disp, (BYTE*)&disp + 4);
            }
        }
        return result;

    case vmXor:
    case vmAdd:
    case vmSub:
    case vmAnd:
    case vmOr: {
        BYTE opB0, opB1m, opB1r, opImm, opImmExt;
        switch (instr.type) {
        case vmXor: opB0 = 0x33; opB1m = 0x31; opB1r = 0x33; opImm = 0x83; opImmExt = 0xF0; break;
        case vmAdd: opB0 = 0x03; opB1m = 0x01; opB1r = 0x03; opImm = 0x83; opImmExt = 0xC0; break;
        case vmSub: opB0 = 0x2B; opB1m = 0x29; opB1r = 0x2B; opImm = 0x83; opImmExt = 0xE8; break;
        case vmAnd: opB0 = 0x23; opB1m = 0x21; opB1r = 0x23; opImm = 0x83; opImmExt = 0xE0; break;
        case vmOr:  opB0 = 0x0B; opB1m = 0x09; opB1r = 0x0B; opImm = 0x83; opImmExt = 0xC8; break;
        default: return result;
        }
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(opB0);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
            return result;
        }
        if (instr.immediate != 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            DWORD imm = (DWORD)(instr.immediate & 0xFFFFFFFF);
            if (imm <= 127 || (int32_t)imm >= -128) {
                result.push_back(opImm);
                result.push_back(opImmExt | (reg1 & 7));
                result.push_back((BYTE)(imm & 0xFF));
            } else {
                result.push_back(0x81);
                result.push_back(opImmExt | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
            return result;
        }
        return result;
    }

    case vmShl:
    case vmShr:
    case vmSar:
    case vmRol:
    case vmRor: {
        BYTE opcode;
        switch (instr.type) {
        case vmShl: opcode = 0xE0; break;
        case vmShr: opcode = 0xE8; break;
        case vmSar: opcode = 0xF8; break;
        case vmRol: opcode = 0xC0; break;
        case vmRor: opcode = 0xC8; break;
        default: return result;
        }

        BYTE rex = rexW();
        if (rex) result.push_back(rex);
        if (instr.regIndex2 >= 0 && instr.regIndex2 <= 1) {
            // shift by cl
            result.push_back(0xD3);
            result.push_back(opcode | (reg1 & 7));
        } else {
            BYTE imm = (BYTE)(instr.immediate & 0xFF);
            if (imm == 1) { result.push_back(0xD1); result.push_back(opcode | (reg1 & 7)); }
            else { result.push_back(0xC1); result.push_back(opcode | (reg1 & 7)); result.push_back(imm); }
        }
        return result;
    }

    case vmNot:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0xF7); result.push_back(0xD0 | (reg1 & 7));
        }
        return result;

    case vmNeg:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0xF7); result.push_back(0xD8 | (reg1 & 7));
        }
        return result;

    case vmInc:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0xFF); result.push_back(0xC0 | (reg1 & 7));
        }
        return result;

    case vmDec:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0xFF); result.push_back(0xC8 | (reg1 & 7));
        }
        return result;

    case vmCmp:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x3B);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            DWORD imm = (DWORD)(instr.immediate & 0xFFFFFFFF);
            if (imm <= 127 || (int32_t)imm >= -128) {
                result.push_back(0x83); result.push_back(0xF8 | (reg1 & 7)); result.push_back((BYTE)(imm & 0xFF));
            } else {
                result.push_back(0x81); result.push_back(0xF8 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmTest:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x85);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmMul:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xAF);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg1 & 7));
        }
        return result;

    case vmDiv:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0xF7); result.push_back(0xF8 | (reg1 & 7));
        }
        return result;

    case vmBswap:
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xC8 | (reg1 & 7));
        }
        return result;

    case vmSetcc:
        if (instr.regIndex >= 0) {
            result.push_back(0x0F);
            result.push_back(0x90 | (instr.jccType & 0x0F));
            BYTE ext = 0xC0 | (reg1 & 7);
            if (is64 && reg1 >= 8) { result.push_back(0x41); }
            result.push_back(ext);
        }
        return result;

    case vmMovzx:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = 0;
            if (is64 && (reg1 >= 8 || reg2 >= 8)) { rex = 0x40; if (reg1 >= 8) rex |= 0x44; if (reg2 >= 8) rex |= 0x41; }
            if (rex) result.push_back(rex);
            if (instr.size == vmSizeByte) {
                result.push_back(0x0F); result.push_back(0xB6);
            } else {
                result.push_back(0x0F); result.push_back(0xB7);
            }
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmMovsx:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = 0;
            if (is64 && (reg1 >= 8 || reg2 >= 8)) { rex = 0x40; if (reg1 >= 8) rex |= 0x44; if (reg2 >= 8) rex |= 0x41; }
            if (rex) result.push_back(rex);
            if (instr.size == vmSizeByte) {
                result.push_back(0x0F); result.push_back(0xBE);
            } else {
                result.push_back(0x0F); result.push_back(0xBF);
            }
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmPushMem:
    case vmPopMem:
        // Simplified: just emit push/pop reg for now
        if (instr.type == vmPushMem) {
            if (instr.regIndex >= 0) {
                BYTE r = (is64 && reg1 >= 8) ? (0x41) : 0;
                if (r) result.push_back(r);
                result.push_back(0x50 | (reg1 & 7));
            } else result.push_back(0x50);
        } else {
            if (instr.regIndex >= 0) {
                BYTE r = (is64 && reg1 >= 8) ? (0x41) : 0;
                if (r) result.push_back(r);
                result.push_back(0x58 | (reg1 & 7));
            } else result.push_back(0x58);
        }
        return result;

    case vmXadd:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xC1);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmCmpxchg:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xB1);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmReadTls:
    case vmReadGs:
    case vmReadFs:
        // Read from TLS/GS/FS segment
        if (instr.regIndex >= 0) {
            BYTE rex = rexW();
            if (rex) result.push_back(rex);
            result.push_back(0x8B);
            BYTE seg = (instr.type == vmReadTls) ? 0x2C : (instr.type == vmReadGs) ? 0x2C : 0x24;
            // mov reg1, [seg:0]
            result.push_back(0x04 | ((reg1 & 7) << 3));
            result.push_back(0x25);  // FS:0 or GS:0
            DWORD zero = 0;
            result.insert(result.end(), (BYTE*)&zero, (BYTE*)&zero + 4);
        }
        return result;

    default:
        result.push_back(0x90);
        break;
    }

    return result;
}

/* Generate human-readable disassembly */
static std::string DisasmInstruction(const VMInstruction& instr, bool is64) {
    std::ostringstream ss;
    auto regName = [is64](int idx) -> std::string {
        if (idx < 0) return "???";
        return GetRegName(idx, is64);
    };
    auto sizeName = [](VMOpSize s) -> std::string {
        switch (s) {
        case vmSizeByte: return "byte";
        case vmSizeWord: return "word";
        case vmSizeDword: return "dword";
        case vmSizeQword: return "qword";
        default: return "";
        }
    };

    switch (instr.type) {
    case vmNop: ss << "nop"; break;
    case vmPush:
        if (instr.regIndex >= 0 && instr.immediate == 0 && instr.regIndex2 < 0)
            ss << "push " << regName(instr.regIndex);
        else if (instr.immediate != 0)
            ss << "push 0x" << std::hex << instr.immediate;
        else ss << "push 0";
        break;
    case vmPop: ss << "pop " << regName(instr.regIndex); break;
    case vmMov:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "mov " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else if (instr.regIndex >= 0)
            ss << "mov " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmLea:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "lea " << regName(instr.regIndex) << ", [" << regName(instr.regIndex2) << "+0x" << std::hex << instr.immediate << "]";
        break;
    case vmAdd:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "add " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else ss << "add " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmSub:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "sub " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else ss << "sub " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmXor:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0 && instr.regIndex == instr.regIndex2)
            ss << "xor " << regName(instr.regIndex) << ", " << regName(instr.regIndex);
        else if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "xor " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else ss << "xor " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmAnd:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "and " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else ss << "and " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmOr:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "or " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else ss << "or " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmShl: ss << "shl " << regName(instr.regIndex) << ", " << (instr.regIndex2 >= 0 ? "cl" : "0x" + to_hex((DWORD)instr.immediate)); break;
    case vmShr: ss << "shr " << regName(instr.regIndex) << ", " << (instr.regIndex2 >= 0 ? "cl" : "0x" + to_hex((DWORD)instr.immediate)); break;
    case vmSar: ss << "sar " << regName(instr.regIndex) << ", " << (instr.regIndex2 >= 0 ? "cl" : "0x" + to_hex((DWORD)instr.immediate)); break;
    case vmRol: ss << "rol " << regName(instr.regIndex) << ", " << (instr.regIndex2 >= 0 ? "cl" : "0x" + to_hex((DWORD)instr.immediate)); break;
    case vmRor: ss << "ror " << regName(instr.regIndex) << ", " << (instr.regIndex2 >= 0 ? "cl" : "0x" + to_hex((DWORD)instr.immediate)); break;
    case vmNot: ss << "not " << regName(instr.regIndex); break;
    case vmNeg: ss << "neg " << regName(instr.regIndex); break;
    case vmInc: ss << "inc " << regName(instr.regIndex); break;
    case vmDec: ss << "dec " << regName(instr.regIndex); break;
    case vmCmp:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "cmp " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else ss << "cmp " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
        break;
    case vmTest: ss << "test " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmCall:
        if (instr.isExtern) ss << "call [import#" << std::dec << instr.immediate << "]";
        else if (instr.regIndex >= 0) ss << "call " << regName(instr.regIndex);
        else ss << "call 0x" << std::hex << instr.immediate;
        break;
    case vmJmp: ss << "jmp " << (instr.regIndex >= 0 ? regName(instr.regIndex) : "0x" + to_hex((DWORD)instr.immediate)); break;
    case vmJcc: ss << "j" << GetJccName(instr.jccType) << " 0x" << std::hex << instr.immediate; break;
    case vmRet: ss << "ret"; break;
    case vmPushf: ss << "pushf"; break;
    case vmPopf: ss << "popf"; break;
    case vmLeave: ss << "leave"; break;
    case vmBswap: ss << "bswap " << regName(instr.regIndex); break;
    case vmCwde: ss << "cwde"; break;
    case vmCdq: ss << "cdq"; break;
    case vmCqo: ss << "cqo"; break;
    case vmMovzx: ss << "movzx " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmMovsx: ss << "movsx " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmSetcc: ss << "set" << GetJccName(instr.jccType) << " " << regName(instr.regIndex); break;
    case vmMul: ss << "imul " << regName(instr.regIndex); break;
    case vmDiv: ss << "idiv " << regName(instr.regIndex); break;
    case vmXadd: ss << "xadd " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmCmpxchg: ss << "cmpxchg " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmReadTls: ss << "mov " << regName(instr.regIndex) << ", fs:[0] (TLS)"; break;
    case vmReadGs: ss << "mov " << regName(instr.regIndex) << ", gs:[0]"; break;
    case vmReadFs: ss << "mov " << regName(instr.regIndex) << ", fs:[0]"; break;
    case vmRdtsc: ss << "rdtsc"; break;
    case vmCpuid: ss << "cpuid"; break;
    default: ss << "db 0x" << std::hex << instr.type << " ; unknown"; break;
    }
    return ss.str();
}

/* Devirtualize a single decoded VM trace back to native code */
static bool DevirtualizeTrace(const VMTrace& trace, bool is64, DevirtResult& out) {
    out.success = false;
    out.is64Bit = is64;
    out.instrCount = 0;
    if (!trace.success || trace.instrs.empty()) return false;

    VMState state(is64);
    out.asmLines.clear();
    out.disassembly.clear();
    out.outputCode.clear();
    out.relocSites.clear();
    std::ostringstream disasm;

    for (size_t i = 0; i < trace.instrs.size(); ++i) {
        const VMInstruction& instr = trace.instrs[i];
        std::vector<BYTE> code = EmitNative(instr, state);
        size_t offset = out.outputCode.size();
        out.outputCode.insert(out.outputCode.end(), code.begin(), code.end());

        // Track reloc sites for external calls
        if (instr.type == vmCall && instr.isExtern && code.size() >= 6 && code[0] == 0xFF && code[1] == 0x15) {
            out.relocSites.push_back({ (DWORD)offset + 2, (DWORD)instr.immediate });
        }

        std::string line = DisasmInstruction(instr, is64);
        out.asmLines.push_back(line);

        char buf[256];
        std::string hexBytes;
        for (size_t bi = 0; bi < min(code.size(), (size_t)12); ++bi) {
            char h[16]; snprintf(h, sizeof(h), "%02X ", code[bi]); hexBytes += h;
        }
        if (code.size() > 12) hexBytes += "...";
        snprintf(buf, sizeof(buf), "  0x%08X: %-20s %s", trace.bytecodeRva, hexBytes.c_str(), line.c_str());
        disasm << buf << "\n";
        out.instrCount++;
    }

    out.disassembly = disasm.str();
    out.outputSize = (DWORD)out.outputCode.size();
    out.success = true;

    DbgLogF("[DEVIRT] devirtualized %d instructions -> %u bytes of native code", out.instrCount, out.outputSize);
    return true;
}

/*
 * Devirtualize all discovered VM entry points.
 */
static std::vector<DevirtResult> DevirtualizeAll(BYTE* dump, DWORD sizeOfImage,
    const VMPDetectResult& detect, bool is64) {
    std::vector<DevirtResult> results;
    if (!detect.detected || detect.entries.empty()) {
        DbgLog("[*] no VM entries to devirtualize");
        return results;
    }

    DbgLogF("[DEVIRT] devirtualizing %d VM entry points...", (int)detect.entries.size());

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dump;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dump + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    WORD sectionCount = nt->FileHeader.NumberOfSections;

    // Find a good place to put devirtualized code: either extend the VMP section
    // or find the executable section with the most room
    DWORD codeInsertRva = 0;
    DWORD codeInsertEnd = 0;
    for (WORD i = 0; i < sectionCount; ++i) {
        DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (end > codeInsertEnd && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            codeInsertEnd = end;
            codeInsertRva = sections[i].VirtualAddress;
        }
    }
    // If VMP section found (largest RVA), use it for code placement
    for (WORD i = 0; i < sectionCount; ++i) {
        DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (end > codeInsertEnd) {
            codeInsertEnd = end;
            codeInsertRva = sections[i].VirtualAddress;
        }
    }
    // Align to 16-byte boundary
    DWORD lastEnd = codeInsertEnd;
    if (lastEnd == 0) {
        // Fallback: use end of last section
        for (WORD i = 0; i < sectionCount; ++i) {
            DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
            if (end > lastEnd) lastEnd = end;
        }
    }
    codeInsertRva = (lastEnd + 0x0F) & ~0x0F;

    DbgLogF("[DEVIRT] placing devirtualized code at RVA 0x%X", codeInsertRva);

    for (size_t i = 0; i < detect.entries.size(); ++i) {
        const VMEntryPoint& entry = detect.entries[i];

        VMTrace trace;
        if (!DecodeBytecode(dump, sizeOfImage, entry, detect.handlers,
            detect.handlerTableRva, detect.isV2, trace)) {
            DbgLogF("[DEVIRT] entry %zu: decode failed: %s", i, trace.error.c_str());
            continue;
        }

        DevirtResult result;
        if (!DevirtualizeTrace(trace, is64, result)) {
            DbgLogF("[DEVIRT] entry %zu: devirtualization failed", i);
            continue;
        }

        result.outputRva = codeInsertRva;
        if (codeInsertRva + result.outputSize <= sizeOfImage) {
            memcpy(dump + codeInsertRva, result.outputCode.data(), result.outputSize);
            DbgLogF("[DEVIRT] entry 0x%X: wrote %u bytes at RVA 0x%X",
                entry.rva, result.outputSize, codeInsertRva);
        } else {
            DbgLogF("[DEVIRT] entry 0x%X: output %u bytes exceeds buffer", entry.rva, result.outputSize);
            continue;
        }

        // Patch original entry to jmp to devirtualized code
        // The entry starts with push bytecode; call/jmp dispatcher
        // We replace the entire sequence with jmp devirtCode
        DWORD patchSize = 5;
        if (entry.rva + patchSize <= sizeOfImage) {
            dump[entry.rva] = 0xE9;
            int32_t rel = (int32_t)(codeInsertRva - entry.rva - 5);
            *(int32_t*)(dump + entry.rva + 1) = rel;
            // NOP the rest of the original instruction sequence
            DWORD origSeqLen = 10;  // push imm32 (5) + call rel32 (5)
            if (dump[entry.rva + 5] == 0xFF && dump[entry.rva + 6] == 0x15)
                origSeqLen = 11;  // push imm32 (5) + jmp [iat] (6)
            for (DWORD j = 5; j < origSeqLen; ++j)
                if (entry.rva + j < sizeOfImage) dump[entry.rva + j] = 0x90;
            DbgLogF("[DEVIRT] patched entry 0x%X -> jmp 0x%X", entry.rva, codeInsertRva);
        }

        codeInsertRva += result.outputSize;
        results.push_back(result);
    }

    // Extend last section if devirtualized code overflows
    DWORD finalEnd = codeInsertRva;
    for (WORD i = 0; i < sectionCount; ++i) {
        DWORD secEnd = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (finalEnd > secEnd) {
            DWORD newSize = finalEnd - sections[i].VirtualAddress;
            if (newSize > sections[i].Misc.VirtualSize) {
                DbgLogF("[DEVIRT] extending section %d (0x%X -> 0x%X)",
                    i, sections[i].Misc.VirtualSize, newSize);
                sections[i].Misc.VirtualSize = newSize;
            }
        }
    }

    DbgLogF("[DEVIRT] devirtualized %zu/%zu entries successfully", results.size(), detect.entries.size());
    return results;
}

} // namespace vmp
