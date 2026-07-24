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

/*
 * VMP Devirtualization Engine
 * Converts VM bytecode traces back into native x86/x64 machine code
 * and patches the original VM entry points.
 */

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

// Virtual machine state: registers, stack, flags tracker
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
    ULONGLONG Peek(int offset = 0) {
        if (stack.empty()) return 0;
        int idx = (int)stack.size() - 1 - offset;
        return (idx < 0) ? 0 : stack[idx];
    }
    int AllocSlot() { return nextSlot++; }
};

/* Emit native x86/x64 machine code for a single VM instruction */
static std::vector<BYTE> EmitX86(const VMInstruction& instr, VMState& state) {
    std::vector<BYTE> result;
    int reg1 = instr.regIndex >= 0 ? instr.regIndex : 0;
    int reg2 = instr.regIndex2 >= 0 ? instr.regIndex2 : 0;
    BYTE rex = 0;

    if (state.is64Bit) {
        rex = 0x48;
        if (reg1 >= 8) rex |= 0x44;
        if (reg2 >= 8) rex |= 0x41;
    }

    switch (instr.type) {
    case vmNop:
        result.push_back(0x90); return result;
    case vmRet:
        result.push_back(0xC3); return result;
    case vmPushf:
        result.push_back(0x9C); return result;
    case vmPopf:
        result.push_back(0x9D); return result;
    case vmCwde:
        result.push_back(0x98); return result;
    case vmCdq:
        result.push_back(0x99); return result;
    case vmLeave:
        result.push_back(0xC9); return result;

    case vmPush:
        if (instr.regIndex >= 0 && instr.immediate == 0) {
            if (!state.is64Bit || reg1 < 8) {
                result.push_back(0x50 | (reg1 & 7));
            } else {
                result.push_back(0x41); result.push_back(0x50 | (reg1 & 7));
            }
        } else if (instr.immediate != 0) {
            if (instr.immediate <= 0x7F) {
                result.push_back(0x6A); result.push_back((BYTE)(instr.immediate & 0xFF));
            } else {
                result.push_back(0x68); DWORD imm = (DWORD)instr.immediate;
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        } else {
            result.push_back(0x6A); result.push_back(0x00);
        }
        return result;

    case vmPop:
        if (!state.is64Bit || reg1 < 8) {
            result.push_back(0x58 | (reg1 & 7));
        } else {
            result.push_back(0x41); result.push_back(0x58 | (reg1 & 7));
        }
        return result;

    case vmCall:
        if (instr.isExtern || instr.regIndex < 0) {
            result.push_back(0xE8); DWORD placeholder = 0;
            result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4);
        } else {
            result.push_back(0xFF); result.push_back(0xD0 | (reg1 & 7));
        }
        return result;

    case vmJmp:
        if (instr.regIndex >= 0) {
            result.push_back(0xFF); result.push_back(0xE0 | (reg1 & 7));
        } else {
            result.push_back(0xE9); DWORD placeholder = 0;
            result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4);
        }
        return result;

    case vmJcc:
        result.push_back(0x0F);
        result.push_back(0x80 | (instr.jccType & 0x0F));
        { DWORD placeholder = 0; result.insert(result.end(), (BYTE*)&placeholder, (BYTE*)&placeholder + 4); }
        return result;

    case vmMov:
        if (instr.immediate != 0 || (instr.regIndex >= 0 && instr.regIndex2 < 0)) {
            DWORD imm = (DWORD)instr.immediate;
            if (instr.size == vmSizeQword && state.is64Bit) {
                result.push_back(0x48 | ((reg1 >= 8) ? 0x41 : 0x40));
                result.push_back(0xB8 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&instr.immediate, (BYTE*)&instr.immediate + 8);
                return result;
            }
            if (rex) result.push_back(rex);
            result.push_back(0xB8 | (reg1 & 7));
            result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
        } else if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x89);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmXor:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x33);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            DWORD imm = (DWORD)instr.immediate;
            if (imm <= 0x7F) {
                if (rex) result.push_back(rex);
                result.push_back(0x83); result.push_back(0xF0 | (reg1 & 7)); result.push_back((BYTE)imm);
            } else {
                if (rex) result.push_back(rex);
                result.push_back(0x81); result.push_back(0xF0 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmAdd:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x03);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            DWORD imm = (DWORD)instr.immediate;
            if (imm <= 0x7F) {
                if (rex) result.push_back(rex);
                result.push_back(0x83); result.push_back(0xC0 | (reg1 & 7)); result.push_back((BYTE)imm);
            } else {
                if (rex) result.push_back(rex);
                result.push_back(0x81); result.push_back(0xC0 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmSub:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x2B);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            DWORD imm = (DWORD)instr.immediate;
            if (imm <= 0x7F) {
                if (rex) result.push_back(rex);
                result.push_back(0x83); result.push_back(0xE8 | (reg1 & 7)); result.push_back((BYTE)imm);
            } else {
                if (rex) result.push_back(rex);
                result.push_back(0x81); result.push_back(0xE8 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmAnd:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x23);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            DWORD imm = (DWORD)instr.immediate;
            if (imm <= 0x7F) {
                if (rex) result.push_back(rex);
                result.push_back(0x83); result.push_back(0xE0 | (reg1 & 7)); result.push_back((BYTE)imm);
            } else {
                if (rex) result.push_back(rex);
                result.push_back(0x81); result.push_back(0xE0 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmOr:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x0B);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            DWORD imm = (DWORD)instr.immediate;
            if (imm <= 0x7F) {
                if (rex) result.push_back(rex);
                result.push_back(0x83); result.push_back(0xC8 | (reg1 & 7)); result.push_back((BYTE)imm);
            } else {
                if (rex) result.push_back(rex);
                result.push_back(0x81); result.push_back(0xC8 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmInc:
        if (rex) result.push_back(rex);
        if (state.is64Bit) {
            result.push_back(0xFF); result.push_back(0xC0 | (reg1 & 7));
        } else {
            result.push_back(0x40 | (reg1 & 7));
        }
        return result;

    case vmDec:
        if (rex) result.push_back(rex);
        if (state.is64Bit) {
            result.push_back(0xFF); result.push_back(0xC8 | (reg1 & 7));
        } else {
            result.push_back(0x48 | (reg1 & 7));
        }
        return result;

    case vmNot:
        if (rex) result.push_back(rex);
        result.push_back(0xF7); result.push_back(0xD0 | (reg1 & 7));
        return result;

    case vmNeg:
        if (rex) result.push_back(rex);
        result.push_back(0xF7); result.push_back(0xD8 | (reg1 & 7));
        return result;

    case vmCmp:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x3B);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else if (instr.immediate != 0) {
            DWORD imm = (DWORD)instr.immediate;
            if (imm <= 0x7F) {
                if (rex) result.push_back(rex);
                result.push_back(0x83); result.push_back(0xF8 | (reg1 & 7)); result.push_back((BYTE)imm);
            } else {
                if (rex) result.push_back(rex);
                result.push_back(0x81); result.push_back(0xF8 | (reg1 & 7));
                result.insert(result.end(), (BYTE*)&imm, (BYTE*)&imm + 4);
            }
        }
        return result;

    case vmShl:
        if (instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0xD3); result.push_back(0xE0 | (reg1 & 7));
        } else if (instr.immediate != 0) {
            BYTE imm = (BYTE)instr.immediate;
            if (rex) result.push_back(rex);
            if (imm == 1) result.push_back(0xD1); else result.push_back(0xC1);
            result.push_back(0xE0 | (reg1 & 7));
            if (imm != 1) result.push_back(imm);
        }
        return result;

    case vmShr:
        if (instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0xD3); result.push_back(0xE8 | (reg1 & 7));
        } else if (instr.immediate != 0) {
            BYTE imm = (BYTE)instr.immediate;
            if (rex) result.push_back(rex);
            if (imm == 1) result.push_back(0xD1); else result.push_back(0xC1);
            result.push_back(0xE8 | (reg1 & 7));
            if (imm != 1) result.push_back(imm);
        }
        return result;

    case vmSar:
        if (instr.regIndex2 >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0xD3); result.push_back(0xF8 | (reg1 & 7));
        } else if (instr.immediate != 0) {
            BYTE imm = (BYTE)instr.immediate;
            if (rex) result.push_back(rex);
            if (imm == 1) result.push_back(0xD1); else result.push_back(0xC1);
            result.push_back(0xF8 | (reg1 & 7));
            if (imm != 1) result.push_back(imm);
        }
        return result;

    case vmBswap:
        if (rex) result.push_back(rex);
        result.push_back(0x0F); result.push_back(0xC8 | (reg1 & 7));
        return result;

    case vmSetcc:
        result.push_back(0x0F);
        result.push_back(0x90 | (instr.jccType & 0x0F));
        result.push_back(0xC0 | (reg1 & 7));
        return result;

    case vmMovzx:
        if (instr.size == vmSizeByte) {
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xB6);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else {
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xB7);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmMovsx:
        if (instr.size == vmSizeByte) {
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xBE);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        } else {
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xBF);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | (reg2 & 7));
        }
        return result;

    case vmMul:
        if (instr.regIndex >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0x0F); result.push_back(0xAF);
            result.push_back(0xC0 | ((reg1 & 7) << 3) | ((instr.regIndex2 >= 0 ? reg2 : reg1) & 7));
        }
        return result;

    case vmDiv:
        if (instr.regIndex >= 0) {
            if (rex) result.push_back(rex);
            result.push_back(0xF7); result.push_back(0xF8 | (reg1 & 7));
        }
        return result;

    default:
        result.push_back(0x90);
        break;
    }

    return result;
}

/* Generate human-readable disassembly for a VM instruction */
static std::string DisasmInstruction(const VMInstruction& instr, bool is64) {
    std::ostringstream ss;
    auto regName = [is64](int idx) -> std::string {
        if (idx < 0) return "???";
        return GetRegName(idx, is64);
    };

    switch (instr.type) {
    case vmNop: ss << "nop"; break;
    case vmPush:
        if (instr.regIndex >= 0 && instr.immediate == 0) ss << "push " << regName(instr.regIndex);
        else if (instr.immediate != 0) ss << "push 0x" << std::hex << instr.immediate;
        else ss << "push 0";
        break;
    case vmPop: ss << "pop " << regName(instr.regIndex); break;
    case vmMov:
        if (instr.regIndex >= 0 && instr.regIndex2 >= 0)
            ss << "mov " << regName(instr.regIndex) << ", " << regName(instr.regIndex2);
        else if (instr.regIndex >= 0)
            ss << "mov " << regName(instr.regIndex) << ", 0x" << std::hex << instr.immediate;
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
    case vmMovzx: ss << "movzx " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmMovsx: ss << "movsx " << regName(instr.regIndex) << ", " << regName(instr.regIndex2); break;
    case vmSetcc: ss << "set" << GetJccName(instr.jccType) << " " << regName(instr.regIndex); break;
    case vmMul: ss << "imul " << regName(instr.regIndex); break;
    case vmDiv: ss << "idiv " << regName(instr.regIndex); break;
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
    std::ostringstream disasm;

    for (size_t i = 0; i < trace.instrs.size(); ++i) {
        const VMInstruction& instr = trace.instrs[i];
        std::vector<BYTE> code = EmitX86(instr, state);
        size_t offset = out.outputCode.size();
        out.outputCode.insert(out.outputCode.end(), code.begin(), code.end());

        std::string line = DisasmInstruction(instr, is64);
        out.asmLines.push_back(line);

        char buf[256];
        if (code.size() <= 8) {
            std::string hexBytes;
            for (auto b : code) { char h[8]; snprintf(h, sizeof(h), "%02X ", b); hexBytes += h; }
            snprintf(buf, sizeof(buf), "  0x%08X: %-20s %s", trace.bytecodeRva, hexBytes.c_str(), line.c_str());
        } else {
            snprintf(buf, sizeof(buf), "  0x%08X: %-20s %s", trace.bytecodeRva, "(...)", line.c_str());
        }
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
 * Each entry's bytecode is decoded into a trace, then devirtualized
 * to native code. The native code is written into the dump buffer
 * and the original entry is patched to jmp to the new code.
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

    DWORD codeInsertRva = 0;
    for (WORD i = 0; i < sectionCount; ++i) {
        DWORD end = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
        if (end > codeInsertRva && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            codeInsertRva = end;
        }
    }
    codeInsertRva = (codeInsertRva + 0x0F) & ~0x0F;
    DbgLogF("[DEVIRT] placing devirtualized code starting at RVA 0x%X", codeInsertRva);

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
        }

        // Patch original entry to jmp to devirtualized code
        DWORD callSize = 5;
        if (entry.rva + callSize <= sizeOfImage) {
            dump[entry.rva] = 0xE9;
            int32_t rel = (int32_t)(codeInsertRva - entry.rva - 5);
            *(int32_t*)(dump + entry.rva + 1) = rel;
            DWORD remaining = callSize - 5;
            for (DWORD j = 0; j < remaining; ++j)
                if (entry.rva + 5 + j < sizeOfImage) dump[entry.rva + 5 + j] = 0x90;
            DbgLogF("[DEVIRT] patched entry 0x%X -> jmp 0x%X", entry.rva, codeInsertRva);
        }

        codeInsertRva += result.outputSize;
        results.push_back(result);
    }

    // Extend executable section if devirtualized code spills over
    for (WORD i = 0; i < sectionCount; ++i) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD secEnd = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
            if (codeInsertRva > secEnd) {
                DbgLogF("[DEVIRT] extending section %d (0x%X -> 0x%X)",
                    i, sections[i].Misc.VirtualSize, codeInsertRva - sections[i].VirtualAddress);
                sections[i].Misc.VirtualSize = codeInsertRva - sections[i].VirtualAddress;
            }
        }
    }

    DbgLogF("[DEVIRT] devirtualized %zu/%zu entries successfully", results.size(), detect.entries.size());
    return results;
}

} // namespace vmp
