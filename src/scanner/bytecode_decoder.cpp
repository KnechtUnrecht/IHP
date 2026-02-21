#include "bytecode_decoder.h"
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace ihp {

// Opcode table (all 256 JVM opcodes)

const OpcodeInfo BytecodeDecoder::OPCODES[256] = {
    {"nop",             0}, // 0x00
    {"aconst_null",     0}, // 0x01
    {"iconst_m1",       0}, // 0x02
    {"iconst_0",        0}, // 0x03
    {"iconst_1",        0}, // 0x04
    {"iconst_2",        0}, // 0x05
    {"iconst_3",        0}, // 0x06
    {"iconst_4",        0}, // 0x07
    {"iconst_5",        0}, // 0x08
    {"lconst_0",        0}, // 0x09
    {"lconst_1",        0}, // 0x0A
    {"fconst_0",        0}, // 0x0B
    {"fconst_1",        0}, // 0x0C
    {"fconst_2",        0}, // 0x0D
    {"dconst_0",        0}, // 0x0E
    {"dconst_1",        0}, // 0x0F
    {"bipush",          1}, // 0x10
    {"sipush",          2}, // 0x11
    {"ldc",             1}, // 0x12
    {"ldc_w",           2}, // 0x13
    {"ldc2_w",          2}, // 0x14
    {"iload",           1}, // 0x15
    {"lload",           1}, // 0x16
    {"fload",           1}, // 0x17
    {"dload",           1}, // 0x18
    {"aload",           1}, // 0x19
    {"iload_0",         0}, // 0x1A
    {"iload_1",         0}, // 0x1B
    {"iload_2",         0}, // 0x1C
    {"iload_3",         0}, // 0x1D
    {"lload_0",         0}, // 0x1E
    {"lload_1",         0}, // 0x1F
    {"lload_2",         0}, // 0x20
    {"lload_3",         0}, // 0x21
    {"fload_0",         0}, // 0x22
    {"fload_1",         0}, // 0x23
    {"fload_2",         0}, // 0x24
    {"fload_3",         0}, // 0x25
    {"dload_0",         0}, // 0x26
    {"dload_1",         0}, // 0x27
    {"dload_2",         0}, // 0x28
    {"dload_3",         0}, // 0x29
    {"aload_0",         0}, // 0x2A
    {"aload_1",         0}, // 0x2B
    {"aload_2",         0}, // 0x2C
    {"aload_3",         0}, // 0x2D
    {"iaload",          0}, // 0x2E
    {"laload",          0}, // 0x2F
    {"faload",          0}, // 0x30
    {"daload",          0}, // 0x31
    {"aaload",          0}, // 0x32
    {"baload",          0}, // 0x33
    {"caload",          0}, // 0x34
    {"saload",          0}, // 0x35
    {"istore",          1}, // 0x36
    {"lstore",          1}, // 0x37
    {"fstore",          1}, // 0x38
    {"dstore",          1}, // 0x39
    {"astore",          1}, // 0x3A
    {"istore_0",        0}, // 0x3B
    {"istore_1",        0}, // 0x3C
    {"istore_2",        0}, // 0x3D
    {"istore_3",        0}, // 0x3E
    {"lstore_0",        0}, // 0x3F
    {"lstore_1",        0}, // 0x40
    {"lstore_2",        0}, // 0x41
    {"lstore_3",        0}, // 0x42
    {"fstore_0",        0}, // 0x43
    {"fstore_1",        0}, // 0x44
    {"fstore_2",        0}, // 0x45
    {"fstore_3",        0}, // 0x46
    {"dstore_0",        0}, // 0x47
    {"dstore_1",        0}, // 0x48
    {"dstore_2",        0}, // 0x49
    {"dstore_3",        0}, // 0x4A
    {"astore_0",        0}, // 0x4B
    {"astore_1",        0}, // 0x4C
    {"astore_2",        0}, // 0x4D
    {"astore_3",        0}, // 0x4E
    {"iastore",         0}, // 0x4F
    {"lastore",         0}, // 0x50
    {"fastore",         0}, // 0x51
    {"dastore",         0}, // 0x52
    {"aastore",         0}, // 0x53
    {"bastore",         0}, // 0x54
    {"castore",         0}, // 0x55
    {"sastore",         0}, // 0x56
    {"pop",             0}, // 0x57
    {"pop2",            0}, // 0x58
    {"dup",             0}, // 0x59
    {"dup_x1",          0}, // 0x5A
    {"dup_x2",          0}, // 0x5B
    {"dup2",            0}, // 0x5C
    {"dup2_x1",         0}, // 0x5D
    {"dup2_x2",         0}, // 0x5E
    {"swap",            0}, // 0x5F
    {"iadd",            0}, // 0x60
    {"ladd",            0}, // 0x61
    {"fadd",            0}, // 0x62
    {"dadd",            0}, // 0x63
    {"isub",            0}, // 0x64
    {"lsub",            0}, // 0x65
    {"fsub",            0}, // 0x66
    {"dsub",            0}, // 0x67
    {"imul",            0}, // 0x68
    {"lmul",            0}, // 0x69
    {"fmul",            0}, // 0x6A
    {"dmul",            0}, // 0x6B
    {"idiv",            0}, // 0x6C
    {"ldiv",            0}, // 0x6D
    {"fdiv",            0}, // 0x6E
    {"ddiv",            0}, // 0x6F
    {"irem",            0}, // 0x70
    {"lrem",            0}, // 0x71
    {"frem",            0}, // 0x72
    {"drem",            0}, // 0x73
    {"ineg",            0}, // 0x74
    {"lneg",            0}, // 0x75
    {"fneg",            0}, // 0x76
    {"dneg",            0}, // 0x77
    {"ishl",            0}, // 0x78
    {"lshl",            0}, // 0x79
    {"ishr",            0}, // 0x7A
    {"lshr",            0}, // 0x7B
    {"iushr",           0}, // 0x7C
    {"lushr",           0}, // 0x7D
    {"iand",            0}, // 0x7E
    {"land",            0}, // 0x7F
    {"ior",             0}, // 0x80
    {"lor",             0}, // 0x81
    {"ixor",            0}, // 0x82
    {"lxor",            0}, // 0x83
    {"iinc",            2}, // 0x84
    {"i2l",             0}, // 0x85
    {"i2f",             0}, // 0x86
    {"i2d",             0}, // 0x87
    {"l2i",             0}, // 0x88
    {"l2f",             0}, // 0x89
    {"l2d",             0}, // 0x8A
    {"f2i",             0}, // 0x8B
    {"f2l",             0}, // 0x8C
    {"f2d",             0}, // 0x8D
    {"d2i",             0}, // 0x8E
    {"d2l",             0}, // 0x8F
    {"d2f",             0}, // 0x90
    {"i2b",             0}, // 0x91
    {"i2c",             0}, // 0x92
    {"i2s",             0}, // 0x93
    {"lcmp",            0}, // 0x94
    {"fcmpl",           0}, // 0x95
    {"fcmpg",           0}, // 0x96
    {"dcmpl",           0}, // 0x97
    {"dcmpg",           0}, // 0x98
    {"ifeq",            2}, // 0x99
    {"ifne",            2}, // 0x9A
    {"iflt",            2}, // 0x9B
    {"ifge",            2}, // 0x9C
    {"ifgt",            2}, // 0x9D
    {"ifle",            2}, // 0x9E
    {"if_icmpeq",       2}, // 0x9F
    {"if_icmpne",       2}, // 0xA0
    {"if_icmplt",       2}, // 0xA1
    {"if_icmpge",       2}, // 0xA2
    {"if_icmpgt",       2}, // 0xA3
    {"if_icmple",       2}, // 0xA4
    {"if_acmpeq",       2}, // 0xA5
    {"if_acmpne",       2}, // 0xA6
    {"goto",            2}, // 0xA7
    {"jsr",             2}, // 0xA8
    {"ret",             1}, // 0xA9
    {"tableswitch",    -1}, // 0xAA
    {"lookupswitch",   -1}, // 0xAB
    {"ireturn",         0}, // 0xAC
    {"lreturn",         0}, // 0xAD
    {"freturn",         0}, // 0xAE
    {"dreturn",         0}, // 0xAF
    {"areturn",         0}, // 0xB0
    {"return",          0}, // 0xB1
    {"getstatic",       2}, // 0xB2
    {"putstatic",       2}, // 0xB3
    {"getfield",        2}, // 0xB4
    {"putfield",        2}, // 0xB5
    {"invokevirtual",   2}, // 0xB6
    {"invokespecial",   2}, // 0xB7
    {"invokestatic",    2}, // 0xB8
    {"invokeinterface", 4}, // 0xB9
    {"invokedynamic",   4}, // 0xBA
    {"new",             2}, // 0xBB
    {"newarray",        1}, // 0xBC
    {"anewarray",       2}, // 0xBD
    {"arraylength",     0}, // 0xBE
    {"athrow",          0}, // 0xBF
    {"checkcast",       2}, // 0xC0
    {"instanceof",      2}, // 0xC1
    {"monitorenter",    0}, // 0xC2
    {"monitorexit",     0}, // 0xC3
    {"wide",           -1}, // 0xC4
    {"multianewarray",  3}, // 0xC5
    {"ifnull",          2}, // 0xC6
    {"ifnonnull",       2}, // 0xC7
    {"goto_w",          4}, // 0xC8
    {"jsr_w",           4}, // 0xC9
    {"breakpoint",      0}, // 0xCA
    // 0xCB - 0xFD: undefined
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"<undefined>",0},{"<undefined>",0},{"<undefined>",0},
    {"impdep1",         0}, // 0xFE
    {"impdep2",         0}, // 0xFF
};

// --- suspicious patterns --- (the magic or something like that (>.O) )

BytecodeDecoder::BytecodeDecoder() {
    init_suspicious_patterns();
}

void BytecodeDecoder::init_suspicious_patterns() {
    suspicious_apis_ = {
        // Command execution
        "java/lang/Runtime.exec",
        "java/lang/Runtime.getRuntime",
        "java/lang/ProcessBuilder.<init>",
        "java/lang/ProcessBuilder.start",
        "java/lang/ProcessBuilder.command",
        // Dynamic class loading
        "java/lang/Class.forName",
        "java/lang/ClassLoader.loadClass",
        "java/lang/ClassLoader.defineClass",
        "java/net/URLClassLoader.<init>",
        "java/net/URLClassLoader.loadClass",
        "java/net/URLClassLoader.newInstance",
        // Reflection
        "java/lang/reflect/Method.invoke",
        "java/lang/reflect/Constructor.newInstance",
        "java/lang/Class.getDeclaredMethod",
        "java/lang/Class.getDeclaredField",
        "java/lang/Class.getMethod",
        "java/lang/reflect/Field.setAccessible",
        "java/lang/reflect/Method.setAccessible",
        // Network / Sockets
        "java/net/Socket.<init>",
        "java/net/ServerSocket.<init>",
        "java/net/URL.openConnection",
        "java/net/URL.openStream",
        "java/net/HttpURLConnection",
        "javax/net/ssl/HttpsURLConnection",
        // File system
        "java/io/FileOutputStream.<init>",
        "java/io/FileWriter.<init>",
        "java/io/File.delete",
        "java/io/File.deleteOnExit",
        "java/nio/file/Files.write",
        "java/nio/file/Files.delete",
        "java/nio/file/Files.copy",
        "java/nio/file/Files.move",
        // Screen / Clipboard / KeyLogger
        "java/awt/Robot.createScreenCapture",
        "java/awt/Robot.<init>",
        "java/awt/Toolkit.getSystemClipboard",
        "java/awt/event/KeyListener",
        // Registry / Persistence
        "java/util/prefs/Preferences.systemRoot",
        "java/util/prefs/Preferences.userRoot",
        // Crypto / Encoding (often used to hide payloads)
        "java/util/Base64$Decoder.decode",
        "javax/crypto/Cipher.getInstance",
        "javax/crypto/Cipher.doFinal",
        // System properties / env
        "java/lang/System.getenv",
        "java/lang/System.getProperty",
        // Thread (stealth)
        "java/lang/Thread.setDaemon",
        // Dc (Discord Obviously) / webhook exfiltration
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
    };
}

bool BytecodeDecoder::check_suspicious(const std::string& resolved_ref, std::string& reason) const {
    for (const auto& pattern : suspicious_apis_) {
        if (resolved_ref.find(pattern) != std::string::npos) {
            // Determine reason category
            if (pattern.find("Runtime") != std::string::npos || pattern.find("ProcessBuilder") != std::string::npos)
                reason = "CMD_EXEC: " + pattern;
            else if (pattern.find("forName") != std::string::npos || pattern.find("ClassLoader") != std::string::npos || pattern.find("URLClassLoader") != std::string::npos)
                reason = "DYNAMIC_LOADING: " + pattern;
            else if (pattern.find("reflect") != std::string::npos || pattern.find("getDeclared") != std::string::npos || pattern.find("setAccessible") != std::string::npos)
                reason = "REFLECTION: " + pattern;
            else if (pattern.find("Socket") != std::string::npos || pattern.find("URL") != std::string::npos || pattern.find("HttpURLConnection") != std::string::npos || pattern.find("HttpsURLConnection") != std::string::npos)
                reason = "NETWORK: " + pattern;
            else if (pattern.find("File") != std::string::npos || pattern.find("Files") != std::string::npos)
                reason = "FILE_ACCESS: " + pattern;
            else if (pattern.find("Robot") != std::string::npos || pattern.find("Clipboard") != std::string::npos || pattern.find("KeyListener") != std::string::npos)
                reason = "SURVEILLANCE: " + pattern;
            else if (pattern.find("discord") != std::string::npos || pattern.find("webhook") != std::string::npos)
                reason = "EXFILTRATION: " + pattern;
            else
                reason = "SUSPICIOUS: " + pattern;
            return true;
        }
    }
    return false;
}

// --- read helpers ---

uint8_t BytecodeDecoder::read_u1(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr >= end) throw std::runtime_error("unexpected end of class data");
    return *ptr++;
}

uint16_t BytecodeDecoder::read_u2(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr + 2 > end) throw std::runtime_error("unexpected end of class data");
    uint16_t val = (static_cast<uint16_t>(ptr[0]) << 8) | ptr[1];
    ptr += 2;
    return val;
}

uint32_t BytecodeDecoder::read_u4(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr + 4 > end) throw std::runtime_error("unexpected end of class data");
    uint32_t val = (static_cast<uint32_t>(ptr[0]) << 24) |
                   (static_cast<uint32_t>(ptr[1]) << 16) |
                   (static_cast<uint32_t>(ptr[2]) << 8) |
                    static_cast<uint32_t>(ptr[3]);
    ptr += 4;
    return val;
}

// --- constant pool resolution --

std::string BytecodeDecoder::resolve_utf8(uint16_t idx) const {
    if (idx == 0 || idx >= pool_.size()) return "";
    if (pool_[idx].tag == CP_Utf8) return pool_[idx].utf8_value;
    return "";
}

std::string BytecodeDecoder::resolve_class(uint16_t idx) const {
    if (idx == 0 || idx >= pool_.size()) return "";
    if (pool_[idx].tag == CP_Class) {
        return resolve_utf8(pool_[idx].index1);
    }
    return "";
}

std::string BytecodeDecoder::resolve_name_and_type(uint16_t idx) const {
    if (idx == 0 || idx >= pool_.size()) return "";
    if (pool_[idx].tag == CP_NameAndType) {
        std::string name = resolve_utf8(pool_[idx].index1);
        std::string desc = resolve_utf8(pool_[idx].index2);
        return name + ":" + desc;
    }
    return "";
}

std::string BytecodeDecoder::resolve_method_or_field_ref(uint16_t idx) const {
    if (idx == 0 || idx >= pool_.size()) return "";
    const auto& e = pool_[idx];
    if (e.tag == CP_Methodref || e.tag == CP_InterfaceMethodref || e.tag == CP_Fieldref) {
        std::string cls = resolve_class(e.index1);
        std::string nat = resolve_name_and_type(e.index2);
        if (!cls.empty() && !nat.empty())
            return cls + "." + nat;
        if (!cls.empty()) return cls;
        return nat;
    }
    return "";
}

std::string BytecodeDecoder::resolve_constant(uint16_t idx) const {
    if (idx == 0 || idx >= pool_.size()) return "";
    const auto& e = pool_[idx];
    char buf[64];
    switch (e.tag) {
        case CP_String: {
            std::string s = resolve_utf8(e.index1);
            if (s.length() > 80) s = s.substr(0, 77) + "...";
            // Escape special chars (my mom told me i am special so i know what im doing (~.~) (percussion emoji))
            std::string escaped;
            for (char c : s) {
                if (c == '\n') escaped += "\\n";
                else if (c == '\r') escaped += "\\r";
                else if (c == '\t') escaped += "\\t";
                else if (c == '"') escaped += "\\\"";
                else if (c == '\\') escaped += "\\\\";
                else if (c >= 32 && c < 127) escaped += c;
                else { snprintf(buf, sizeof(buf), "\\x%02x", (unsigned char)c); escaped += buf; }
            }
            return "\"" + escaped + "\"";
        }
        case CP_Integer:
            snprintf(buf, sizeof(buf), "%d", e.int_value);
            return buf;
        case CP_Float:
            snprintf(buf, sizeof(buf), "%gf", e.float_value);
            return buf;
        case CP_Long:
            snprintf(buf, sizeof(buf), "%lldL", (long long)e.long_value);
            return buf;
        case CP_Double:
            snprintf(buf, sizeof(buf), "%gd", e.double_value);
            return buf;
        case CP_Class:
            return resolve_class(idx);
        case CP_Utf8:
            return e.utf8_value;
        default:
            return "<cp#" + std::to_string(idx) + ">";
    }
}

// --- access flag decoding ---

std::string BytecodeDecoder::decode_class_access(uint16_t flags) {
    std::string r;
    if (flags & 0x0001) r += "public ";
    if (flags & 0x0010) r += "final ";
    if (flags & 0x0020) r += "super ";
    if (flags & 0x0200) r += "interface ";
    if (flags & 0x0400) r += "abstract ";
    if (flags & 0x1000) r += "synthetic ";
    if (flags & 0x2000) r += "annotation ";
    if (flags & 0x4000) r += "enum ";
    if (!r.empty() && r.back() == ' ') r.pop_back();
    return r;
}

std::string BytecodeDecoder::decode_method_access(uint16_t flags) {
    std::string r;
    if (flags & 0x0001) r += "public ";
    if (flags & 0x0002) r += "private ";
    if (flags & 0x0004) r += "protected ";
    if (flags & 0x0008) r += "static ";
    if (flags & 0x0010) r += "final ";
    if (flags & 0x0020) r += "synchronized ";
    if (flags & 0x0040) r += "bridge ";
    if (flags & 0x0080) r += "varargs ";
    if (flags & 0x0100) r += "native ";
    if (flags & 0x0400) r += "abstract ";
    if (flags & 0x0800) r += "strictfp ";
    if (flags & 0x1000) r += "synthetic ";
    if (!r.empty() && r.back() == ' ') r.pop_back();
    return r;
}

std::string BytecodeDecoder::decode_field_access(uint16_t flags) {
    std::string r;
    if (flags & 0x0001) r += "public ";
    if (flags & 0x0002) r += "private ";
    if (flags & 0x0004) r += "protected ";
    if (flags & 0x0008) r += "static ";
    if (flags & 0x0010) r += "final ";
    if (flags & 0x0040) r += "volatile ";
    if (flags & 0x0080) r += "transient ";
    if (flags & 0x1000) r += "synthetic ";
    if (flags & 0x4000) r += "enum ";
    if (!r.empty() && r.back() == ' ') r.pop_back();
    return r;
}

std::string BytecodeDecoder::major_to_java_version(uint16_t major) {
    if (major <= 44) return "Java 1.0";
    if (major <= 48) return "Java 1." + std::to_string(major - 44);
    return "Java " + std::to_string(major - 44);
}

// --- bytecode disassembler ---

std::vector<DecodedInstruction> BytecodeDecoder::decode_bytecode(
    const uint8_t* code, size_t code_length)
{
    std::vector<DecodedInstruction> instructions;
    const uint8_t* start = code;
    const uint8_t* ptr = code;
    const uint8_t* end = code + code_length;

    while (ptr < end) {
        DecodedInstruction instr;
        instr.offset = static_cast<uint32_t>(ptr - start);
        instr.opcode = *ptr++;

        const auto& info = OPCODES[instr.opcode];
        instr.mnemonic = info.mnemonic ? info.mnemonic : "<unknown>";

        if (info.operand_bytes == 0) {
            // No operands
        }
        else if (info.operand_bytes == -1) {
            // Variable-length opcodes
            if (instr.opcode == 0xAA) {
                // tableswitch
                // Align to 4-byte boundary relative to method start
                while ((ptr - start) % 4 != 0 && ptr < end) ptr++;
                if (ptr + 12 > end) break;
                int32_t default_off = static_cast<int32_t>(read_u4(ptr, end));
                int32_t low = static_cast<int32_t>(read_u4(ptr, end));
                int32_t high = static_cast<int32_t>(read_u4(ptr, end));
                int32_t count = high - low + 1;
                char buf[128];
                snprintf(buf, sizeof(buf), "%d to %d, default->%d", low, high,
                         (int)instr.offset + default_off);
                instr.operand_str = buf;
                // Skip jump table
                for (int32_t i = 0; i < count && ptr + 4 <= end; i++) {
                    ptr += 4;
                }
            }
            else if (instr.opcode == 0xAB) {
                // lookupswitch
                while ((ptr - start) % 4 != 0 && ptr < end) ptr++;
                if (ptr + 8 > end) break;
                int32_t default_off = static_cast<int32_t>(read_u4(ptr, end));
                int32_t npairs = static_cast<int32_t>(read_u4(ptr, end));
                char buf[128];
                snprintf(buf, sizeof(buf), "%d pairs, default->%d",
                         npairs, (int)instr.offset + default_off);
                instr.operand_str = buf;
                for (int32_t i = 0; i < npairs && ptr + 8 <= end; i++) {
                    ptr += 8; // key + offset
                }
            }
            else if (instr.opcode == 0xC4) {
                // wide
                if (ptr >= end) break;
                uint8_t sub_opcode = *ptr++;
                instr.mnemonic = std::string("wide ") + (OPCODES[sub_opcode].mnemonic ? OPCODES[sub_opcode].mnemonic : "?");
                if (sub_opcode == 0x84) {
                    // wide iinc: 2-byte index + 2-byte const
                    if (ptr + 4 > end) break;
                    uint16_t idx = read_u2(ptr, end);
                    int16_t val = static_cast<int16_t>(read_u2(ptr, end));
                    char buf[64];
                    snprintf(buf, sizeof(buf), "%d, %d", idx, val);
                    instr.operand_str = buf;
                } else {
                    // wide load/store: 2-byte index
                    if (ptr + 2 > end) break;
                    uint16_t idx = read_u2(ptr, end);
                    instr.operand_str = std::to_string(idx);
                }
            }
        }
        else {
            // Fixed-length operands
            int nbytes = info.operand_bytes;
            if (ptr + nbytes > end) break;

            // Read raw operand value
            uint16_t op16 = 0;
            uint8_t op8 = 0;

            switch (instr.opcode) {
                // 1-byte constant pool index
                case 0x12: { // ldc
                    op8 = *ptr++;
                    std::string resolved = resolve_constant(op8);
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", op8);
                    instr.operand_str = std::string(buf) + "  // " + resolved;
                    break;
                }
                // 2-byte constant pool index — invoke, field, new, checkcast, etc.
                case 0x13: // ldc_w
                case 0x14: // ldc2_w
                {
                    op16 = read_u2(ptr, end);
                    std::string resolved = resolve_constant(op16);
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", op16);
                    instr.operand_str = std::string(buf) + "  // " + resolved;
                    break;
                }
                case 0xB2: // getstatic
                case 0xB3: // putstatic
                case 0xB4: // getfield
                case 0xB5: // putfield
                case 0xB6: // invokevirtual
                case 0xB7: // invokespecial
                case 0xB8: // invokestatic
                {
                    op16 = read_u2(ptr, end);
                    std::string resolved = resolve_method_or_field_ref(op16);
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", op16);
                    instr.operand_str = std::string(buf) + "  // " + resolved;
                    break;
                }
                case 0xB9: // invokeinterface
                {
                    op16 = read_u2(ptr, end);
                    uint8_t count = *ptr++; // count
                    ptr++; // always 0
                    std::string resolved = resolve_method_or_field_ref(op16);
                    char buf[32];
                    snprintf(buf, sizeof(buf), "#%d, %d", op16, count);
                    instr.operand_str = std::string(buf) + "  // " + resolved;
                    break;
                }
                case 0xBA: // invokedynamic
                {
                    op16 = read_u2(ptr, end);
                    ptr += 2; // two zero bytes
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", op16);
                    // Try to resolve InvokeDynamic entry
                    if (op16 < pool_.size() && pool_[op16].tag == CP_InvokeDynamic) {
                        std::string nat = resolve_name_and_type(pool_[op16].index2);
                        instr.operand_str = std::string(buf) + "  // InvokeDynamic " + nat;
                    } else {
                        instr.operand_str = buf;
                    }
                    break;
                }
                case 0xBB: // new
                case 0xBD: // anewarray
                case 0xC0: // checkcast
                case 0xC1: // instanceof
                {
                    op16 = read_u2(ptr, end);
                    std::string resolved = resolve_class(op16);
                    char buf[16];
                    snprintf(buf, sizeof(buf), "#%d", op16);
                    instr.operand_str = std::string(buf) + "  // " + resolved;
                    break;
                }
                // Branch offsets (2-byte signed)
                case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: // if<cond>
                case 0x9F: case 0xA0: case 0xA1: case 0xA2: case 0xA3: case 0xA4: // if_icmp<cond>
                case 0xA5: case 0xA6: // if_acmp<cond>
                case 0xA7: // goto
                case 0xA8: // jsr
                case 0xC6: case 0xC7: // ifnull/ifnonnull
                {
                    int16_t offset = static_cast<int16_t>(read_u2(ptr, end));
                    int32_t target = static_cast<int32_t>(instr.offset) + offset;
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%d (->%d)", offset, target);
                    instr.operand_str = buf;
                    break;
                }
                // 4-byte branch (goto_w, jsr_w)
                case 0xC8: case 0xC9:
                {
                    int32_t offset = static_cast<int32_t>(read_u4(ptr, end));
                    int32_t target = static_cast<int32_t>(instr.offset) + offset;
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%d (->%d)", offset, target);
                    instr.operand_str = buf;
                    break;
                }
                // bipush (1-byte signed value)
                case 0x10:
                {
                    int8_t val = static_cast<int8_t>(*ptr++);
                    instr.operand_str = std::to_string(val);
                    break;
                }
                // sipush (2-byte signed value)
                case 0x11:
                {
                    int16_t val = static_cast<int16_t>(read_u2(ptr, end));
                    instr.operand_str = std::to_string(val);
                    break;
                }
                // iinc (1-byte index, 1-byte const)
                case 0x84:
                {
                    uint8_t idx = *ptr++;
                    int8_t val = static_cast<int8_t>(*ptr++);
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%d, %d", idx, val);
                    instr.operand_str = buf;
                    break;
                }
                // newarray type
                case 0xBC:
                {
                    uint8_t atype = *ptr++;
                    const char* type_names[] = {"", "", "", "", "boolean", "char", "float",
                                                "double", "byte", "short", "int", "long"};
                    if (atype >= 4 && atype <= 11)
                        instr.operand_str = type_names[atype];
                    else
                        instr.operand_str = std::to_string(atype);
                    break;
                }
                // multianewarray (2-byte CP index + 1-byte dimensions)
                case 0xC5:
                {
                    op16 = read_u2(ptr, end);
                    uint8_t dims = *ptr++;
                    std::string resolved = resolve_class(op16);
                    char buf[32];
                    snprintf(buf, sizeof(buf), "#%d, %d", op16, dims);
                    instr.operand_str = std::string(buf) + "  // " + resolved;
                    break;
                }
                default:
                {
                    // Local variable index or other simple operand
                    if (nbytes == 1) {
                        uint8_t val = *ptr++;
                        instr.operand_str = std::to_string(val);
                    } else if (nbytes == 2) {
                        uint16_t val = read_u2(ptr, end);
                        instr.operand_str = std::to_string(val);
                    } else {
                        // Skip remaining bytes
                        for (int b = 0; b < nbytes && ptr < end; b++) ptr++;
                    }
                    break;
                }
            }
        }

        // Check suspicion
        std::string reason;
        if (check_suspicious(instr.operand_str, reason)) {
            instr.is_suspicious = true;
            instr.suspicion_reason = reason;
        }

        instructions.push_back(std::move(instr));
    }

    return instructions;
}

// --- main decoder --- (i already lost the overview...)

DecodedClass BytecodeDecoder::decode(const uint8_t* data, size_t size) {
    DecodedClass dc;
    dc.valid = false;

    if (size < 10) {
        dc.error = "File too small";
        return dc;
    }

    const uint8_t* ptr = data;
    const uint8_t* end = data + size;

    try {
        // Magic
        uint32_t magic = read_u4(ptr, end);
        if (magic != 0xCAFEBABE) {
            dc.error = "Invalid magic number";
            return dc;
        }

        dc.minor_version = read_u2(ptr, end);
        dc.major_version = read_u2(ptr, end);
        dc.java_version_str = major_to_java_version(dc.major_version) +
                              " (" + std::to_string(dc.major_version) + "." +
                              std::to_string(dc.minor_version) + ")";

        // Constant pool
        uint16_t cp_count = read_u2(ptr, end);
        pool_.clear();
        pool_.resize(cp_count);

        for (uint16_t i = 1; i < cp_count; i++) {
            CPEntry& e = pool_[i];
            e.tag = read_u1(ptr, end);

            switch (e.tag) {
                case CP_Utf8: {
                    uint16_t len = read_u2(ptr, end);
                    if (ptr + len > end) throw std::runtime_error("truncated utf8");
                    e.utf8_value.assign(reinterpret_cast<const char*>(ptr), len);
                    ptr += len;
                    break;
                }
                case CP_Integer: {
                    uint32_t raw = read_u4(ptr, end);
                    memcpy(&e.int_value, &raw, 4);
                    break;
                }
                case CP_Float: {
                    uint32_t raw = read_u4(ptr, end);
                    memcpy(&e.float_value, &raw, 4);
                    break;
                }
                case CP_Long: {
                    uint32_t hi = read_u4(ptr, end);
                    uint32_t lo = read_u4(ptr, end);
                    e.long_value = (static_cast<int64_t>(hi) << 32) | lo;
                    i++; // Long takes two slots
                    break;
                }
                case CP_Double: {
                    uint32_t hi = read_u4(ptr, end);
                    uint32_t lo = read_u4(ptr, end);
                    uint64_t raw = (static_cast<uint64_t>(hi) << 32) | lo;
                    memcpy(&e.double_value, &raw, 8);
                    i++; // Double takes two slots
                    break;
                }
                case CP_Class:
                case CP_String:
                case CP_MethodType:
                case CP_Module:
                case CP_Package:
                    e.index1 = read_u2(ptr, end);
                    break;
                case CP_Fieldref:
                case CP_Methodref:
                case CP_InterfaceMethodref:
                case CP_NameAndType:
                    e.index1 = read_u2(ptr, end);
                    e.index2 = read_u2(ptr, end);
                    break;
                case CP_MethodHandle:
                    ptr += 1; // reference_kind
                    e.index1 = read_u2(ptr, end); // reference_index
                    break;
                case CP_Dynamic:
                case CP_InvokeDynamic:
                    e.index1 = read_u2(ptr, end); // bootstrap_method_attr_index
                    e.index2 = read_u2(ptr, end); // name_and_type_index
                    break;
                default:
                    dc.error = "Unknown constant pool tag: " + std::to_string(e.tag);
                    return dc;
            }
        }

        // Resolve string literals
        for (uint16_t i = 1; i < cp_count; i++) {
            if (pool_[i].tag == CP_String) {
                std::string val = resolve_utf8(pool_[i].index1);
                if (!val.empty()) dc.string_literals.push_back(val);
            }
        }

        // Access flags, this/super, interfaces
        uint16_t access_flags = read_u2(ptr, end);
        dc.access_str = decode_class_access(access_flags);

        uint16_t this_class_idx = read_u2(ptr, end);
        dc.this_class = resolve_class(this_class_idx);

        uint16_t super_class_idx = read_u2(ptr, end);
        dc.super_class = resolve_class(super_class_idx);

        uint16_t interfaces_count = read_u2(ptr, end);
        for (uint16_t i = 0; i < interfaces_count; i++) {
            uint16_t iface_idx = read_u2(ptr, end);
            std::string iface = resolve_class(iface_idx);
            if (!iface.empty()) dc.interfaces.push_back(iface);
        }

        // Fields
        uint16_t fields_count = read_u2(ptr, end);
        for (uint16_t i = 0; i < fields_count; i++) {
            DecodedField field;
            uint16_t f_access = read_u2(ptr, end);
            field.access_str = decode_field_access(f_access);
            uint16_t name_idx = read_u2(ptr, end);
            field.name = resolve_utf8(name_idx);
            uint16_t desc_idx = read_u2(ptr, end);
            field.descriptor = resolve_utf8(desc_idx);

            uint16_t attrs_count = read_u2(ptr, end);
            for (uint16_t j = 0; j < attrs_count; j++) {
                ptr += 2; // attribute_name_index
                uint32_t attr_len = read_u4(ptr, end);
                if (ptr + attr_len > end) throw std::runtime_error("truncated field attribute");
                ptr += attr_len;
            }

            dc.fields.push_back(std::move(field));
        }

        // Methods
        uint16_t methods_count = read_u2(ptr, end);
        for (uint16_t i = 0; i < methods_count; i++) {
            DecodedMethod method;
            uint16_t m_access = read_u2(ptr, end);
            method.access_str = decode_method_access(m_access);
            uint16_t name_idx = read_u2(ptr, end);
            method.name = resolve_utf8(name_idx);
            uint16_t desc_idx = read_u2(ptr, end);
            method.descriptor = resolve_utf8(desc_idx);

            uint16_t attrs_count = read_u2(ptr, end);
            for (uint16_t j = 0; j < attrs_count; j++) {
                uint16_t attr_name_idx = read_u2(ptr, end);
                uint32_t attr_len = read_u4(ptr, end);
                const uint8_t* attr_end = ptr + attr_len;
                if (attr_end > end) throw std::runtime_error("truncated method attribute");

                std::string attr_name = resolve_utf8(attr_name_idx);
                if (attr_name == "Code") {
                    method.has_code = true;
                    method.max_stack = read_u2(ptr, end);
                    method.max_locals = read_u2(ptr, end);
                    uint32_t code_length = read_u4(ptr, end);

                    if (ptr + code_length <= end) {
                        method.instructions = decode_bytecode(ptr, code_length);
                        ptr += code_length;
                    }

                    // Exception table
                    if (ptr + 2 <= attr_end) {
                        uint16_t exception_count = read_u2(ptr, end);
                        for (uint16_t k = 0; k < exception_count && ptr + 8 <= attr_end; k++) {
                            ptr += 8; // start_pc, end_pc, handler_pc, catch_type
                        }
                    }

                    // Skip sub-attributes of Code (LineNumberTable, StackMapTable, etc.)
                    if (ptr + 2 <= attr_end) {
                        uint16_t sub_attrs_count = read_u2(ptr, end);
                        for (uint16_t k = 0; k < sub_attrs_count && ptr + 6 <= attr_end; k++) {
                            ptr += 2; // attribute_name_index
                            uint32_t sub_len = read_u4(ptr, end);
                            if (ptr + sub_len <= attr_end) {
                                ptr += sub_len;
                            } else {
                                ptr = attr_end;
                                break;
                            }
                        }
                    }
                } else {
                    ptr = attr_end;
                }
            }

            // Count suspicious instructions
            for (const auto& instr : method.instructions) {
                if (instr.is_suspicious) dc.suspicious_line_count++;
            }

            dc.methods.push_back(std::move(method));
        }

        dc.valid = true;
    }
    catch (const std::exception& e) {
        dc.error = e.what();
        // Partial decode may still be useful
        if (!dc.methods.empty() || !dc.fields.empty()) {
            dc.valid = true;
        }
    }

    // Extract intelligence from string constants and bytecode
    if (dc.valid) {
        extract_intel(dc);
    }

    return dc;
}

// --- intelligence extraction ---

static bool looks_like_url(const std::string& s) {
    return (s.find("http://") != std::string::npos ||
            s.find("https://") != std::string::npos ||
            s.find("ftp://") != std::string::npos);
}

static bool looks_like_webhook(const std::string& s) {
    return (s.find("discord.com/api/webhooks") != std::string::npos ||
            s.find("discordapp.com/api/webhooks") != std::string::npos ||
            s.find("hooks.slack.com") != std::string::npos ||
            s.find("webhook") != std::string::npos);
}

static bool looks_like_ip(const std::string& s) {
    // Simple check for IPv4 pattern: N.N.N.N
    int dots = 0, digits = 0;
    for (char c : s) {
        if (c == '.') { dots++; digits = 0; }
        else if (c >= '0' && c <= '9') { digits++; if (digits > 3) return false; }
        else return false;
    }
    return dots == 3 && !s.empty() && s[0] != '.' && s.back() != '.';
}

static bool looks_like_cmd(const std::string& s) {
    // Common command prefixes
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return (lower.find("cmd /c") != std::string::npos ||
            lower.find("cmd.exe") != std::string::npos ||
            lower.find("powershell") != std::string::npos ||
            lower.find("/bin/sh") != std::string::npos ||
            lower.find("/bin/bash") != std::string::npos ||
            lower.find("bash -c") != std::string::npos ||
            lower.find("reg add") != std::string::npos ||
            lower.find("reg delete") != std::string::npos ||
            lower.find("wmic") != std::string::npos ||
            lower.find("schtasks") != std::string::npos ||
            lower.find("certutil") != std::string::npos ||
            lower.find("bitsadmin") != std::string::npos ||
            lower.find("curl ") != std::string::npos ||
            lower.find("wget ") != std::string::npos ||
            lower.find("taskkill") != std::string::npos ||
            lower.find("net user") != std::string::npos ||
            lower.find("net localgroup") != std::string::npos ||
            lower.find("netsh ") != std::string::npos ||
            lower.find("rundll32") != std::string::npos ||
            lower.find("mshta") != std::string::npos ||
            lower.find("regsvr32") != std::string::npos);
}

static bool looks_like_filepath(const std::string& s) {
    if (s.length() < 4) return false;
    // Windows paths
    if (s.length() >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))
        return true;
    // Environment variable paths
    if (s.find("%APPDATA%") != std::string::npos ||
        s.find("%TEMP%") != std::string::npos ||
        s.find("%USERPROFILE%") != std::string::npos ||
        s.find("%LOCALAPPDATA%") != std::string::npos ||
        s.find("%PROGRAMDATA%") != std::string::npos ||
        s.find("%PROGRAMFILES%") != std::string::npos)
        return true;
    // Unix paths
    if (s.length() >= 5 && s[0] == '/' && (s.find("/tmp/") != std::string::npos ||
        s.find("/home/") != std::string::npos ||
        s.find("/var/") != std::string::npos ||
        s.find("/etc/") != std::string::npos ||
        s.find("/usr/") != std::string::npos))
        return true;
    // user.home + path
    if (s.find("user.home") != std::string::npos ||
        s.find("user.dir") != std::string::npos)
        return true;
    return false;
}

void BytecodeDecoder::extract_intel(DecodedClass& dc) const {
    dc.intel_items.clear();

    // Scan all string literals
    for (const auto& s : dc.string_literals) {
        if (s.empty() || s.length() < 4) continue;

        // URLs
        if (looks_like_url(s)) {
            IntelItem item;
            if (looks_like_webhook(s)) {
                item.category = IntelItem::WEBHOOK;
                item.is_dangerous = true;
                item.detail = "Webhook URL — may be used for data exfiltration";
            } else {
                item.category = IntelItem::URL;
                // Check if URL points to executable/jar/dll downloads
                std::string lower = s;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                if (lower.find(".exe") != std::string::npos ||
                    lower.find(".jar") != std::string::npos ||
                    lower.find(".dll") != std::string::npos ||
                    lower.find(".bat") != std::string::npos ||
                    lower.find(".vbs") != std::string::npos ||
                    lower.find(".ps1") != std::string::npos) {
                    item.category = IntelItem::DOWNLOAD_TARGET;
                    item.is_dangerous = true;
                    item.detail = "Downloads executable payload";
                } else if (lower.find("pastebin.com") != std::string::npos ||
                           lower.find("paste.ee") != std::string::npos ||
                           lower.find("hastebin.com") != std::string::npos ||
                           lower.find("ghostbin.") != std::string::npos ||
                           lower.find("raw.githubusercontent.com") != std::string::npos) {
                    item.is_dangerous = true;
                    item.detail = "Paste/raw service — possible C2 or payload source";
                }
            }
            item.value = s;
            item.context = dc.this_class;
            dc.intel_items.push_back(std::move(item));
        }

        // CMD / Shell commands
        if (looks_like_cmd(s)) {
            IntelItem item;
            item.category = IntelItem::CMD_COMMAND;
            item.value = s;
            item.context = dc.this_class;
            item.is_dangerous = true;
            // Categorize command
            std::string lower = s;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.find("reg add") != std::string::npos || lower.find("schtasks") != std::string::npos)
                item.detail = "Registry/scheduled task modification — persistence mechanism";
            else if (lower.find("taskkill") != std::string::npos)
                item.detail = "Process termination — may kill security software";
            else if (lower.find("net user") != std::string::npos || lower.find("net localgroup") != std::string::npos)
                item.detail = "User/group management — privilege escalation";
            else if (lower.find("certutil") != std::string::npos || lower.find("bitsadmin") != std::string::npos)
                item.detail = "LOLBIN download technique";
            else if (lower.find("powershell") != std::string::npos)
                item.detail = "PowerShell execution — common malware technique";
            else
                item.detail = "Shell command execution";
            dc.intel_items.push_back(std::move(item));
        }

        // File paths
        if (looks_like_filepath(s) && !looks_like_cmd(s)) {
            IntelItem item;
            item.category = IntelItem::FILE_PATH;
            item.value = s;
            item.context = dc.this_class;
            // Check if suspicious
            std::string lower = s;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.find("startup") != std::string::npos ||
                lower.find("autorun") != std::string::npos ||
                lower.find("\\run\\") != std::string::npos) {
                item.is_dangerous = true;
                item.detail = "Startup/autorun path — persistence mechanism";
            } else if (lower.find(".exe") != std::string::npos ||
                       lower.find(".dll") != std::string::npos ||
                       lower.find(".bat") != std::string::npos) {
                item.is_dangerous = true;
                item.detail = "Executable file path";
            } else {
                item.detail = "File system reference";
            }
            dc.intel_items.push_back(std::move(item));
        }

        // IP addresses
        if (looks_like_ip(s)) {
            IntelItem item;
            item.category = IntelItem::IP_ADDRESS;
            item.value = s;
            item.context = dc.this_class;
            item.is_dangerous = true;
            item.detail = "Raw IP address — potential C2 server";
            dc.intel_items.push_back(std::move(item));
        }
    }

    // Also scan method instructions for constructed URLs/commands
    // (strings pushed via ldc that are used with invoke calls)
    for (const auto& method : dc.methods) {
        if (!method.has_code) continue;
        for (size_t i = 0; i < method.instructions.size(); i++) {
            const auto& instr = method.instructions[i];

            // Look for ldc/ldc_w instructions that load suspicious strings
            if (instr.opcode == 0x12 || instr.opcode == 0x13) { // ldc, ldc_w
                // Check if the loaded string contains a URL
                if (instr.operand_str.find("http") != std::string::npos) {
                    // Extract the URL from the operand string (between quotes)
                    auto q1 = instr.operand_str.find('"');
                    auto q2 = instr.operand_str.rfind('"');
                    if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1) {
                        std::string url = instr.operand_str.substr(q1 + 1, q2 - q1 - 1);

                        // Check if next instruction is an invoke that downloads
                        if (i + 1 < method.instructions.size()) {
                            const auto& next = method.instructions[i + 1];
                            if (next.operand_str.find("URL") != std::string::npos ||
                                next.operand_str.find("openConnection") != std::string::npos ||
                                next.operand_str.find("openStream") != std::string::npos) {
                                // Already captured as URL in string literals scan
                            }
                        }
                    }
                }
            }

            // Look for Runtime.exec with a nearby string constant
            if (instr.is_suspicious && instr.suspicion_reason.find("CMD_EXEC") != std::string::npos) {
                // Look backwards for the command string
                for (int j = (int)i - 1; j >= 0 && j >= (int)i - 5; j--) {
                    const auto& prev = method.instructions[j];
                    if (prev.opcode == 0x12 || prev.opcode == 0x13) { // ldc/ldc_w
                        auto q1 = prev.operand_str.find('"');
                        auto q2 = prev.operand_str.rfind('"');
                        if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1) {
                            std::string cmd = prev.operand_str.substr(q1 + 1, q2 - q1 - 1);
                            // Add as CMD_COMMAND if not already added
                            bool already_found = false;
                            for (const auto& existing : dc.intel_items) {
                                if (existing.value == cmd && existing.category == IntelItem::CMD_COMMAND) {
                                    already_found = true;
                                    break;
                                }
                            }
                            if (!already_found && cmd.length() > 2) {
                                IntelItem item;
                                item.category = IntelItem::CMD_COMMAND;
                                item.value = cmd;
                                item.context = dc.this_class + "." + method.name;
                                item.is_dangerous = true;
                                item.detail = "Command passed to Runtime.exec()";
                                dc.intel_items.push_back(std::move(item));
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
}

} // namespace ihp (if you didn't read the readme i got allot of this from Fernflower decompiler. Aint no way im building it myself!)
