#include "class_parser.h"
#include <stdexcept>
#include <cstring>

namespace ihp {

uint8_t ClassParser::read_u1(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr >= end) throw std::runtime_error("unexpected end of class data");
    return *ptr++;
}

uint16_t ClassParser::read_u2(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr + 2 > end) throw std::runtime_error("unexpected end of class data");
    uint16_t val = (static_cast<uint16_t>(ptr[0]) << 8) | ptr[1];
    ptr += 2;
    return val;
}

uint32_t ClassParser::read_u4(const uint8_t*& ptr, const uint8_t* end) {
    if (ptr + 4 > end) throw std::runtime_error("unexpected end of class data");
    uint32_t val = (static_cast<uint32_t>(ptr[0]) << 24) |
                   (static_cast<uint32_t>(ptr[1]) << 16) |
                   (static_cast<uint32_t>(ptr[2]) << 8) |
                    static_cast<uint32_t>(ptr[3]);
    ptr += 4;
    return val;
}

std::string ClassParser::resolve_utf8(uint16_t index, const std::vector<ConstantPoolEntry>& pool) {
    if (index == 0 || index >= pool.size()) return "";
    if (pool[index].tag == CONSTANT_Utf8) return pool[index].utf8_value;
    return "";
}

std::string ClassParser::resolve_class(uint16_t index, const std::vector<ConstantPoolEntry>& pool) {
    if (index == 0 || index >= pool.size()) return "";
    if (pool[index].tag == CONSTANT_Class) {
        return resolve_utf8(pool[index].index1, pool);
    }
    return "";
}

ClassInfo ClassParser::parse(const uint8_t* data, size_t size) {
    ClassInfo info;
    info.valid = false;

    if (size < 10) return info;

    const uint8_t* ptr = data;
    const uint8_t* end = data + size;

    try {
        // Magic number
        uint32_t magic = read_u4(ptr, end);
        if (magic != 0xCAFEBABE) return info;

        info.minor_version = read_u2(ptr, end);
        info.major_version = read_u2(ptr, end);

        // Constant pool
        uint16_t cp_count = read_u2(ptr, end);
        std::vector<ConstantPoolEntry> pool(cp_count);

        for (uint16_t i = 1; i < cp_count; i++) {
            ConstantPoolEntry& entry = pool[i];
            entry.tag = static_cast<ConstantTag>(read_u1(ptr, end));

            switch (entry.tag) {
                case CONSTANT_Utf8: {
                    uint16_t len = read_u2(ptr, end);
                    if (ptr + len > end) throw std::runtime_error("truncated utf8");
                    entry.utf8_value.assign(reinterpret_cast<const char*>(ptr), len);
                    ptr += len;
                    break;
                }
                case CONSTANT_Integer:
                case CONSTANT_Float:
                    ptr += 4;
                    break;
                case CONSTANT_Long:
                case CONSTANT_Double:
                    ptr += 8;
                    i++; // long and double take 2 slots in the constant pool, super annoying
                    break;
                case CONSTANT_Class:
                    entry.index1 = read_u2(ptr, end); // name_index
                    break;
                case CONSTANT_String:
                    entry.index1 = read_u2(ptr, end); // string_index
                    break;
                case CONSTANT_Fieldref:
                case CONSTANT_Methodref:
                case CONSTANT_InterfaceMethodref:
                    entry.index1 = read_u2(ptr, end); // class_index
                    entry.index2 = read_u2(ptr, end); // name_and_type_index
                    break;
                case CONSTANT_NameAndType:
                    entry.index1 = read_u2(ptr, end); // name_index
                    entry.index2 = read_u2(ptr, end); // descriptor_index
                    break;
                case CONSTANT_MethodHandle:
                    ptr += 1; // reference_kind
                    ptr += 2; // reference_index
                    break;
                case CONSTANT_MethodType:
                    ptr += 2; // descriptor_index
                    break;
                case CONSTANT_Dynamic:
                case CONSTANT_InvokeDynamic:
                    ptr += 2; // bootstrap_method_attr_index
                    entry.index2 = read_u2(ptr, end); // name_and_type_index
                    break;
                case CONSTANT_Module:
                case CONSTANT_Package:
                    entry.index1 = read_u2(ptr, end); // name_index
                    break;
                default:
                    // Unknown tag — bail out gracefully
                    return info;
            }
        }

        // Resolve constant pool references
        for (uint16_t i = 1; i < cp_count; i++) {
            const auto& entry = pool[i];
            switch (entry.tag) {
                case CONSTANT_Class: {
                    std::string name = resolve_utf8(entry.index1, pool);
                    if (!name.empty()) info.class_references.push_back(name);
                    break;
                }
                case CONSTANT_String: {
                    std::string val = resolve_utf8(entry.index1, pool);
                    if (!val.empty()) info.string_literals.push_back(val);
                    break;
                }
                case CONSTANT_Fieldref: {
                    FieldRef ref;
                    ref.class_name = resolve_class(entry.index1, pool);
                    if (entry.index2 < pool.size() && pool[entry.index2].tag == CONSTANT_NameAndType) {
                        ref.field_name = resolve_utf8(pool[entry.index2].index1, pool);
                        ref.descriptor = resolve_utf8(pool[entry.index2].index2, pool);
                    }
                    info.field_references.push_back(ref);
                    break;
                }
                case CONSTANT_Methodref:
                case CONSTANT_InterfaceMethodref: {
                    MethodRef ref;
                    ref.class_name = resolve_class(entry.index1, pool);
                    if (entry.index2 < pool.size() && pool[entry.index2].tag == CONSTANT_NameAndType) {
                        ref.method_name = resolve_utf8(pool[entry.index2].index1, pool);
                        ref.descriptor = resolve_utf8(pool[entry.index2].index2, pool);
                    }
                    info.method_references.push_back(ref);
                    break;
                }
                case CONSTANT_NameAndType: {
                    std::string name = resolve_utf8(entry.index1, pool);
                    std::string desc = resolve_utf8(entry.index2, pool);
                    if (!name.empty()) info.name_and_types.push_back(name + ":" + desc);
                    break;
                }
                default:
                    break;
            }
        }

        // Access flags
        uint16_t access_flags = read_u2(ptr, end);

        // This class
        uint16_t this_class_idx = read_u2(ptr, end);
        info.this_class = resolve_class(this_class_idx, pool);

        // Super class
        uint16_t super_class_idx = read_u2(ptr, end);
        info.super_class = resolve_class(super_class_idx, pool);

        // Interfaces
        uint16_t interfaces_count = read_u2(ptr, end);
        for (uint16_t i = 0; i < interfaces_count; i++) {
            uint16_t iface_idx = read_u2(ptr, end);
            std::string iface = resolve_class(iface_idx, pool);
            if (!iface.empty()) info.interfaces.push_back(iface);
        }

        // Fields — scan for native flags
        uint16_t fields_count = read_u2(ptr, end);
        for (uint16_t i = 0; i < fields_count; i++) {
            uint16_t f_access = read_u2(ptr, end);
            ptr += 2; // name_index
            ptr += 2; // descriptor_index
            uint16_t attrs_count = read_u2(ptr, end);
            for (uint16_t j = 0; j < attrs_count; j++) {
                ptr += 2; // attribute_name_index
                uint32_t attr_len = read_u4(ptr, end);
                if (ptr + attr_len > end) throw std::runtime_error("truncated attribute");
                ptr += attr_len;
            }
        }

        // Methods — scan for native flag (0x0100) + lightweight bytecode analysis
        uint16_t methods_count = read_u2(ptr, end);
        for (uint16_t i = 0; i < methods_count; i++) {
            uint16_t m_access = read_u2(ptr, end);
            if (m_access & 0x0100) {
                info.has_native_methods = true;
            }
            uint16_t m_name_idx = read_u2(ptr, end);
            ptr += 2; // descriptor_index

            std::string method_name = resolve_utf8(m_name_idx, pool);

            uint16_t attrs_count = read_u2(ptr, end);
            for (uint16_t j = 0; j < attrs_count; j++) {
                uint16_t attr_name_idx = read_u2(ptr, end);
                uint32_t attr_len = read_u4(ptr, end);
                if (ptr + attr_len > end) throw std::runtime_error("truncated attribute");

                std::string attr_name = resolve_utf8(attr_name_idx, pool);
                if (attr_name == "Code" && attr_len >= 12) {
                    // Parse Code attribute for lightweight instruction analysis
                    const uint8_t* code_start = ptr;
                    uint16_t max_stack = read_u2(ptr, end);
                    uint16_t max_locals = read_u2(ptr, end);
                    uint32_t code_length = read_u4(ptr, end);
                    (void)max_stack; (void)max_locals;

                    if (ptr + code_length <= end && code_length > 0) {
                        MethodCallSequence seq;
                        seq.method_name = method_name;
                        seq.instruction_count = 0;
                        int sb_append_count = 0;

                        const uint8_t* code = ptr;
                        const uint8_t* code_end = ptr + code_length;
                        uint32_t pc = 0;

                        while (code + pc < code_end) {
                            uint8_t opcode = code[pc];
                            seq.instruction_count++;
                            uint32_t next_pc = pc + 1;

                            switch (opcode) {
                                // invokevirtual (0xB6), invokespecial (0xB7),
                                // invokestatic (0xB8), invokeinterface (0xB9)
                                case 0xB6: case 0xB7: case 0xB8: case 0xB9: {
                                    if (code + pc + 2 < code_end) {
                                        uint16_t cp_idx = (static_cast<uint16_t>(code[pc+1]) << 8) | code[pc+2];
                                        // Resolve the method reference
                                        if (cp_idx > 0 && cp_idx < pool.size()) {
                                            const auto& ref = pool[cp_idx];
                                            if (ref.tag == CONSTANT_Methodref || ref.tag == CONSTANT_InterfaceMethodref) {
                                                std::string cls = resolve_class(ref.index1, pool);
                                                std::string mname;
                                                if (ref.index2 < pool.size() && pool[ref.index2].tag == CONSTANT_NameAndType) {
                                                    mname = resolve_utf8(pool[ref.index2].index1, pool);
                                                }
                                                std::string full = cls + "." + mname;
                                                seq.calls.push_back(full);

                                                // Track StringBuilder.append chains
                                                if ((cls == "java/lang/StringBuilder" || cls == "java/lang/StringBuffer") &&
                                                    mname == "append") {
                                                    sb_append_count++;
                                                }

                                                // Track Method.invoke calls
                                                if (cls == "java/lang/reflect/Method" && mname == "invoke") {
                                                    info.reflection_invoke_count++;
                                                }
                                            }
                                        }
                                    }
                                    next_pc = pc + 3;
                                    if (opcode == 0xB9) next_pc = pc + 5; // invokeinterface has 4 operand bytes
                                    break;
                                }
                                // invokedynamic (0xBA) — 4 operand bytes
                                case 0xBA:
                                    next_pc = pc + 5;
                                    break;

                                // Backward branches detect loops
                                // goto (0xA7), if_icmp* (0x9F-0xA6), if* (0x99-0x9E),
                                // ifnull/ifnonnull (0xC6-0xC7), goto_w (0xC8)
                                case 0x99: case 0x9A: case 0x9B: case 0x9C:
                                case 0x9D: case 0x9E: case 0x9F: case 0xA0:
                                case 0xA1: case 0xA2: case 0xA3: case 0xA4:
                                case 0xA5: case 0xA6: case 0xC6: case 0xC7: {
                                    if (code + pc + 2 < code_end) {
                                        int16_t offset = static_cast<int16_t>(
                                            (static_cast<uint16_t>(code[pc+1]) << 8) | code[pc+2]);
                                        if (offset < 0) seq.has_loop = true;
                                    }
                                    next_pc = pc + 3;
                                    break;
                                }
                                case 0xA7: { // goto
                                    if (code + pc + 2 < code_end) {
                                        int16_t offset = static_cast<int16_t>(
                                            (static_cast<uint16_t>(code[pc+1]) << 8) | code[pc+2]);
                                        if (offset < 0) seq.has_loop = true;
                                    }
                                    next_pc = pc + 3;
                                    break;
                                }
                                case 0xC8: { // goto_w
                                    if (code + pc + 4 < code_end) {
                                        int32_t offset = static_cast<int32_t>(
                                            (static_cast<uint32_t>(code[pc+1]) << 24) |
                                            (static_cast<uint32_t>(code[pc+2]) << 16) |
                                            (static_cast<uint32_t>(code[pc+3]) << 8) |
                                             static_cast<uint32_t>(code[pc+4]));
                                        if (offset < 0) seq.has_loop = true;
                                    }
                                    next_pc = pc + 5;
                                    break;
                                }

                                // Variable-length: tableswitch
                                case 0xAA: {
                                    uint32_t pad = (4 - ((pc + 1) % 4)) % 4;
                                    uint32_t base = pc + 1 + pad;
                                    if (base + 12 <= code_length) {
                                        int32_t low = static_cast<int32_t>(
                                            (static_cast<uint32_t>(code[base+4]) << 24) |
                                            (static_cast<uint32_t>(code[base+5]) << 16) |
                                            (static_cast<uint32_t>(code[base+6]) << 8) |
                                             static_cast<uint32_t>(code[base+7]));
                                        int32_t high = static_cast<int32_t>(
                                            (static_cast<uint32_t>(code[base+8]) << 24) |
                                            (static_cast<uint32_t>(code[base+9]) << 16) |
                                            (static_cast<uint32_t>(code[base+10]) << 8) |
                                             static_cast<uint32_t>(code[base+11]));
                                        int32_t count = high - low + 1;
                                        if (count < 0) count = 0;
                                        next_pc = base + 12 + count * 4;
                                    } else {
                                        next_pc = code_length; // bail
                                    }
                                    break;
                                }
                                // Variable-length: lookupswitch
                                case 0xAB: {
                                    uint32_t pad = (4 - ((pc + 1) % 4)) % 4;
                                    uint32_t base = pc + 1 + pad;
                                    if (base + 8 <= code_length) {
                                        int32_t npairs = static_cast<int32_t>(
                                            (static_cast<uint32_t>(code[base+4]) << 24) |
                                            (static_cast<uint32_t>(code[base+5]) << 16) |
                                            (static_cast<uint32_t>(code[base+6]) << 8) |
                                             static_cast<uint32_t>(code[base+7]));
                                        if (npairs < 0) npairs = 0;
                                        next_pc = base + 8 + npairs * 8;
                                    } else {
                                        next_pc = code_length; // bail
                                    }
                                    break;
                                }
                                // wide
                                case 0xC4: {
                                    if (code + pc + 1 < code_end) {
                                        uint8_t sub = code[pc+1];
                                        next_pc = (sub == 0x84) ? pc + 6 : pc + 4;
                                    } else {
                                        next_pc = code_length;
                                    }
                                    break;
                                }

                                // Fixed-length opcodes
                                // 0 operand bytes (most)
                                case 0x00: case 0x01: case 0x02: case 0x03: case 0x04:
                                case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
                                case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x0E:
                                case 0x0F: case 0x1A: case 0x1B: case 0x1C: case 0x1D:
                                case 0x1E: case 0x1F: case 0x20: case 0x21: case 0x22:
                                case 0x23: case 0x24: case 0x25: case 0x26: case 0x27:
                                case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C:
                                case 0x2D: case 0x2E: case 0x2F: case 0x30: case 0x31:
                                case 0x32: case 0x33: case 0x34: case 0x35:
                                case 0x3B: case 0x3C: case 0x3D: case 0x3E: case 0x3F:
                                case 0x40: case 0x41: case 0x42: case 0x43: case 0x44:
                                case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A:
                                case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                                case 0x50: case 0x51: case 0x52: case 0x53: case 0x54:
                                case 0x55: case 0x56: case 0x57: case 0x58: case 0x59:
                                case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E:
                                case 0x5F: case 0x60: case 0x61: case 0x62: case 0x63:
                                case 0x64: case 0x65: case 0x66: case 0x67: case 0x68:
                                case 0x69: case 0x6A: case 0x6B: case 0x6C: case 0x6D:
                                case 0x6E: case 0x6F: case 0x70: case 0x71: case 0x72:
                                case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
                                case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C:
                                case 0x7D: case 0x7E: case 0x7F: case 0x80: case 0x81:
                                case 0x82: case 0x83: case 0x84: // iinc has 2 bytes
                                case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                                case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E:
                                case 0x8F: case 0x90: case 0x91: case 0x92: case 0x93:
                                case 0x94: case 0x95: case 0x96: case 0x97: case 0x98:
                                case 0xAC: case 0xAD: case 0xAE: case 0xAF: case 0xB0:
                                case 0xB1: case 0xBE: case 0xBF: case 0xC2: case 0xC3:
                                    if (opcode == 0x84) next_pc = pc + 3; // iinc
                                    else next_pc = pc + 1;
                                    break;

                                // 1 operand byte
                                case 0x10: case 0x12: case 0x15: case 0x16: case 0x17:
                                case 0x18: case 0x19: case 0x36: case 0x37: case 0x38:
                                case 0x39: case 0x3A: case 0xA9: case 0xBC:
                                    next_pc = pc + 2;
                                    break;

                                // 2 operand bytes
                                case 0x11: case 0x13: case 0x14: // sipush, ldc_w, ldc2_w
                                case 0xA8: // jsr
                                case 0xB2: case 0xB3: case 0xB4: case 0xB5: // getstatic/putstatic/getfield/putfield
                                case 0xBB: case 0xBD: case 0xC0: case 0xC1: // new/anewarray/checkcast/instanceof
                                case 0xC5: // multianewarray — actually 3 bytes
                                    if (opcode == 0xC5) next_pc = pc + 4;
                                    else next_pc = pc + 3;
                                    break;

                                // jsr_w
                                case 0xC9:
                                    next_pc = pc + 5;
                                    break;

                                default:
                                    // Unknown opcode, advance by 1 and hope for the best
                                    next_pc = pc + 1;
                                    break;
                            }

                            if (next_pc <= pc) break; // safety: prevent infinite loop
                            pc = next_pc;
                        }

                        // Track StringBuilder chain count
                        if (sb_append_count >= 5) {
                            info.string_builder_chain_count++;
                        }

                        if (!seq.calls.empty()) {
                            info.method_call_sequences.push_back(std::move(seq));
                        }
                    }

                    // Skip rest of Code attribute (we already parsed it partially)
                    ptr = code_start + attr_len;
                } else {
                    ptr += attr_len;
                }
            }
        }

        info.valid = true;
        // Suppress unused variable warning
        (void)access_flags;
    }
    catch (const std::exception&) {
        // Partial parse is still useful — mark as valid if we got the constant pool
        if (!info.class_references.empty() || !info.string_literals.empty()) {
            info.valid = true;
        }
    }

    return info;
}

} // namespace ihp another one
