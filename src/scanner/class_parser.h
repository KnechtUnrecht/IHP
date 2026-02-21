#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace ihp {

struct MethodRef {
    std::string class_name;
    std::string method_name;
    std::string descriptor;
};

struct FieldRef {
    std::string class_name;
    std::string field_name;
    std::string descriptor;
};

struct MethodCallSequence {
    std::string method_name;                // e.g., "doStuff" or "<init>"
    std::vector<std::string> calls;
    bool has_loop = false;
    int instruction_count = 0;
};

struct ClassInfo {
    std::string this_class;
    std::string super_class;
    std::vector<std::string> interfaces;
    std::vector<std::string> string_literals;
    std::vector<std::string> class_references;
    std::vector<MethodRef> method_references;
    std::vector<FieldRef> field_references;
    std::vector<std::string> name_and_types;
    bool has_native_methods = false;
    uint16_t major_version = 0;
    uint16_t minor_version = 0;
    bool valid = false;

    // Instruction-level analysis data
    std::vector<MethodCallSequence> method_call_sequences;
    int string_builder_chain_count = 0;
    int reflection_invoke_count = 0;
};

class ClassParser {
public:
    ClassInfo parse(const uint8_t* data, size_t size);

private:
    enum ConstantTag : uint8_t {
        CONSTANT_Utf8 = 1,
        CONSTANT_Integer = 3,
        CONSTANT_Float = 4,
        CONSTANT_Long = 5,
        CONSTANT_Double = 6,
        CONSTANT_Class = 7,
        CONSTANT_String = 8,
        CONSTANT_Fieldref = 9,
        CONSTANT_Methodref = 10,
        CONSTANT_InterfaceMethodref = 11,
        CONSTANT_NameAndType = 12,
        CONSTANT_MethodHandle = 15,
        CONSTANT_MethodType = 16,
        CONSTANT_Dynamic = 17,
        CONSTANT_InvokeDynamic = 18,
        CONSTANT_Module = 19,
        CONSTANT_Package = 20,
    };

    struct ConstantPoolEntry {
        ConstantTag tag;
        std::string utf8_value;
        uint16_t index1 = 0;
        uint16_t index2 = 0;
    };

    uint8_t read_u1(const uint8_t*& ptr, const uint8_t* end);
    uint16_t read_u2(const uint8_t*& ptr, const uint8_t* end);
    uint32_t read_u4(const uint8_t*& ptr, const uint8_t* end);

    std::string resolve_utf8(uint16_t index, const std::vector<ConstantPoolEntry>& pool);
    std::string resolve_class(uint16_t index, const std::vector<ConstantPoolEntry>& pool);
};

} // namespace ihp
