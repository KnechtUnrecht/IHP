#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_set>

namespace ihp {

// Single decoded bytecode instruction
struct DecodedInstruction {
    uint32_t offset = 0;          // byte offset in Code attribute
    uint8_t  opcode = 0;
    std::string mnemonic;         // "invokevirtual", "aload_0"
    std::string operand_str;      // "#42 // java/lang/Runtime.exec:()V"
    bool is_suspicious = false;
    std::string suspicion_reason; // "CMD_EXEC: Runtime.exec"
};

// Decoded method
struct DecodedMethod {
    std::string access_str;       // "public static"
    std::string name;
    std::string descriptor;       // "(Ljava/lang/String;)V"
    uint16_t max_stack = 0;
    uint16_t max_locals = 0;
    std::vector<DecodedInstruction> instructions;
    bool has_code = false;        // false for abstract/native
};

// Decoded field
struct DecodedField {
    std::string access_str;
    std::string name;
    std::string descriptor;
};

// Extracted intelligence item
struct IntelItem {
    enum Category {
        URL,                // http/https URLs found in strings
        CMD_COMMAND,        // Strings that look like shell/cmd commands
        DOWNLOAD_TARGET,    // URL + destination path pair (from context)
        FILE_PATH,          // File system paths referenced
        WEBHOOK,            // Discord/other webhook URLs
        IP_ADDRESS,         // Raw IP addresses
    } category;
    std::string value;          // the actual URL/command/path
    std::string context;        // method or class where found
    std::string detail;         // extra info (e.g. "downloads to %APPDATA%/...")
    bool is_dangerous = false;  // flagged as dangerous
};

// Full decoded class
struct DecodedClass {
    bool valid = false;
    std::string error;

    std::string this_class;
    std::string super_class;
    std::string access_str;
    std::string java_version_str; // "Java 8 (52.0)"
    uint16_t major_version = 0;
    uint16_t minor_version = 0;

    std::vector<std::string> interfaces;
    std::vector<DecodedField> fields;
    std::vector<DecodedMethod> methods;
    std::vector<std::string> string_literals;
    int suspicious_line_count = 0;

    // Extracted intelligence
    std::vector<IntelItem> intel_items;
};

// Opcode table entry
struct OpcodeInfo {
    const char* mnemonic;
    int8_t operand_bytes; // 0, 1, 2, 3, 4, or -1 for variable-length
};

// Bytecode decoder
class BytecodeDecoder {
public:
    BytecodeDecoder();

    // Main entry point: decode raw .class bytes
    DecodedClass decode(const uint8_t* data, size_t size);

private:
    // Constant pool entry (internal)
    enum ConstantTag : uint8_t {
        CP_Utf8 = 1,
        CP_Integer = 3,
        CP_Float = 4,
        CP_Long = 5,
        CP_Double = 6,
        CP_Class = 7,
        CP_String = 8,
        CP_Fieldref = 9,
        CP_Methodref = 10,
        CP_InterfaceMethodref = 11,
        CP_NameAndType = 12,
        CP_MethodHandle = 15,
        CP_MethodType = 16,
        CP_Dynamic = 17,
        CP_InvokeDynamic = 18,
        CP_Module = 19,
        CP_Package = 20,
    };

    struct CPEntry {
        uint8_t tag = 0;
        std::string utf8_value;
        uint16_t index1 = 0;
        uint16_t index2 = 0;
        int32_t  int_value = 0;
        float    float_value = 0;
        int64_t  long_value = 0;
        double   double_value = 0;
    };

    // Read helpers
    static uint8_t  read_u1(const uint8_t*& ptr, const uint8_t* end);
    static uint16_t read_u2(const uint8_t*& ptr, const uint8_t* end);
    static uint32_t read_u4(const uint8_t*& ptr, const uint8_t* end);

    // Constant pool resolution
    std::string resolve_utf8(uint16_t idx) const;
    std::string resolve_class(uint16_t idx) const;
    std::string resolve_name_and_type(uint16_t idx) const;
    std::string resolve_method_or_field_ref(uint16_t idx) const;
    std::string resolve_constant(uint16_t idx) const;

    // Disassemble a Code attribute
    std::vector<DecodedInstruction> decode_bytecode(const uint8_t* code, size_t code_length);

    // Suspicious API check
    bool check_suspicious(const std::string& resolved_ref, std::string& reason) const;

    // Intelligence extraction from string constants
    void extract_intel(DecodedClass& dc) const;

    // Access flag decoding
    static std::string decode_class_access(uint16_t flags);
    static std::string decode_method_access(uint16_t flags);
    static std::string decode_field_access(uint16_t flags);

    // Java version from major_version
    static std::string major_to_java_version(uint16_t major);

    // Opcode table
    static const OpcodeInfo OPCODES[256];

    // Current constant pool (set during decode())
    std::vector<CPEntry> pool_;

    // Suspicious patterns
    std::unordered_set<std::string> suspicious_apis_;
    void init_suspicious_patterns();
};

} // namespace ihp
