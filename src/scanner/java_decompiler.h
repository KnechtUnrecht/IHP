#pragma once
#include "bytecode_decoder.h"
#include <string>
#include <vector>

namespace ihp {

struct DecompiledLine {
    std::string text;
    int indent = 0;            // indentation level (0 = class level, 1 = method, 2 = body)
    bool is_suspicious = false;
    std::string suspicion_reason;
    bool is_comment = false;
    bool is_keyword = false;   // for syntax highlighting: class/method declarations
    bool is_string = false;    // for syntax highlighting: string literals
};

struct DecompiledClass {
    bool valid = false;
    std::string error;
    std::vector<DecompiledLine> lines;
};

class JavaDecompiler {
public:
    // Main entry: decompile a DecodedClass into pseudo-Java source
    DecompiledClass decompile(const DecodedClass& dc);

private:
    // Convert JVM type descriptor to readable Java type
    static std::string descriptor_to_type(const std::string& desc, size_t& pos);
    static std::string descriptor_to_type(const std::string& desc);

    // Parse method descriptor "(Ljava/lang/String;I)V" -> returns (param_types, return_type)
    struct MethodSignature {
        std::string return_type;
        std::vector<std::string> param_types;
    };
    static MethodSignature parse_method_descriptor(const std::string& desc);

    // Convert JVM class name to Java name (/ -> .)
    static std::string class_to_java(const std::string& jvm_name);

    // Decompile a single method's bytecode into pseudo-Java lines
    void decompile_method(const DecodedMethod& method, std::vector<DecompiledLine>& lines);

    // Decompile the method body instructions (called from decompile_method)
    void decompile_method_body(const DecodedMethod& method, std::vector<DecompiledLine>& lines);

    // Extract the resolved reference from an operand string like "#42 // java/lang/Runtime.exec:()V"
    static std::string extract_ref(const std::string& operand_str);

    // Extract the string constant from operand like "#5 // \"hello world\""
    static std::string extract_string(const std::string& operand_str);

    // Extract class name from operand like "#5 // java/lang/StringBuilder"
    static std::string extract_class(const std::string& operand_str);

    // Extract branch target offset from operand like "5 (->12)"
    static int extract_branch_target(const std::string& operand_str);

    // Simple stack simulation for reconstructing expressions
    struct StackItem {
        std::string expr;
        bool is_suspicious = false;
        std::string suspicion_reason;
    };

    std::vector<StackItem> stack_;
    std::vector<std::string> locals_;  // local variable names
    bool method_is_static_ = false;

    void push(const std::string& expr, bool suspicious = false, const std::string& reason = "");
    StackItem pop();
    void clear_stack();

    // Generate local variable name from index
    std::string local_name(int index, bool is_param = false);

    // Emit a decompiled line into the output
    static void emit(std::vector<DecompiledLine>& lines, int indent, const std::string& text,
                     bool suspicious = false, const std::string& reason = "",
                     bool is_comment = false, bool is_keyword = false, bool is_string = false);

    // Parse a method/field reference: "java/lang/Runtime.exec:(Ljava/lang/String;)Ljava/lang/Process;"
    struct ParsedRef {
        std::string class_name;   // "java/lang/Runtime"
        std::string member_name;  // "exec"
        std::string descriptor;   // "(Ljava/lang/String;)Ljava/lang/Process;"
    };
    static ParsedRef parse_ref(const std::string& ref);

    // Count method parameters from descriptor (for pop count)
    static int count_method_params(const std::string& descriptor);
};

} // namespace ihp
