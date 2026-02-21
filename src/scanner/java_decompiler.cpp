#include "java_decompiler.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

namespace ihp {

//get some popcorn this is gonna be looonnnggg
// --- Utility helpers ---

void JavaDecompiler::emit(std::vector<DecompiledLine>& lines, int indent,
                          const std::string& text, bool suspicious,
                          const std::string& reason, bool is_comment,
                          bool is_keyword, bool is_string) {
    DecompiledLine line;
    line.text = text;
    line.indent = indent;
    line.is_suspicious = suspicious;
    line.suspicion_reason = reason;
    line.is_comment = is_comment;
    line.is_keyword = is_keyword;
    line.is_string = is_string;
    lines.push_back(std::move(line));
}

void JavaDecompiler::push(const std::string& expr, bool suspicious, const std::string& reason) {
    stack_.push_back({expr, suspicious, reason});
}

JavaDecompiler::StackItem JavaDecompiler::pop() {
    if (stack_.empty()) {
        return {"/* stack underflow */", false, ""};
    }
    StackItem item = std::move(stack_.back());
    stack_.pop_back();
    return item;
}

void JavaDecompiler::clear_stack() {
    stack_.clear();
}

std::string JavaDecompiler::local_name(int index, bool is_param) {
    if (!method_is_static_ && index == 0) {
        return "this";
    }
    if (index < (int)locals_.size() && !locals_[index].empty()) {
        return locals_[index];
    }
    if (is_param) {
        return "arg" + std::to_string(index);
    }
    return "var" + std::to_string(index);
}

// --- Descriptor to Java type conversion ---

std::string JavaDecompiler::descriptor_to_type(const std::string& desc, size_t& pos) {
    if (pos >= desc.size()) return "void";

    char c = desc[pos];
    pos++;

    switch (c) {
        case 'B': return "byte";
        case 'C': return "char";
        case 'D': return "double";
        case 'F': return "float";
        case 'I': return "int";
        case 'J': return "long";
        case 'S': return "short";
        case 'Z': return "boolean";
        case 'V': return "void";
        case '[': {
            std::string element = descriptor_to_type(desc, pos);
            return element + "[]";
        }
        case 'L': {
            size_t semi = desc.find(';', pos);
            if (semi == std::string::npos) {
                // Malformed descriptor, consume rest
                std::string raw = desc.substr(pos);
                pos = desc.size();
                return class_to_java(raw);
            }
            std::string class_name = desc.substr(pos, semi - pos);
            pos = semi + 1;
            return class_to_java(class_name);
        }
        default:
            return std::string(1, c);
    }
}

std::string JavaDecompiler::descriptor_to_type(const std::string& desc) {
    size_t pos = 0;
    return descriptor_to_type(desc, pos);
}

JavaDecompiler::MethodSignature JavaDecompiler::parse_method_descriptor(const std::string& desc) {
    MethodSignature sig;

    if (desc.empty() || desc[0] != '(') {
        sig.return_type = "void";
        return sig;
    }

    size_t pos = 1; // skip '('
    while (pos < desc.size() && desc[pos] != ')') {
        sig.param_types.push_back(descriptor_to_type(desc, pos));
    }

    if (pos < desc.size() && desc[pos] == ')') {
        pos++; // skip ')'
    }

    if (pos < desc.size()) {
        sig.return_type = descriptor_to_type(desc, pos);
    } else {
        sig.return_type = "void";
    }

    return sig;
}

int JavaDecompiler::count_method_params(const std::string& descriptor) {
    if (descriptor.empty() || descriptor[0] != '(') return 0;

    int count = 0;
    size_t pos = 1;
    while (pos < descriptor.size() && descriptor[pos] != ')') {
        char c = descriptor[pos];
        if (c == 'L') {
            size_t semi = descriptor.find(';', pos);
            if (semi == std::string::npos) break;
            pos = semi + 1;
            count++;
        } else if (c == '[') {
            pos++;
            // Arrays: skip until base type
            continue;
        } else if (c == 'D' || c == 'J') {
            // long and double take two slots on the JVM stack,
            // but for our invocation pop count they are one argument
            pos++;
            count++;
        } else {
            pos++;
            count++;
        }
    }
    return count;
}

// --- Class name conversion ---

std::string JavaDecompiler::class_to_java(const std::string& jvm_name) {
    if (jvm_name.empty()) return "Object";

    // Well-known short names
    static const std::unordered_map<std::string, std::string> short_names = {
        {"java/lang/String", "String"},
        {"java/lang/Object", "Object"},
        {"java/lang/Integer", "Integer"},
        {"java/lang/Long", "Long"},
        {"java/lang/Float", "Float"},
        {"java/lang/Double", "Double"},
        {"java/lang/Boolean", "Boolean"},
        {"java/lang/Byte", "Byte"},
        {"java/lang/Character", "Character"},
        {"java/lang/Short", "Short"},
        {"java/lang/Void", "Void"},
        {"java/lang/Class", "Class"},
        {"java/lang/System", "System"},
        {"java/lang/Runtime", "Runtime"},
        {"java/lang/Process", "Process"},
        {"java/lang/ProcessBuilder", "ProcessBuilder"},
        {"java/lang/Thread", "Thread"},
        {"java/lang/Runnable", "Runnable"},
        {"java/lang/Exception", "Exception"},
        {"java/lang/RuntimeException", "RuntimeException"},
        {"java/lang/Throwable", "Throwable"},
        {"java/lang/Error", "Error"},
        {"java/lang/StringBuilder", "StringBuilder"},
        {"java/lang/StringBuffer", "StringBuffer"},
        {"java/lang/Math", "Math"},
        {"java/lang/Number", "Number"},
        {"java/lang/Iterable", "Iterable"},
        {"java/lang/Comparable", "Comparable"},
        {"java/lang/Enum", "Enum"},
        {"java/lang/reflect/Method", "Method"},
        {"java/lang/reflect/Field", "Field"},
        {"java/lang/reflect/Constructor", "Constructor"},
        {"java/util/List", "List"},
        {"java/util/ArrayList", "ArrayList"},
        {"java/util/LinkedList", "LinkedList"},
        {"java/util/Map", "Map"},
        {"java/util/HashMap", "HashMap"},
        {"java/util/TreeMap", "TreeMap"},
        {"java/util/Set", "Set"},
        {"java/util/HashSet", "HashSet"},
        {"java/util/Collection", "Collection"},
        {"java/util/Collections", "Collections"},
        {"java/util/Arrays", "Arrays"},
        {"java/util/Iterator", "Iterator"},
        {"java/util/Optional", "Optional"},
        {"java/util/stream/Stream", "Stream"},
        {"java/util/stream/Collectors", "Collectors"},
        {"java/util/UUID", "UUID"},
        {"java/util/Date", "Date"},
        {"java/util/Random", "Random"},
        {"java/util/regex/Pattern", "Pattern"},
        {"java/util/regex/Matcher", "Matcher"},
        {"java/util/Base64", "Base64"},
        {"java/util/Base64$Decoder", "Base64.Decoder"},
        {"java/util/Base64$Encoder", "Base64.Encoder"},
        {"java/io/File", "File"},
        {"java/io/InputStream", "InputStream"},
        {"java/io/OutputStream", "OutputStream"},
        {"java/io/FileInputStream", "FileInputStream"},
        {"java/io/FileOutputStream", "FileOutputStream"},
        {"java/io/BufferedReader", "BufferedReader"},
        {"java/io/BufferedWriter", "BufferedWriter"},
        {"java/io/InputStreamReader", "InputStreamReader"},
        {"java/io/OutputStreamWriter", "OutputStreamWriter"},
        {"java/io/PrintStream", "PrintStream"},
        {"java/io/IOException", "IOException"},
        {"java/io/Serializable", "Serializable"},
        {"java/io/FileWriter", "FileWriter"},
        {"java/io/FileReader", "FileReader"},
        {"java/io/ByteArrayInputStream", "ByteArrayInputStream"},
        {"java/io/ByteArrayOutputStream", "ByteArrayOutputStream"},
        {"java/net/URL", "URL"},
        {"java/net/URI", "URI"},
        {"java/net/Socket", "Socket"},
        {"java/net/ServerSocket", "ServerSocket"},
        {"java/net/HttpURLConnection", "HttpURLConnection"},
        {"java/net/URLClassLoader", "URLClassLoader"},
        {"java/net/InetAddress", "InetAddress"},
        {"java/net/URLConnection", "URLConnection"},
        {"javax/net/ssl/HttpsURLConnection", "HttpsURLConnection"},
        {"javax/crypto/Cipher", "Cipher"},
        {"javax/crypto/SecretKey", "SecretKey"},
        {"java/nio/file/Files", "Files"},
        {"java/nio/file/Path", "Path"},
        {"java/nio/file/Paths", "Paths"},
        {"java/awt/Robot", "Robot"},
        {"java/awt/Toolkit", "Toolkit"},
    };

    auto it = short_names.find(jvm_name);
    if (it != short_names.end()) {
        return it->second;
    }

    // For everything else, convert slashes to dots and return the simple name
    // If it's in java/lang or a simple name, just use the short class name
    std::string dotted = jvm_name;
    for (auto& ch : dotted) {
        if (ch == '/') ch = '.';
        if (ch == '$') ch = '.';
    }

    // Return just the short class name for readability
    size_t last_dot = dotted.rfind('.');
    if (last_dot != std::string::npos) {
        std::string pkg = dotted.substr(0, last_dot);
        std::string simple = dotted.substr(last_dot + 1);
        // For java.lang classes always use short name
        if (pkg == "java.lang") return simple;
        // For other well-known packages, use short name
        // but keep the full name in a comment-style if ambiguous
        return simple;
    }

    return dotted;
}

// --- Reference parsing from operand strings ---

std::string JavaDecompiler::extract_ref(const std::string& operand_str) {
    // Operand format: "#42  // java/lang/Runtime.exec:(Ljava/lang/String;)Ljava/lang/Process;"
    // We want everything after "// "
    auto comment = operand_str.find("// ");
    if (comment != std::string::npos) {
        return operand_str.substr(comment + 3);
    }
    return operand_str;
}

std::string JavaDecompiler::extract_string(const std::string& operand_str) {
    // Operand format: #5  // "hello world"
    // Find the opening quote after //
    auto comment = operand_str.find("// ");
    if (comment == std::string::npos) return operand_str;

    std::string after = operand_str.substr(comment + 3);
    if (after.size() >= 2 && after.front() == '"' && after.back() == '"') {
        return after; // already quoted
    }
    return after;
}

std::string JavaDecompiler::extract_class(const std::string& operand_str) {
    // Operand format: "#5  // java/lang/StringBuilder"
    auto comment = operand_str.find("// ");
    if (comment != std::string::npos) {
        return operand_str.substr(comment + 3);
    }
    return operand_str;
}

int JavaDecompiler::extract_branch_target(const std::string& operand_str) {
    // Format: "5 (->12)"
    auto arrow = operand_str.find("->");
    if (arrow != std::string::npos) {
        std::string num = operand_str.substr(arrow + 2);
        // Remove trailing ')'
        if (!num.empty() && num.back() == ')') num.pop_back();
        try { return std::stoi(num); } catch (...) {}
    }
    return -1;
}

JavaDecompiler::ParsedRef JavaDecompiler::parse_ref(const std::string& ref) {
    ParsedRef result;

    // Format: "java/lang/Runtime.exec:(Ljava/lang/String;)Ljava/lang/Process;"
    // Split at the last dot before ':'
    auto colon = ref.find(':');
    std::string class_and_member;
    if (colon != std::string::npos) {
        class_and_member = ref.substr(0, colon);
        result.descriptor = ref.substr(colon + 1);
    } else {
        class_and_member = ref;
    }

    auto dot = class_and_member.rfind('.');
    if (dot != std::string::npos) {
        result.class_name = class_and_member.substr(0, dot);
        result.member_name = class_and_member.substr(dot + 1);
    } else {
        result.member_name = class_and_member;
    }

    return result;
}

// --- Main decompile entry point ---

DecompiledClass JavaDecompiler::decompile(const DecodedClass& dc) {
    DecompiledClass result;

    if (!dc.valid) {
        result.valid = false;
        result.error = dc.error;
        return result;
    }

    try {
        auto& lines = result.lines;

        // Header comment
        emit(lines, 0, "// Decompiled by IHP - Pseudo-Java (best-effort reconstruction)", false, "", true);
        emit(lines, 0, "// " + dc.java_version_str, false, "", true);
        emit(lines, 0, "", false, "", false);

        // Package declaration from class name
        std::string java_class = dc.this_class;
        for (auto& ch : java_class) {
            if (ch == '/') ch = '.';
        }

        size_t last_dot = java_class.rfind('.');
        std::string package_name;
        std::string simple_class_name;
        if (last_dot != std::string::npos) {
            package_name = java_class.substr(0, last_dot);
            simple_class_name = java_class.substr(last_dot + 1);
            emit(lines, 0, "package " + package_name + ";", false, "", false, true);
            emit(lines, 0, "", false, "", false);
        } else {
            simple_class_name = java_class;
        }

        // Build a set of referenced classes for "import-like" comments
        std::unordered_set<std::string> referenced_classes;
        for (const auto& m : dc.methods) {
            for (const auto& instr : m.instructions) {
                std::string ref_str = extract_ref(instr.operand_str);
                auto parsed = parse_ref(ref_str);
                if (!parsed.class_name.empty() && parsed.class_name != dc.this_class) {
                    // Convert to dotted form
                    std::string dotted = parsed.class_name;
                    for (auto& ch : dotted) { if (ch == '/') ch = '.'; }
                    // Only add imports for non-java.lang and non-trivial classes
                    if (dotted.find('.') != std::string::npos &&
                        dotted.substr(0, 10) != "java.lang." &&
                        dotted.find("java.lang.") != 0) {
                        referenced_classes.insert(dotted);
                    }
                }
            }
        }

        // Emit imports (as real import statements for readability)
        if (!referenced_classes.empty()) {
            std::vector<std::string> sorted_imports(referenced_classes.begin(), referenced_classes.end());
            std::sort(sorted_imports.begin(), sorted_imports.end());
            for (const auto& imp : sorted_imports) {
                emit(lines, 0, "import " + imp + ";", false, "", false, true);
            }
            emit(lines, 0, "", false, "", false);
        }

        // Class declaration
        std::string class_decl;

        // Filter out JVM internal flags from access string for display
        std::string display_access = dc.access_str;
        // Remove "super" flag (it's a JVM internal flag, not a Java keyword)
        {
            size_t sp = display_access.find("super");
            if (sp != std::string::npos) {
                display_access.erase(sp, 5);
                // Clean up extra spaces
                while (display_access.find("  ") != std::string::npos) {
                    size_t ds = display_access.find("  ");
                    display_access.erase(ds, 1);
                }
                if (!display_access.empty() && display_access[0] == ' ')
                    display_access.erase(0, 1);
                if (!display_access.empty() && display_access.back() == ' ')
                    display_access.pop_back();
            }
        }

        if (!display_access.empty()) {
            class_decl += display_access + " ";
        }

        // Determine if interface or class
        bool is_interface = display_access.find("interface") != std::string::npos;
        bool is_enum = display_access.find("enum") != std::string::npos;

        if (!is_interface && !is_enum) {
            class_decl += "class ";
        }
        class_decl += simple_class_name;

        // Extends
        if (!dc.super_class.empty() && dc.super_class != "java/lang/Object") {
            class_decl += " extends " + class_to_java(dc.super_class);
        }

        // Implements
        if (!dc.interfaces.empty()) {
            class_decl += is_interface ? " extends " : " implements ";
            for (size_t i = 0; i < dc.interfaces.size(); i++) {
                if (i > 0) class_decl += ", ";
                class_decl += class_to_java(dc.interfaces[i]);
            }
        }

        class_decl += " {";
        emit(lines, 0, class_decl, false, "", false, true);
        emit(lines, 0, "", false, "", false);

        // Fields
        for (const auto& f : dc.fields) {
            std::string field_line = "    ";
            if (!f.access_str.empty()) {
                // Remove "synthetic" and "enum" from field display
                std::string fa = f.access_str;
                // Keep it simple: just use the access string
                field_line += fa + " ";
            }
            field_line += descriptor_to_type(f.descriptor) + " " + f.name + ";";
            emit(lines, 1, field_line, false, "", false, false);
        }

        if (!dc.fields.empty()) {
            emit(lines, 0, "", false, "", false);
        }

        // Methods
        for (const auto& m : dc.methods) {
            decompile_method(m, lines);
            emit(lines, 0, "", false, "", false);
        }

        // Closing brace
        emit(lines, 0, "}", false, "", false, true);

        result.valid = true;
    }
    catch (const std::exception& e) {
        result.valid = false;
        result.error = std::string("Decompiler error: ") + e.what();
    }
    catch (...) {
        result.valid = false;
        result.error = "Decompiler encountered an unknown error";
    }

    return result;
}

// --- Method decompilation ---

void JavaDecompiler::decompile_method(const DecodedMethod& method,
                                       std::vector<DecompiledLine>& lines) {
    // Parse method signature
    MethodSignature sig = parse_method_descriptor(method.descriptor);

    method_is_static_ = (method.access_str.find("static") != std::string::npos);

    // Build method declaration
    std::string decl = "    ";

    // Filter display access flags
    std::string display_access = method.access_str;
    // Remove bridge, varargs, synthetic from display
    {
        for (const char* kw : {"bridge", "varargs", "synthetic"}) {
            size_t pos = display_access.find(kw);
            if (pos != std::string::npos) {
                display_access.erase(pos, strlen(kw));
                while (display_access.find("  ") != std::string::npos) {
                    size_t ds = display_access.find("  ");
                    display_access.erase(ds, 1);
                }
            }
        }
        // Trim
        while (!display_access.empty() && display_access[0] == ' ')
            display_access.erase(0, 1);
        while (!display_access.empty() && display_access.back() == ' ')
            display_access.pop_back();
    }

    if (!display_access.empty()) {
        decl += display_access + " ";
    }

    // Handle special method names
    std::string method_display_name = method.name;
    bool is_constructor = (method.name == "<init>");
    bool is_static_init = (method.name == "<clinit>");

    if (is_constructor) {
        // Use class-style declaration (no return type)
        // We don't have the simple class name easily here, so use a generic approach
        method_display_name = "/* <init> */";
        decl += method_display_name;
    } else if (is_static_init) {
        emit(lines, 1, "    static {", false, "", false, true);
        // Static initializer has no signature to display
        // Fall through to body
        if (!method.has_code) {
            emit(lines, 2, "        // (no code)", false, "", true);
            emit(lines, 1, "    }", false, "", false, true);
            return;
        }
        // Decompile body
        clear_stack();
        locals_.clear();
        locals_.resize(method.max_locals);
        decompile_method_body(method, lines);
        emit(lines, 1, "    }", false, "", false, true);
        return;
    } else {
        decl += sig.return_type + " " + method_display_name;
    }

    // Parameters
    decl += "(";
    for (size_t i = 0; i < sig.param_types.size(); i++) {
        if (i > 0) decl += ", ";
        decl += sig.param_types[i] + " arg" + std::to_string(i + (method_is_static_ ? 0 : 1));
    }
    decl += ")";

    if (!method.has_code) {
        decl += ";";
        emit(lines, 1, decl, false, "", false, true);
        return;
    }

    decl += " {";
    emit(lines, 1, decl, false, "", false, true);

    // Prepare local variable slots
    clear_stack();
    locals_.clear();
    locals_.resize(method.max_locals);

    // Name the parameters in the locals table
    int local_idx = method_is_static_ ? 0 : 1; // slot 0 = this for instance methods
    for (size_t i = 0; i < sig.param_types.size(); i++) {
        if (local_idx < (int)locals_.size()) {
            locals_[local_idx] = "arg" + std::to_string(local_idx);
        }
        local_idx++;
        // Double and long take two slots
        if (sig.param_types[i] == "long" || sig.param_types[i] == "double") {
            local_idx++;
        }
    }

    // Decompile the method body
    decompile_method_body(method, lines);

    emit(lines, 1, "    }", false, "", false, true);
}

// --- Method body decompilation (bytecode -> pseudo-java) ---

// Forward declaration of the body decompilation to keep code organized.
// This is called from decompile_method for both regular methods and static initializers.
void JavaDecompiler::decompile_method_body(const DecodedMethod& method,
                                            std::vector<DecompiledLine>& lines) {
    const auto& instrs = method.instructions;
    if (instrs.empty()) return;

    // Track which offsets are branch targets (for placing labels/comments)
    std::unordered_set<int> branch_targets;
    for (const auto& instr : instrs) {
        int target = extract_branch_target(instr.operand_str);
        if (target >= 0) {
            branch_targets.insert(target);
        }
    }

    // Track declared local variables to emit declarations
    std::unordered_set<int> declared_locals;

    for (size_t i = 0; i < instrs.size(); i++) {
        const auto& instr = instrs[i];
        uint8_t op = instr.opcode;
        const std::string& mnemonic = instr.mnemonic;
        const std::string& operand = instr.operand_str;
        bool suspicious = instr.is_suspicious;
        const std::string& susp_reason = instr.suspicion_reason;

        // Check if this offset is a branch target — emit a label comment
        if (branch_targets.count((int)instr.offset)) {
            emit(lines, 2, "      label_" + std::to_string(instr.offset) + ":", false, "", true);
        }

        try {
            // NOP
            if (op == 0x00) {
                // nop - skip silently
                continue;
            }

            // CONSTANTS
            else if (op == 0x01) { // aconst_null
                push("null");
            }
            else if (op >= 0x02 && op <= 0x08) { // iconst_m1 .. iconst_5
                int val = op - 0x03; // iconst_0 = 0x03
                push(std::to_string(val));
            }
            else if (op == 0x09 || op == 0x0A) { // lconst_0, lconst_1
                push(std::to_string(op - 0x09) + "L");
            }
            else if (op >= 0x0B && op <= 0x0D) { // fconst_0, fconst_1, fconst_2
                push(std::to_string(op - 0x0B) + ".0f");
            }
            else if (op == 0x0E || op == 0x0F) { // dconst_0, dconst_1
                push(std::to_string(op - 0x0E) + ".0");
            }
            else if (op == 0x10) { // bipush
                push(operand);
            }
            else if (op == 0x11) { // sipush
                push(operand);
            }
            else if (op == 0x12 || op == 0x13 || op == 0x14) { // ldc, ldc_w, ldc2_w
                std::string val = extract_string(operand);
                push(val, suspicious, susp_reason);
            }

            // LOADS
            else if (op >= 0x15 && op <= 0x19) { // iload, lload, fload, dload, aload
                int idx = 0;
                try { idx = std::stoi(operand); } catch (...) {}
                push(local_name(idx));
            }
            else if (op >= 0x1A && op <= 0x1D) { // iload_0 .. iload_3
                push(local_name(op - 0x1A));
            }
            else if (op >= 0x1E && op <= 0x21) { // lload_0 .. lload_3
                push(local_name(op - 0x1E));
            }
            else if (op >= 0x22 && op <= 0x25) { // fload_0 .. fload_3
                push(local_name(op - 0x22));
            }
            else if (op >= 0x26 && op <= 0x29) { // dload_0 .. dload_3
                push(local_name(op - 0x26));
            }
            else if (op >= 0x2A && op <= 0x2D) { // aload_0 .. aload_3
                push(local_name(op - 0x2A));
            }

            // ARRAY LOADS
            else if (op >= 0x2E && op <= 0x35) {
                // iaload, laload, faload, daload, aaload, baload, caload, saload
                auto index_item = pop();
                auto array_item = pop();
                push(array_item.expr + "[" + index_item.expr + "]",
                     array_item.is_suspicious || index_item.is_suspicious,
                     array_item.suspicion_reason.empty() ? index_item.suspicion_reason : array_item.suspicion_reason);
            }

            // STORES
            else if (op >= 0x36 && op <= 0x3A) { // istore, lstore, fstore, dstore, astore
                int idx = 0;
                try { idx = std::stoi(operand); } catch (...) {}
                auto val = pop();
                std::string vname = local_name(idx);
                // Track that we've set this local
                if (idx < (int)locals_.size() && locals_[idx].empty()) {
                    locals_[idx] = vname;
                }
                std::string stmt;
                if (declared_locals.find(idx) == declared_locals.end()) {
                    declared_locals.insert(idx);
                    stmt = "        var " + vname + " = " + val.expr + ";";
                } else {
                    stmt = "        " + vname + " = " + val.expr + ";";
                }
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }
            else if (op >= 0x3B && op <= 0x3E) { // istore_0 .. istore_3
                int idx = op - 0x3B;
                auto val = pop();
                std::string vname = local_name(idx);
                if (idx < (int)locals_.size() && locals_[idx].empty()) locals_[idx] = vname;
                std::string stmt;
                if (declared_locals.find(idx) == declared_locals.end()) {
                    declared_locals.insert(idx);
                    stmt = "        var " + vname + " = " + val.expr + ";";
                } else {
                    stmt = "        " + vname + " = " + val.expr + ";";
                }
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }
            else if (op >= 0x3F && op <= 0x42) { // lstore_0 .. lstore_3
                int idx = op - 0x3F;
                auto val = pop();
                std::string vname = local_name(idx);
                if (idx < (int)locals_.size() && locals_[idx].empty()) locals_[idx] = vname;
                std::string stmt;
                if (declared_locals.find(idx) == declared_locals.end()) {
                    declared_locals.insert(idx);
                    stmt = "        var " + vname + " = " + val.expr + ";";
                } else {
                    stmt = "        " + vname + " = " + val.expr + ";";
                }
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }
            else if (op >= 0x43 && op <= 0x46) { // fstore_0 .. fstore_3
                int idx = op - 0x43;
                auto val = pop();
                std::string vname = local_name(idx);
                if (idx < (int)locals_.size() && locals_[idx].empty()) locals_[idx] = vname;
                std::string stmt;
                if (declared_locals.find(idx) == declared_locals.end()) {
                    declared_locals.insert(idx);
                    stmt = "        var " + vname + " = " + val.expr + ";";
                } else {
                    stmt = "        " + vname + " = " + val.expr + ";";
                }
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }
            else if (op >= 0x47 && op <= 0x4A) { // dstore_0 .. dstore_3
                int idx = op - 0x47;
                auto val = pop();
                std::string vname = local_name(idx);
                if (idx < (int)locals_.size() && locals_[idx].empty()) locals_[idx] = vname;
                std::string stmt;
                if (declared_locals.find(idx) == declared_locals.end()) {
                    declared_locals.insert(idx);
                    stmt = "        var " + vname + " = " + val.expr + ";";
                } else {
                    stmt = "        " + vname + " = " + val.expr + ";";
                }
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }
            else if (op >= 0x4B && op <= 0x4E) { // astore_0 .. astore_3
                int idx = op - 0x4B;
                auto val = pop();
                std::string vname = local_name(idx);
                if (idx < (int)locals_.size() && locals_[idx].empty()) locals_[idx] = vname;
                std::string stmt;
                if (declared_locals.find(idx) == declared_locals.end()) {
                    declared_locals.insert(idx);
                    stmt = "        var " + vname + " = " + val.expr + ";";
                } else {
                    stmt = "        " + vname + " = " + val.expr + ";";
                }
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }

            // ARRAY STORES
            else if (op >= 0x4F && op <= 0x56) {
                // iastore, lastore, fastore, dastore, aastore, bastore, castore, sastore
                auto val = pop();
                auto index_item = pop();
                auto array_item = pop();
                std::string stmt = "        " + array_item.expr + "[" + index_item.expr + "] = " + val.expr + ";";
                emit(lines, 2, stmt, val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }

            // STACK MANIPULATION
            else if (op == 0x57) { // pop
                auto val = pop();
                // If the popped value looks like a method call, emit it as a statement
                if (val.expr.find('(') != std::string::npos && val.expr != "/* stack underflow */") {
                    emit(lines, 2, "        " + val.expr + ";", val.is_suspicious, val.suspicion_reason);
                }
                // else: silently discard
            }
            else if (op == 0x58) { // pop2
                auto val1 = pop();
                if (val1.expr.find('(') != std::string::npos && val1.expr != "/* stack underflow */") {
                    emit(lines, 2, "        " + val1.expr + ";", val1.is_suspicious, val1.suspicion_reason);
                }
                auto val2 = pop();
                if (val2.expr.find('(') != std::string::npos && val2.expr != "/* stack underflow */") {
                    emit(lines, 2, "        " + val2.expr + ";", val2.is_suspicious, val2.suspicion_reason);
                }
            }
            else if (op == 0x59) { // dup
                if (!stack_.empty()) {
                    auto top = stack_.back();
                    push(top.expr, top.is_suspicious, top.suspicion_reason);
                } else {
                    push("/* dup: empty stack */");
                }
            }
            else if (op == 0x5A) { // dup_x1
                if (stack_.size() >= 2) {
                    auto v1 = pop();
                    auto v2 = pop();
                    push(v1.expr, v1.is_suspicious, v1.suspicion_reason);
                    push(v2.expr, v2.is_suspicious, v2.suspicion_reason);
                    push(v1.expr, v1.is_suspicious, v1.suspicion_reason);
                } else {
                    push("/* dup_x1: stack too small */");
                }
            }
            else if (op == 0x5B) { // dup_x2
                // Best effort: just dup
                if (!stack_.empty()) {
                    auto top = stack_.back();
                    push(top.expr, top.is_suspicious, top.suspicion_reason);
                }
            }
            else if (op == 0x5C) { // dup2
                if (stack_.size() >= 2) {
                    auto v1 = stack_[stack_.size() - 1];
                    auto v2 = stack_[stack_.size() - 2];
                    push(v2.expr, v2.is_suspicious, v2.suspicion_reason);
                    push(v1.expr, v1.is_suspicious, v1.suspicion_reason);
                } else if (!stack_.empty()) {
                    auto top = stack_.back();
                    push(top.expr, top.is_suspicious, top.suspicion_reason);
                }
            }
            else if (op == 0x5D || op == 0x5E) { // dup2_x1, dup2_x2
                // Best effort: treat as nop for stack tracking
            }
            else if (op == 0x5F) { // swap
                if (stack_.size() >= 2) {
                    auto v1 = pop();
                    auto v2 = pop();
                    push(v1.expr, v1.is_suspicious, v1.suspicion_reason);
                    push(v2.expr, v2.is_suspicious, v2.suspicion_reason);
                }
            }

            // ARITHMETIC
            else if (op >= 0x60 && op <= 0x63) { // iadd, ladd, fadd, dadd
                auto b = pop();
                auto a = pop();
                push("(" + a.expr + " + " + b.expr + ")",
                     a.is_suspicious || b.is_suspicious,
                     a.suspicion_reason.empty() ? b.suspicion_reason : a.suspicion_reason);
            }
            else if (op >= 0x64 && op <= 0x67) { // isub, lsub, fsub, dsub
                auto b = pop();
                auto a = pop();
                push("(" + a.expr + " - " + b.expr + ")",
                     a.is_suspicious || b.is_suspicious,
                     a.suspicion_reason.empty() ? b.suspicion_reason : a.suspicion_reason);
            }
            else if (op >= 0x68 && op <= 0x6B) { // imul, lmul, fmul, dmul
                auto b = pop();
                auto a = pop();
                push("(" + a.expr + " * " + b.expr + ")",
                     a.is_suspicious || b.is_suspicious,
                     a.suspicion_reason.empty() ? b.suspicion_reason : a.suspicion_reason);
            }
            else if (op >= 0x6C && op <= 0x6F) { // idiv, ldiv, fdiv, ddiv
                auto b = pop();
                auto a = pop();
                push("(" + a.expr + " / " + b.expr + ")",
                     a.is_suspicious || b.is_suspicious,
                     a.suspicion_reason.empty() ? b.suspicion_reason : a.suspicion_reason);
            }
            else if (op >= 0x70 && op <= 0x73) { // irem, lrem, frem, drem
                auto b = pop();
                auto a = pop();
                push("(" + a.expr + " % " + b.expr + ")",
                     a.is_suspicious || b.is_suspicious,
                     a.suspicion_reason.empty() ? b.suspicion_reason : a.suspicion_reason);
            }
            else if (op >= 0x74 && op <= 0x77) { // ineg, lneg, fneg, dneg
                auto a = pop();
                push("(-" + a.expr + ")", a.is_suspicious, a.suspicion_reason);
            }

            // BIT SHIFTS
            else if (op == 0x78 || op == 0x79) { // ishl, lshl
                auto b = pop(); auto a = pop();
                push("(" + a.expr + " << " + b.expr + ")");
            }
            else if (op == 0x7A || op == 0x7B) { // ishr, lshr
                auto b = pop(); auto a = pop();
                push("(" + a.expr + " >> " + b.expr + ")");
            }
            else if (op == 0x7C || op == 0x7D) { // iushr, lushr
                auto b = pop(); auto a = pop();
                push("(" + a.expr + " >>> " + b.expr + ")");
            }
            else if (op == 0x7E || op == 0x7F) { // iand, land
                auto b = pop(); auto a = pop();
                push("(" + a.expr + " & " + b.expr + ")");
            }
            else if (op == 0x80 || op == 0x81) { // ior, lor
                auto b = pop(); auto a = pop();
                push("(" + a.expr + " | " + b.expr + ")");
            }
            else if (op == 0x82 || op == 0x83) { // ixor, lxor
                auto b = pop(); auto a = pop();
                push("(" + a.expr + " ^ " + b.expr + ")");
            }

            // IINC
            else if (op == 0x84) { // iinc
                // operand: "idx, val"
                int idx = 0, val = 0;
                if (sscanf(operand.c_str(), "%d, %d", &idx, &val) == 2) {
                    std::string vname = local_name(idx);
                    if (val == 1) {
                        emit(lines, 2, "        " + vname + "++;");
                    } else if (val == -1) {
                        emit(lines, 2, "        " + vname + "--;");
                    } else {
                        emit(lines, 2, "        " + vname + " += " + std::to_string(val) + ";");
                    }
                }
            }

            // TYPE CONVERSIONS
            else if (op == 0x85) { auto a = pop(); push("(long)" + a.expr); }   // i2l
            else if (op == 0x86) { auto a = pop(); push("(float)" + a.expr); }  // i2f
            else if (op == 0x87) { auto a = pop(); push("(double)" + a.expr); } // i2d
            else if (op == 0x88) { auto a = pop(); push("(int)" + a.expr); }    // l2i
            else if (op == 0x89) { auto a = pop(); push("(float)" + a.expr); }  // l2f
            else if (op == 0x8A) { auto a = pop(); push("(double)" + a.expr); } // l2d
            else if (op == 0x8B) { auto a = pop(); push("(int)" + a.expr); }    // f2i
            else if (op == 0x8C) { auto a = pop(); push("(long)" + a.expr); }   // f2l
            else if (op == 0x8D) { auto a = pop(); push("(double)" + a.expr); } // f2d
            else if (op == 0x8E) { auto a = pop(); push("(int)" + a.expr); }    // d2i
            else if (op == 0x8F) { auto a = pop(); push("(long)" + a.expr); }   // d2l
            else if (op == 0x90) { auto a = pop(); push("(float)" + a.expr); }  // d2f
            else if (op == 0x91) { auto a = pop(); push("(byte)" + a.expr); }   // i2b
            else if (op == 0x92) { auto a = pop(); push("(char)" + a.expr); }   // i2c
            else if (op == 0x93) { auto a = pop(); push("(short)" + a.expr); }  // i2s

            // COMPARISONS
            else if (op == 0x94) { // lcmp
                auto b = pop(); auto a = pop();
                push("Long.compare(" + a.expr + ", " + b.expr + ")");
            }
            else if (op == 0x95 || op == 0x96) { // fcmpl, fcmpg
                auto b = pop(); auto a = pop();
                push("Float.compare(" + a.expr + ", " + b.expr + ")");
            }
            else if (op == 0x97 || op == 0x98) { // dcmpl, dcmpg
                auto b = pop(); auto a = pop();
                push("Double.compare(" + a.expr + ", " + b.expr + ")");
            }

            // CONDITIONAL BRANCHES
            else if (op == 0x99) { // ifeq
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " == 0) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0x9A) { // ifne
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " != 0) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0x9B) { // iflt
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " < 0) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0x9C) { // ifge
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " >= 0) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0x9D) { // ifgt
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " > 0) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0x9E) { // ifle
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " <= 0) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }

            // INTEGER COMPARISON BRANCHES
            else if (op == 0x9F) { // if_icmpeq
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " == " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xA0) { // if_icmpne
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " != " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xA1) { // if_icmplt
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " < " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xA2) { // if_icmpge
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " >= " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xA3) { // if_icmpgt
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " > " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xA4) { // if_icmple
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " <= " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }

            // REFERENCE COMPARISON BRANCHES
            else if (op == 0xA5) { // if_acmpeq
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " == " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xA6) { // if_acmpne
                auto b = pop(); auto a = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + a.expr + " != " + b.expr + ") goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }

            // GOTO
            else if (op == 0xA7 || op == 0xC8) { // goto, goto_w
                int target = extract_branch_target(operand);
                emit(lines, 2, "        goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }

            // JSR/RET (legacy)
            else if (op == 0xA8 || op == 0xC9) { // jsr, jsr_w
                emit(lines, 2, "        // jsr " + operand, false, "", true);
            }
            else if (op == 0xA9) { // ret
                emit(lines, 2, "        // ret " + operand, false, "", true);
            }

            // SWITCH
            else if (op == 0xAA) { // tableswitch
                auto val = pop();
                emit(lines, 2, "        switch (" + val.expr + ") { // tableswitch: " + operand,
                     suspicious, susp_reason);
                emit(lines, 2, "            // ...", false, "", true);
                emit(lines, 2, "        }", false, "");
            }
            else if (op == 0xAB) { // lookupswitch
                auto val = pop();
                emit(lines, 2, "        switch (" + val.expr + ") { // lookupswitch: " + operand,
                     suspicious, susp_reason);
                emit(lines, 2, "            // ...", false, "", true);
                emit(lines, 2, "        }", false, "");
            }

            // RETURNS
            else if (op == 0xAC || op == 0xAD || op == 0xAE || op == 0xAF || op == 0xB0) {
                // ireturn, lreturn, freturn, dreturn, areturn
                auto val = pop();
                emit(lines, 2, "        return " + val.expr + ";",
                     val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
                clear_stack(); // unreachable after return
            }
            else if (op == 0xB1) { // return (void)
                emit(lines, 2, "        return;", suspicious, susp_reason);
                clear_stack();
            }

            // FIELD ACCESS
            else if (op == 0xB2) { // getstatic
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                std::string java_class_name = class_to_java(parsed.class_name);
                std::string expr = java_class_name + "." + parsed.member_name;
                push(expr, suspicious, susp_reason);
            }
            else if (op == 0xB3) { // putstatic
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                auto val = pop();
                std::string java_class_name = class_to_java(parsed.class_name);
                emit(lines, 2, "        " + java_class_name + "." + parsed.member_name + " = " + val.expr + ";",
                     val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }
            else if (op == 0xB4) { // getfield
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                auto obj = pop();
                std::string expr;
                if (obj.expr == "this") {
                    expr = "this." + parsed.member_name;
                } else {
                    expr = obj.expr + "." + parsed.member_name;
                }
                push(expr, obj.is_suspicious || suspicious,
                     obj.suspicion_reason.empty() ? susp_reason : obj.suspicion_reason);
            }
            else if (op == 0xB5) { // putfield
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                auto val = pop();
                auto obj = pop();
                std::string target_str;
                if (obj.expr == "this") {
                    target_str = "this." + parsed.member_name;
                } else {
                    target_str = obj.expr + "." + parsed.member_name;
                }
                emit(lines, 2, "        " + target_str + " = " + val.expr + ";",
                     val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
            }

            // METHOD INVOCATIONS
            else if (op == 0xB6 || op == 0xB9) { // invokevirtual, invokeinterface
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                int param_count = count_method_params(parsed.descriptor);
                auto ret_sig = parse_method_descriptor(parsed.descriptor);
                bool has_return = (ret_sig.return_type != "void");

                // Pop arguments in reverse order
                std::vector<StackItem> args;
                for (int p = 0; p < param_count; p++) {
                    args.push_back(pop());
                }
                std::reverse(args.begin(), args.end());

                // Pop objectref
                auto obj = pop();

                // Build argument string
                std::string arg_str;
                bool any_suspicious = suspicious || obj.is_suspicious;
                std::string combined_reason = susp_reason;
                for (size_t a = 0; a < args.size(); a++) {
                    if (a > 0) arg_str += ", ";
                    arg_str += args[a].expr;
                    if (args[a].is_suspicious) any_suspicious = true;
                    if (combined_reason.empty() && !args[a].suspicion_reason.empty())
                        combined_reason = args[a].suspicion_reason;
                }
                if (combined_reason.empty() && !obj.suspicion_reason.empty())
                    combined_reason = obj.suspicion_reason;

                std::string call_expr;
                if (obj.expr == "this") {
                    call_expr = parsed.member_name + "(" + arg_str + ")";
                } else {
                    call_expr = obj.expr + "." + parsed.member_name + "(" + arg_str + ")";
                }

                // Detect StringBuilder chains: if the result type is StringBuilder and
                // the method is "append" or "toString", try to simplify
                if (parsed.member_name == "toString" &&
                    parsed.class_name.find("StringBuilder") != std::string::npos) {
                    // Try to detect chained appends by looking at the expression
                    // The obj.expr might be something like:
                    //   new StringBuilder().append("a").append("b")
                    // We can try to simplify to string concatenation
                    std::string simplified = obj.expr;
                    // Replace StringBuilder chain with concatenation (best-effort)
                    if (simplified.find("new StringBuilder(") != std::string::npos) {
                        // Attempt to extract append arguments
                        // This is a best-effort heuristic
                        std::string concat;
                        size_t search_pos = 0;
                        bool first = true;
                        while (true) {
                            size_t append_pos = simplified.find(".append(", search_pos);
                            if (append_pos == std::string::npos) break;
                            size_t arg_start = append_pos + 8;
                            // Find matching closing paren (simple: count parens)
                            int depth = 1;
                            size_t arg_end = arg_start;
                            while (arg_end < simplified.size() && depth > 0) {
                                if (simplified[arg_end] == '(') depth++;
                                else if (simplified[arg_end] == ')') depth--;
                                if (depth > 0) arg_end++;
                            }
                            if (depth == 0) {
                                std::string append_arg = simplified.substr(arg_start, arg_end - arg_start);
                                if (!first) concat += " + ";
                                concat += append_arg;
                                first = false;
                                search_pos = arg_end + 1;
                            } else {
                                break;
                            }
                        }
                        if (!concat.empty()) {
                            call_expr = concat;
                        }
                    }
                }

                if (has_return) {
                    push(call_expr, any_suspicious, combined_reason);
                } else {
                    emit(lines, 2, "        " + call_expr + ";", any_suspicious, combined_reason);
                }
            }
            else if (op == 0xB8) { // invokestatic
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                int param_count = count_method_params(parsed.descriptor);
                auto ret_sig = parse_method_descriptor(parsed.descriptor);
                bool has_return = (ret_sig.return_type != "void");

                std::vector<StackItem> args;
                for (int p = 0; p < param_count; p++) {
                    args.push_back(pop());
                }
                std::reverse(args.begin(), args.end());

                std::string arg_str;
                bool any_suspicious = suspicious;
                std::string combined_reason = susp_reason;
                for (size_t a = 0; a < args.size(); a++) {
                    if (a > 0) arg_str += ", ";
                    arg_str += args[a].expr;
                    if (args[a].is_suspicious) any_suspicious = true;
                    if (combined_reason.empty() && !args[a].suspicion_reason.empty())
                        combined_reason = args[a].suspicion_reason;
                }

                std::string java_class_name = class_to_java(parsed.class_name);
                std::string call_expr = java_class_name + "." + parsed.member_name + "(" + arg_str + ")";

                if (has_return) {
                    push(call_expr, any_suspicious, combined_reason);
                } else {
                    emit(lines, 2, "        " + call_expr + ";", any_suspicious, combined_reason);
                }
            }
            else if (op == 0xB7) { // invokespecial
                std::string ref = extract_ref(operand);
                auto parsed = parse_ref(ref);
                int param_count = count_method_params(parsed.descriptor);
                auto ret_sig = parse_method_descriptor(parsed.descriptor);
                bool has_return = (ret_sig.return_type != "void");

                std::vector<StackItem> args;
                for (int p = 0; p < param_count; p++) {
                    args.push_back(pop());
                }
                std::reverse(args.begin(), args.end());

                auto obj = pop();

                std::string arg_str;
                bool any_suspicious = suspicious || obj.is_suspicious;
                std::string combined_reason = susp_reason;
                for (size_t a = 0; a < args.size(); a++) {
                    if (a > 0) arg_str += ", ";
                    arg_str += args[a].expr;
                    if (args[a].is_suspicious) any_suspicious = true;
                    if (combined_reason.empty() && !args[a].suspicion_reason.empty())
                        combined_reason = args[a].suspicion_reason;
                }
                if (combined_reason.empty() && !obj.suspicion_reason.empty())
                    combined_reason = obj.suspicion_reason;

                if (parsed.member_name == "<init>") {
                    // Constructor call
                    std::string java_class_name = class_to_java(parsed.class_name);

                    // Check if the objectref is a "new ClassName" expression
                    if (obj.expr.find("new ") == 0) {
                        // Combine: "new ClassName" + args -> "new ClassName(args)"
                        std::string new_expr = obj.expr + "(" + arg_str + ")";
                        push(new_expr, any_suspicious, combined_reason);
                    }
                    else if (obj.expr == "this") {
                        // super() or this() call
                        emit(lines, 2, "        super(" + arg_str + ");",
                             any_suspicious, combined_reason);
                    }
                    else {
                        // Some other init call
                        std::string call_expr = "new " + java_class_name + "(" + arg_str + ")";
                        push(call_expr, any_suspicious, combined_reason);
                    }
                } else {
                    // Non-init invokespecial (super.method() or private method)
                    std::string call_expr;
                    if (obj.expr == "this") {
                        call_expr = "super." + parsed.member_name + "(" + arg_str + ")";
                    } else {
                        call_expr = obj.expr + "." + parsed.member_name + "(" + arg_str + ")";
                    }

                    if (has_return) {
                        push(call_expr, any_suspicious, combined_reason);
                    } else {
                        emit(lines, 2, "        " + call_expr + ";", any_suspicious, combined_reason);
                    }
                }
            }
            else if (op == 0xBA) { // invokedynamic
                std::string ref = extract_ref(operand);
                // InvokeDynamic ref may be prefixed with "InvokeDynamic "
                if (ref.find("InvokeDynamic ") == 0) {
                    ref = ref.substr(14);
                }
                // InvokeDynamic is complex; best effort: show as a call
                auto parsed = parse_ref(ref);
                int param_count = 0;
                if (!parsed.descriptor.empty()) {
                    param_count = count_method_params(parsed.descriptor);
                }
                auto ret_sig = parse_method_descriptor(parsed.descriptor);
                bool has_return = (!parsed.descriptor.empty() && ret_sig.return_type != "void");

                std::vector<StackItem> args;
                for (int p = 0; p < param_count; p++) {
                    args.push_back(pop());
                }
                std::reverse(args.begin(), args.end());

                std::string arg_str;
                for (size_t a = 0; a < args.size(); a++) {
                    if (a > 0) arg_str += ", ";
                    arg_str += args[a].expr;
                }

                std::string call_expr = "/* invokedynamic */ " + parsed.member_name + "(" + arg_str + ")";
                if (has_return) {
                    push(call_expr, suspicious, susp_reason);
                } else {
                    emit(lines, 2, "        " + call_expr + ";", suspicious, susp_reason);
                }
            }

            // OBJECT CREATION
            else if (op == 0xBB) { // new
                std::string class_name = extract_class(operand);
                std::string java_name = class_to_java(class_name);
                // Push partial "new ClassName" - will be completed by invokespecial <init>
                push("new " + java_name, suspicious, susp_reason);
            }
            else if (op == 0xBC) { // newarray (primitive)
                auto count_item = pop();
                // operand is the type name (from decoder): "int", "byte", etc.
                push("new " + operand + "[" + count_item.expr + "]");
            }
            else if (op == 0xBD) { // anewarray
                auto count_item = pop();
                std::string class_name = extract_class(operand);
                std::string java_name = class_to_java(class_name);
                push("new " + java_name + "[" + count_item.expr + "]");
            }
            else if (op == 0xBE) { // arraylength
                auto arr = pop();
                push(arr.expr + ".length", arr.is_suspicious, arr.suspicion_reason);
            }

            // THROW
            else if (op == 0xBF) { // athrow
                auto val = pop();
                emit(lines, 2, "        throw " + val.expr + ";",
                     val.is_suspicious || suspicious,
                     val.suspicion_reason.empty() ? susp_reason : val.suspicion_reason);
                clear_stack();
            }

            // TYPE CHECK/CAST
            else if (op == 0xC0) { // checkcast
                std::string class_name = extract_class(operand);
                std::string java_name = class_to_java(class_name);
                auto val = pop();
                push("(" + java_name + ") " + val.expr, val.is_suspicious, val.suspicion_reason);
            }
            else if (op == 0xC1) { // instanceof
                std::string class_name = extract_class(operand);
                std::string java_name = class_to_java(class_name);
                auto val = pop();
                push(val.expr + " instanceof " + java_name, val.is_suspicious, val.suspicion_reason);
            }

            // MONITOR
            else if (op == 0xC2) { // monitorenter
                auto obj = pop();
                emit(lines, 2, "        synchronized (" + obj.expr + ") { // monitorenter");
            }
            else if (op == 0xC3) { // monitorexit
                emit(lines, 2, "        } // monitorexit");
            }

            // WIDE
            else if (op == 0xC4) { // wide prefix
                // The decoder already handles this; the mnemonic will be "wide iload" etc.
                // Just emit as a comment
                emit(lines, 2, "        // " + mnemonic + " " + operand, false, "", true);
            }

            // MULTIANEWARRAY
            else if (op == 0xC5) { // multianewarray
                std::string ref = extract_ref(operand);
                // Pop dimension counts
                // operand format from decoder: "#idx, dims  // class"
                int dims = 1;
                // Try to parse dimension count from operand
                auto comma = operand.find(',');
                if (comma != std::string::npos) {
                    std::string dims_str = operand.substr(comma + 1);
                    // Trim and get number before any space
                    size_t start = dims_str.find_first_not_of(' ');
                    if (start != std::string::npos) {
                        size_t end_pos = dims_str.find_first_of(' ', start);
                        if (end_pos != std::string::npos)
                            dims_str = dims_str.substr(start, end_pos - start);
                        else
                            dims_str = dims_str.substr(start);
                        try { dims = std::stoi(dims_str); } catch (...) {}
                    }
                }
                std::vector<StackItem> dim_sizes;
                for (int d = 0; d < dims; d++) {
                    dim_sizes.push_back(pop());
                }
                std::reverse(dim_sizes.begin(), dim_sizes.end());

                std::string class_name = extract_class(operand);
                std::string java_name = class_to_java(class_name);
                std::string expr = "new " + java_name;
                for (auto& ds : dim_sizes) {
                    expr += "[" + ds.expr + "]";
                }
                push(expr);
            }

            // NULL CHECKS
            else if (op == 0xC6) { // ifnull
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " == null) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }
            else if (op == 0xC7) { // ifnonnull
                auto val = pop();
                int target = extract_branch_target(operand);
                emit(lines, 2, "        if (" + val.expr + " != null) goto label_" + std::to_string(target) + ";",
                     suspicious, susp_reason);
            }

            // EVERYTHING ELSE
            else {
                // Unknown or unhandled opcode: emit as comment
                std::string comment = "        // " + mnemonic;
                if (!operand.empty()) comment += " " + operand;
                emit(lines, 2, comment, suspicious, susp_reason, true);
            }
        }
        catch (...) {
            // If any single instruction fails, fall back to raw display
            std::string fallback = "        // [error] " + mnemonic;
            if (!operand.empty()) fallback += " " + operand;
            emit(lines, 2, fallback, suspicious, susp_reason, true);
        }
    }

    // If there's anything left on the stack, it's likely an expression that was never consumed
    // (usually means the bytecode ended in an unusual way)
    // Don't emit these to avoid noise
    clear_stack();
}

} // namespace ihp
