#include "obfuscation_detector.h"
#include "../../utils/string_utils.h"
#include <algorithm>
#include <numeric>

namespace ihp {

std::vector<Detection> ObfuscationDetector::scan_class(const ClassInfo& cls, const std::string& filename) {
    std::vector<Detection> detections;

    // Rule 1: Obfuscated class name (very short or random characters)
    // NOTE: Many legit mods use obfuscation (ProGuard, etc.) to protect IP - this is INFO only
    {
        std::string simple_name = cls.this_class;
        auto slash_pos = simple_name.rfind('/');
        if (slash_pos != std::string::npos) {
            simple_name = simple_name.substr(slash_pos + 1);
        }
        auto dollar_pos = simple_name.find('$');
        if (dollar_pos != std::string::npos) {
            simple_name = simple_name.substr(dollar_pos + 1);
        }
        if (!simple_name.empty() && simple_name.size() <= 2) {
            detections.push_back({Severity::INFO, "OBFUSCATED_CLASS_NAME",
                "Class has very short name (common with ProGuard/obfuscation - usually harmless)",
                filename, "class: " + cls.this_class});
        }
        if (looks_obfuscated(simple_name)) {
            detections.push_back({Severity::INFO, "OBFUSCATED_CLASS_NAME",
                "Class name appears obfuscated (common with ProGuard - usually harmless)",
                filename, "class: " + cls.this_class});
        }
    }

    // Rule 2: High ratio of single-char method names
    // NOTE: Totally normal for obfuscated mods - INFO only
    {
        int short_methods = 0;
        int total_methods = 0;
        for (const auto& mr : cls.method_references) {
            if (mr.class_name == cls.this_class) {
                total_methods++;
                if (mr.method_name.size() <= 2 && mr.method_name != "<init>" && mr.method_name != "<clinit>") {
                    short_methods++;
                }
            }
        }
        if (total_methods >= 5 && static_cast<float>(short_methods) / total_methods > 0.7f) {
            detections.push_back({Severity::INFO, "OBFUSCATED_METHODS",
                "Most methods have very short names (common with ProGuard - usually harmless)",
                filename, std::to_string(short_methods) + "/" + std::to_string(total_methods) + " short method names"});
        }
    }

    // Rule 3: Base64 encoded strings in constant pool
    // NOTE: Lots of legit uses (textures, config, etc.) - only LOW
    {
        int b64_count = 0;
        for (const auto& s : cls.string_literals) {
            if (is_base64_string(s) && s.size() >= 32) {
                b64_count++;
            }
        }
        if (b64_count >= 3) {
            detections.push_back({Severity::LOW, "BASE64_STRINGS",
                "Contains multiple Base64-encoded strings (often harmless, but can hide payloads)",
                filename, std::to_string(b64_count) + " base64 strings found"});
        }
    }

    // Rule 4: XOR / cipher patterns in string constants
    // This one is MORE suspicious - actual encrypted blobs are less common in legit mods
    {
        int suspicious_binary = 0;
        for (const auto& s : cls.string_literals) {
            if (s.size() >= 8) {
                int non_printable = 0;
                for (char c : s) {
                    if (static_cast<unsigned char>(c) < 32 || static_cast<unsigned char>(c) > 126) {
                        non_printable++;
                    }
                }
                if (non_printable > static_cast<int>(s.size()) / 3) {
                    suspicious_binary++;
                }
            }
        }
        if (suspicious_binary >= 3) {
            detections.push_back({Severity::MEDIUM, "ENCRYPTED_STRINGS",
                "Contains strings with non-printable characters - possibly XOR/encrypted data",
                filename, std::to_string(suspicious_binary) + " encrypted strings"});
        }
    }

    // Rule 5: Heavy Class.forName / reflection usage
    // NOTE: Many legit frameworks use reflection - LOW only
    {
        int forname_count = 0;
        for (const auto& mr : cls.method_references) {
            if (mr.class_name == "java/lang/Class" && mr.method_name == "forName") {
                forname_count++;
            }
        }
        if (forname_count >= 3) {
            detections.push_back({Severity::LOW, "DYNAMIC_LOADING",
                "Uses Class.forName to dynamically load classes (common in plugin systems, but can be used for evasion)",
                filename, std::to_string(forname_count) + " Class.forName calls"});
        }
    }

    // Rule 6: Custom ClassLoader subclass
    // This is somewhat suspicious but legit mods sometimes do this too - keep at MEDIUM
    if (cls.super_class == "java/lang/ClassLoader" ||
        cls.super_class == "java/security/SecureClassLoader" ||
        cls.super_class == "java/net/URLClassLoader") {
        detections.push_back({Severity::MEDIUM, "CUSTOM_CLASSLOADER",
            "Implements custom ClassLoader - can load code at runtime (sometimes legit, but worth noting)",
            filename, "extends " + cls.super_class});
    }

    // Rule 7: Extremely large constant pool (packed code indicator)
    // NOTE: Big mods just have lots of strings - INFO only
    if (cls.string_literals.size() > 500) {
        detections.push_back({Severity::INFO, "LARGE_CONSTANT_POOL",
            "Unusually large number of string constants (often just a big mod, not necessarily suspicious)",
            filename, std::to_string(cls.string_literals.size()) + " string literals"});
    }

    // Rule 8: String building to construct class names (anti-analysis)
    // This combined pattern is more suspicious - keep at LOW
    {
        bool builds_classnames = false;
        for (const auto& mr : cls.method_references) {
            if (mr.class_name == "java/lang/StringBuilder" || mr.class_name == "java/lang/StringBuffer") {
                for (const auto& mr2 : cls.method_references) {
                    if ((mr2.class_name == "java/lang/Class" && mr2.method_name == "forName") ||
                        (mr2.method_name == "loadClass")) {
                        builds_classnames = true;
                        break;
                    }
                }
                break;
            }
        }
        if (builds_classnames) {
            detections.push_back({Severity::LOW, "DYNAMIC_CLASS_CONSTRUCTION",
                "Builds class names dynamically then loads them (sometimes legit, can be anti-analysis)",
                filename, "StringBuilder + Class.forName"});
        }
    }

    return detections;
}

} // namespace ihp
