#pragma once
#include <string>
#include <vector>
#include "../class_parser.h"
#include "../jar_reader.h"

namespace ihp {

enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

inline const char* severity_to_string(Severity s) {
    switch (s) {
        case Severity::INFO: return "INFO";
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

inline int severity_to_score(Severity s) {
    switch (s) {
        case Severity::INFO: return 0;
        case Severity::LOW: return 1;
        case Severity::MEDIUM: return 3;
        case Severity::HIGH: return 7;
        case Severity::CRITICAL: return 15;
    }
    return 0;
}

struct Detection {
    Severity severity;
    std::string rule_name;
    std::string description;
    std::string file_name;      // which .class or file triggered it
    std::string evidence;       // the specific string/reference that triggered
};

class BaseDetector {
public:
    virtual ~BaseDetector() = default;
    virtual std::string name() const = 0;
    virtual std::vector<Detection> scan_class(const ClassInfo& cls, const std::string& filename) = 0;
    virtual std::vector<Detection> scan_jar(const JarContents& jar) { return {}; }
};

} // namespace ihp
