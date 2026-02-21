#pragma once
#include "base_detector.h"

namespace ihp {

class RATDetector : public BaseDetector {
public:
    std::string name() const override { return "RAT Detector"; }
    std::vector<Detection> scan_class(const ClassInfo& cls, const std::string& filename) override;
    std::vector<Detection> scan_jar(const JarContents& jar) override;

private:
    bool has_class_ref(const ClassInfo& cls, const std::string& ref);
    bool has_method_ref(const ClassInfo& cls, const std::string& class_name, const std::string& method_name);
    bool has_string_containing(const ClassInfo& cls, const std::string& substr);
    int count_class_refs(const ClassInfo& cls, const std::string& ref);
};

} // namespace ihp
