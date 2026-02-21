#pragma once
#include "base_detector.h"

namespace ihp {

class TrojanDetector : public BaseDetector {
public:
    std::string name() const override { return "Trojan Detector"; }
    std::vector<Detection> scan_class(const ClassInfo& cls, const std::string& filename) override;
    std::vector<Detection> scan_jar(const JarContents& jar) override;
};

} // namespace ihp
