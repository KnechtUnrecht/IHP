#pragma once
#include "base_detector.h"

namespace ihp {

class ObfuscationDetector : public BaseDetector {
public:
    std::string name() const override { return "Obfuscation Detector"; }
    std::vector<Detection> scan_class(const ClassInfo& cls, const std::string& filename) override;
};

} // namespace ihp
