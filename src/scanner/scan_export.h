#pragma once
#include "scanner_engine.h"
#include <string>

namespace ihp {

class ScanExporter {
public:
    static std::string to_json(const ScanResults& results);
    static std::string to_text_report(const ScanResults& results);
    static std::string to_text_single(const FileScanResult& result); // for the context menu
    static bool save_to_file(const std::string& content, const std::string& path);
};

} // namespace ihp
