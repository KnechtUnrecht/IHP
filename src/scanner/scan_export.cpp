#include "scan_export.h"
#include "../version.h"
#include "detections/base_detector.h"
#include <sstream>
#include <fstream>
#include <ctime>
#include <iomanip>

namespace ihp {

// manualy building json because nlohmann is overkill for output lol
static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) >= 32)
                    out += c;
                else {
                    char hex[8];
                    snprintf(hex, sizeof(hex), "\\u%04x", (unsigned char)c);
                    out += hex;
                }
                break;
        }
    }
    return out;
}

std::string ScanExporter::to_json(const ScanResults& results) {
    std::ostringstream ss;
    ss << "{\n";
    ss << "  \"scanner\": \"IHP\",\n";
    ss << "  \"version\": \"" << IHP_VERSION << "\",\n";
    ss << "  \"scan_time_ms\": " << std::fixed << std::setprecision(1) << results.scan_time_ms << ",\n";
    ss << "  \"total_files\": " << results.file_results.size() << ",\n";
    ss << "  \"total_detections\": " << results.total_detections << ",\n";

    ss << "  \"severity_counts\": {\n";
    ss << "    \"critical\": " << results.critical_count << ",\n";
    ss << "    \"high\": " << results.high_count << ",\n";
    ss << "    \"medium\": " << results.medium_count << ",\n";
    ss << "    \"low\": " << results.low_count << "\n";
    ss << "  },\n";

    ss << "  \"files\": [\n";
    for (size_t fi = 0; fi < results.file_results.size(); fi++) {
        const auto& fr = results.file_results[fi];
        ss << "    {\n";
        ss << "      \"file_name\": \"" << json_escape(fr.file_name) << "\",\n";
        ss << "      \"file_path\": \"" << json_escape(fr.file_path) << "\",\n";
        ss << "      \"sha256\": \"" << json_escape(fr.sha256) << "\",\n";
        ss << "      \"threat_level\": \"" << threat_level_string(fr.threat_level) << "\",\n";
        ss << "      \"threat_score\": " << fr.threat_score << ",\n";
        ss << "      \"class_count\": " << fr.class_count << ",\n";

        ss << "      \"detections\": [\n";
        for (size_t di = 0; di < fr.detections.size(); di++) {
            const auto& d = fr.detections[di];
            ss << "        {\n";
            ss << "          \"severity\": \"" << severity_to_string(d.severity) << "\",\n";
            ss << "          \"rule\": \"" << json_escape(d.rule_name) << "\",\n";
            ss << "          \"description\": \"" << json_escape(d.description) << "\",\n";
            ss << "          \"file\": \"" << json_escape(d.file_name) << "\",\n";
            ss << "          \"evidence\": \"" << json_escape(d.evidence) << "\"\n";
            ss << "        }";
            if (di + 1 < fr.detections.size()) ss << ",";
            ss << "\n";
        }
        ss << "      ]\n";
        ss << "    }";
        if (fi + 1 < results.file_results.size()) ss << ",";
        ss << "\n";
    }
    ss << "  ]\n";
    ss << "}\n";
    return ss.str();
}

// get current time as string for the report header
static std::string current_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}

static std::string pad_severity(const char* sev, int width = 10) {
    std::string s(sev);
    while (static_cast<int>(s.size()) < width) s += ' ';
    return s;
}

// builds the text for one file result
static std::string file_text_block(const FileScanResult& result) {
    std::ostringstream ss;
    ss << "[" << threat_level_string(result.threat_level) << "] "
       << result.file_name << "  (Score: " << result.threat_score << ")\n";
    ss << "  SHA-256: " << result.sha256 << "\n";
    ss << "  Classes: " << result.class_count << "\n";

    if (result.detections.empty()) {
        ss << "  No detections.\n";
    } else {
        ss << "\n  Detections:\n";
        for (const auto& d : result.detections) {
            ss << "    " << pad_severity(severity_to_string(d.severity))
               << d.rule_name;

            // Pad rule name for alignment
            int rule_pad = 28 - static_cast<int>(d.rule_name.size());
            if (rule_pad > 0) ss << std::string(rule_pad, ' ');

            ss << d.description << "\n";

            if (!d.evidence.empty())
                ss << "              Evidence: " << d.evidence << "\n";
            if (!d.file_name.empty())
                ss << "              File: " << d.file_name << "\n";
        }
    }
    return ss.str();
}

std::string ScanExporter::to_text_report(const ScanResults& results) {
    std::ostringstream ss;
    ss << "IHP Scan Report\n";
    ss << "Generated: " << current_timestamp() << "\n\n";

    ss << "Summary:\n";
    ss << "  Files Scanned: " << results.file_results.size() << "\n";
    ss << "  Total Detections: " << results.total_detections << "\n";
    ss << "  Scan Time: " << std::fixed << std::setprecision(1)
       << results.scan_time_ms << " ms\n\n";

    ss << "  Severity Breakdown:\n";
    ss << "    Critical: " << results.critical_count << "\n";
    ss << "    High: " << results.high_count << "\n";
    ss << "    Medium: " << results.medium_count << "\n";
    ss << "    Low: " << results.low_count << "\n\n";

    // each file gets its own section
    for (const auto& fr : results.file_results) {
        ss << "---\n";
        ss << file_text_block(fr);
    }

    return ss.str();
}

std::string ScanExporter::to_text_single(const FileScanResult& result) {
    // just the one file, used for the context menu copy thing
    return file_text_block(result);
}

bool ScanExporter::save_to_file(const std::string& content, const std::string& path) {
    std::ofstream ofs(path, std::ios::out | std::ios::binary);
    if (!ofs.is_open()) return false;
    ofs.write(content.data(), content.size());
    return ofs.good();
}

} // namespace ihp
