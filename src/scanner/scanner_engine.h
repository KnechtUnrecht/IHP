#pragma once
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include "detections/base_detector.h"
#include "signature_db.h"

namespace ihp {

enum class ThreatLevel {
    CLEAN,
    SUSPICIOUS,
    MALICIOUS
};

inline const char* threat_level_string(ThreatLevel t) {
    switch (t) {
        case ThreatLevel::CLEAN: return "CLEAN";
        case ThreatLevel::SUSPICIOUS: return "SUSPICIOUS";
        case ThreatLevel::MALICIOUS: return "MALICIOUS";
    }
    return "UNKNOWN";
}

struct FileScanResult {
    std::string file_path;
    std::string file_name;
    std::string sha256;
    ThreatLevel threat_level = ThreatLevel::CLEAN;
    int threat_score = 0;
    int class_count = 0;
    std::vector<Detection> detections;
    std::vector<std::string> class_names;
    std::vector<std::string> all_filenames;
    std::string manifest;
};

struct ScanProgress {
    std::atomic<int> total_files{0};
    std::atomic<int> scanned_files{0};
    std::atomic<bool> scanning{false};
    std::atomic<bool> done{false};
    std::string current_file;
    std::mutex current_file_mutex;

    void set_current_file(const std::string& f) {
        std::lock_guard<std::mutex> lock(current_file_mutex);
        current_file = f;
    }
    std::string get_current_file() {
        std::lock_guard<std::mutex> lock(current_file_mutex);
        return current_file;
    }
};

struct ScanResults {
    std::vector<FileScanResult> file_results;
    int total_detections = 0;
    int critical_count = 0;
    int high_count = 0;
    int medium_count = 0;
    int low_count = 0;
    double scan_time_ms = 0;
    std::mutex mutex;

    void add_result(FileScanResult&& result) {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& d : result.detections) {
            total_detections++;
            switch (d.severity) {
                case Severity::CRITICAL: critical_count++; break;
                case Severity::HIGH: high_count++; break;
                case Severity::MEDIUM: medium_count++; break;
                case Severity::LOW: low_count++; break;
                default: break;
            }
        }
        file_results.push_back(std::move(result));
    }
};

struct AttackChainPattern {
    std::string chain_name;
    std::string description;
    Severity severity;
    std::vector<std::vector<std::string>> required_groups;
};

class ScannerEngine {
public:
    ScannerEngine();
    ~ScannerEngine();

    void init(const std::string& signatures_path = "");

    // Start scanning (runs on background thread)
    void scan_files(const std::vector<std::string>& file_paths);
    void scan_directory(const std::string& dir_path);

    // State
    ScanProgress& progress() { return progress_; }
    ScanResults& results() { return results_; }
    bool is_scanning() const { return progress_.scanning; }

private:
    void scan_worker(std::vector<std::string> files);
    FileScanResult scan_single_jar(const std::string& path);
    void analyze_attack_chains(FileScanResult& result);

    SignatureDB sig_db_;
    std::vector<std::unique_ptr<BaseDetector>> detectors_;
    ScanProgress progress_;
    ScanResults results_;
    std::thread scan_thread_;
};

} // namespace ihp
