#include "scanner_engine.h"
#include "jar_reader.h"
#include "class_parser.h"
#include "../utils/hash.h"
#include "../utils/string_utils.h"
#include "detections/rat_detector.h"
#include "detections/obfuscation_detector.h"
#include "detections/trojan_detector.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <filesystem>
#include <chrono>
#include <algorithm>
#include <unordered_set>

namespace fs = std::filesystem;

namespace ihp {

ScannerEngine::ScannerEngine() = default;

ScannerEngine::~ScannerEngine() {
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }
}

void ScannerEngine::init(const std::string& /*signatures_path*/) {
    // Load built-in signature database (everything is embedded in the EXE)
    sig_db_.load_default();

    // Register detectors
    detectors_.clear();
    detectors_.push_back(std::make_unique<RATDetector>());
    detectors_.push_back(std::make_unique<ObfuscationDetector>());
    detectors_.push_back(std::make_unique<TrojanDetector>());
}

void ScannerEngine::scan_files(const std::vector<std::string>& file_paths) {
    if (progress_.scanning) return;

    // Wait for previous scan thread
    if (scan_thread_.joinable()) {
        scan_thread_.join();
    }

    // Reset state
    {
        std::lock_guard<std::mutex> lock(results_.mutex);
        results_.file_results.clear();
        results_.total_detections = 0;
        results_.critical_count = 0;
        results_.high_count = 0;
        results_.medium_count = 0;
        results_.low_count = 0;
        results_.scan_time_ms = 0;
    }
    progress_.total_files = 0;
    progress_.scanned_files = 0;
    progress_.done = false;

    // Filter to only .jar files
    std::vector<std::string> jars;
    for (const auto& p : file_paths) {
        std::string lower = to_lower(p);
        if (ends_with(lower, ".jar")) {
            jars.push_back(p);
        }
    }

    if (jars.empty()) {
        progress_.done = true;
        return;
    }

    progress_.total_files = static_cast<int>(jars.size());
    progress_.scanning = true;

    scan_thread_ = std::thread(&ScannerEngine::scan_worker, this, std::move(jars));
}

void ScannerEngine::scan_directory(const std::string& dir_path) {
    std::vector<std::string> jar_files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".jar") {
                    jar_files.push_back(entry.path().string());
                }
            }
        }
    } catch (...) {}

    scan_files(jar_files);
}

void ScannerEngine::scan_worker(std::vector<std::string> files) {
    auto start = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < files.size(); i++) {
        progress_.set_current_file(fs::path(files[i]).filename().string());

        auto result = scan_single_jar(files[i]);
        results_.add_result(std::move(result));

        progress_.scanned_files = static_cast<int>(i + 1);
    }

    auto end = std::chrono::high_resolution_clock::now();
    results_.scan_time_ms = std::chrono::duration<double, std::milli>(end - start).count();

    progress_.scanning = false;
    progress_.done = true;
}

FileScanResult ScannerEngine::scan_single_jar(const std::string& path) {
    FileScanResult result;
    result.file_path = path;
    result.file_name = fs::path(path).filename().string();

    // Step 1: Compute SHA-256 hash
    result.sha256 = Hash::sha256_file(path);

    // Step 2: Check against known malware hashes
    if (sig_db_.is_known_malware_hash(result.sha256)) {
        result.detections.push_back({Severity::CRITICAL, "KNOWN_MALWARE_HASH",
            "File matches known malware SHA-256 hash",
            result.file_name, "SHA-256: " + result.sha256});
    }

    // Step 3: Read JAR contents
    JarReader reader;
    JarContents jar = reader.read(path);
    if (!jar.valid) {
        result.detections.push_back({Severity::LOW, "INVALID_JAR",
            "Could not read JAR file: " + jar.error,
            result.file_name, jar.error});
        result.threat_level = ThreatLevel::CLEAN;
        return result;
    }

    // Store JAR metadata for comparison feature
    result.all_filenames = jar.all_filenames;
    result.manifest = jar.manifest;

    // Step 4: Check filenames in JAR against signature database
    auto filename_detections = sig_db_.check_filenames(jar.all_filenames);
    result.detections.insert(result.detections.end(), filename_detections.begin(), filename_detections.end());

    // Step 5: Run JAR-level detectors
    for (auto& detector : detectors_) {
        auto jar_detections = detector->scan_jar(jar);
        result.detections.insert(result.detections.end(), jar_detections.begin(), jar_detections.end());
    }

    // Step 6: Parse each .class file and run detectors
    ClassParser parser;
    for (const auto& entry : jar.entries) {
        if (!entry.is_class_file || entry.data.empty()) continue;

        result.class_count++;
        ClassInfo cls = parser.parse(entry.data.data(), entry.data.size());
        if (!cls.valid) continue;

        // Store class name for comparison feature
        if (!cls.this_class.empty()) {
            result.class_names.push_back(cls.this_class);
        }

        // Check class references against signature DB
        auto class_detections = sig_db_.check_classes(cls.class_references, entry.filename);
        result.detections.insert(result.detections.end(), class_detections.begin(), class_detections.end());

        // Check strings against signature DB
        auto string_detections = sig_db_.check_strings(cls.string_literals, entry.filename);
        result.detections.insert(result.detections.end(), string_detections.begin(), string_detections.end());

        // Run each detector on this class
        for (auto& detector : detectors_) {
            auto detections = detector->scan_class(cls, entry.filename);
            result.detections.insert(result.detections.end(), detections.begin(), detections.end());
        }
    }

    // Step 6.5: Analyze cross-class attack chains & elevate obfuscation
    analyze_attack_chains(result);

    // Step 7: Calculate threat score and level
    int score = 0;
    for (const auto& d : result.detections) {
        score += severity_to_score(d.severity);
    }
    result.threat_score = score;

    if (score >= 15) {
        result.threat_level = ThreatLevel::MALICIOUS;
    } else if (score >= 5) {
        result.threat_level = ThreatLevel::SUSPICIOUS;
    } else {
        result.threat_level = ThreatLevel::CLEAN;
    }

    return result;
}

// --- cross-class attack chain analysis ---

// aggrgate detections across the whole jar to find coordinated attacks
void ScannerEngine::analyze_attack_chains(FileScanResult& result) {
    // Collect all triggered rule names
    std::unordered_set<std::string> triggered_rules;
    int high_critical_count = 0;
    int obfuscation_count = 0;

    static const std::unordered_set<std::string> obfuscation_rules = {
        "OBFUSCATED_CLASS_NAME", "OBFUSCATED_METHODS", "BASE64_STRINGS",
        "ENCRYPTED_STRINGS", "DYNAMIC_LOADING", "CUSTOM_CLASSLOADER",
        "LARGE_CONSTANT_POOL", "DYNAMIC_CLASS_CONSTRUCTION"
    };

    for (const auto& d : result.detections) {
        triggered_rules.insert(d.rule_name);
        if (d.severity == Severity::HIGH || d.severity == Severity::CRITICAL)
            high_critical_count++;
        if (obfuscation_rules.count(d.rule_name))
            obfuscation_count++;
    }

    // Define attack chain patterns
    static const std::vector<AttackChainPattern> chains = {
        {"COORDINATED_STEALER",
         "Multiple data theft techniques combined with exfiltration - coordinated stealer",
         Severity::CRITICAL,
         {
             // Group 1: Any data theft
             {"CHROME_DATA_THEFT", "FIREFOX_DATA_THEFT", "BROWSER_DATA_THEFT",
              "BROWSER_LOCALSTORAGE_THEFT", "DISCORD_TOKEN_STEALER", "STEAM_SESSION_THEFT",
              "TELEGRAM_SESSION_THEFT", "CRYPTO_WALLET_THEFT", "BROWSER_WALLET_THEFT",
              "SSH_KEY_THEFT", "WINDOWS_CREDENTIAL_THEFT", "ROBLOX_TOKEN_THEFT",
              "EPIC_SESSION_THEFT", "MC_SESSION_THEFT", "CREDENTIAL_ACCESS", "CREDENTIAL_THEFT"},
             // Group 2: Any exfiltration
             {"DISCORD_WEBHOOK_EXFIL", "TELEGRAM_BOT_EXFIL", "FILEHOST_EXFIL",
              "DATA_EXFILTRATION", "SUSPICIOUS_URL", "NET_SOCKET"}
         }},
        {"COORDINATED_DROPPER",
         "Downloads and executes payloads with persistence - dropper/installer",
         Severity::CRITICAL,
         {
             {"CMD_EXEC", "POWERSHELL_HIDDEN", "SCRIPT_DROPPER"},
             {"SUSPICIOUS_URL", "DROPPER", "NET_SOCKET"},
             {"PERSISTENCE", "REGISTRY_PERSISTENCE", "STARTUP_WRITE", "SECURITY_BYPASS"}
         }},
        {"COORDINATED_WORM",
         "Self-replicating code with network capability - worm behavior",
         Severity::CRITICAL,
         {
             {"SELF_REPLICATION", "MOD_INFECTION"},
             {"SUSPICIOUS_URL", "NET_SOCKET", "CMD_EXEC", "DROPPER"}
         }},
        {"COORDINATED_RECON",
         "System fingerprinting combined with data packaging and network upload",
         Severity::HIGH,
         {
             {"SYSTEM_FINGERPRINT", "WMI_RECON", "PROCESS_MANIPULATION"},
             {"DATA_PACKAGING", "DATA_EXFILTRATION"},
             {"SUSPICIOUS_URL", "NET_SOCKET", "DISCORD_WEBHOOK_EXFIL", "TELEGRAM_BOT_EXFIL"}
         }}
    };

    // Check standard chain patterns
    for (const auto& chain : chains) {
        if (triggered_rules.count(chain.chain_name)) continue; // skip duplicates

        bool all_groups_matched = true;
        std::string evidence_parts;

        for (const auto& group : chain.required_groups) {
            bool group_matched = false;
            for (const auto& rule : group) {
                if (triggered_rules.count(rule)) {
                    group_matched = true;
                    if (!evidence_parts.empty()) evidence_parts += ", ";
                    evidence_parts += rule;
                    break;
                }
            }
            if (!group_matched) {
                all_groups_matched = false;
                break;
            }
        }

        if (all_groups_matched) {
            result.detections.push_back({
                chain.severity, chain.chain_name, chain.description,
                result.file_name, "Attack chain: " + evidence_parts
            });
            triggered_rules.insert(chain.chain_name);
        }
    }

    // Special: COORDINATED_CREDENTIAL_HARVEST - needs 3+ different theft rules
    {
        static const std::vector<std::string> theft_rules = {
            "CHROME_DATA_THEFT", "FIREFOX_DATA_THEFT", "BROWSER_DATA_THEFT",
            "BROWSER_LOCALSTORAGE_THEFT", "BROWSER_EXTENSION_THEFT",
            "DISCORD_TOKEN_STEALER", "STEAM_SESSION_THEFT", "TELEGRAM_SESSION_THEFT",
            "CRYPTO_WALLET_THEFT", "BROWSER_WALLET_THEFT", "CRYPTO_CLIPJACKER",
            "SSH_KEY_THEFT", "WINDOWS_CREDENTIAL_THEFT", "ROBLOX_TOKEN_THEFT",
            "EPIC_SESSION_THEFT", "MC_SESSION_THEFT", "CREDENTIAL_ACCESS", "CREDENTIAL_THEFT"
        };
        std::string evidence;
        int theft_count = 0;
        for (const auto& rule : theft_rules) {
            if (triggered_rules.count(rule)) {
                theft_count++;
                if (!evidence.empty()) evidence += ", ";
                evidence += rule;
            }
        }
        if (theft_count >= 3 && !triggered_rules.count("COORDINATED_CREDENTIAL_HARVEST")) {
            result.detections.push_back({
                Severity::CRITICAL, "COORDINATED_CREDENTIAL_HARVEST",
                "Targets 3+ different credential sources - broad credential harvesting",
                result.file_name,
                "Theft targets (" + std::to_string(theft_count) + "): " + evidence
            });
        }
    }

    // Special: COORDINATED_EVASION - 3+ obfuscation + any HIGH/CRITICAL
    if (obfuscation_count >= 3 && high_critical_count >= 1 &&
        !triggered_rules.count("COORDINATED_EVASION")) {
        result.detections.push_back({
            Severity::HIGH, "COORDINATED_EVASION",
            "Heavy obfuscation combined with confirmed malicious behavior",
            result.file_name,
            std::to_string(obfuscation_count) + " obfuscation techniques + " +
                std::to_string(high_critical_count) + " high/critical findings"
        });
    }

    // Obfuscation severity elevation: 3+ obfuscation AND 2+ HIGH/CRITICAL
    // → elevate INFO/LOW obfuscation detections to MEDIUM
    if (obfuscation_count >= 3 && high_critical_count >= 2) {
        for (auto& d : result.detections) {
            if (obfuscation_rules.count(d.rule_name) &&
                (d.severity == Severity::INFO || d.severity == Severity::LOW)) {
                d.severity = Severity::MEDIUM;
            }
        }
    }
}

} // namespace ihp
