#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include "detections/base_detector.h"

namespace ihp {

struct SignatureDatabase {
    std::unordered_set<std::string> known_hashes;           // SHA-256/SHA-1 of known malicious JARs
    std::vector<std::string> malicious_classes;              // Known bad class/package names
    std::vector<std::string> malicious_domains;              // Known C2 domains
    std::vector<std::string> malicious_ips;                  // Known C2 IPs
    std::unordered_set<std::string> suspicious_extensions;   // File extensions that shouldn't be in mods
    std::vector<std::string> suspicious_urls;                // Known malicious URLs
    std::vector<std::string> suspicious_webhook_patterns;    // Discord webhooks, Telegram bot APIs
    std::vector<std::string> suspicious_exfil_services;      // File hosting services used for exfil
    std::vector<std::string> suspicious_paste_services;      // Paste services used for C2 config
    std::vector<std::string> suspicious_file_artifacts;      // Known malware file artifacts inside JARs
    std::vector<std::string> suspicious_system_properties;   // Java system properties set by malware
    std::vector<std::string> suspicious_method_names;        // Known malicious obfuscated method names
};

class SignatureDB {
public:
    bool load(const std::string& json_path);
    bool load_default();

    bool is_known_malware_hash(const std::string& sha256) const;
    std::vector<Detection> check_classes(const std::vector<std::string>& class_refs, const std::string& filename) const;
    std::vector<Detection> check_strings(const std::vector<std::string>& strings, const std::string& filename) const;
    std::vector<Detection> check_filenames(const std::vector<std::string>& filenames) const;

    const SignatureDatabase& data() const { return db_; }

private:
    SignatureDatabase db_;
};

} // namespace ihp
