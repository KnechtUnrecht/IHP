#pragma once
#include <string>
#include <algorithm>
#include <vector>

namespace ihp {

inline std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

inline bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

inline bool contains_any(const std::string& haystack, const std::vector<std::string>& needles) {
    for (const auto& n : needles) {
        if (contains(haystack, n)) return true;
    }
    return false;
}

inline bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline bool is_base64_string(const std::string& s) {
    if (s.size() < 16) return false;
    int valid = 0;
    for (char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
            valid++;
        }
    }
    double ratio = static_cast<double>(valid) / s.size();
    return ratio > 0.95 && s.size() >= 24;
}

inline bool looks_like_ip(const std::string& s) {
    int dots = 0;
    int digits = 0;
    for (char c : s) {
        if (c == '.') dots++;
        else if (c >= '0' && c <= '9') digits++;
        else return false;
    }
    return dots == 3 && digits >= 4;
}

inline bool looks_like_url(const std::string& s) {
    return starts_with(s, "http://") || starts_with(s, "https://") ||
           starts_with(s, "ftp://") || starts_with(s, "ws://") || starts_with(s, "wss://");
}

// Check if a class/method name looks obfuscated
inline bool looks_obfuscated(const std::string& name) {
    if (name.empty()) return false;
    if (name.size() <= 2 && name.size() >= 1) return true;
    // Count consonant clusters that don't form real words
    int consecutive_consonants = 0;
    int max_consecutive = 0;
    for (char c : name) {
        char lower = static_cast<char>(::tolower(c));
        if (lower >= 'a' && lower <= 'z') {
            if (lower != 'a' && lower != 'e' && lower != 'i' && lower != 'o' && lower != 'u') {
                consecutive_consonants++;
                max_consecutive = std::max(max_consecutive, consecutive_consonants);
            } else {
                consecutive_consonants = 0;
            }
        }
    }
    return max_consecutive >= 5;
}

} // namespace ihp
