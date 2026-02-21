#include "jar_metadata.h"
#include <algorithm>
#include <sstream>
#include <cctype>

namespace ihp {

// --- Manifest parser ---

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::tolower);
    return r;
}

static bool ends_with_ci(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    std::string end = to_lower(s.substr(s.size() - suffix.size()));
    return end == to_lower(suffix);
}

std::vector<std::pair<std::string, std::string>> JarMetadataParser::parse_manifest(const std::string& content) {
    std::vector<std::pair<std::string, std::string>> attrs;
    if (content.empty()) return attrs;

    // MANIFEST.MF uses RFC 822 format:
    //   Key: Value
    //   Continuation lines start with a space
    //   Blank lines separate sections
    std::istringstream iss(content);
    std::string line;
    std::string current_key;
    std::string current_value;

    auto flush = [&]() {
        if (!current_key.empty()) {
            attrs.push_back({current_key, trim(current_value)});
            current_key.clear();
            current_value.clear();
        }
    };

    while (std::getline(iss, line)) {
        // Remove trailing \r
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (line.empty()) {
            flush();
            continue;
        }

        // Continuation line (starts with space)
        if (line[0] == ' ' && !current_key.empty()) {
            current_value += line.substr(1);
            continue;
        }

        // New key: value pair
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            flush();
            current_key = line.substr(0, colon);
            if (colon + 1 < line.size())
                current_value = line.substr(colon + 1);
            else
                current_value.clear();
        }
    }
    flush();

    return attrs;
}

// --- File classification ---

JarMetadataParser::FileType JarMetadataParser::classify_file(const std::string& filename) {
    if (filename.empty()) return OTHER;
    if (filename.back() == '/') return DIRECTORY;

    std::string lower = to_lower(filename);

    if (ends_with_ci(lower, ".class")) return CLASS;

    // Images
    if (ends_with_ci(lower, ".png") || ends_with_ci(lower, ".jpg") ||
        ends_with_ci(lower, ".jpeg") || ends_with_ci(lower, ".gif") ||
        ends_with_ci(lower, ".bmp") || ends_with_ci(lower, ".ico") ||
        ends_with_ci(lower, ".svg") || ends_with_ci(lower, ".webp"))
        return IMAGE;

    // Config files
    if (ends_with_ci(lower, ".yml") || ends_with_ci(lower, ".yaml") ||
        ends_with_ci(lower, ".json") || ends_with_ci(lower, ".toml") ||
        ends_with_ci(lower, ".cfg") || ends_with_ci(lower, ".properties") ||
        ends_with_ci(lower, ".xml") || ends_with_ci(lower, ".conf") ||
        ends_with_ci(lower, ".ini") || ends_with_ci(lower, ".mcmeta"))
        return CONFIG;

    // Text files
    if (ends_with_ci(lower, ".txt") || ends_with_ci(lower, ".md") ||
        ends_with_ci(lower, ".log") || ends_with_ci(lower, ".csv") ||
        ends_with_ci(lower, ".html") || ends_with_ci(lower, ".htm") ||
        ends_with_ci(lower, ".css") || ends_with_ci(lower, ".js"))
        return TEXT;

    // Native libraries
    if (ends_with_ci(lower, ".dll") || ends_with_ci(lower, ".so") ||
        ends_with_ci(lower, ".dylib") || ends_with_ci(lower, ".jnilib") ||
        ends_with_ci(lower, ".exe") || ends_with_ci(lower, ".bin"))
        return NATIVE_LIB;

    // Scripts
    if (ends_with_ci(lower, ".bat") || ends_with_ci(lower, ".sh") ||
        ends_with_ci(lower, ".ps1") || ends_with_ci(lower, ".vbs") ||
        ends_with_ci(lower, ".cmd") || ends_with_ci(lower, ".bash"))
        return SCRIPT;

    return OTHER;
}

// --- Entry analysis ---

void JarMetadataParser::analyze_entries(JarMetadata& meta, const std::vector<std::string>& filenames) {
    meta.total_entries = static_cast<int>(filenames.size());

    for (const auto& name : filenames) {
        FileType type = classify_file(name);
        switch (type) {
            case CLASS:      meta.class_file_count++; break;
            case IMAGE:      meta.image_count++; meta.resource_count++; break;
            case CONFIG:     meta.config_count++; meta.resource_count++; break;
            case TEXT:       meta.text_count++; meta.resource_count++; break;
            case NATIVE_LIB: meta.native_lib_count++; meta.resource_count++; break;
            case SCRIPT:     meta.script_count++; meta.resource_count++; break;
            case DIRECTORY:  meta.directory_count++; break;
            case OTHER:      meta.other_count++; meta.resource_count++; break;
        }

        // Check for suspicious entries
        std::string lower = to_lower(name);

        // Native libraries bundled in a mod = very suspicious
        if (type == NATIVE_LIB) {
            meta.suspicious_entries.push_back({name, "Native library bundled in JAR — may contain native malware"});
        }

        // Scripts
        if (type == SCRIPT) {
            meta.suspicious_entries.push_back({name, "Script file bundled in JAR — may be used for system commands"});
        }

        // Executable files
        if (ends_with_ci(lower, ".exe")) {
            meta.suspicious_entries.push_back({name, "Executable file inside JAR — highly suspicious"});
        }

        // Hidden/dot files
        if (name.find("/.") != std::string::npos || name.find("\\.") != std::string::npos) {
            // Skip .class and standard dotfiles
            if (lower.find(".gitignore") == std::string::npos &&
                lower.find(".gitattributes") == std::string::npos) {
                // Only flag truly suspicious ones
                if (lower.find("..") != std::string::npos) {
                    meta.suspicious_entries.push_back({name, "Path traversal pattern — may escape JAR directory"});
                }
            }
        }

        // Classes with suspicious names
        if (type == CLASS) {
            // Very short obfuscated names
            std::string class_name = name;
            auto last_slash = class_name.rfind('/');
            std::string short_name = (last_slash != std::string::npos)
                ? class_name.substr(last_slash + 1) : class_name;
            // Remove .class extension
            if (short_name.size() > 6) short_name = short_name.substr(0, short_name.size() - 6);

            if (short_name.size() <= 2 && short_name.size() > 0) {
                // Single or two letter class names are often obfuscated
                // But don't flag common ones
                if (short_name != "R" && short_name != "a" && short_name != "b") {
                    // Only flag if there are many such classes (checked elsewhere)
                }
            }

            // Suspicious class names
            if (lower.find("stealer") != std::string::npos ||
                lower.find("grabber") != std::string::npos ||
                lower.find("rat/") != std::string::npos ||
                lower.find("backdoor") != std::string::npos ||
                lower.find("keylog") != std::string::npos ||
                lower.find("exploit") != std::string::npos ||
                lower.find("inject") != std::string::npos ||
                lower.find("payload") != std::string::npos ||
                lower.find("dropper") != std::string::npos ||
                lower.find("c2/") != std::string::npos ||
                lower.find("botnet") != std::string::npos) {
                meta.suspicious_entries.push_back({name, "Class name suggests malicious intent"});
            }
        }

        // Check for signing-related files
        if (lower.find("meta-inf/") != std::string::npos) {
            if (ends_with_ci(lower, ".sf") || ends_with_ci(lower, ".dsa") ||
                ends_with_ci(lower, ".rsa") || ends_with_ci(lower, ".ec")) {
                meta.is_signed = true;
                if (meta.signer_info.empty()) {
                    // Extract signer name from filename
                    std::string signer = name;
                    auto slash = signer.rfind('/');
                    if (slash != std::string::npos) signer = signer.substr(slash + 1);
                    auto dot = signer.rfind('.');
                    if (dot != std::string::npos) signer = signer.substr(0, dot);
                    meta.signer_info = signer;
                }
            }
        }
    }
}

// --- Minecraft metadata parsers ---

void JarMetadataParser::parse_plugin_yml(JarMetadata& meta, const std::string& content) {
    // Simple YAML parser for plugin.yml — just extract key: value lines
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        // Skip indented lines (we only want top-level)
        if (line[0] == ' ' || line[0] == '\t') continue;

        auto colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = trim(line.substr(0, colon));
        std::string value = trim(line.substr(colon + 1));
        // Remove quotes
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
            value = value.substr(1, value.size() - 2);
        if (value.size() >= 2 && value.front() == '\'' && value.back() == '\'')
            value = value.substr(1, value.size() - 2);

        std::string lower_key = to_lower(key);
        if (lower_key == "name") meta.plugin_name = value;
        else if (lower_key == "version") meta.plugin_version = value;
        else if (lower_key == "author") meta.plugin_author = value;
        else if (lower_key == "description") meta.plugin_description = value;
        else if (lower_key == "main") meta.plugin_main = value;
    }
}

void JarMetadataParser::parse_fabric_mod_json(JarMetadata& meta, const std::string& content) {
    // Very simple JSON value extraction — not a full parser
    // Looks for "key": "value" patterns
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\"";
        auto pos = content.find(search);
        if (pos == std::string::npos) return "";

        // Find the colon after the key
        pos = content.find(':', pos + search.size());
        if (pos == std::string::npos) return "";

        // Find the opening quote of the value
        pos = content.find('"', pos + 1);
        if (pos == std::string::npos) return "";
        pos++; // skip the quote

        // Find the closing quote
        auto end = content.find('"', pos);
        if (end == std::string::npos) return "";

        return content.substr(pos, end - pos);
    };

    std::string id = extract("id");
    std::string name = extract("name");
    std::string version = extract("version");
    std::string description = extract("description");

    if (!id.empty()) meta.forge_mod_id = id;
    if (!name.empty()) meta.plugin_name = name;
    if (!version.empty()) meta.plugin_version = version;
    if (!description.empty()) meta.plugin_description = description;

    // Store the raw JSON content summary
    if (!content.empty()) {
        meta.fabric_mod_json = content.substr(0, 500);
        if (content.size() > 500) meta.fabric_mod_json += "...";
    }
}

// --- Main parser ---

JarMetadata JarMetadataParser::parse(const std::string& manifest_content,
                                      const std::vector<std::string>& all_filenames) {
    JarMetadata meta;

    // Parse MANIFEST.MF
    auto attrs = parse_manifest(manifest_content);
    meta.raw_attributes = attrs;

    for (const auto& [key, value] : attrs) {
        std::string lower_key = to_lower(key);

        if (lower_key == "manifest-version") meta.manifest_version = value;
        else if (lower_key == "created-by") meta.created_by = value;
        else if (lower_key == "built-by") meta.built_by = value;
        else if (lower_key == "build-jdk") meta.build_jdk = value;
        else if (lower_key == "build-jdk-spec") meta.build_jdk_spec = value;
        else if (lower_key == "main-class") meta.main_class = value;
        else if (lower_key == "implementation-title") meta.implementation_title = value;
        else if (lower_key == "implementation-version") meta.implementation_version = value;
        else if (lower_key == "implementation-vendor") meta.implementation_vendor = value;
        else if (lower_key == "implementation-vendor-id") meta.implementation_vendor_id = value;
        else if (lower_key == "specification-title") meta.specification_title = value;
        else if (lower_key == "specification-version") meta.specification_version = value;
        else if (lower_key == "specification-vendor") meta.specification_vendor = value;
        else if (lower_key == "bundle-name") meta.bundle_name = value;
        else if (lower_key == "bundle-symbolicname") meta.bundle_symbolic_name = value;
        else if (lower_key == "bundle-version") meta.bundle_version = value;
        else if (lower_key == "bundle-vendor") meta.bundle_vendor = value;
        else if (lower_key == "bundle-license") meta.bundle_license = value;
        else if (lower_key == "bundle-description") meta.bundle_description = value;
        else if (lower_key == "fmlcoreplugin" || lower_key == "fmlat" ||
                 lower_key == "modid" || lower_key == "forceloadasmods")
            meta.forge_mod_id = value;
    }

    // analyze file entries
    analyze_entries(meta, all_filenames);

    meta.valid = true;
    return meta;
}

} // namespace ihp
