#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace ihp {

// Parsed JAR metadata from MANIFEST.MF and JAR structure
struct JarMetadata {
    // MANIFEST.MF attributes
    std::string manifest_version;
    std::string created_by;
    std::string built_by;
    std::string build_jdk;
    std::string build_jdk_spec;
    std::string main_class;

    // Implementation info (common in Bukkit/Forge/Fabric mods)
    std::string implementation_title;
    std::string implementation_version;
    std::string implementation_vendor;
    std::string implementation_vendor_id;

    // Specification info
    std::string specification_title;
    std::string specification_version;
    std::string specification_vendor;

    // OSGi / Bundle info
    std::string bundle_name;
    std::string bundle_symbolic_name;
    std::string bundle_version;
    std::string bundle_vendor;
    std::string bundle_license;
    std::string bundle_description;

    // Minecraft-specific
    std::string forge_mod_id;        // FMLCorePlugin, etc.
    std::string fabric_mod_json;     // from fabric.mod.json
    std::string plugin_name;         // Bukkit plugin.yml name
    std::string plugin_version;
    std::string plugin_author;
    std::string plugin_description;
    std::string plugin_main;

    // All raw key-value pairs from MANIFEST.MF
    std::vector<std::pair<std::string, std::string>> raw_attributes;

    // JAR structure analysis
    int total_entries = 0;
    int class_file_count = 0;
    int resource_count = 0;
    int directory_count = 0;
    uint64_t total_uncompressed_size = 0;

    // File type breakdown
    int image_count = 0;     // .png, .jpg, .gif
    int config_count = 0;    // .yml, .yaml, .json, .toml, .cfg, .properties
    int text_count = 0;      // .txt, .md, .log
    int native_lib_count = 0; // .dll, .so, .dylib
    int script_count = 0;    // .bat, .sh, .ps1, .vbs
    int other_count = 0;

    // Suspicious file entries
    struct SuspiciousEntry {
        std::string filename;
        std::string reason;
    };
    std::vector<SuspiciousEntry> suspicious_entries;

    // Signing info
    bool is_signed = false;
    std::string signer_info;

    bool valid = false;
};

// Metadata parser
class JarMetadataParser {
public:
    // Parse manifest string + JAR file list into metadata
    JarMetadata parse(const std::string& manifest_content,
                      const std::vector<std::string>& all_filenames);

    // Parse Minecraft-specific metadata files
    void parse_plugin_yml(JarMetadata& meta, const std::string& content);
    void parse_fabric_mod_json(JarMetadata& meta, const std::string& content);

private:
    // Parse MANIFEST.MF format (RFC 822-style key: value pairs)
    std::vector<std::pair<std::string, std::string>> parse_manifest(const std::string& content);

    // Analyze file entries for suspicious patterns
    void analyze_entries(JarMetadata& meta, const std::vector<std::string>& filenames);

    // Classify a filename by type
    enum FileType { CLASS, IMAGE, CONFIG, TEXT, NATIVE_LIB, SCRIPT, DIRECTORY, OTHER };
    static FileType classify_file(const std::string& filename);
};

} // namespace ihp
