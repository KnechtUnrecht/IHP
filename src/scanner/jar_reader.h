#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace ihp {

struct JarEntry {
    std::string filename;
    std::vector<uint8_t> data;
    bool is_class_file;
    bool is_directory;
};

struct JarContents {
    std::string jar_path;
    std::vector<JarEntry> entries;
    std::vector<std::string> all_filenames;
    std::string manifest;
    bool valid = false;
    std::string error;
};

class JarReader {
public:
    JarContents read(const std::string& path);
    JarContents read_from_memory(const uint8_t* data, size_t size, const std::string& name = "");
};

} // namespace ihp
