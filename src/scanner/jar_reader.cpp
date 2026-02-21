#include "jar_reader.h"

#include "../../third_party/miniz/miniz.h"
#include "../../third_party/miniz/miniz_zip.h"

#include <fstream>
#include <algorithm>

namespace ihp {

JarContents JarReader::read(const std::string& path) {
    JarContents contents;
    contents.jar_path = path;

    // Read entire file
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        contents.error = "Failed to open file: " + path;
        return contents;
    }

    auto file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> file_data(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(file_data.data()), file_size)) {
        contents.error = "Failed to read file: " + path;
        return contents;
    }
    file.close();

    return read_from_memory(file_data.data(), file_data.size(), path);
}

JarContents JarReader::read_from_memory(const uint8_t* data, size_t size, const std::string& name) {
    JarContents contents;
    contents.jar_path = name;

    mz_zip_archive zip = {};
    if (!mz_zip_reader_init_mem(&zip, data, size, 0)) {
        contents.error = "Not a valid ZIP/JAR file";
        return contents;
    }

    mz_uint num_files = mz_zip_reader_get_num_files(&zip);

    for (mz_uint i = 0; i < num_files; i++) {
        mz_zip_archive_file_stat file_stat;
        if (!mz_zip_reader_file_stat(&zip, i, &file_stat)) continue;

        std::string filename = file_stat.m_filename;
        contents.all_filenames.push_back(filename);

        bool is_dir = mz_zip_reader_is_file_a_directory(&zip, i);
        bool is_class = false;
        if (!is_dir && filename.size() > 6) {
            std::string ext = filename.substr(filename.size() - 6);
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            is_class = (ext == ".class");
        }

        // Check for MANIFEST.MF
        bool is_manifest = (filename.find("META-INF/MANIFEST.MF") != std::string::npos);

        // Check for Minecraft metadata files we want to extract
        bool is_metadata = false;
        if (!is_dir && !is_class && !is_manifest) {
            std::string lower_name = filename;
            std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
            is_metadata = (lower_name == "plugin.yml" ||
                           lower_name == "bungee.yml" ||
                           lower_name == "fabric.mod.json" ||
                           lower_name == "mcmod.info" ||
                           lower_name == "pack.mcmeta" ||
                           filename.find("META-INF/mods.toml") != std::string::npos);
        }

        // Extract class files, manifest, and metadata files
        if (is_class || is_manifest || is_metadata) {
            size_t uncomp_size = static_cast<size_t>(file_stat.m_uncomp_size);
            std::vector<uint8_t> entry_data(uncomp_size);
            if (mz_zip_reader_extract_to_mem(&zip, i, entry_data.data(), uncomp_size, 0)) {
                if (is_manifest) {
                    contents.manifest.assign(reinterpret_cast<const char*>(entry_data.data()), uncomp_size);
                }
                JarEntry entry;
                entry.filename = filename;
                entry.data = std::move(entry_data);
                entry.is_class_file = is_class;
                entry.is_directory = false;
                contents.entries.push_back(std::move(entry));
            }
        } else if (!is_dir) {
            // Still track non-class files (but don't extract data)
            JarEntry entry;
            entry.filename = filename;
            entry.is_class_file = false;
            entry.is_directory = is_dir;
            contents.entries.push_back(std::move(entry));
        }
    }

    mz_zip_reader_end(&zip);
    contents.valid = true;
    return contents;
}

} // namespace ihp
