#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace ihp {

class Hash {
public:
    static std::string sha256_file(const std::string& filepath);
    static std::string sha256_data(const uint8_t* data, size_t size);
    static std::string to_hex(const uint8_t* data, size_t size);
};

} // namespace ihp
