#include "hash.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

namespace ihp {

std::string Hash::to_hex(const uint8_t* data, size_t size) {
    std::ostringstream ss;
    for (size_t i = 0; i < size; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string Hash::sha256_data(const uint8_t* data, size_t size) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result;
    uint8_t hash[32] = {};

    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return "";

    DWORD hash_obj_size = 0;
    DWORD data_size = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_obj_size, sizeof(hash_obj_size), &data_size, 0);

    std::vector<uint8_t> hash_obj(hash_obj_size);
    status = BCryptCreateHash(hAlg, &hHash, hash_obj.data(), hash_obj_size, nullptr, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    // feed data in chunks so ULONG doesnt truncate on huge files
    size_t offset = 0;
    while (offset < size) {
        ULONG chunk = static_cast<ULONG>((std::min)(size - offset, (size_t)0xFFFFFFFFu));
        BCryptHashData(hHash, (PUCHAR)(data + offset), chunk, 0);
        offset += chunk;
    }
    BCryptFinishHash(hHash, hash, sizeof(hash), 0);

    result = to_hex(hash, sizeof(hash));

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

std::string Hash::sha256_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return "";

    auto file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(data.data()), file_size)) return "";

    return sha256_data(data.data(), data.size());
}

} // namespace ihp
