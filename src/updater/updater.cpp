#include "updater.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#include <fstream>
#include <sstream>
#include <vector>
#include <filesystem>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4244 4267)
#endif
#include "../../third_party/json/json.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace ihp {

void Updater::set_repo(const std::string& owner, const std::string& repo) {
    owner_ = owner;
    repo_ = repo;
}

void Updater::set_current_version(const std::string& version) {
    current_version_ = version;
}

std::string Updater::get_exe_path() {
    char buf[MAX_PATH];
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::string(buf);
}

std::string Updater::get_exe_dir() {
    return fs::path(get_exe_path()).parent_path().string();
}

std::string Updater::http_get(const std::string& url, int max_redirects) {
    if (max_redirects <= 0) return "";
    // Parse URL to extract host and path
    std::string host, path;
    {
        size_t start = url.find("://");
        if (start == std::string::npos) return "";
        start += 3;
        size_t slash = url.find('/', start);
        if (slash == std::string::npos) {
            host = url.substr(start);
            path = "/";
        } else {
            host = url.substr(start, slash - start);
            path = url.substr(slash);
        }
    }

    int whost_len = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, nullptr, 0);
    int wpath_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring whost(whost_len, 0);
    std::wstring wpath(wpath_len, 0);
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, &whost[0], whost_len);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wpath_len);

    HINTERNET session = WinHttpOpen(L"IHP-Updater/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return "";

    HINTERNET connection = WinHttpConnect(session, whost.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection) {
        WinHttpCloseHandle(session);
        return "";
    }

    HINTERNET request = WinHttpOpenRequest(connection, L"GET", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return "";
    }

    WinHttpAddRequestHeaders(request,
        L"Accept: application/vnd.github.v3+json\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return "";
    }

    if (!WinHttpReceiveResponse(request, nullptr)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return "";
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);

    // Follow redirects
    if (status_code >= 300 && status_code < 400) {
        DWORD redirect_size = 0;
        WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION,
            WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &redirect_size, WINHTTP_NO_HEADER_INDEX);
        if (redirect_size > 0) {
            std::wstring redirect_url(redirect_size / sizeof(wchar_t), 0);
            WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION,
                WINHTTP_HEADER_NAME_BY_INDEX, &redirect_url[0], &redirect_size, WINHTTP_NO_HEADER_INDEX);

            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);

            int utf8_len = WideCharToMultiByte(CP_UTF8, 0, redirect_url.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string redirect_utf8(utf8_len, 0);
            WideCharToMultiByte(CP_UTF8, 0, redirect_url.c_str(), -1, &redirect_utf8[0], utf8_len, nullptr, nullptr);

            return http_get(redirect_utf8, max_redirects - 1);
        }
    }

    if (status_code != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return "";
    }

    std::string result;
    DWORD available = 0;
    do {
        available = 0;
        WinHttpQueryDataAvailable(request, &available);
        if (available > 0) {
            std::vector<char> buffer(available + 1, 0);
            DWORD read = 0;
            WinHttpReadData(request, buffer.data(), available, &read);
            result.append(buffer.data(), read);
        }
    } while (available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    return result;
}

bool Updater::http_download_file(const std::string& url, const std::string& dest_path, int max_redirects) {
    if (max_redirects <= 0) return false;
    std::string host, path;
    {
        size_t start = url.find("://");
        if (start == std::string::npos) return false;
        start += 3;
        size_t slash = url.find('/', start);
        if (slash == std::string::npos) {
            host = url.substr(start);
            path = "/";
        } else {
            host = url.substr(start, slash - start);
            path = url.substr(slash);
        }
    }

    int whost_len = MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, nullptr, 0);
    int wpath_len = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring whost(whost_len, 0);
    std::wstring wpath(wpath_len, 0);
    MultiByteToWideChar(CP_UTF8, 0, host.c_str(), -1, &whost[0], whost_len);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wpath[0], wpath_len);

    HINTERNET session = WinHttpOpen(L"IHP-Updater/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return false;

    HINTERNET connection = WinHttpConnect(session, whost.c_str(),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!connection) {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET request = WinHttpOpenRequest(connection, L"GET", wpath.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    // For binary downloads, accept anything
    WinHttpAddRequestHeaders(request,
        L"Accept: application/octet-stream\r\n",
        (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    if (!WinHttpReceiveResponse(request, nullptr)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);

    // Follow redirects (GitHub redirects to CDN for release assets)
    if (status_code >= 300 && status_code < 400) {
        DWORD redirect_size = 0;
        WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION,
            WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &redirect_size, WINHTTP_NO_HEADER_INDEX);
        if (redirect_size > 0) {
            std::wstring redirect_url(redirect_size / sizeof(wchar_t), 0);
            WinHttpQueryHeaders(request, WINHTTP_QUERY_LOCATION,
                WINHTTP_HEADER_NAME_BY_INDEX, &redirect_url[0], &redirect_size, WINHTTP_NO_HEADER_INDEX);

            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);

            int utf8_len = WideCharToMultiByte(CP_UTF8, 0, redirect_url.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string redirect_utf8(utf8_len, 0);
            WideCharToMultiByte(CP_UTF8, 0, redirect_url.c_str(), -1, &redirect_utf8[0], utf8_len, nullptr, nullptr);

            return http_download_file(redirect_utf8, dest_path, max_redirects - 1);
        }
    }

    if (status_code != 200) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    // write response body to file
    std::ofstream file(dest_path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD available = 0;
    bool write_ok = true;
    do {
        available = 0;
        WinHttpQueryDataAvailable(request, &available);
        if (available > 0) {
            std::vector<char> buffer(available);
            DWORD read = 0;
            WinHttpReadData(request, buffer.data(), available, &read);
            file.write(buffer.data(), read);
            if (!file.good()) { write_ok = false; break; }
        }
    } while (available > 0);

    file.close();

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);

    return write_ok && file.good();
}

UpdateInfo Updater::check_for_update() {
    UpdateInfo info;
    info.current_version = current_version_;

    if (owner_.empty() || repo_.empty()) {
        info.check_failed = true;
        info.error = "Repository not configured";
        return info;
    }

    std::string api_url = "https://api.github.com/repos/" + owner_ + "/" + repo_ + "/releases/latest";
    std::string response = http_get(api_url);

    if (response.empty()) {
        info.check_failed = true;
        info.error = "Could not connect to GitHub";
        return info;
    }

    try {
        json j = json::parse(response);

        if (j.contains("tag_name")) {
            info.latest_version = j["tag_name"].get<std::string>();
        }
        if (j.contains("body")) {
            info.release_notes = j["body"].get<std::string>();
            if (info.release_notes.size() > 500) {
                info.release_notes = info.release_notes.substr(0, 500) + "...";
            }
        }

        // Find IHP.exe in release assets
        if (j.contains("assets") && j["assets"].is_array()) {
            for (const auto& asset : j["assets"]) {
                std::string name = asset.value("name", "");
                if (name == "IHP.exe") {
                    info.download_url = asset.value("browser_download_url", "");
                    break;
                }
            }
        }

        // compare versions update if latest is different from current
        if (!info.latest_version.empty() && info.latest_version != current_version_) {
            info.update_available = true;
        }

    } catch (const std::exception& e) {
        info.check_failed = true;
        info.error = std::string("Failed to parse response: ") + e.what();
    }

    return info;
}

bool Updater::download_and_apply(const UpdateInfo& info) {
    if (info.download_url.empty()) return false;

    std::string exe_path = get_exe_path();
    std::string exe_dir = get_exe_dir();
    std::string update_exe = exe_dir + "\\IHP_update.exe";
    std::string bat_path = exe_dir + "\\ihp_update.bat";

    // download new exe
    if (!http_download_file(info.download_url, update_exe)) {
        // Clean up failed download
        DeleteFileA(update_exe.c_str());
        return false;
    }

    // Verify the downloaded file is at least a reasonable size (not an error page)
    HANDLE hFile = CreateFileA(update_exe.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER file_size;
    GetFileSizeEx(hFile, &file_size);
    CloseHandle(hFile);
    if (file_size.QuadPart < 100000) { // EXE should be at least 100KB
        DeleteFileA(update_exe.c_str());
        return false;
    }

// the whole rename process!
    std::ofstream bat(bat_path, std::ios::trunc);
    if (!bat.is_open()) {
        DeleteFileA(update_exe.c_str());
        return false;
    }

    bat << "@echo off\r\n";
    bat << "echo Updating IHP...\r\n";
    bat << "timeout /t 2 /nobreak >nul\r\n";
    // Retry loop in case the process didn't fully exit
    bat << ":retry\r\n";
    bat << "del \"" << exe_path << "\" >nul 2>&1\r\n";
    bat << "if exist \"" << exe_path << "\" (\r\n";
    bat << "    timeout /t 1 /nobreak >nul\r\n";
    bat << "    goto retry\r\n";
    bat << ")\r\n";
    bat << "move \"" << update_exe << "\" \"" << exe_path << "\" >nul\r\n";
    bat << "start \"\" \"" << exe_path << "\"\r\n";
    bat << "del \"%~f0\" >nul 2>&1\r\n";
    bat.close();

        // launch the batch script hidden
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    std::string cmd = "cmd.exe /c \"" + bat_path + "\"";
    if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, exe_dir.c_str(), &si, &pi)) {
        DeleteFileA(update_exe.c_str());
        DeleteFileA(bat_path.c_str());
        return false;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return true; // Caller should be extinggg.....
}

} // namespace ihp (lol)
