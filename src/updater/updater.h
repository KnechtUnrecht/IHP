#pragma once
#include <string>

namespace ihp {

struct UpdateInfo {
    bool update_available = false;
    bool check_failed = false;
    std::string latest_version;
    std::string current_version;
    std::string download_url;       // URL to the EXE asset
    std::string release_notes;
    std::string error;
};

class Updater {
public:
    // Set the GitHub repo (e.g., "owner", "repo")
    void set_repo(const std::string& owner, const std::string& repo);

    // Set current app version
    void set_current_version(const std::string& version);

    // Check for updates (blocking - call on background thread)
    UpdateInfo check_for_update();

    // Download new EXE and launch swap script (blocking - call on background thread)
    // Returns true if download Succeeded and swap script was launched
    // The caller exits apllication if true
    bool download_and_apply(const UpdateInfo& info);

private:
    std::string http_get(const std::string& url, int max_redirects = 5);
    bool http_download_file(const std::string& url, const std::string& dest_path, int max_redirects = 5);
    std::string get_exe_path();
    std::string get_exe_dir();

    std::string owner_;
    std::string repo_;
    std::string current_version_;
};

} // namespace ihp
