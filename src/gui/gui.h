#pragma once
#include "../scanner/scanner_engine.h"
#include "../updater/updater.h"
#include "anim.h"
#include "code_viewer.h"
#include "../../third_party/imgui/imgui.h"
#include <string>
#include <vector>
#include <set>
#include <thread>
#include <atomic>
#include <mutex>

namespace ihp {

class GUI {
public:
    GUI(ScannerEngine& engine, ImFont* font_regular, ImFont* font_large, ImFont* font_small, ImFont* font_mono = nullptr);
    ~GUI();

    void render();
    void on_files_dropped(const std::vector<std::string>& files);
    bool should_exit() const { return should_exit_; }

private:
    void render_header();
    void render_file_selection();
    void render_scan_button();
    void render_progress();
    void render_summary_cards();
    void render_filter_bar();
    void render_results_table();
    void render_result_details(const FileScanResult& result);
    void render_detection_info_panel(const Detection& d, float height_override = 0.0f);
    void render_compare_window();

    void open_file_dialog();
    void open_folder_dialog();
    void start_scan();
    void check_for_updates();
    void download_update();

    // Helpers
    void push_font(ImFont* f);
    void pop_font();
    bool passes_table_filter(const FileScanResult& fr) const;
    bool passes_detail_filter(const Detection& d) const;
    void copy_to_clipboard(const std::string& text);
    void open_file_location(const std::string& path);

    ScannerEngine& engine_;
    ImFont* font_regular_;
    ImFont* font_large_;
    ImFont* font_small_;
    ImFont* font_mono_;

    std::vector<std::string> selected_files_;
    std::string selected_path_;
    bool show_details_ = false;
    int selected_result_index_ = -1;
    float anim_time_ = 0.0f;
    AnimStore anim_;
    float smooth_progress_ = 0.0f;
    bool scan_just_completed_ = false;
    float scan_complete_time_ = 0.0f;
    float results_appear_time_ = 0.0f;

    // Filters (results table)
    bool filter_show_clean_ = true;
    bool filter_show_suspicious_ = true;
    bool filter_show_malicious_ = true;

    // Filters (detail window)
    bool detail_show_critical_ = true;
    bool detail_show_high_ = true;
    bool detail_show_medium_ = true;
    bool detail_show_low_ = true;
    bool detail_show_info_ = false;

    int expanded_detection_index_ = -1;

    // Comparison
    bool show_compare_ = false;
    int compare_index_a_ = -1;
    int compare_index_b_ = -1;

    // Updater
    Updater updater_;
    UpdateInfo update_info_;
    std::mutex update_mutex_;
    std::thread update_thread_;
    std::atomic<bool> update_checking_{false};
    std::atomic<bool> update_downloading_{false};
    bool update_checked_ = false;
    bool should_exit_ = false;
    std::string update_error_;

    // Code viewer
    CodeViewer code_viewer_;
};

} // namespace ihp
