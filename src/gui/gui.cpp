#include "gui.h"
#include "../version.h"
#include "../utils/string_utils.h"
#include "../scanner/detections/rule_info.h"
#include "../scanner/scan_export.h"
#include "../../third_party/imgui/imgui.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <filesystem>
#include <cmath>
#include <algorithm>
#include <unordered_set>
#include <shellapi.h>

namespace fs = std::filesystem;

namespace ihp {

// Colors
static const ImVec4 COL_CRITICAL    = ImVec4(0.95f, 0.22f, 0.22f, 1.0f);
static const ImVec4 COL_HIGH        = ImVec4(0.95f, 0.55f, 0.10f, 1.0f);
static const ImVec4 COL_MEDIUM      = ImVec4(0.95f, 0.80f, 0.15f, 1.0f);
static const ImVec4 COL_LOW         = ImVec4(0.40f, 0.70f, 0.95f, 1.0f);
static const ImVec4 COL_INFO        = ImVec4(0.55f, 0.55f, 0.60f, 1.0f);
static const ImVec4 COL_CLEAN       = ImVec4(0.20f, 0.88f, 0.45f, 1.0f);
static const ImVec4 COL_MALICIOUS   = ImVec4(0.95f, 0.18f, 0.18f, 1.0f);
static const ImVec4 COL_SUSPICIOUS  = ImVec4(0.95f, 0.55f, 0.10f, 1.0f);
static const ImVec4 COL_ACCENT      = ImVec4(0.85f, 0.28f, 0.22f, 1.0f);
static const ImVec4 COL_ACCENT_DIM  = ImVec4(0.55f, 0.20f, 0.18f, 1.0f);
static const ImVec4 COL_TEXT_DIM    = ImVec4(0.50f, 0.52f, 0.56f, 1.0f);
static const ImVec4 COL_CARD_BG     = ImVec4(0.11f, 0.115f, 0.14f, 1.0f);

static ImVec4 severity_color(Severity s) {
    switch (s) {
        case Severity::CRITICAL: return COL_CRITICAL;
        case Severity::HIGH:     return COL_HIGH;
        case Severity::MEDIUM:   return COL_MEDIUM;
        case Severity::LOW:      return COL_LOW;
        case Severity::INFO:     return COL_INFO;
    }
    return COL_INFO;
}

static ImVec4 threat_color(ThreatLevel t) {
    switch (t) {
        case ThreatLevel::CLEAN:      return COL_CLEAN;
        case ThreatLevel::SUSPICIOUS: return COL_SUSPICIOUS;
        case ThreatLevel::MALICIOUS:  return COL_MALICIOUS;
    }
    return COL_INFO;
}

GUI::GUI(ScannerEngine& engine, ImFont* font_regular, ImFont* font_large, ImFont* font_small, ImFont* font_mono)
    : engine_(engine), font_regular_(font_regular), font_large_(font_large), font_small_(font_small), font_mono_(font_mono)
{
    updater_.set_repo("KnechtUnrecht", "IHP");
    updater_.set_current_version(IHP_VERSION);
    code_viewer_.set_fonts(font_regular, font_small, font_mono);
}

GUI::~GUI() {
    if (update_thread_.joinable()) {
        update_thread_.join();
    }
}

void GUI::push_font(ImFont* f) {
    if (f) ImGui::PushFont(f);
}
void GUI::pop_font() {
    ImGui::PopFont();
}

bool GUI::passes_table_filter(const FileScanResult& fr) const {
    switch (fr.threat_level) {
        case ThreatLevel::CLEAN:      return filter_show_clean_;
        case ThreatLevel::SUSPICIOUS: return filter_show_suspicious_;
        case ThreatLevel::MALICIOUS:  return filter_show_malicious_;
    }
    return true;
}

bool GUI::passes_detail_filter(const Detection& d) const {
    switch (d.severity) {
        case Severity::CRITICAL: return detail_show_critical_;
        case Severity::HIGH:     return detail_show_high_;
        case Severity::MEDIUM:   return detail_show_medium_;
        case Severity::LOW:      return detail_show_low_;
        case Severity::INFO:     return detail_show_info_;
    }
    return true;
}

void GUI::render() {
    anim_time_ += ImGui::GetIO().DeltaTime;
    anim_.gc();
    float dt = ImGui::GetIO().DeltaTime;

    if (engine_.progress().done && !scan_just_completed_) {
        scan_just_completed_ = true;
        scan_complete_time_ = anim_time_;
        results_appear_time_ = anim_time_;
    }

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 20));
    ImGui::Begin("##MainWindow", nullptr, flags);
    ImGui::PopStyleVar();

    render_header();
    ImGui::Spacing();

    render_file_selection();
    render_scan_button();

    if (engine_.is_scanning()) {
        render_progress();
    }

    if (engine_.progress().done) {
        render_summary_cards();
        render_filter_bar();
        render_results_table();
    }

    ImGui::End();

    // Detail window
    if (show_details_ && selected_result_index_ >= 0) {
        auto& res = engine_.results();
        std::lock_guard<std::mutex> lock(res.mutex);
        if (selected_result_index_ < static_cast<int>(res.file_results.size())) {
            render_result_details(res.file_results[selected_result_index_]);
        }
    }

    // Compare window
    if (show_compare_) {
        render_compare_window();
    }

    // Code viewer window
    if (code_viewer_.is_open()) {
        code_viewer_.render();
    }
}

void GUI::render_header() {
    float w = ImGui::GetContentRegionAvail().x;

    if (font_large_) {
        push_font(font_large_);
        ImVec2 ts = ImGui::CalcTextSize("Imagine Hacking People");
        float title_x = (w - ts.x) * 0.5f;
        ImGui::SetCursorPosX(title_x);
        ImGui::TextColored(COL_ACCENT, "Imagine Hacking People");
        pop_font();
    } else {
        ImVec2 ts = ImGui::CalcTextSize("Imagine Hacking People");
        float title_x = (w - ts.x) * 0.5f;
        ImGui::SetCursorPosX(title_x);
        ImGui::TextColored(COL_ACCENT, "Imagine Hacking People");
    }

    if (font_small_) push_font(font_small_);
    const char* subtitle = "IHP \xE2\x80\x94 Imagine Hacking People";
    ImVec2 ss = ImGui::CalcTextSize(subtitle);
    ImGui::SetCursorPosX((w - ss.x) * 0.5f);
    ImGui::TextColored(COL_TEXT_DIM, "%s", subtitle);

    // Update status (top-right corner)
    {
        float btn_x = w - 10;
        bool checking = update_checking_.load();
        bool downloading = update_downloading_.load();

        // Show version number
        char ver_text[64];
        snprintf(ver_text, sizeof(ver_text), "v%s", IHP_VERSION);

        if (checking) {
            const char* msg = "Checking for updates...";
            ImVec2 msz = ImGui::CalcTextSize(msg);
            ImGui::SameLine(btn_x - msz.x);
            ImGui::TextColored(COL_TEXT_DIM, "%s", msg);
        } else if (downloading) {
            const char* msg = "Downloading update...";
            ImVec2 msz = ImGui::CalcTextSize(msg);
            ImGui::SameLine(btn_x - msz.x);
            ImGui::TextColored(ImVec4(0.4f, 0.7f, 0.95f, 1.0f), "%s", msg);
        } else if (update_checked_) {
            std::lock_guard<std::mutex> lock(update_mutex_);
            if (update_info_.update_available) {
                char msg[128];
                snprintf(msg, sizeof(msg), "Update available: %s", update_info_.latest_version.c_str());
                ImVec2 msz = ImGui::CalcTextSize(msg);
                float update_btn_w = 70;
                ImGui::SameLine(btn_x - msz.x - update_btn_w - 8);
                ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.2f, 1.0f), "%s", msg);
                ImGui::SameLine(0, 8);
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.15f, 0.35f, 0.15f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.2f, 0.5f, 0.2f, 1.0f));
                if (ImGui::SmallButton("Update")) {
                    download_update();
                }
                ImGui::PopStyleColor(2);
            } else if (update_info_.check_failed) {
                // Show version only
                ImVec2 vs = ImGui::CalcTextSize(ver_text);
                ImGui::SameLine(btn_x - vs.x);
                ImGui::TextColored(COL_TEXT_DIM, "%s", ver_text);
            } else {
                char msg[128];
                snprintf(msg, sizeof(msg), "%s  (up to date)", ver_text);
                ImVec2 msz = ImGui::CalcTextSize(msg);
                ImGui::SameLine(btn_x - msz.x);
                ImGui::TextColored(COL_TEXT_DIM, "%s", msg);
            }
        } else {
            // Show version + check button
            ImVec2 vs = ImGui::CalcTextSize(ver_text);
            float check_btn_w = ImGui::CalcTextSize("Check Updates").x + 12;
            ImGui::SameLine(btn_x - vs.x - check_btn_w - 16);
            ImGui::TextColored(COL_TEXT_DIM, "%s", ver_text);
            ImGui::SameLine(0, 8);
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.14f, 0.20f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.18f, 0.28f, 1.0f));
            if (ImGui::SmallButton("Check Updates")) {
                check_for_updates();
            }
            ImGui::PopStyleColor(2);
        }
    }
    if (font_small_) pop_font();

    ImGui::Spacing();
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float pad = 40.0f;
    float line_w = w - pad * 2.0f;
    // Static gradient separator
    draw_gradient_separator(dl, p.x + pad, p.y, line_w, IM_COL32(120, 50, 45, 120));
    ImGui::Dummy(ImVec2(0, 4));
}

void GUI::render_file_selection() {
    ImGui::Spacing();
    bool scanning = engine_.is_scanning();
    if (scanning) ImGui::BeginDisabled();

    float btn_h = 38.0f;
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.17f, 0.21f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f, 0.17f, 0.17f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.30f, 0.18f, 0.16f, 1.0f));

    if (ImGui::Button("Select JAR File(s)", ImVec2(170, btn_h))) open_file_dialog();
    ImGui::SameLine(0, 12);
    if (ImGui::Button("Select Folder", ImVec2(140, btn_h))) open_folder_dialog();
    ImGui::PopStyleColor(3);

    if (!selected_path_.empty()) {
        ImGui::SameLine(0, 16);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8);
        if (font_small_) push_font(font_small_);
        ImGui::TextColored(ImVec4(0.45f, 0.75f, 0.50f, 1.0f), "%s", selected_path_.c_str());
        if (font_small_) pop_font();
    }
    if (scanning) ImGui::EndDisabled();

    if (selected_files_.empty() && !engine_.is_scanning() && !engine_.progress().done) {
        ImGui::Spacing(); ImGui::Spacing();
        float w = ImGui::GetContentRegionAvail().x;
        float h = 100.0f;
        ImVec2 pos = ImGui::GetCursorScreenPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h), IM_COL32(18, 20, 26, 180), 10.0f);
        dl->AddRect(pos, ImVec2(pos.x + w, pos.y + h), IM_COL32(100, 55, 55, 140), 10.0f, 0, 1.5f);
        const char* drop_text = "Drag & Drop JAR files here";
        ImVec2 text_sz = ImGui::CalcTextSize(drop_text);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (h - text_sz.y) * 0.5f);
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (w - text_sz.x) * 0.5f);
        ImGui::TextColored(ImVec4(0.45f, 0.42f, 0.42f, 0.9f), "%s", drop_text);
        ImGui::SetCursorScreenPos(ImVec2(pos.x, pos.y + h + 8));
    }
    ImGui::Spacing();
}

void GUI::render_scan_button() {
    if (selected_files_.empty()) return;
    bool scanning = engine_.is_scanning();
    float dt = ImGui::GetIO().DeltaTime;

    ImGui::Spacing();
    float w = ImGui::GetContentRegionAvail().x;
    float btn_w = 280.0f;
    float btn_h = 48.0f;
    float btn_x = (w - btn_w) * 0.5f;

    ImDrawList* dl = ImGui::GetWindowDrawList();

    // Hover animation
    ImGui::SetCursorPosX(btn_x);
    ImVec2 btn_pos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##ScanBtn", ImVec2(btn_w, btn_h));
    bool hovered = ImGui::IsItemHovered() && !scanning;
    bool clicked = ImGui::IsItemClicked() && !scanning;

    AnimState& astate = anim_.get(ImGui::GetID("##ScanBtnAnim"));
    astate.hover = smooth_damp(astate.hover, hovered ? 1.0f : 0.0f, 10.0f, dt);

    float breath = sinf(anim_time_ * 2.0f) * 0.003f;
    float scale = 1.0f + astate.hover * 0.02f + breath;
    float scaled_w = btn_w * scale;
    float scaled_h = btn_h * scale;
    float sx = btn_pos.x + (btn_w - scaled_w) * 0.5f;
    float sy = btn_pos.y + (btn_h - scaled_h) * 0.5f;
    ImVec2 bmin(sx, sy);
    ImVec2 bmax(sx + scaled_w, sy + scaled_h);

    // Shadow (intensifies on hover)
    float shadow_r = 6.0f + astate.hover * 6.0f;
    int shadow_a = (int)(30 + astate.hover * 40);
    draw_shadow(dl, bmin, bmax, shadow_r, IM_COL32(120, 30, 25, shadow_a), 10.0f);

    ImU32 col_l = IM_COL32(140, 38, 30, 255);
    ImU32 col_r = IM_COL32(210, 60, 45, 255);
    dl->AddRectFilledMultiColor(bmin, bmax, col_l, col_r, col_r, col_l);
    // Rounded corners overlay (clip to rounded shape)
    dl->AddRectFilled(bmin, bmax, IM_COL32(0, 0, 0, 0), 10.0f);

    // White overlay on hover
    if (astate.hover > 0.01f) {
        int ov_a = (int)(25 * astate.hover);
        dl->AddRectFilled(bmin, bmax, IM_COL32(255, 255, 255, ov_a), 10.0f);
    }

    // Rotating dots when scanning
    if (scanning) {
        float cx = (bmin.x + bmax.x) * 0.5f;
        float cy = (bmin.y + bmax.y) * 0.5f;
        float rx = scaled_w * 0.5f + 6.0f;
        float ry = scaled_h * 0.5f + 6.0f;
        for (int di = 0; di < 8; di++) {
            float angle = anim_time_ * 3.0f + di * (3.14159f * 2.0f / 8.0f);
            float dx = cx + cosf(angle) * rx;
            float dy = cy + sinf(angle) * ry;
            int alpha = 60 + (int)(195 * (0.5f + 0.5f * sinf(angle + anim_time_ * 4.0f)));
            dl->AddCircleFilled(ImVec2(dx, dy), 2.5f, IM_COL32(255, 120, 100, alpha));
        }
    }

    // Button text
    const char* btn_text = scanning ? "SCANNING..." : "SCAN";
    if (font_regular_) push_font(font_regular_);
    ImVec2 text_sz = ImGui::CalcTextSize(btn_text);
    dl->AddText(ImVec2(bmin.x + (scaled_w - text_sz.x) * 0.5f, bmin.y + (scaled_h - text_sz.y) * 0.5f),
                IM_COL32(255, 255, 255, 255), btn_text);
    if (font_regular_) pop_font();

    if (clicked) start_scan();

    // File count text below
    if (font_small_) push_font(font_small_);
    char buf[64];
    snprintf(buf, sizeof(buf), "%d file(s) selected", static_cast<int>(selected_files_.size()));
    ImVec2 ts = ImGui::CalcTextSize(buf);
    ImGui::SetCursorPosX((w - ts.x) * 0.5f);
    ImGui::TextColored(COL_TEXT_DIM, "%s", buf);
    if (font_small_) pop_font();
    ImGui::Spacing();
}

void GUI::render_progress() {
    ImGui::Spacing();
    float dt = ImGui::GetIO().DeltaTime;
    auto& prog = engine_.progress();
    int total = prog.total_files.load();
    int done = prog.scanned_files.load();
    float target = total > 0 ? static_cast<float>(done) / total : 0.0f;
    smooth_progress_ = smooth_damp(smooth_progress_, target, 5.0f, dt);

    float w = ImGui::GetContentRegionAvail().x;
    float bar_h = 28.0f;
    ImVec2 bar_pos = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    // Background track
    dl->AddRectFilled(bar_pos, ImVec2(bar_pos.x + w, bar_pos.y + bar_h),
                      IM_COL32(30, 30, 38, 255), 8.0f);

    // Gradient fill bar
    float fill_w = w * smooth_progress_;
    if (fill_w > 1.0f) {
        ImVec2 fill_min = bar_pos;
        ImVec2 fill_max = ImVec2(bar_pos.x + fill_w, bar_pos.y + bar_h);
        dl->AddRectFilledMultiColor(fill_min, fill_max,
            IM_COL32(160, 45, 35, 255), IM_COL32(220, 70, 55, 255),
            IM_COL32(220, 70, 55, 255), IM_COL32(160, 45, 35, 255));

        // Shimmer stripe sweeping across
        float shimmer_w = 60.0f;
        float shimmer_x = fmodf(anim_time_ * 120.0f, fill_w + shimmer_w) - shimmer_w;
        float s_x0 = (std::max)(bar_pos.x + shimmer_x, bar_pos.x);
        float s_x1 = (std::min)(bar_pos.x + shimmer_x + shimmer_w, bar_pos.x + fill_w);
        if (s_x1 > s_x0) {
            dl->AddRectFilledMultiColor(
                ImVec2(s_x0, bar_pos.y), ImVec2(s_x1, bar_pos.y + bar_h),
                IM_COL32(255, 255, 255, 0), IM_COL32(255, 255, 255, 40),
                IM_COL32(255, 255, 255, 40), IM_COL32(255, 255, 255, 0)
            );
        }
    }

    // Rounded clip overlay (draw border)
    dl->AddRect(bar_pos, ImVec2(bar_pos.x + w, bar_pos.y + bar_h),
                IM_COL32(80, 40, 40, 100), 8.0f, 0, 1.0f);

    // Overlay text centered
    char overlay[128];
    snprintf(overlay, sizeof(overlay), "Scanning %d / %d", done, total);
    ImVec2 text_sz = ImGui::CalcTextSize(overlay);
    dl->AddText(ImVec2(bar_pos.x + (w - text_sz.x) * 0.5f, bar_pos.y + (bar_h - text_sz.y) * 0.5f),
                IM_COL32(255, 255, 255, 230), overlay);

    ImGui::Dummy(ImVec2(w, bar_h));

    // Current file text below
    std::string current = prog.get_current_file();
    if (!current.empty()) {
        if (font_small_) push_font(font_small_);
        ImGui::TextColored(COL_TEXT_DIM, "  %s", current.c_str());
        if (font_small_) pop_font();
    }
    ImGui::Spacing();
}

void GUI::render_summary_cards() {
    ImGui::Spacing();
    float dt = ImGui::GetIO().DeltaTime;
    auto& res = engine_.results();
    std::lock_guard<std::mutex> lock(res.mutex);

    float w = ImGui::GetContentRegionAvail().x;
    float card_w = (w - 40) / 5.0f;
    float card_h = 65.0f;
    ImVec2 start = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();

    struct CardData { const char* label; int value; ImU32 color; ImU32 bg; };
    CardData cards[] = {
        {"Files",    (int)res.file_results.size(), IM_COL32(180, 185, 195, 255), IM_COL32(28, 30, 38, 255)},
        {"Critical", res.critical_count,           IM_COL32(240, 56, 56, 255),   IM_COL32(40, 18, 18, 255)},
        {"High",     res.high_count,               IM_COL32(240, 140, 25, 255),  IM_COL32(38, 28, 14, 255)},
        {"Medium",   res.medium_count,             IM_COL32(240, 205, 40, 255),  IM_COL32(36, 34, 14, 255)},
        {"Clean",    0,                            IM_COL32(50, 225, 115, 255),  IM_COL32(14, 36, 22, 255)},
    };
    int clean = 0;
    for (const auto& fr : res.file_results)
        if (fr.threat_level == ThreatLevel::CLEAN) clean++;
    cards[4].value = clean;

    for (int i = 0; i < 5; i++) {
        // pop-in anim
        float entrance_elapsed = anim_time_ - scan_complete_time_ - i * 0.08f;
        float entrance_raw = (entrance_elapsed > 0.0f) ? (std::min)(entrance_elapsed / 0.35f, 1.0f) : 0.0f;
        float entrance_t = ease::out_back(entrance_raw);

        // Get per-card AnimState for smooth appear
        ImGui::PushID(i + 9000); // offset to avoid collision with other IDs
        AnimState& cas = anim_.get(ImGui::GetID("##SummaryCard"));
        cas.appear = smooth_damp(cas.appear, entrance_raw > 0.01f ? 1.0f : 0.0f, 6.0f, dt);
        ImGui::PopID();

        float appear_val = cas.appear * entrance_t;
        if (appear_val < 0.01f) continue;

        // Hover detection
        float x = start.x + i * (card_w + 10);
        float slide_y = 20.0f * (1.0f - entrance_t);
        ImVec2 cpos(x, start.y + slide_y);
        ImVec2 cmax(cpos.x + card_w, cpos.y + card_h);

        ImVec2 mouse = ImGui::GetMousePos();
        bool card_hovered = (mouse.x >= cpos.x && mouse.x <= cmax.x && mouse.y >= cpos.y && mouse.y <= cmax.y);
        ImGui::PushID(i + 9000);
        AnimState& cas2 = anim_.get(ImGui::GetID("##SummaryCard"));
        cas2.hover = smooth_damp(cas2.hover, card_hovered ? 1.0f : 0.0f, 10.0f, dt);
        ImGui::PopID();

        // Lift on hover
        float lift = cas2.hover * 4.0f;
        cpos.y -= lift;
        cmax.y -= lift;

        // Alpha based on appear value
        int alpha = (int)(255 * appear_val);

        // Shadow on hover
        if (cas2.hover > 0.01f) {
            draw_shadow(dl, cpos, cmax, 6.0f * cas2.hover,
                        IM_COL32(0, 0, 0, (int)(40 * cas2.hover)), 8.0f);
        }

        // Card background with alpha
        ImU32 bg = cards[i].bg;
        int bg_r = (bg >> 0) & 0xFF, bg_g = (bg >> 8) & 0xFF, bg_b = (bg >> 16) & 0xFF;
        dl->AddRectFilled(cpos, cmax, IM_COL32(bg_r, bg_g, bg_b, alpha), 8.0f);

        // Accent stripe at top (2px)
        ImU32 accent = cards[i].color;
        int ac_r = (accent >> 0) & 0xFF, ac_g = (accent >> 8) & 0xFF, ac_b = (accent >> 16) & 0xFF;
        dl->AddRectFilled(cpos, ImVec2(cmax.x, cpos.y + 2), IM_COL32(ac_r, ac_g, ac_b, alpha), 8.0f);

        // Number text
        char num[16]; snprintf(num, sizeof(num), "%d", cards[i].value);
        if (font_large_) push_font(font_large_);
        ImVec2 ns = ImGui::CalcTextSize(num);
        dl->AddText(ImVec2(cpos.x + (card_w - ns.x) * 0.5f, cpos.y + 8),
                    IM_COL32(ac_r, ac_g, ac_b, alpha), num);
        if (font_large_) pop_font();

        // Label text
        if (font_small_) push_font(font_small_);
        ImVec2 ls = ImGui::CalcTextSize(cards[i].label);
        dl->AddText(ImVec2(cpos.x + (card_w - ls.x) * 0.5f, cpos.y + card_h - 20),
                    IM_COL32(140, 142, 150, (int)(220.0f * appear_val)), cards[i].label);
        if (font_small_) pop_font();
    }
    ImGui::Dummy(ImVec2(0, card_h + 8));

    if (font_small_) push_font(font_small_);
    ImGui::TextColored(COL_TEXT_DIM, "Scan completed in %.0f ms", res.scan_time_ms);
    if (font_small_) pop_font();
    ImGui::Spacing();
}

// --- filter bar ---

void GUI::render_filter_bar() {
    auto& res = engine_.results();

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 3));
    if (font_small_) push_font(font_small_);

    ImGui::TextColored(COL_TEXT_DIM, "Filter:");
    ImGui::SameLine(0, 8);

    ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_MALICIOUS));
    ImGui::Checkbox("Malicious", &filter_show_malicious_);
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 12);

    ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_SUSPICIOUS));
    ImGui::Checkbox("Suspicious", &filter_show_suspicious_);
    ImGui::PopStyleColor();
    ImGui::SameLine(0, 12);

    ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_CLEAN));
    ImGui::Checkbox("Clean", &filter_show_clean_);
    ImGui::PopStyleColor();

    // Compare button (right side)
    {
        std::lock_guard<std::mutex> lock(res.mutex);
        if (res.file_results.size() >= 2) {
            float btn_w = 130.0f;
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - btn_w + ImGui::GetCursorPosX());

            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.14f, 0.22f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.24f, 0.18f, 0.30f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.30f, 0.22f, 0.38f, 1.0f));
            if (ImGui::Button("Compare Mods", ImVec2(btn_w, 0))) {
                show_compare_ = true;
                if (compare_index_a_ < 0) compare_index_a_ = 0;
                if (compare_index_b_ < 0) compare_index_b_ = (res.file_results.size() > 1) ? 1 : 0;
            }
            ImGui::PopStyleColor(3);
        }
    }

    if (font_small_) pop_font();
    ImGui::PopStyleVar(2);
    ImGui::Spacing();
}

// --- results table ---

void GUI::render_results_table() {
    auto& res = engine_.results();
    std::lock_guard<std::mutex> lock(res.mutex);

    if (ImGui::BeginTable("Results", 5,
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp |
        ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_PadOuterX,
        ImVec2(0, ImGui::GetContentRegionAvail().y - 4))) {

        ImGui::TableSetupColumn("Verdict",    ImGuiTableColumnFlags_WidthFixed, 95.0f);
        ImGui::TableSetupColumn("File",        ImGuiTableColumnFlags_WidthStretch, 3.0f);
        ImGui::TableSetupColumn("Classes",     ImGuiTableColumnFlags_WidthFixed, 65.0f);
        ImGui::TableSetupColumn("Detections",  ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Score",       ImGuiTableColumnFlags_WidthFixed, 55.0f);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        float tbl_dt = ImGui::GetIO().DeltaTime;
        for (size_t i = 0; i < res.file_results.size(); i++) {
            const auto& fr = res.file_results[i];
            if (!passes_table_filter(fr)) continue;

            ImGui::TableNextRow(0, 30.0f);

            // Per-row hover animation
            ImGui::PushID(static_cast<int>(i));
            AnimState& row_anim = anim_.get(ImGui::GetID("##TblRow"));
            ImGui::PopID();

            ImGui::TableNextColumn();
            {
                ImVec4 tc = threat_color(fr.threat_level);
                const char* label = threat_level_string(fr.threat_level);
                ImVec2 ts = ImGui::CalcTextSize(label);
                ImVec2 pos = ImGui::GetCursorScreenPos();
                ImDrawList* dl = ImGui::GetWindowDrawList();
                float pill_w = ts.x + 16, pill_h = ts.y + 6;
                float py = pos.y + (30.0f - pill_h) * 0.5f - 3;
                ImU32 pill_col = ImGui::ColorConvertFloat4ToU32(ImVec4(tc.x*0.25f, tc.y*0.25f, tc.z*0.25f, 0.6f));
                dl->AddRectFilled(ImVec2(pos.x, py), ImVec2(pos.x + pill_w, py + pill_h), pill_col, pill_h * 0.5f);
                dl->AddText(ImVec2(pos.x + 8, py + 3), ImGui::ColorConvertFloat4ToU32(tc), label);
                ImGui::Dummy(ImVec2(pill_w, pill_h));
            }

            ImGui::TableNextColumn();
            if (ImGui::Selectable(fr.file_name.c_str(), selected_result_index_ == static_cast<int>(i),
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                selected_result_index_ = static_cast<int>(i);
                show_details_ = true;
                expanded_detection_index_ = -1;  // reset expanded detection when switching files
            }

            // Right-click context menu
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("View Details")) {
                    selected_result_index_ = static_cast<int>(i);
                    show_details_ = true;
                    expanded_detection_index_ = -1;
                }
                if (ImGui::MenuItem("View Code")) {
                    code_viewer_.open(fr.file_path);
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Copy SHA-256")) {
                    copy_to_clipboard(fr.sha256);
                }
                if (ImGui::MenuItem("Copy File Path")) {
                    copy_to_clipboard(fr.file_path);
                }
                if (ImGui::MenuItem("Copy Scan Report")) {
                    copy_to_clipboard(ScanExporter::to_text_single(fr));
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Open File Location")) {
                    open_file_location(fr.file_path);
                }
                ImGui::EndPopup();
            }

            bool row_hovered = ImGui::IsItemHovered();
            row_anim.hover = smooth_damp(row_anim.hover, row_hovered ? 1.0f : 0.0f, 10.0f, tbl_dt);
            if (row_anim.hover > 0.01f) {
                int hover_alpha = (int)(18 * row_anim.hover);
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, IM_COL32(180, 60, 50, hover_alpha));
            }

            ImGui::TableNextColumn();
            ImGui::TextColored(COL_TEXT_DIM, "%d", fr.class_count);

            ImGui::TableNextColumn();
            if (!fr.detections.empty())
                ImGui::TextColored(COL_HIGH, "%d", static_cast<int>(fr.detections.size()));
            else
                ImGui::TextColored(COL_CLEAN, "0");

            ImGui::TableNextColumn();
            if (fr.threat_score >= 15) ImGui::TextColored(COL_CRITICAL, "%d", fr.threat_score);
            else if (fr.threat_score >= 5) ImGui::TextColored(COL_HIGH, "%d", fr.threat_score);
            else if (fr.threat_score > 0) ImGui::Text("%d", fr.threat_score);
            else ImGui::TextColored(COL_TEXT_DIM, "-");
        }
        ImGui::EndTable();
    }
}

// --- detail window ---

void GUI::render_result_details(const FileScanResult& result) {
    ImGui::SetNextWindowSize(ImVec2(860, 580), ImGuiCond_FirstUseEver);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 14));

    if (ImGui::Begin("Detection Details", &show_details_)) {
        if (font_large_) push_font(font_large_);
        ImGui::TextColored(COL_ACCENT, "%s", result.file_name.c_str());
        if (font_large_) pop_font();

        ImGui::SameLine();
        ImGui::TextColored(threat_color(result.threat_level), "  %s", threat_level_string(result.threat_level));

        ImGui::Spacing();
        if (font_small_) push_font(font_small_);
        ImGui::TextColored(COL_TEXT_DIM, "Path:    %s", result.file_path.c_str());
        ImGui::TextColored(COL_TEXT_DIM, "SHA-256: %s", result.sha256.c_str());
        ImGui::TextColored(COL_TEXT_DIM, "Classes: %d    Threat Score: %d", result.class_count, result.threat_score);
        if (font_small_) pop_font();

        // Action buttons row (right-aligned)
        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 320);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.16f, 0.22f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.22f, 0.32f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.22f, 0.26f, 0.38f, 1.0f));
        if (ImGui::Button("View Code", ImVec2(96, 24))) {
            code_viewer_.open(result.file_path);
        }
        ImGui::SameLine(0, 6);
        if (ImGui::Button("Copy Report", ImVec2(96, 24))) {
            copy_to_clipboard(ScanExporter::to_text_single(result));
        }
        ImGui::SameLine(0, 6);
        if (ImGui::Button("Export JSON", ImVec2(96, 24))) {
            char filename[MAX_PATH] = "ihp_report.json";
            OPENFILENAMEA ofn = {};
            ofn.lStructSize = sizeof(ofn);
            ofn.hwndOwner = nullptr;
            ofn.lpstrFilter = "JSON Files\0*.json\0All Files\0*.*\0";
            ofn.lpstrFile = filename;
            ofn.nMaxFile = MAX_PATH;
            ofn.Flags = OFN_OVERWRITEPROMPT;
            ofn.lpstrDefExt = "json";
            if (GetSaveFileNameA(&ofn)) {
                // mutex already locked above
                ScanExporter::save_to_file(ScanExporter::to_json(engine_.results()), filename);
            }
        }
        ImGui::PopStyleColor(3);

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        if (result.detections.empty()) {
            float w = ImGui::GetContentRegionAvail().x;
            const char* msg = "No threats detected - this file appears clean.";
            ImVec2 ms = ImGui::CalcTextSize(msg);
            ImGui::SetCursorPosX((w - ms.x) * 0.5f);
            ImGui::TextColored(COL_CLEAN, "%s", msg);
        } else {
            // Severity filter bar
            if (font_small_) push_font(font_small_);
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 2));

            ImGui::TextColored(COL_TEXT_DIM, "Show:");
            ImGui::SameLine(0, 6);
            ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_CRITICAL));
            ImGui::Checkbox("Critical", &detail_show_critical_); ImGui::PopStyleColor();
            ImGui::SameLine(0, 8);
            ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_HIGH));
            ImGui::Checkbox("High", &detail_show_high_); ImGui::PopStyleColor();
            ImGui::SameLine(0, 8);
            ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_MEDIUM));
            ImGui::Checkbox("Medium", &detail_show_medium_); ImGui::PopStyleColor();
            ImGui::SameLine(0, 8);
            ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_LOW));
            ImGui::Checkbox("Low", &detail_show_low_); ImGui::PopStyleColor();
            ImGui::SameLine(0, 8);
            ImGui::PushStyleColor(ImGuiCol_CheckMark, ImGui::ColorConvertFloat4ToU32(COL_INFO));
            ImGui::Checkbox("Info", &detail_show_info_); ImGui::PopStyleColor();

            int visible = 0;
            for (const auto& d : result.detections)
                if (passes_detail_filter(d)) visible++;
            ImGui::SameLine(0, 16);
            ImGui::TextColored(COL_TEXT_DIM, "(%d / %d)", visible, (int)result.detections.size());

            ImGui::PopStyleVar(2);
            if (font_small_) pop_font();
            ImGui::Spacing();

            // Filtered detection list (scrollable)
            float det_dt = ImGui::GetIO().DeltaTime;
            ImGui::BeginChild("DetList", ImVec2(0, ImGui::GetContentRegionAvail().y), false);
            int vis_idx = 0;
            for (int di = 0; di < static_cast<int>(result.detections.size()); di++) {
                const auto& d = result.detections[di];
                if (!passes_detail_filter(d)) continue;

                ImGui::PushID(di);
                bool is_expanded = (expanded_detection_index_ == di);

                // Per-detection AnimState
                AnimState& det_anim = anim_.get(ImGui::GetID("##DetRow"));
                det_anim.expand = smooth_damp(det_anim.expand, is_expanded ? 1.0f : 0.0f, 8.0f, det_dt);

                // Detection row
                ImVec2 row_start = ImGui::GetCursorScreenPos();
                float row_w = ImGui::GetContentRegionAvail().x;
                float row_h = 42.0f;
                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImVec4 sc = severity_color(d.severity);

                // Row background
                ImU32 row_bg = is_expanded
                    ? IM_COL32(35, 28, 28, 255)
                    : (vis_idx % 2 == 0 ? IM_COL32(22, 24, 30, 255) : IM_COL32(26, 28, 34, 255));
                dl->AddRectFilled(row_start, ImVec2(row_start.x + row_w, row_start.y + row_h), row_bg, 4.0f);

                // idk why but imgui needs this offset or it looks weird
                ImGui::Dummy(ImVec2(row_w, row_h));
                if (ImGui::IsItemClicked()) {
                    expanded_detection_index_ = is_expanded ? -1 : di;
                }
                bool hovered = ImGui::IsItemHovered();
                det_anim.hover = smooth_damp(det_anim.hover, hovered ? 1.0f : 0.0f, 10.0f, det_dt);

                // Severity color stripe on left — brightens on hover
                float stripe_brightness = 1.0f + det_anim.hover * 0.5f;
                ImVec4 stripe_col = ImVec4(
                    (std::min)(sc.x * stripe_brightness, 1.0f),
                    (std::min)(sc.y * stripe_brightness, 1.0f),
                    (std::min)(sc.z * stripe_brightness, 1.0f), sc.w);
                dl->AddRectFilled(row_start, ImVec2(row_start.x + 4, row_start.y + row_h),
                                  ImGui::ColorConvertFloat4ToU32(stripe_col), 4.0f);

                if (det_anim.hover > 0.01f && !is_expanded) {
                    int h_alpha = (int)(12 * det_anim.hover);
                    dl->AddRectFilled(row_start, ImVec2(row_start.x + row_w, row_start.y + row_h),
                                      IM_COL32(255, 255, 255, h_alpha), 4.0f);
                }
                // Tooltip hint
                if (hovered) {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                }

                // Draw row content on top of the Dummy
                float cx = row_start.x + 14;
                float cy = row_start.y + 5;

                // Severity pill
                {
                    const char* sev_text = severity_to_string(d.severity);
                    if (font_small_) push_font(font_small_);
                    ImVec2 sev_sz = ImGui::CalcTextSize(sev_text);
                    float pill_w = sev_sz.x + 12, pill_h = sev_sz.y + 4;
                    float pill_y = cy + (row_h - 10 - pill_h) * 0.5f;
                    ImU32 pill_bg = ImGui::ColorConvertFloat4ToU32(ImVec4(sc.x*0.25f, sc.y*0.25f, sc.z*0.25f, 0.7f));
                    dl->AddRectFilled(ImVec2(cx, pill_y), ImVec2(cx + pill_w, pill_y + pill_h), pill_bg, pill_h * 0.5f);
                    dl->AddText(ImVec2(cx + 6, pill_y + 2), ImGui::ColorConvertFloat4ToU32(sc), sev_text);
                    if (font_small_) pop_font();
                    cx += pill_w + 10;
                }

                // Rule name
                {
                    dl->AddText(ImVec2(cx, cy + 2), IM_COL32(220, 222, 230, 255), d.rule_name.c_str());
                    ImVec2 rn_sz = ImGui::CalcTextSize(d.rule_name.c_str());
                    cx += rn_sz.x + 14;
                }

                // Description (truncated to fit)
                {
                    if (font_small_) push_font(font_small_);
                    float max_desc_w = row_start.x + row_w - cx - 30;
                    if (max_desc_w > 50) {
                        std::string desc = d.description;
                        ImVec2 desc_sz = ImGui::CalcTextSize(desc.c_str());
                        if (desc_sz.x > max_desc_w) {
                            while (desc.size() > 3) {
                                desc.pop_back();
                                ImVec2 ts = ImGui::CalcTextSize((desc + "...").c_str());
                                if (ts.x <= max_desc_w) break;
                            }
                            desc += "...";
                        }
                        dl->AddText(ImVec2(cx, cy + 4), IM_COL32(140, 142, 155, 220), desc.c_str());
                    }
                    if (font_small_) pop_font();
                }

                // Expand arrow indicator on right
                {
                    const char* arrow = is_expanded ? "v" : ">";
                    if (font_small_) push_font(font_small_);
                    ImVec2 arr_sz = ImGui::CalcTextSize(arrow);
                    dl->AddText(ImVec2(row_start.x + row_w - arr_sz.x - 12, cy + (row_h - 10 - arr_sz.y) * 0.5f),
                                IM_COL32(100, 105, 115, 180), arrow);
                    if (font_small_) pop_font();
                }

                // Expanded info panel
                if (det_anim.expand > 0.01f) {
                    // Render the panel at full size but clip to animated height
                    render_detection_info_panel(d, det_anim.expand);
                }

                ImGui::Dummy(ImVec2(0, 2)); // spacing between rows
                ImGui::PopID();
                vis_idx++;
            }
            ImGui::EndChild();
        }
    }
    ImGui::End();
    ImGui::PopStyleVar();
}

// --- detection info panel ---

void GUI::render_detection_info_panel(const Detection& d, float height_override) {
    const RuleInfo* info = get_rule_info(d.rule_name);
    ImVec4 sc = severity_color(d.severity);
    float panel_w = ImGui::GetContentRegionAvail().x;
    float indent = 18.0f;

    // Panel background
    ImVec2 panel_top = ImGui::GetCursorScreenPos();

    // Build sections
    struct Section {
        const char* heading;
        std::string text;
        ImVec4 color;
    };
    std::vector<Section> sections;

    if (!d.evidence.empty())
        sections.push_back({"Evidence", d.evidence, ImVec4(0.75f, 0.55f, 0.30f, 1.0f)});
    if (!d.file_name.empty())
        sections.push_back({"File", d.file_name, COL_TEXT_DIM});

    if (info) {
        sections.push_back({"What it detects", info->what_it_does, ImVec4(0.70f, 0.75f, 0.85f, 1.0f)});
        sections.push_back({"Why it's dangerous", info->why_its_bad, ImVec4(0.95f, 0.40f, 0.35f, 1.0f)});
        sections.push_back({"How detection works", info->how_it_works, ImVec4(0.55f, 0.70f, 0.80f, 1.0f)});
        sections.push_back({"Recommendation", info->recommendation, COL_CLEAN});
    } else {
        sections.push_back({"Description", d.description, ImVec4(0.70f, 0.75f, 0.85f, 1.0f)});
    }

    // Total panel height
    float total_h = 12.0f; // top padding
    float inner_w = panel_w - indent - 12.0f;

    if (font_small_) push_font(font_small_);
    float heading_h = ImGui::CalcTextSize("X").y;
    if (font_small_) pop_font();

    for (const auto& sec : sections) {
        total_h += heading_h + 2; // heading
        ImVec2 ts = ImGui::CalcTextSize(sec.text.c_str(), nullptr, false, inner_w);
        total_h += ts.y + 8; // text + spacing
    }
    total_h += 8.0f; // bottom padding

    // If height_override is between 0 and 1, treat as expand fraction
    float visible_h = total_h;
    bool clipping = false;
    if (height_override > 0.0f && height_override < 1.0f) {
        visible_h = total_h * height_override;
        clipping = true;
    }

    // Apply clip rect if animating
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (clipping) {
        dl->PushClipRect(panel_top, ImVec2(panel_top.x + panel_w, panel_top.y + visible_h), true);
    }

    // Draw background and accent stripe
    dl->AddRectFilled(panel_top, ImVec2(panel_top.x + panel_w, panel_top.y + total_h),
                      IM_COL32(16, 18, 25, 255), 0.0f);
    dl->AddRectFilled(panel_top, ImVec2(panel_top.x + 4, panel_top.y + total_h),
                      ImGui::ColorConvertFloat4ToU32(ImVec4(sc.x * 0.5f, sc.y * 0.5f, sc.z * 0.5f, 0.9f)));
    dl->AddLine(ImVec2(panel_top.x + 4, panel_top.y),
                ImVec2(panel_top.x + panel_w, panel_top.y),
                IM_COL32(60, 45, 45, 140), 1.0f);

    // Draw text content
    float tx = panel_top.x + indent;
    float ty = panel_top.y + 12.0f;

    for (const auto& sec : sections) {
        // Heading
        if (font_small_) push_font(font_small_);
        dl->AddText(ImVec2(tx, ty), IM_COL32(100, 105, 125, 200), sec.heading);
        ty += heading_h + 2;
        if (font_small_) pop_font();

        // Body text (wrapped, using draw list)
        ImU32 text_col = ImGui::ColorConvertFloat4ToU32(sec.color);
        ImFont* font = ImGui::GetFont();
        float font_size = ImGui::GetFontSize();
        dl->AddText(font, font_size, ImVec2(tx, ty), text_col,
                    sec.text.c_str(), sec.text.c_str() + sec.text.size(), inner_w);
        ImVec2 ts = ImGui::CalcTextSize(sec.text.c_str(), nullptr, false, inner_w);
        ty += ts.y + 8;
    }

    if (clipping) {
        dl->PopClipRect();
    }

    // Reserve space for the panel
    ImGui::Dummy(ImVec2(panel_w, visible_h));
}

// --- comparison window ---

void GUI::render_compare_window() {
    auto& res = engine_.results();
    std::lock_guard<std::mutex> lock(res.mutex);

    if (res.file_results.size() < 2) { show_compare_ = false; return; }

    ImGui::SetNextWindowSize(ImVec2(960, 640), ImGuiCond_FirstUseEver);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 14));

    if (ImGui::Begin("Compare Mods", &show_compare_)) {
        // Mod selectors
        if (font_small_) push_font(font_small_);
        float half_w = ImGui::GetContentRegionAvail().x * 0.5f - 12;

        ImGui::TextColored(COL_ACCENT, "Mod A:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(half_w - 60);
        if (ImGui::BeginCombo("##ModA", (compare_index_a_ >= 0 && compare_index_a_ < (int)res.file_results.size())
                ? res.file_results[compare_index_a_].file_name.c_str() : "(none)")) {
            for (int i = 0; i < (int)res.file_results.size(); i++)
                if (ImGui::Selectable(res.file_results[i].file_name.c_str(), compare_index_a_ == i))
                    compare_index_a_ = i;
            ImGui::EndCombo();
        }

        ImGui::SameLine(0, 24);
        ImGui::TextColored(COL_ACCENT, "Mod B:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(half_w - 60);
        if (ImGui::BeginCombo("##ModB", (compare_index_b_ >= 0 && compare_index_b_ < (int)res.file_results.size())
                ? res.file_results[compare_index_b_].file_name.c_str() : "(none)")) {
            for (int i = 0; i < (int)res.file_results.size(); i++)
                if (ImGui::Selectable(res.file_results[i].file_name.c_str(), compare_index_b_ == i))
                    compare_index_b_ = i;
            ImGui::EndCombo();
        }
        if (font_small_) pop_font();

        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        if (compare_index_a_ < 0 || compare_index_a_ >= (int)res.file_results.size() ||
            compare_index_b_ < 0 || compare_index_b_ >= (int)res.file_results.size()) {
            ImGui::TextColored(COL_TEXT_DIM, "Select two mods to compare.");
            ImGui::End(); ImGui::PopStyleVar(); return;
        }

        const auto& a = res.file_results[compare_index_a_];
        const auto& b = res.file_results[compare_index_b_];

        // Overview table
        if (ImGui::BeginTable("CompOverview", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_PadOuterX)) {
            ImGui::TableSetupColumn("Property", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("Mod A",    ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Mod B",    ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            auto row = [](const char* prop) { ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextColored(COL_TEXT_DIM, "%s", prop); };

            row("File");
            ImGui::TableNextColumn(); ImGui::Text("%s", a.file_name.c_str());
            ImGui::TableNextColumn(); ImGui::Text("%s", b.file_name.c_str());

            row("SHA-256");
            ImGui::TableNextColumn(); if (font_small_) push_font(font_small_); ImGui::Text("%.16s...", a.sha256.c_str()); if (font_small_) pop_font();
            ImGui::TableNextColumn(); if (font_small_) push_font(font_small_);
            if (a.sha256 == b.sha256 && !a.sha256.empty()) ImGui::TextColored(COL_CLEAN, "IDENTICAL");
            else ImGui::Text("%.16s...", b.sha256.c_str());
            if (font_small_) pop_font();

            row("Verdict");
            ImGui::TableNextColumn(); ImGui::TextColored(threat_color(a.threat_level), "%s", threat_level_string(a.threat_level));
            ImGui::TableNextColumn(); ImGui::TextColored(threat_color(b.threat_level), "%s", threat_level_string(b.threat_level));

            row("Threat Score");
            ImGui::TableNextColumn(); ImGui::Text("%d", a.threat_score);
            ImGui::TableNextColumn();
            if (b.threat_score > a.threat_score) ImGui::TextColored(COL_CRITICAL, "%d (+%d)", b.threat_score, b.threat_score - a.threat_score);
            else if (b.threat_score < a.threat_score) ImGui::TextColored(COL_CLEAN, "%d (%d)", b.threat_score, b.threat_score - a.threat_score);
            else ImGui::Text("%d", b.threat_score);

            row("Classes");
            ImGui::TableNextColumn(); ImGui::Text("%d", a.class_count);
            ImGui::TableNextColumn(); ImGui::Text("%d", b.class_count);

            row("Detections");
            ImGui::TableNextColumn(); ImGui::Text("%d", (int)a.detections.size());
            ImGui::TableNextColumn();
            if ((int)b.detections.size() > (int)a.detections.size())
                ImGui::TextColored(COL_HIGH, "%d (+%d)", (int)b.detections.size(), (int)b.detections.size() - (int)a.detections.size());
            else ImGui::Text("%d", (int)b.detections.size());

            ImGui::EndTable();
        }

        ImGui::Spacing();

        // Similarity
        std::unordered_set<std::string> classes_a(a.class_names.begin(), a.class_names.end());
        std::unordered_set<std::string> classes_b(b.class_names.begin(), b.class_names.end());
        std::vector<std::string> only_in_a, only_in_b;
        int shared_count = 0;
        for (const auto& c : a.class_names) { if (classes_b.count(c)) shared_count++; else only_in_a.push_back(c); }
        for (const auto& c : b.class_names) { if (!classes_a.count(c)) only_in_b.push_back(c); }
        int total_unique = (int)(classes_a.size() + classes_b.size() - shared_count);
        float similarity = total_unique > 0 ? (float)shared_count / total_unique * 100.0f : 0.0f;

        ImVec4 sim_col = similarity >= 90 ? COL_CLEAN : similarity >= 60 ? COL_MEDIUM : similarity >= 30 ? COL_HIGH : COL_CRITICAL;
        const char* sim_label = similarity >= 90 ? "Nearly identical" : similarity >= 60 ? "Partially similar" : similarity >= 30 ? "Significantly different" : "Completely different";

        ImGui::TextColored(COL_TEXT_DIM, "Class Similarity:");
        ImGui::SameLine();
        ImGui::TextColored(sim_col, "%.1f%%", similarity);
        ImGui::SameLine(0, 12);
        if (font_small_) push_font(font_small_);
        ImGui::TextColored(COL_TEXT_DIM, "(%s | %d shared, %d only A, %d only B)", sim_label, shared_count, (int)only_in_a.size(), (int)only_in_b.size());
        if (font_small_) pop_font();

        ImGui::Spacing();

        // Tabs
        if (ImGui::BeginTabBar("CompTabs")) {
            if (ImGui::BeginTabItem("Detection Differences")) {
                std::unordered_set<std::string> rules_a, rules_b;
                for (const auto& d : a.detections) rules_a.insert(d.rule_name);
                for (const auto& d : b.detections) rules_b.insert(d.rule_name);

                if (ImGui::BeginTable("DetDiff", 2,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_PadOuterX,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {

                    ImGui::TableSetupColumn("Only in Mod A", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Only in Mod B", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();

                    std::vector<const Detection*> ua, ub;
                    for (const auto& d : a.detections) if (!rules_b.count(d.rule_name)) ua.push_back(&d);
                    for (const auto& d : b.detections) if (!rules_a.count(d.rule_name)) ub.push_back(&d);

                    size_t mr = std::max(ua.size(), ub.size());
                    if (mr == 0) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextColored(COL_TEXT_DIM, "Same detection rules");
                        ImGui::TableNextColumn(); ImGui::TextColored(COL_TEXT_DIM, "Same detection rules");
                    }
                    for (size_t i = 0; i < mr; i++) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if (i < ua.size()) { ImGui::TextColored(severity_color(ua[i]->severity), "%s", severity_to_string(ua[i]->severity)); ImGui::SameLine(); ImGui::Text("%s", ua[i]->rule_name.c_str()); }
                        ImGui::TableNextColumn();
                        if (i < ub.size()) { ImGui::TextColored(severity_color(ub[i]->severity), "%s", severity_to_string(ub[i]->severity)); ImGui::SameLine(); ImGui::Text("%s", ub[i]->rule_name.c_str()); }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Class Differences")) {
                if (ImGui::BeginTable("ClassDiff", 2,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_PadOuterX,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {

                    char ha[128], hb[128];
                    snprintf(ha, sizeof(ha), "Only in A (%d)", (int)only_in_a.size());
                    snprintf(hb, sizeof(hb), "Only in B (%d)", (int)only_in_b.size());
                    ImGui::TableSetupColumn(ha, ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn(hb, ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();

                    size_t mr = std::max(only_in_a.size(), only_in_b.size());
                    if (mr == 0) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextColored(COL_CLEAN, "Identical class structure");
                        ImGui::TableNextColumn(); ImGui::TextColored(COL_CLEAN, "Identical class structure");
                    }
                    for (size_t i = 0; i < mr; i++) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if (i < only_in_a.size()) { if (font_small_) push_font(font_small_); ImGui::Text("%s", only_in_a[i].c_str()); if (font_small_) pop_font(); }
                        ImGui::TableNextColumn();
                        if (i < only_in_b.size()) {
                            if (font_small_) push_font(font_small_);
                            std::string lo = to_lower(only_in_b[i]);
                            bool sus = only_in_b[i].size() <= 3 || contains(lo, "stealer") || contains(lo, "rat") ||
                                       contains(lo, "hook") || contains(lo, "inject") || contains(lo, "grab") ||
                                       contains(lo, "token") || contains(lo, "webhook");
                            if (sus) ImGui::TextColored(COL_CRITICAL, "%s", only_in_b[i].c_str());
                            else ImGui::Text("%s", only_in_b[i].c_str());
                            if (font_small_) pop_font();
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("File Entry Differences")) {
                std::unordered_set<std::string> fa(a.all_filenames.begin(), a.all_filenames.end());
                std::unordered_set<std::string> fb(b.all_filenames.begin(), b.all_filenames.end());
                std::vector<std::string> foa, fob;
                for (const auto& f : a.all_filenames) if (!fb.count(f)) foa.push_back(f);
                for (const auto& f : b.all_filenames) if (!fa.count(f)) fob.push_back(f);

                if (ImGui::BeginTable("FileDiff", 2,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV |
                    ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_PadOuterX,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {

                    char ha[128], hb[128];
                    snprintf(ha, sizeof(ha), "Only in A (%d)", (int)foa.size());
                    snprintf(hb, sizeof(hb), "Only in B (%d)", (int)fob.size());
                    ImGui::TableSetupColumn(ha, ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn(hb, ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();

                    size_t mr = std::max(foa.size(), fob.size());
                    if (mr == 0) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn(); ImGui::TextColored(COL_CLEAN, "Identical file entries");
                        ImGui::TableNextColumn(); ImGui::TextColored(COL_CLEAN, "Identical file entries");
                    }
                    for (size_t i = 0; i < mr; i++) {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if (i < foa.size()) { if (font_small_) push_font(font_small_); ImGui::Text("%s", foa[i].c_str()); if (font_small_) pop_font(); }
                        ImGui::TableNextColumn();
                        if (i < fob.size()) {
                            if (font_small_) push_font(font_small_);
                            std::string lo = to_lower(fob[i]);
                            bool sus = ends_with(lo, ".dll") || ends_with(lo, ".exe") || ends_with(lo, ".bat") || ends_with(lo, ".ps1");
                            if (sus) ImGui::TextColored(COL_CRITICAL, "%s", fob[i].c_str());
                            else ImGui::Text("%s", fob[i].c_str());
                            if (font_small_) pop_font();
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
    }
    ImGui::End();
    ImGui::PopStyleVar();
}

// --- file dialogs & scan ---

void GUI::open_file_dialog() {
    char filename[4096] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = "JAR Files (*.jar)\0*.jar\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = sizeof(filename);
    ofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_FILEMUSTEXIST;
    ofn.lpstrTitle = "Select JAR File(s) to Scan";

    if (GetOpenFileNameA(&ofn)) {
        selected_files_.clear();
        std::string dir = filename;
        char* p = filename + dir.size() + 1;
        if (*p) {
            while (*p) {
                selected_files_.push_back(dir + "\\" + std::string(p));
                p += strlen(p) + 1;
            }
            selected_path_ = dir + " (" + std::to_string(selected_files_.size()) + " files)";
        } else {
            selected_files_.push_back(dir);
            selected_path_ = dir;
        }
    }
}

void GUI::open_folder_dialog() {
    BROWSEINFOA bi = {};
    bi.lpszTitle = "Select Folder with JAR Files";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl) {
        char path[MAX_PATH];
        SHGetPathFromIDListA(pidl, path);
        CoTaskMemFree(pidl);
        selected_files_.clear();
        std::string dir = path;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".jar") selected_files_.push_back(entry.path().string());
                }
            }
        } catch (...) {}
        selected_path_ = dir + " (" + std::to_string(selected_files_.size()) + " JAR files)";
    }
}

void GUI::start_scan() {
    if (!selected_files_.empty()) {
        scan_just_completed_ = false;
        scan_complete_time_ = 0.0f;
        results_appear_time_ = 0.0f;
        smooth_progress_ = 0.0f;
        show_details_ = false;
        show_compare_ = false;
        selected_result_index_ = -1;
        expanded_detection_index_ = -1;
        compare_index_a_ = -1;
        compare_index_b_ = -1;
        engine_.scan_files(selected_files_);
    }
}

void GUI::on_files_dropped(const std::vector<std::string>& files) {
    selected_files_.clear();
    for (const auto& f : files) {
        std::string lower = f;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.size() > 4 && lower.substr(lower.size() - 4) == ".jar")
            selected_files_.push_back(f);
        try {
            if (fs::is_directory(f)) {
                for (const auto& entry : fs::recursive_directory_iterator(f)) {
                    if (entry.is_regular_file()) {
                        std::string ext = entry.path().extension().string();
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                        if (ext == ".jar") selected_files_.push_back(entry.path().string());
                    }
                }
            }
        } catch (...) {}
    }
    if (selected_files_.size() == 1) selected_path_ = selected_files_[0];
    else if (!selected_files_.empty()) selected_path_ = std::to_string(selected_files_.size()) + " JAR files";
}

// --- updater ---

void GUI::check_for_updates() {
    if (update_checking_.load() || update_downloading_.load()) return;
    if (update_thread_.joinable()) update_thread_.join();

    update_checking_ = true;
    update_checked_ = false;

    update_thread_ = std::thread([this]() {
        UpdateInfo info = updater_.check_for_update();
        {
            std::lock_guard<std::mutex> lock(update_mutex_);
            update_info_ = info;
        }
        update_checking_ = false;
        update_checked_ = true;
    });
}

void GUI::download_update() {
    if (update_checking_.load() || update_downloading_.load()) return;
    if (update_thread_.joinable()) update_thread_.join();

    update_downloading_ = true;

    update_thread_ = std::thread([this]() {
        UpdateInfo info;
        {
            std::lock_guard<std::mutex> lock(update_mutex_);
            info = update_info_;
        }
        bool success = updater_.download_and_apply(info);
        update_downloading_ = false;

        if (success) {
            // The batch script is running — we need to exit so it can replace the EXE
            should_exit_ = true;
        } else {
            std::lock_guard<std::mutex> lock(update_mutex_);
            update_info_.check_failed = true;
            update_info_.error = "Download failed";
        }
    });
}

// --- clipboard & helpers ---

void GUI::copy_to_clipboard(const std::string& text) {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hg) {
            memcpy(GlobalLock(hg), text.c_str(), text.size() + 1);
            GlobalUnlock(hg);
            SetClipboardData(CF_TEXT, hg);
        }
        CloseClipboard();
    }
}

void GUI::open_file_location(const std::string& path) {
    std::string cmd = "/select," + path;
    ShellExecuteA(nullptr, "open", "explorer.exe", cmd.c_str(), nullptr, SW_SHOWNORMAL);
}

} // namespace ihp
