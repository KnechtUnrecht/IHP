#include "code_viewer.h"
#include <algorithm>
#include <cmath>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

namespace ihp {

// Colors
static const ImU32 COL_LINE_NUM     = IM_COL32(80, 85, 100, 180);
static const ImU32 COL_GUTTER_LINE  = IM_COL32(50, 50, 60, 120);
static const ImU32 COL_KEYWORD      = IM_COL32(200, 120, 220, 255);    // purple
static const ImU32 COL_TYPE         = IM_COL32(80, 200, 170, 255);     // teal
static const ImU32 COL_OPCODE       = IM_COL32(100, 160, 230, 255);    // blue
static const ImU32 COL_STRING       = IM_COL32(150, 200, 120, 255);    // green
static const ImU32 COL_COMMENT      = IM_COL32(100, 105, 120, 180);    // gray
static const ImU32 COL_NUMBER       = IM_COL32(180, 140, 100, 255);    // brown
static const ImU32 COL_SUSPICIOUS   = IM_COL32(255, 80, 60, 255);     // bright red
static const ImU32 COL_NORMAL       = IM_COL32(200, 205, 215, 255);   // light gray
static const ImU32 COL_HEADER       = IM_COL32(180, 185, 195, 255);   // white-ish
static const ImU32 COL_METHOD       = IM_COL32(220, 220, 150, 255);   // yellow
static const ImU32 COL_SUSP_BG      = IM_COL32(80, 25, 20, 180);     // dark red bg
static const ImU32 COL_HOVER_BG     = IM_COL32(255, 255, 255, 12);   // subtle white
static const ImU32 COL_DIM          = IM_COL32(130, 135, 145, 200);
static const ImU32 COL_TREE_BG      = IM_COL32(16, 17, 22, 255);
static const ImU32 COL_CODE_BG      = IM_COL32(20, 21, 27, 255);
static const ImU32 COL_ACCENT       = IM_COL32(200, 65, 55, 255);
static const ImU32 COL_SEARCH_BG    = IM_COL32(120, 100, 30, 90);    // dim yellow for matches
static const ImU32 COL_SEARCH_CUR   = IM_COL32(200, 170, 40, 140);   // bright yellow for current match

// --- setup ---

void CodeViewer::set_fonts(ImFont* font_regular, ImFont* font_small, ImFont* font_mono) {
    font_regular_ = font_regular;
    font_small_ = font_small;
    font_mono_ = font_mono;
}

// --- open / close ---

void CodeViewer::open(const std::string& jar_path) {
    jar_path_ = jar_path;
    is_open_ = true;
    selected_class_.clear();
    decode_cache_.clear();
    decompile_cache_.clear();
    formatted_lines_.clear();
    formatted_class_.clear();
    search_buf_[0] = '\0';
    active_tab_ = ViewTab::DECOMPILED;
    jar_intel_.clear();
    jar_intel_built_ = false;
    jar_metadata_ = JarMetadata{};
    jar_metadata_built_ = false;
    show_url_popup_ = false;
    pending_url_.clear();
    show_search_ = false;
    code_search_buf_[0] = '\0';
    search_matches_.clear();
    current_match_ = -1;

    // Read JAR to get raw .class bytes
    JarReader reader;
    jar_ = reader.read(jar_path);

    // Build lookup structures
    class_map_.clear();
    class_names_.clear();
    for (auto& entry : jar_.entries) {
        if (entry.is_class_file && !entry.data.empty()) {
            class_map_[entry.filename] = &entry;
            class_names_.push_back(entry.filename);
        }
    }
    std::sort(class_names_.begin(), class_names_.end());

    build_tree();
}

void CodeViewer::close() {
    is_open_ = false;
    jar_ = JarContents{};
    class_map_.clear();
    class_names_.clear();
    decode_cache_.clear();
    decompile_cache_.clear();
    formatted_lines_.clear();
    formatted_class_.clear();
}

// --- tree building ---

void CodeViewer::build_tree() {
    tree_root_ = TreeNode{"root", "", false, false, {}};

    for (const auto& path : class_names_) {
        TreeNode* current = &tree_root_;
        size_t start = 0;
        while (start < path.size()) {
            size_t slash = path.find('/', start);
            std::string segment;
            if (slash == std::string::npos) {
                segment = path.substr(start);
                start = path.size();
            } else {
                segment = path.substr(start, slash - start);
                start = slash + 1;
            }

            TreeNode* found = nullptr;
            for (auto& child : current->children) {
                if (child.name == segment) { found = &child; break; }
            }
            if (!found) {
                current->children.push_back({segment, "", false, false, {}});
                found = &current->children.back();
            }
            current = found;
        }
        current->is_leaf = true;
        current->full_path = path;
    }
}

// --- on-demand decode ---

const DecodedClass& CodeViewer::get_decoded(const std::string& class_name) {
    auto it = decode_cache_.find(class_name);
    if (it != decode_cache_.end()) return it->second;

    // Evict if cache full
    if (decode_cache_.size() >= MAX_CACHE) {
        decode_cache_.erase(decode_cache_.begin());
    }

    // Decode
    auto entry_it = class_map_.find(class_name);
    if (entry_it == class_map_.end()) {
        static DecodedClass empty;
        empty.error = "Class not found in JAR";
        return empty;
    }

    const JarEntry* entry = entry_it->second;
    auto result = decode_cache_.emplace(class_name,
        decoder_.decode(entry->data.data(), entry->data.size()));
    return result.first->second;
}

// --- format decoded class into lines ---

void CodeViewer::format_class(const DecodedClass& dc) {
    formatted_lines_.clear();

    auto add = [&](const std::string& text, FormattedLine::Type type,
                   ImU32 color, bool suspicious = false, const std::string& reason = "") {
        formatted_lines_.push_back({text, type, suspicious, reason, color});
    };

    // Class header
    std::string class_decl = "// Class: " + dc.this_class;
    add(class_decl, FormattedLine::HEADER, COL_COMMENT);
    add("// " + dc.java_version_str, FormattedLine::HEADER, COL_COMMENT);

    std::string flags_line = dc.access_str;
    if (flags_line.find("interface") != std::string::npos)
        flags_line += " " + dc.this_class;
    else
        flags_line = flags_line + " class " + dc.this_class;
    if (!dc.super_class.empty() && dc.super_class != "java/lang/Object")
        flags_line += " extends " + dc.super_class;
    add(flags_line, FormattedLine::HEADER, COL_HEADER);

    for (const auto& iface : dc.interfaces)
        add("    implements " + iface, FormattedLine::HEADER, COL_TYPE);

    add("", FormattedLine::BLANK, COL_NORMAL);

    // Fields
    if (!dc.fields.empty()) {
        add("// ---- Fields ----", FormattedLine::HEADER, COL_COMMENT);
        for (const auto& f : dc.fields) {
            std::string line = "  ";
            if (!f.access_str.empty()) line += f.access_str + " ";
            line += f.descriptor + " " + f.name;
            add(line, FormattedLine::FIELD, COL_NORMAL);
        }
        add("", FormattedLine::BLANK, COL_NORMAL);
    }

    // Methods
    for (const auto& m : dc.methods) {
        add("// ---- Method ----", FormattedLine::HEADER, COL_COMMENT);
        std::string sig = "  ";
        if (!m.access_str.empty()) sig += m.access_str + " ";
        sig += m.name + m.descriptor;
        add(sig, FormattedLine::METHOD_SIG, COL_METHOD);

        if (!m.has_code) {
            add("    // (no code - abstract or native)", FormattedLine::CODE_META, COL_COMMENT);
        } else {
            char meta[128];
            snprintf(meta, sizeof(meta), "    Code: max_stack=%d, max_locals=%d",
                     m.max_stack, m.max_locals);
            add(meta, FormattedLine::CODE_META, COL_DIM);

            for (const auto& instr : m.instructions) {
                char offset_str[16];
                snprintf(offset_str, sizeof(offset_str), "%6d: ", instr.offset);
                std::string line = "      " + std::string(offset_str) + instr.mnemonic;
                if (!instr.operand_str.empty())
                    line += "  " + instr.operand_str;
                add(line, FormattedLine::INSTRUCTION,
                    instr.is_suspicious ? COL_SUSPICIOUS : COL_OPCODE,
                    instr.is_suspicious, instr.suspicion_reason);
            }
        }
        add("", FormattedLine::BLANK, COL_NORMAL);
    }

    // String literals
    if (!dc.string_literals.empty()) {
        add("// ---- String Constants ----", FormattedLine::HEADER, COL_COMMENT);
        for (size_t i = 0; i < dc.string_literals.size(); i++) {
            std::string s = dc.string_literals[i];
            if (s.length() > 100) s = s.substr(0, 97) + "...";
            // Escape for display
            std::string escaped;
            for (char c : s) {
                if (c == '\n') escaped += "\\n";
                else if (c == '\r') escaped += "\\r";
                else if (c == '\t') escaped += "\\t";
                else if (c >= 32 && c < 127) escaped += c;
                else escaped += '.';
            }
            add("  \"" + escaped + "\"", FormattedLine::FIELD, COL_STRING);
        }
    }
}

// --- render ---

bool CodeViewer::render() {
    if (!is_open_) return false;

    anim_time_ += ImGui::GetIO().DeltaTime;
    anim_.gc();

    ImGui::SetNextWindowSize(ImVec2(1100, 700), ImGuiCond_FirstUseEver);

    // Extract filename for title
    std::string filename = jar_path_;
    auto pos = filename.find_last_of("/\\");
    if (pos != std::string::npos) filename = filename.substr(pos + 1);

    char title[512];
    snprintf(title, sizeof(title), "Code Viewer - %s###CodeViewer", filename.c_str());

    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.07f, 0.07f, 0.09f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));

    bool open = true;
    if (!ImGui::Begin(title, &open, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
        ImGui::End();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
        is_open_ = open;
        return is_open_;
    }

    float total_w = ImGui::GetContentRegionAvail().x;
    float tree_w = 280.0f;

    // Left panel
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.063f, 0.067f, 0.086f, 1.0f));
    ImGui::BeginChild("##ClassTree", ImVec2(tree_w, -1), ImGuiChildFlags_Borders);
    render_class_tree();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SameLine(0, 0);

    // Right panel
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.078f, 0.082f, 0.106f, 1.0f));
    ImGui::BeginChild("##RightPanel", ImVec2(0, -1), ImGuiChildFlags_Borders);
    {
        // Tab bar
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16, 8));
        if (ImGui::BeginTabBar("##CodeViewerTabs")) {
            if (ImGui::BeginTabItem("Source Code")) {
                active_tab_ = ViewTab::DECOMPILED;
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Bytecode")) {
                active_tab_ = ViewTab::BYTECODE;
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Intelligence")) {
                active_tab_ = ViewTab::INTEL;
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("JAR Info")) {
                active_tab_ = ViewTab::METADATA;
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::PopStyleVar();

        // Ctrl+F to toggle search (only on source/bytecode tabs)
        if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F) &&
            (active_tab_ == ViewTab::DECOMPILED || active_tab_ == ViewTab::BYTECODE)) {
            show_search_ = !show_search_;
            if (show_search_) {
                search_needs_focus_ = true;
            } else {
                code_search_buf_[0] = '\0';
                search_matches_.clear();
                current_match_ = -1;
            }
        }

        // Search bar overlay (for Source Code and Bytecode tabs)
        if (show_search_ && (active_tab_ == ViewTab::DECOMPILED || active_tab_ == ViewTab::BYTECODE)) {
            float panel_w = ImGui::GetContentRegionAvail().x;
            float bar_w = (std::min)(440.0f, panel_w - 16.0f);
            float bar_x = panel_w - bar_w - 8.0f;

            ImGui::SetCursorPos(ImVec2(bar_x, ImGui::GetCursorPosY()));
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.12f, 0.13f, 0.17f, 0.97f));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
            ImGui::BeginChild("##SearchBar", ImVec2(bar_w, 36), ImGuiChildFlags_Borders);
            {
                ImGui::SetCursorPos(ImVec2(8, 5));

                // Search input
                ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.09f, 0.12f, 1.0f));
                ImGui::PushItemWidth(bar_w - 220);
                bool text_changed = ImGui::InputTextWithHint("##CodeSearch", "Search...",
                    code_search_buf_, sizeof(code_search_buf_),
                    ImGuiInputTextFlags_EnterReturnsTrue);

                // hacky workaround for the focussing issue
                if (search_needs_focus_) {
                    ImGui::SetKeyboardFocusHere(-1);
                    search_needs_focus_ = false;
                }

                // Enter to navigate forward
                if (text_changed) {
                    if (ImGui::GetIO().KeyShift)
                        search_navigate(-1);
                    else
                        search_navigate(1);
                }

                // Detect text changes for live search (also re-search on class/tab change)
                static std::string last_query;
                static bool last_case = false;
                std::string current_query(code_search_buf_);
                if (current_query != last_query || search_case_sensitive_ != last_case ||
                    search_built_for_class_ != selected_class_ || search_built_for_tab_ != active_tab_) {
                    last_query = current_query;
                    last_case = search_case_sensitive_;
                    search_built_for_class_ = selected_class_;
                    search_built_for_tab_ = active_tab_;
                    update_search_matches();
                }

                ImGui::PopItemWidth();
                ImGui::PopStyleColor();

                // Match count
                ImGui::SameLine(0, 8);
                if (!search_matches_.empty()) {
                    char count_buf[32];
                    snprintf(count_buf, sizeof(count_buf), "%d/%d",
                             current_match_ + 1, (int)search_matches_.size());
                    ImGui::TextColored(ImVec4(0.6f, 0.65f, 0.7f, 1.0f), "%s", count_buf);
                } else if (code_search_buf_[0] != '\0') {
                    ImGui::TextColored(ImVec4(0.8f, 0.3f, 0.25f, 1.0f), "0");
                }

                // Up/Down buttons
                ImGui::SameLine(0, 8);
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.17f, 0.22f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f, 0.23f, 0.30f, 1.0f));
                if (ImGui::SmallButton("^")) search_navigate(-1);
                ImGui::SameLine(0, 4);
                if (ImGui::SmallButton("v")) search_navigate(1);
                ImGui::PopStyleColor(2);

                // Case sensitivity toggle
                ImGui::SameLine(0, 8);
                ImGui::PushStyleColor(ImGuiCol_CheckMark,
                    search_case_sensitive_ ? IM_COL32(200, 120, 220, 255) : IM_COL32(100, 105, 120, 180));
                ImGui::Checkbox("Aa", &search_case_sensitive_);
                ImGui::PopStyleColor();

                // Close button
                ImGui::SameLine(0, 8);
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.1f, 0.1f, 1.0f));
                if (ImGui::SmallButton("X")) {
                    show_search_ = false;
                    code_search_buf_[0] = '\0';
                    search_matches_.clear();
                    current_match_ = -1;
                }
                ImGui::PopStyleColor(2);
            }
            ImGui::EndChild();
            ImGui::PopStyleVar();
            ImGui::PopStyleColor();

            // Escape to close search
            if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
                show_search_ = false;
                code_search_buf_[0] = '\0';
                search_matches_.clear();
                current_match_ = -1;
            }
        }

        // Tab content
        switch (active_tab_) {
            case ViewTab::DECOMPILED: render_decompiled_view(); break;
            case ViewTab::BYTECODE:   render_bytecode_view(); break;
            case ViewTab::INTEL:      render_intel_panel(); break;
            case ViewTab::METADATA:   render_metadata_panel(); break;
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleColor();

    // URL confirmation popup
    render_url_confirm_popup();

    ImGui::End();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    is_open_ = open;
    return is_open_;
}

// --- class tree ---

void CodeViewer::render_class_tree() {
    // Search filter
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 6));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.10f, 0.10f, 0.14f, 1.0f));
    ImGui::PushItemWidth(-1);
    ImGui::InputTextWithHint("##ClassFilter", "Filter classes...", search_buf_, sizeof(search_buf_));
    ImGui::PopItemWidth();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Class count
    if (font_small_) ImGui::PushFont(font_small_);
    ImGui::TextColored(ImVec4(0.5f, 0.52f, 0.56f, 1.0f), "  %d classes", (int)class_names_.size());
    if (font_small_) ImGui::PopFont();
    ImGui::Spacing();

    // If search filter is active, show flat list instead of tree
    std::string filter(search_buf_);
    if (!filter.empty()) {
        // Convert filter to lowercase
        std::string filter_lower = filter;
        std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);

        for (const auto& name : class_names_) {
            std::string name_lower = name;
            std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
            if (name_lower.find(filter_lower) == std::string::npos) continue;

            // Extract short name
            std::string short_name = name;
            auto slash = short_name.rfind('/');
            if (slash != std::string::npos) short_name = short_name.substr(slash + 1);

            bool selected = (name == selected_class_);
            if (ImGui::Selectable(short_name.c_str(), selected)) {
                selected_class_ = name;
                formatted_class_.clear(); // force re-format
            }
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted(name.c_str());
                ImGui::EndTooltip();
            }
        }
    } else {
        // Tree view
        for (auto& child : tree_root_.children) {
            render_tree_node(child);
        }
    }
}

void CodeViewer::render_tree_node(TreeNode& node) {
    if (node.is_leaf) {
        // Leaf node — class file
        bool selected = (node.full_path == selected_class_);

        // Check if this class has suspicious content (lazy check)
        auto cache_it = decode_cache_.find(node.full_path);
        bool has_suspicious = false;
        if (cache_it != decode_cache_.end()) {
            has_suspicious = cache_it->second.suspicious_line_count > 0;
        }

        // Red dot for suspicious classes
        if (has_suspicious) {
            ImVec2 pos = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddCircleFilled(
                ImVec2(pos.x + 4, pos.y + ImGui::GetTextLineHeight() * 0.5f),
                3.0f, IM_COL32(230, 60, 50, 255));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 12);
        }

        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen |
                                   ImGuiTreeNodeFlags_SpanAvailWidth;
        if (selected) flags |= ImGuiTreeNodeFlags_Selected;

        ImGui::TreeNodeEx(node.name.c_str(), flags);
        if (ImGui::IsItemClicked()) {
            selected_class_ = node.full_path;
            formatted_class_.clear(); // force re-format
        }
        if (ImGui::IsItemHovered() && node.name != node.full_path) {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted(node.full_path.c_str());
            ImGui::EndTooltip();
        }
    } else {
        // Package node
        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_SpanAvailWidth;
        // Auto-open if only 1 child and it's not a leaf
        if (node.children.size() == 1 && !node.children[0].is_leaf)
            flags |= ImGuiTreeNodeFlags_DefaultOpen;

        bool open = ImGui::TreeNodeEx(node.name.c_str(), flags);
        if (open) {
            for (auto& child : node.children) {
                render_tree_node(child);
            }
            ImGui::TreePop();
        }
    }
}

// --- bytecode view ---

void CodeViewer::render_bytecode_view() {
    if (selected_class_.empty()) {
        // No class selected — show placeholder
        float w = ImGui::GetContentRegionAvail().x;
        float h = ImGui::GetContentRegionAvail().y;
        ImGui::SetCursorPos(ImVec2(w * 0.5f - 120, h * 0.5f - 20));
        ImGui::TextColored(ImVec4(0.4f, 0.42f, 0.48f, 1.0f), "Select a class to view bytecode");
        return;
    }

    // Decode if needed
    const DecodedClass& dc = get_decoded(selected_class_);

    if (!dc.valid) {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "Failed to decode: %s", dc.error.c_str());
        return;
    }

    // Format if needed (only re-format when class changes)
    if (formatted_class_ != selected_class_) {
        format_class(dc);
        formatted_class_ = selected_class_;
    }

    if (formatted_lines_.empty()) {
        ImGui::TextColored(ImVec4(0.4f, 0.42f, 0.48f, 1.0f), "Empty class");
        return;
    }

    // Suspicion summary
    if (dc.suspicious_line_count > 0) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.05f, 0.04f, 1.0f));
        ImGui::BeginChild("##SuspBar", ImVec2(-1, 28), ImGuiChildFlags_None);
        ImGui::SetCursorPos(ImVec2(12, 5));
        ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.25f, 1.0f),
            "! %d suspicious instruction%s found",
            dc.suspicious_line_count, dc.suspicious_line_count != 1 ? "s" : "");
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // Bytecode display (virtual scrolling)
    if (font_mono_) ImGui::PushFont(font_mono_);

    float line_h = ImGui::GetTextLineHeightWithSpacing();
    float gutter_w = 50.0f;
    int total_lines = static_cast<int>(formatted_lines_.size());

    ImGui::BeginChild("##BytecodeScroll", ImVec2(0, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);

    // Scroll to search match if needed
    if (search_needs_scroll_ && active_tab_ == ViewTab::BYTECODE &&
        current_match_ >= 0 && current_match_ < static_cast<int>(search_matches_.size())) {
        float target_y = search_matches_[current_match_] * line_h;
        float avail_h_pre = ImGui::GetContentRegionAvail().y;
        float centered = target_y - avail_h_pre * 0.4f;
        if (centered < 0) centered = 0;
        ImGui::SetScrollY(centered);
        search_needs_scroll_ = false;
    }

    ImVec2 origin = ImGui::GetCursorScreenPos();
    float avail_w = ImGui::GetContentRegionAvail().x;
    float avail_h = ImGui::GetContentRegionAvail().y;
    float scroll_y = ImGui::GetScrollY();

    // Reserve full content height for proper scrollbar
    float content_h = total_lines * line_h;
    ImGui::Dummy(ImVec2(avail_w, content_h));

    // Calculate visible range
    int first_visible = (std::max)(0, (int)(scroll_y / line_h) - 1);
    int visible_count = (int)(avail_h / line_h) + 3;
    int last_visible = (std::min)(first_visible + visible_count, total_lines);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 mouse = ImGui::GetMousePos();

    // Draw gutter background
    dl->AddRectFilled(
        ImVec2(origin.x, origin.y + first_visible * line_h - scroll_y),
        ImVec2(origin.x + gutter_w - 4, origin.y + last_visible * line_h - scroll_y),
        IM_COL32(14, 15, 20, 255));

    for (int i = first_visible; i < last_visible; i++) {
        float y = origin.y + i * line_h - scroll_y;
        const auto& line = formatted_lines_[i];

        // Suspicious line bg
        if (line.is_suspicious) {
            dl->AddRectFilled(
                ImVec2(origin.x, y),
                ImVec2(origin.x + avail_w + 500, y + line_h),
                COL_SUSP_BG);
            // Left accent stripe
            dl->AddRectFilled(
                ImVec2(origin.x, y),
                ImVec2(origin.x + 3, y + line_h),
                IM_COL32(230, 60, 50, 255));
        }

        // Search match highlight
        if (!search_matches_.empty() && active_tab_ == ViewTab::BYTECODE) {
            // Check if this line is a search match
            // Binary search since matches are sorted
            auto sit = std::lower_bound(search_matches_.begin(), search_matches_.end(), i);
            if (sit != search_matches_.end() && *sit == i) {
                int match_idx = static_cast<int>(sit - search_matches_.begin());
                ImU32 bg = (match_idx == current_match_) ? COL_SEARCH_CUR : COL_SEARCH_BG;
                dl->AddRectFilled(
                    ImVec2(origin.x, y),
                    ImVec2(origin.x + avail_w + 500, y + line_h), bg);
            }
        }

        // Hover highlight
        bool hovered = (mouse.y >= y && mouse.y < y + line_h &&
                        mouse.x >= origin.x && mouse.x < origin.x + avail_w);
        if (hovered) {
            dl->AddRectFilled(
                ImVec2(origin.x, y),
                ImVec2(origin.x + avail_w + 500, y + line_h),
                COL_HOVER_BG);

            // Tooltip for suspicious lines
            if (line.is_suspicious && !line.suspicion_reason.empty()) {
                ImGui::BeginTooltip();
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.3f, 0.25f, 1.0f));
                ImGui::Text("! %s", line.suspicion_reason.c_str());
                ImGui::PopStyleColor();
                ImGui::EndTooltip();
            }
        }

        // Line number
        if (line.type != FormattedLine::BLANK) {
            char num_buf[16];
            snprintf(num_buf, sizeof(num_buf), "%4d", i + 1);
            dl->AddText(ImVec2(origin.x + 4, y), COL_LINE_NUM, num_buf);
        }

        // Gutter
        dl->AddLine(
            ImVec2(origin.x + gutter_w - 4, y),
            ImVec2(origin.x + gutter_w - 4, y + line_h),
            COL_GUTTER_LINE);

        // Text content
        if (!line.text.empty()) {
            ImU32 text_color = line.color;

            // Type-specific coloring
            switch (line.type) {
                case FormattedLine::HEADER:
                    text_color = COL_COMMENT;
                    break;
                case FormattedLine::METHOD_SIG:
                    text_color = COL_METHOD;
                    break;
                case FormattedLine::CODE_META:
                    text_color = COL_DIM;
                    break;
                case FormattedLine::INSTRUCTION:
                    if (line.is_suspicious)
                        text_color = COL_SUSPICIOUS;
                    else
                        text_color = COL_OPCODE;
                    break;
                case FormattedLine::FIELD:
                    text_color = COL_NORMAL;
                    // Color string constants green
                    if (!line.text.empty() && line.text.find('"') != std::string::npos)
                        text_color = COL_STRING;
                    break;
                default:
                    break;
            }

            dl->AddText(ImVec2(origin.x + gutter_w, y), text_color, line.text.c_str());
        }
    }

    ImGui::EndChild();
    if (font_mono_) ImGui::PopFont();
}

// --- jar-wide intelligence ---

void CodeViewer::build_jar_intel() {
    if (jar_intel_built_) return;
    jar_intel_built_ = true;
    jar_intel_.clear();

    // Decode ALL classes and aggregate their intel items
    for (const auto& class_name : class_names_) {
        const DecodedClass& dc = get_decoded(class_name);
        if (!dc.valid) continue;
        for (const auto& item : dc.intel_items) {
            jar_intel_.push_back(item);
        }
    }
}

// --- intelligence panel ---

void CodeViewer::render_intel_panel() {
    // Build intel on first access
    build_jar_intel();

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));

    if (jar_intel_.empty()) {
        float w = ImGui::GetContentRegionAvail().x;
        float h = ImGui::GetContentRegionAvail().y;
        ImGui::SetCursorPos(ImVec2(w * 0.5f - 120, h * 0.5f - 20));
        ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.5f, 1.0f), "No intelligence items found — JAR appears clean");
        ImGui::PopStyleVar();
        return;
    }

    // Count by category
    int url_count = 0, cmd_count = 0, download_count = 0, filepath_count = 0, webhook_count = 0, ip_count = 0;
    for (const auto& item : jar_intel_) {
        switch (item.category) {
            case IntelItem::URL: url_count++; break;
            case IntelItem::CMD_COMMAND: cmd_count++; break;
            case IntelItem::DOWNLOAD_TARGET: download_count++; break;
            case IntelItem::FILE_PATH: filepath_count++; break;
            case IntelItem::WEBHOOK: webhook_count++; break;
            case IntelItem::IP_ADDRESS: ip_count++; break;
        }
    }

    // Summary header
    ImGui::Spacing();
    if (font_regular_) ImGui::PushFont(font_regular_);
    ImGui::TextColored(ImVec4(0.85f, 0.28f, 0.22f, 1.0f), "Extracted Intelligence");
    if (font_regular_) ImGui::PopFont();
    ImGui::Spacing();

    if (font_small_) ImGui::PushFont(font_small_);
    ImGui::TextColored(ImVec4(0.5f, 0.52f, 0.56f, 1.0f),
        "%d items found across %d classes", (int)jar_intel_.size(), (int)class_names_.size());
    if (font_small_) ImGui::PopFont();
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    // Render each category section
    auto render_section = [&](const char* icon, const char* title, IntelItem::Category cat,
                              int count, ImVec4 header_color) {
        if (count == 0) return;

        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertFloat4ToU32(header_color));
        char header[128];
        snprintf(header, sizeof(header), "%s %s (%d)", icon, title, count);

        bool open = ImGui::TreeNodeEx(header, ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanAvailWidth);
        ImGui::PopStyleColor();

        if (open) {
            ImGui::Spacing();
            for (const auto& item : jar_intel_) {
                if (item.category != cat) continue;

                ImDrawList* dl = ImGui::GetWindowDrawList();
                ImVec2 pos = ImGui::GetCursorScreenPos();
                float avail_w = ImGui::GetContentRegionAvail().x;
                float card_h = 0;

                // Card background
                ImU32 card_bg = item.is_dangerous
                    ? IM_COL32(50, 18, 16, 200)
                    : IM_COL32(22, 24, 32, 200);
                ImU32 stripe_col = item.is_dangerous
                    ? IM_COL32(200, 55, 45, 255)
                    : IM_COL32(80, 130, 200, 255);

                // Measure content height
                ImGui::BeginGroup();
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8);

                // Value
                if (font_mono_) ImGui::PushFont(font_mono_);
                ImVec4 val_col = item.is_dangerous
                    ? ImVec4(0.95f, 0.35f, 0.3f, 1.0f)
                    : ImVec4(0.7f, 0.8f, 0.95f, 1.0f);

                // Truncate very long values for display
                std::string display_val = item.value;
                if (display_val.length() > 120) display_val = display_val.substr(0, 117) + "...";
                ImGui::TextColored(val_col, "%s", display_val.c_str());
                if (font_mono_) ImGui::PopFont();

                // Detail
                if (!item.detail.empty()) {
                    if (font_small_) ImGui::PushFont(font_small_);
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8);
                    ImGui::TextColored(ImVec4(0.55f, 0.57f, 0.62f, 1.0f), "%s", item.detail.c_str());
                    if (font_small_) ImGui::PopFont();
                }

                // Context (which class)
                if (!item.context.empty()) {
                    if (font_small_) ImGui::PushFont(font_small_);
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8);
                    ImGui::TextColored(ImVec4(0.4f, 0.42f, 0.48f, 1.0f), "in %s", item.context.c_str());
                    if (font_small_) ImGui::PopFont();
                }

                // "Open URL" button for URL/WEBHOOK/DOWNLOAD items
                if (cat == IntelItem::URL || cat == IntelItem::WEBHOOK || cat == IntelItem::DOWNLOAD_TARGET) {
                    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8);
                    ImGui::PushID(item.value.c_str());
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.14f, 0.16f, 0.22f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.22f, 0.30f, 1.0f));
                    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.25f, 0.27f, 0.35f, 1.0f));
                    if (ImGui::SmallButton("Open in Browser")) {
                        pending_url_ = item.value;
                        if (item.is_dangerous) {
                            pending_url_warning_ = item.detail;
                        } else {
                            pending_url_warning_ = "This URL was found in a scanned mod file.";
                        }
                        show_url_popup_ = true;
                    }
                    ImGui::PopStyleColor(3);
                    ImGui::PopID();
                }

                ImGui::Spacing();
                ImGui::EndGroup();

                // Draw card background behind the group
                ImVec2 end_pos = ImGui::GetCursorScreenPos();
                card_h = end_pos.y - pos.y;
                dl->AddRectFilled(pos, ImVec2(pos.x + avail_w, pos.y + card_h), card_bg, 6.0f);
                // Left accent stripe
                dl->AddRectFilled(pos, ImVec2(pos.x + 3, pos.y + card_h), stripe_col, 3.0f);

                ImGui::Spacing();
            }
            ImGui::TreePop();
        }
        ImGui::Spacing();
    };

    // Render sections in order of severity
    render_section("!!", "Webhook Exfiltration", IntelItem::WEBHOOK, webhook_count,
                   ImVec4(0.95f, 0.22f, 0.22f, 1.0f));
    render_section(">>", "Download Targets", IntelItem::DOWNLOAD_TARGET, download_count,
                   ImVec4(0.95f, 0.35f, 0.20f, 1.0f));
    render_section(">_", "CMD / Shell Commands", IntelItem::CMD_COMMAND, cmd_count,
                   ImVec4(0.95f, 0.55f, 0.10f, 1.0f));
    render_section("@",  "IP Addresses", IntelItem::IP_ADDRESS, ip_count,
                   ImVec4(0.95f, 0.65f, 0.15f, 1.0f));
    render_section("->", "URLs", IntelItem::URL, url_count,
                   ImVec4(0.60f, 0.75f, 0.95f, 1.0f));
    render_section("[]", "File Paths", IntelItem::FILE_PATH, filepath_count,
                   ImVec4(0.55f, 0.70f, 0.60f, 1.0f));

    ImGui::PopStyleVar();
}

// --- on-demand decompile ---

const DecompiledClass& CodeViewer::get_decompiled(const std::string& class_name) {
    auto it = decompile_cache_.find(class_name);
    if (it != decompile_cache_.end()) return it->second;

    // Evict if cache too large
    if (decompile_cache_.size() >= MAX_CACHE) {
        decompile_cache_.erase(decompile_cache_.begin());
    }

    // First decode, then decompile
    const DecodedClass& dc = get_decoded(class_name);
    auto result = decompile_cache_.emplace(class_name, decompiler_.decompile(dc));
    return result.first->second;
}

// --- decompiled source view ---

// Colors for decompiled Java source
static const ImU32 COL_JAVA_KEYWORD   = IM_COL32(200, 120, 220, 255);    // purple — class, public, void, etc.
static const ImU32 COL_JAVA_COMMENT   = IM_COL32(100, 105, 120, 180);    // gray
static const ImU32 COL_JAVA_STRING    = IM_COL32(150, 200, 120, 255);    // green
static const ImU32 COL_JAVA_SUSP      = IM_COL32(255, 80, 60, 255);     // bright red
static const ImU32 COL_JAVA_NORMAL    = IM_COL32(210, 215, 225, 255);   // light
static const ImU32 COL_JAVA_SUSP_BG   = IM_COL32(80, 25, 20, 180);     // dark red bg

void CodeViewer::render_decompiled_view() {
    if (selected_class_.empty()) {
        float w = ImGui::GetContentRegionAvail().x;
        float h = ImGui::GetContentRegionAvail().y;
        ImGui::SetCursorPos(ImVec2(w * 0.5f - 140, h * 0.5f - 20));
        ImGui::TextColored(ImVec4(0.4f, 0.42f, 0.48f, 1.0f), "Select a class to view decompiled source");
        return;
    }

    const DecompiledClass& dcc = get_decompiled(selected_class_);
    if (!dcc.valid) {
        ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f), "Failed to decompile: %s", dcc.error.c_str());
        return;
    }

    if (dcc.lines.empty()) {
        ImGui::TextColored(ImVec4(0.4f, 0.42f, 0.48f, 1.0f), "Empty class");
        return;
    }

    // Count suspicious lines
    int susp_count = 0;
    for (const auto& line : dcc.lines)
        if (line.is_suspicious) susp_count++;

    // Suspicion summary bar
    if (susp_count > 0) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.05f, 0.04f, 1.0f));
        ImGui::BeginChild("##DecompSuspBar", ImVec2(-1, 28), ImGuiChildFlags_None);
        ImGui::SetCursorPos(ImVec2(12, 5));
        ImGui::TextColored(ImVec4(0.95f, 0.3f, 0.25f, 1.0f),
            "! %d suspicious line%s highlighted",
            susp_count, susp_count != 1 ? "s" : "");
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // Source display with virtual scrolling
    if (font_mono_) ImGui::PushFont(font_mono_);

    float line_h = ImGui::GetTextLineHeightWithSpacing();
    float gutter_w = 50.0f;
    int total_lines = static_cast<int>(dcc.lines.size());

    ImGui::BeginChild("##DecompScroll", ImVec2(0, 0), ImGuiChildFlags_None,
                      ImGuiWindowFlags_HorizontalScrollbar);

    // Scroll to search match if needed
    if (search_needs_scroll_ && active_tab_ == ViewTab::DECOMPILED &&
        current_match_ >= 0 && current_match_ < static_cast<int>(search_matches_.size())) {
        float target_y = search_matches_[current_match_] * line_h;
        float avail_h_pre = ImGui::GetContentRegionAvail().y;
        float centered = target_y - avail_h_pre * 0.4f;
        if (centered < 0) centered = 0;
        ImGui::SetScrollY(centered);
        search_needs_scroll_ = false;
    }

    ImVec2 origin = ImGui::GetCursorScreenPos();
    float avail_w = ImGui::GetContentRegionAvail().x;
    float avail_h = ImGui::GetContentRegionAvail().y;
    float scroll_y = ImGui::GetScrollY();

    float content_h = total_lines * line_h;
    ImGui::Dummy(ImVec2(avail_w, content_h));

    int first_visible = (std::max)(0, (int)(scroll_y / line_h) - 1);
    int visible_count = (int)(avail_h / line_h) + 3;
    int last_visible = (std::min)(first_visible + visible_count, total_lines);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 mouse = ImGui::GetMousePos();

    // Gutter background
    dl->AddRectFilled(
        ImVec2(origin.x, origin.y + first_visible * line_h - scroll_y),
        ImVec2(origin.x + gutter_w - 4, origin.y + last_visible * line_h - scroll_y),
        IM_COL32(14, 15, 20, 255));

    for (int i = first_visible; i < last_visible; i++) {
        float y = origin.y + i * line_h - scroll_y;
        const auto& line = dcc.lines[i];

        // Suspicious line background
        if (line.is_suspicious) {
            dl->AddRectFilled(
                ImVec2(origin.x, y),
                ImVec2(origin.x + avail_w + 500, y + line_h),
                COL_JAVA_SUSP_BG);
            dl->AddRectFilled(
                ImVec2(origin.x, y),
                ImVec2(origin.x + 3, y + line_h),
                IM_COL32(230, 60, 50, 255));
        }

        // Search match highlight
        if (!search_matches_.empty() && active_tab_ == ViewTab::DECOMPILED) {
            auto sit = std::lower_bound(search_matches_.begin(), search_matches_.end(), i);
            if (sit != search_matches_.end() && *sit == i) {
                int match_idx = static_cast<int>(sit - search_matches_.begin());
                ImU32 bg = (match_idx == current_match_) ? COL_SEARCH_CUR : COL_SEARCH_BG;
                dl->AddRectFilled(
                    ImVec2(origin.x, y),
                    ImVec2(origin.x + avail_w + 500, y + line_h), bg);
            }
        }

        // Hover highlight
        bool hovered = (mouse.y >= y && mouse.y < y + line_h &&
                        mouse.x >= origin.x && mouse.x < origin.x + avail_w);
        if (hovered) {
            dl->AddRectFilled(
                ImVec2(origin.x, y),
                ImVec2(origin.x + avail_w + 500, y + line_h),
                COL_HOVER_BG);
            if (line.is_suspicious && !line.suspicion_reason.empty()) {
                ImGui::BeginTooltip();
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.3f, 0.25f, 1.0f));
                ImGui::Text("! %s", line.suspicion_reason.c_str());
                ImGui::PopStyleColor();
                ImGui::EndTooltip();
            }
        }

        // Line number
        if (!line.text.empty()) {
            char num_buf[16];
            snprintf(num_buf, sizeof(num_buf), "%4d", i + 1);
            dl->AddText(ImVec2(origin.x + 4, y), COL_LINE_NUM, num_buf);
        }

        // Gutter separator
        dl->AddLine(
            ImVec2(origin.x + gutter_w - 4, y),
            ImVec2(origin.x + gutter_w - 4, y + line_h),
            COL_GUTTER_LINE);

        // Text content with syntax coloring
        if (!line.text.empty()) {
            ImU32 text_color;
            if (line.is_suspicious)       text_color = COL_JAVA_SUSP;
            else if (line.is_comment)     text_color = COL_JAVA_COMMENT;
            else if (line.is_keyword)     text_color = COL_JAVA_KEYWORD;
            else if (line.is_string)      text_color = COL_JAVA_STRING;
            else                          text_color = COL_JAVA_NORMAL;

            dl->AddText(ImVec2(origin.x + gutter_w, y), text_color, line.text.c_str());
        }
    }

    ImGui::EndChild();
    if (font_mono_) ImGui::PopFont();
}

// --- jar metadata ---

void CodeViewer::build_jar_metadata() {
    if (jar_metadata_built_) return;
    jar_metadata_built_ = true;

    JarMetadataParser parser;
    jar_metadata_ = parser.parse(jar_.manifest, jar_.all_filenames);

    // Also check for plugin.yml and fabric.mod.json in the entries
    for (const auto& entry : jar_.entries) {
        std::string lower = entry.filename;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower == "plugin.yml" && !entry.data.empty()) {
            std::string content(reinterpret_cast<const char*>(entry.data.data()), entry.data.size());
            parser.parse_plugin_yml(jar_metadata_, content);
        }
        else if (lower == "fabric.mod.json" && !entry.data.empty()) {
            std::string content(reinterpret_cast<const char*>(entry.data.data()), entry.data.size());
            parser.parse_fabric_mod_json(jar_metadata_, content);
        }
    }
}

void CodeViewer::render_metadata_panel() {
    build_jar_metadata();

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 12));

    ImGui::Spacing();
    if (font_regular_) ImGui::PushFont(font_regular_);
    ImGui::TextColored(ImVec4(0.70f, 0.75f, 0.85f, 1.0f), "JAR Information");
    if (font_regular_) ImGui::PopFont();
    ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

    ImGui::BeginChild("##MetadataScroll", ImVec2(0, 0), ImGuiChildFlags_None);

    auto& meta = jar_metadata_;

    // Helper: render a labeled field
    auto field = [&](const char* label, const std::string& value, ImVec4 val_color = ImVec4(0.80f, 0.82f, 0.88f, 1.0f)) {
        if (value.empty()) return;
        if (font_small_) ImGui::PushFont(font_small_);
        ImGui::TextColored(ImVec4(0.45f, 0.47f, 0.52f, 1.0f), "%-24s", label);
        ImGui::SameLine(200);
        ImGui::TextColored(val_color, "%s", value.c_str());
        if (font_small_) ImGui::PopFont();
    };

    // Helper: render a section header
    auto section = [&](const char* title) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.65f, 0.50f, 0.42f, 1.0f), "%s", title);
        ImGui::Spacing();
    };

    // Build info
    section("Build Information");
    field("Manifest Version",    meta.manifest_version);
    field("Created By",          meta.created_by);
    field("Built By",            meta.built_by);
    field("Build JDK",           meta.build_jdk);
    field("Build JDK Spec",      meta.build_jdk_spec);
    field("Main Class",          meta.main_class, ImVec4(0.6f, 0.8f, 0.95f, 1.0f));

    // Implementation
    if (!meta.implementation_title.empty() || !meta.implementation_version.empty() ||
        !meta.implementation_vendor.empty()) {
        section("Implementation");
        field("Title",    meta.implementation_title);
        field("Version",  meta.implementation_version, ImVec4(0.4f, 0.85f, 0.55f, 1.0f));
        field("Vendor",   meta.implementation_vendor);
        field("Vendor ID", meta.implementation_vendor_id);
    }

    // Specification
    if (!meta.specification_title.empty() || !meta.specification_version.empty() ||
        !meta.specification_vendor.empty()) {
        section("Specification");
        field("Title",    meta.specification_title);
        field("Version",  meta.specification_version);
        field("Vendor",   meta.specification_vendor);
    }

    // Bundle / license
    if (!meta.bundle_name.empty() || !meta.bundle_version.empty() ||
        !meta.bundle_license.empty()) {
        section("Bundle / License");
        field("Name",           meta.bundle_name);
        field("Symbolic Name",  meta.bundle_symbolic_name);
        field("Version",        meta.bundle_version);
        field("Vendor",         meta.bundle_vendor);
        field("License",        meta.bundle_license, ImVec4(0.4f, 0.85f, 0.55f, 1.0f));
        field("Description",    meta.bundle_description);
    }

    // Minecraft plugin/mod
    if (!meta.plugin_name.empty() || !meta.forge_mod_id.empty()) {
        section("Minecraft Mod / Plugin");
        field("Plugin Name",     meta.plugin_name, ImVec4(0.6f, 0.8f, 0.95f, 1.0f));
        field("Plugin Version",  meta.plugin_version, ImVec4(0.4f, 0.85f, 0.55f, 1.0f));
        field("Author",          meta.plugin_author);
        field("Description",     meta.plugin_description);
        field("Main Class",      meta.plugin_main, ImVec4(0.6f, 0.8f, 0.95f, 1.0f));
        field("Mod ID",          meta.forge_mod_id);
    }

    // Signing
    section("Code Signing");
    if (meta.is_signed) {
        field("Signed", "Yes", ImVec4(0.4f, 0.85f, 0.55f, 1.0f));
        field("Signer", meta.signer_info);
    } else {
        field("Signed", "No", ImVec4(0.6f, 0.6f, 0.65f, 1.0f));
    }

    // File structure
    section("JAR Structure");
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "%d", meta.total_entries);
        field("Total Entries", buf);
        snprintf(buf, sizeof(buf), "%d", meta.class_file_count);
        field("Class Files", buf);
        snprintf(buf, sizeof(buf), "%d", meta.resource_count);
        field("Resources", buf);

        if (meta.image_count > 0) {
            snprintf(buf, sizeof(buf), "%d", meta.image_count);
            field("  Images", buf);
        }
        if (meta.config_count > 0) {
            snprintf(buf, sizeof(buf), "%d", meta.config_count);
            field("  Config Files", buf);
        }
        if (meta.text_count > 0) {
            snprintf(buf, sizeof(buf), "%d", meta.text_count);
            field("  Text Files", buf);
        }
        if (meta.native_lib_count > 0) {
            snprintf(buf, sizeof(buf), "%d", meta.native_lib_count);
            field("  Native Libraries", buf, ImVec4(0.95f, 0.35f, 0.3f, 1.0f));
        }
        if (meta.script_count > 0) {
            snprintf(buf, sizeof(buf), "%d", meta.script_count);
            field("  Scripts", buf, ImVec4(0.95f, 0.35f, 0.3f, 1.0f));
        }
        if (meta.other_count > 0) {
            snprintf(buf, sizeof(buf), "%d", meta.other_count);
            field("  Other", buf);
        }
    }

    // Suspicious entries
    if (!meta.suspicious_entries.empty()) {
        section("Suspicious File Entries");
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.35f, 0.3f, 1.0f));
        for (const auto& entry : meta.suspicious_entries) {
            ImGui::Spacing();
            ImDrawList* sdl = ImGui::GetWindowDrawList();
            ImVec2 pos = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            float card_h = 44;
            sdl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + card_h),
                              IM_COL32(50, 18, 16, 200), 6.0f);
            sdl->AddRectFilled(pos, ImVec2(pos.x + 3, pos.y + card_h),
                              IM_COL32(200, 55, 45, 255), 3.0f);

            ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + 10, ImGui::GetCursorPosY() + 4));
            if (font_mono_) ImGui::PushFont(font_mono_);
            ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.3f, 1.0f), "%s", entry.filename.c_str());
            if (font_mono_) ImGui::PopFont();

            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10);
            if (font_small_) ImGui::PushFont(font_small_);
            ImGui::TextColored(ImVec4(0.55f, 0.57f, 0.62f, 1.0f), "%s", entry.reason.c_str());
            if (font_small_) ImGui::PopFont();

            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        }
        ImGui::PopStyleColor();
    }

    // Raw manifest attributes
    if (!meta.raw_attributes.empty()) {
        section("All Manifest Attributes");
        if (font_small_) ImGui::PushFont(font_small_);
        if (ImGui::BeginTable("##ManifestAttrs", 2,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_PadOuterX | ImGuiTableFlags_Resizable)) {

            ImGui::TableSetupColumn("Key", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& [key, value] : meta.raw_attributes) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(ImVec4(0.55f, 0.57f, 0.62f, 1.0f), "%s", key.c_str());
                ImGui::TableNextColumn();
                ImGui::TextWrapped("%s", value.c_str());
            }
            ImGui::EndTable();
        }
        if (font_small_) ImGui::PopFont();
    }

    ImGui::EndChild();
    ImGui::PopStyleVar();
}

// --- url confirmation popup ---

void CodeViewer::render_url_confirm_popup() {
    if (!show_url_popup_) return;

    ImGui::OpenPopup("Open URL?###URLConfirm");

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(520, 0));

    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.10f, 0.10f, 0.14f, 0.98f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24, 20));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12.0f);

    if (ImGui::BeginPopupModal("Open URL?###URLConfirm", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove)) {

        // Warning icon area
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.55f, 0.10f, 1.0f));
        if (font_regular_) ImGui::PushFont(font_regular_);
        ImGui::Text("!! WARNING !!");
        if (font_regular_) ImGui::PopFont();
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::TextWrapped("You are about to open a URL that was extracted from a scanned mod file. "
                           "This URL may be malicious and could lead to harmful content.");
        ImGui::Spacing();

        // Show the URL
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.06f, 0.06f, 0.08f, 1.0f));
        ImGui::BeginChild("##URLDisplay", ImVec2(-1, 40), ImGuiChildFlags_Borders);
        ImGui::SetCursorPos(ImVec2(10, 10));
        if (font_mono_) ImGui::PushFont(font_mono_);
        ImGui::TextColored(ImVec4(0.7f, 0.8f, 0.95f, 1.0f), "%s", pending_url_.c_str());
        if (font_mono_) ImGui::PopFont();
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::Spacing();

        // Warning detail
        if (!pending_url_warning_.empty()) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 0.35f, 0.3f, 1.0f));
            ImGui::TextWrapped("%s", pending_url_warning_.c_str());
            ImGui::PopStyleColor();
            ImGui::Spacing();
        }

        ImGui::TextWrapped("If you proceed, this is on your own behalf. IHP is not responsible "
                           "for any consequences of visiting this URL.");

        ImGui::Spacing(); ImGui::Spacing();

        // Buttons
        float btn_w = 200;
        float total_w = ImGui::GetContentRegionAvail().x;
        float spacing = 16;
        float start_x = (total_w - btn_w * 2 - spacing) * 0.5f;

        ImGui::SetCursorPosX(start_x);

        // "Nope, too risky!" button (default, safe option)
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.17f, 0.22f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.22f, 0.23f, 0.30f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.28f, 0.29f, 0.36f, 1.0f));
        if (ImGui::Button("Nope, too risky!", ImVec2(btn_w, 36))) {
            show_url_popup_ = false;
            pending_url_.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(3);

        ImGui::SameLine(0, spacing);

        // "Okay, still wanna continue" button (danger)
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.55f, 0.15f, 0.12f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.70f, 0.20f, 0.16f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.85f, 0.25f, 0.20f, 1.0f));
        if (ImGui::Button("Okay, continue", ImVec2(btn_w, 36))) {
            // Open URL in default browser via ShellExecute
            ShellExecuteA(nullptr, "open", pending_url_.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            show_url_popup_ = false;
            pending_url_.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(3);

        ImGui::EndPopup();
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor();
}

// --- code search (Ctrl+F) ---

void CodeViewer::update_search_matches() {
    search_matches_.clear();
    current_match_ = -1;

    std::string query(code_search_buf_);
    if (query.empty()) return;

    // Determine which lines to search based on active tab
    if (active_tab_ == ViewTab::BYTECODE) {
        std::string query_lower;
        if (!search_case_sensitive_) {
            query_lower = query;
            std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), ::tolower);
        }
        for (int i = 0; i < static_cast<int>(formatted_lines_.size()); i++) {
            const auto& text = formatted_lines_[i].text;
            if (text.empty()) continue;
            if (search_case_sensitive_) {
                if (text.find(query) != std::string::npos)
                    search_matches_.push_back(i);
            } else {
                std::string text_lower = text;
                std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
                if (text_lower.find(query_lower) != std::string::npos)
                    search_matches_.push_back(i);
            }
        }
    } else if (active_tab_ == ViewTab::DECOMPILED) {
        if (selected_class_.empty()) return;
        const DecompiledClass& dcc = get_decompiled(selected_class_);
        if (!dcc.valid) return;

        std::string query_lower;
        if (!search_case_sensitive_) {
            query_lower = query;
            std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), ::tolower);
        }
        for (int i = 0; i < static_cast<int>(dcc.lines.size()); i++) {
            const auto& text = dcc.lines[i].text;
            if (text.empty()) continue;
            if (search_case_sensitive_) {
                if (text.find(query) != std::string::npos)
                    search_matches_.push_back(i);
            } else {
                std::string text_lower = text;
                std::transform(text_lower.begin(), text_lower.end(), text_lower.begin(), ::tolower);
                if (text_lower.find(query_lower) != std::string::npos)
                    search_matches_.push_back(i);
            }
        }
    }

    if (!search_matches_.empty()) {
        current_match_ = 0;
        search_needs_scroll_ = true;
    }
}

void CodeViewer::search_navigate(int delta) {
    if (search_matches_.empty()) return;
    current_match_ += delta;
    if (current_match_ < 0) current_match_ = static_cast<int>(search_matches_.size()) - 1;
    if (current_match_ >= static_cast<int>(search_matches_.size())) current_match_ = 0;
    search_needs_scroll_ = true;
}

} // namespace ihp
