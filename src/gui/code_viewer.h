#pragma once
#include "../scanner/bytecode_decoder.h"
#include "../scanner/java_decompiler.h"
#include "../scanner/jar_reader.h"
#include "../scanner/jar_metadata.h"
#include "anim.h"
#include "../../third_party/imgui/imgui.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace ihp {

class CodeViewer {
public:
    CodeViewer() = default;
    void set_fonts(ImFont* font_regular, ImFont* font_small, ImFont* font_mono);

    // Open the viewer for a specific JAR file path
    void open(const std::string& jar_path);
    void close();
    bool render();          // returns false when user closes
    bool is_open() const { return is_open_; }

private:
    // Formatted line for bytecode display
    struct FormattedLine {
        std::string text;
        enum Type { HEADER, FIELD, METHOD_SIG, CODE_META, INSTRUCTION, BLANK } type = BLANK;
        bool is_suspicious = false;
        std::string suspicion_reason;
        ImU32 color = IM_COL32(200, 205, 215, 255);
    };

    // Package tree node
    struct TreeNode {
        std::string name;           // segment: "net", "minecraft", "MyClass.class"
        std::string full_path;      // full JAR entry path (only for leaves)
        bool is_leaf = false;
        bool has_suspicious = false; // any suspicious lines in this class?
        std::vector<TreeNode> children;
    };

    // Left panel
    void render_class_tree();
    void render_tree_node(TreeNode& node);
    void build_tree();

    // Right panel
    void render_bytecode_view();
    void render_decompiled_view();
    void render_intel_panel();
    void render_metadata_panel();
    void render_url_confirm_popup();
    void format_class(const DecodedClass& dc);

    // On-demand decode (cached)
    const DecodedClass& get_decoded(const std::string& class_name);

    // State
    bool is_open_ = false;
    std::string jar_path_;

    // JAR data (loaded on open())
    JarContents jar_;
    std::unordered_map<std::string, const JarEntry*> class_map_;
    std::vector<std::string> class_names_;

    // Selection
    std::string selected_class_;

    // Decode cache (max 32 entries)
    static constexpr size_t MAX_CACHE = 32;
    std::unordered_map<std::string, DecodedClass> decode_cache_;
    BytecodeDecoder decoder_;

    // Formatted lines for current class
    std::vector<FormattedLine> formatted_lines_;
    std::string formatted_class_; // which class is currently formatted

    // Tree
    TreeNode tree_root_;

    // Search filter
    char search_buf_[256] = {};

    // Tab state
    enum class ViewTab { BYTECODE, DECOMPILED, INTEL, METADATA };
    ViewTab active_tab_ = ViewTab::DECOMPILED;

    // JAR-wide intelligence (aggregated from all classes)
    std::vector<IntelItem> jar_intel_;
    bool jar_intel_built_ = false;
    void build_jar_intel();

    // Decompiler
    JavaDecompiler decompiler_;
    std::unordered_map<std::string, DecompiledClass> decompile_cache_;
    const DecompiledClass& get_decompiled(const std::string& class_name);

    // JAR metadata
    JarMetadata jar_metadata_;
    bool jar_metadata_built_ = false;
    void build_jar_metadata();

    // Code search (Ctrl+F)
    bool show_search_ = false;
    char code_search_buf_[512] = {};
    std::vector<int> search_matches_;
    int current_match_ = -1;
    bool search_case_sensitive_ = false;
    bool search_needs_scroll_ = false;
    bool search_needs_focus_ = false;
    std::string search_built_for_class_;
    ViewTab search_built_for_tab_ = ViewTab::DECOMPILED;
    void update_search_matches();
    void search_navigate(int delta);

    // URL confirmation popup
    bool show_url_popup_ = false;
    std::string pending_url_;
    std::string pending_url_warning_;

    // Fonts
    ImFont* font_regular_ = nullptr;
    ImFont* font_small_ = nullptr;
    ImFont* font_mono_ = nullptr;

    // Animation
    AnimStore anim_;
    float anim_time_ = 0.0f;
};

} // namespace ihp
