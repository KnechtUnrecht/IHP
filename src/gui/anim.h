#pragma once
#include "../../third_party/imgui/imgui.h"
#include <unordered_map>
#include <cmath>

namespace ihp {

// Easing functions, t in [0,1] -> [0,1]

namespace ease {
    inline float linear(float t) { return t; }

    inline float in_quad(float t) { return t * t; }
    inline float out_quad(float t) { return t * (2.0f - t); }
    inline float in_out_quad(float t) {
        return t < 0.5f ? 2.0f * t * t : -1.0f + (4.0f - 2.0f * t) * t;
    }

    inline float out_cubic(float t) { float u = t - 1.0f; return u * u * u + 1.0f; }

    // Overshoot — great for pop-in effects
    inline float out_back(float t) {
        const float c = 1.70158f;
        float u = t - 1.0f;
        return 1.0f + (c + 1.0f) * u * u * u + c * u * u;
    }
}

// Frame-rate independent smoothing (higher speed = faster convergence)

inline float smooth_damp(float current, float target, float speed, float dt) {
    float factor = 1.0f - expf(-speed * dt);
    return current + (target - current) * factor;
}

inline ImVec4 smooth_damp_color(ImVec4 current, ImVec4 target, float speed, float dt) {
    return ImVec4(
        smooth_damp(current.x, target.x, speed, dt),
        smooth_damp(current.y, target.y, speed, dt),
        smooth_damp(current.z, target.z, speed, dt),
        smooth_damp(current.w, target.w, speed, dt)
    );
}

// Per-element animation state

struct AnimState {
    float hover   = 0.0f;   // 0..1  smooth hover amount
    float expand  = 0.0f;   // 0..1  expand/collapse progress
    float appear  = 0.0f;   // 0..1  entrance animation progress
    float glow    = 0.0f;   // generic glow intensity
    float value   = 0.0f;   // generic animated value
    int   last_frame = 0;   // last frame this was accessed
};

class AnimStore {
public:
    AnimState& get(ImGuiID id) {
        auto& state = store_[id];
        state.last_frame = ImGui::GetFrameCount();
        return state;
    }

    // Call once per frame to prune stale entries
    void gc() {
        int frame = ImGui::GetFrameCount();
        if (frame % 120 != 0) return; // every ~2 seconds at 60fps
        for (auto it = store_.begin(); it != store_.end(); ) {
            if (frame - it->second.last_frame > 300) // 5 seconds stale
                it = store_.erase(it);
            else
                ++it;
        }
    }

private:
    std::unordered_map<ImGuiID, AnimState> store_;
};

// Draw helpers

// Fake soft shadow: 3 layers of expanding semi-transparent rects
inline void draw_shadow(ImDrawList* dl, ImVec2 min, ImVec2 max,
                         float radius, ImU32 color, float rounding) {
    int base_alpha = (color >> 24) & 0xFF;
    ImU32 base_rgb = color & 0x00FFFFFF;
    for (int i = 0; i < 3; i++) {
        float expand = radius * (float)(i + 1) / 3.0f;
        int alpha = base_alpha / (i + 2);
        ImU32 c = base_rgb | ((ImU32)alpha << 24);
        dl->AddRectFilled(
            ImVec2(min.x - expand, min.y - expand),
            ImVec2(max.x + expand, max.y + expand),
            c, rounding + expand * 0.5f
        );
    }
}

// Gradient separator line: center-bright, edges-transparent
inline void draw_gradient_separator(ImDrawList* dl, float x, float y, float w,
                                     ImU32 center_color) {
    float mid = w * 0.5f;
    int alpha = (center_color >> 24) & 0xFF;
    ImU32 transparent = center_color & 0x00FFFFFF; // alpha = 0
    dl->AddRectFilledMultiColor(
        ImVec2(x, y), ImVec2(x + mid, y + 1),
        transparent, center_color, center_color, transparent
    );
    dl->AddRectFilledMultiColor(
        ImVec2(x + mid, y), ImVec2(x + w, y + 1),
        center_color, transparent, transparent, center_color
    );
    (void)alpha; // suppress unused warning
}

} // namespace ihp
