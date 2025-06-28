#pragma once
#include "../include/includes.h"

class custom_widgets
{
public:
    bool tab(const char* icon, ImFont* icon_font, const char* label, bool selected) {
        auto window = ImGui::GetCurrentWindow();
        auto id = window->GetID(label);

        ImGui::PushFont(icon_font);
        auto icon_size = ImGui::CalcTextSize(icon);
        ImGui::PopFont();

        auto label_size = ImGui::CalcTextSize(label, 0, 1);

        auto pos = window->DC.CursorPos;
        auto draw = window->DrawList;

        ImRect bb(pos, ImVec2(pos.x + ImGui::GetWindowWidth(), pos.y + 30));
        ImGui::ItemAdd(bb, id);
        ImGui::ItemSize(bb, ImGui::GetStyle().FramePadding.y);

        bool hovered, held;
        bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held);

        static std::unordered_map<ImGuiID, float> values;
        auto value = values.find(id);
        if (value == values.end()) {
            values.insert({ id, 0.f });
            value = values.find(id);
        }

        static std::unordered_map<std::string, float> alpha_map;
        float& text_alpha = alpha_map[label];
        if (hovered || selected) {
            text_alpha = ImLerp(text_alpha, 1.f, 0.01f);
        }
        else {
            text_alpha = ImLerp(text_alpha, 0.3f, 0.01f);
        }

        value->second = ImLerp(value->second, (selected ? 1.f : 0.f), 0.05f);

        ImVec4 frame_active = { 0.0509803921568627, 0.0509803921568627, 0.0509803921568627, 0.5f * value->second };
        ImVec4 accent_color = utils.rgb_to_imvec4(0, 0, 255, 1.f);
        draw->AddRectFilled(bb.Min, bb.Max, ImGui::GetColorU32(frame_active), 5);

        ImVec4 icon_color = ImVec4(accent_color.x,
            accent_color.y,
            accent_color.z,
            text_alpha);
        ImGui::PushFont(icon_font);
        draw->AddText(ImVec2(bb.Min.x + 10, bb.GetCenter().y - label_size.y / 2), ImGui::GetColorU32(icon_color), icon);
        ImGui::PopFont();

        ImVec4 label_color = ImVec4(ImGui::GetStyleColorVec4(ImGuiCol_Text).x,
            ImGui::GetStyleColorVec4(ImGuiCol_Text).y,
            ImGui::GetStyleColorVec4(ImGuiCol_Text).z,
            text_alpha);
        draw->AddText(ImVec2(bb.Min.x + 35, bb.GetCenter().y - label_size.y / 2), ImGui::GetColorU32(label_color), label);

        return pressed;
    }

    bool slider_float(const char* label, float* value, float min, float max, bool no_decimals = false, float x_offset = 0.f, float y_offset = 0.f) {
        ImGuiStyle& style = ImGui::GetStyle();
        ImDrawList* draw_list = ImGui::GetWindowDrawList();
        ImVec2 pos = ImGui::GetCurrentWindow()->DC.CursorPos;
        float width = 125;
        float height = 4.0f;

        static std::unordered_map<std::string, float> alpha_map;
        float& labelAlpha = alpha_map[label];
        static std::unordered_map<std::string, float> valueTextAlpha_map;
        float& valueTextAlpha = valueTextAlpha_map[label];

        float t = (*value - min) / (max - min);
        float sliderX = pos.x + x_offset + t * width;

        ImVec4 trackColor = ImGui::GetStyleColorVec4(ImGuiCol_SliderGrab);
        draw_list->AddRectFilled(
            ImVec2(pos.x + x_offset, pos.y + height + style.ItemSpacing.y + y_offset),
            ImVec2(pos.x + x_offset + width, pos.y + height / 2 + 2 + y_offset),
            ImGui::GetColorU32(trackColor)
        );

        ImVec4 activeColor = ImGui::GetStyleColorVec4(ImGuiCol_SliderGrabActive);
        draw_list->AddRectFilled(
            ImVec2(pos.x + x_offset, pos.y + height + style.ItemSpacing.y + y_offset),
            ImVec2(sliderX, pos.y + height / 2 + 2 + y_offset),
            ImGui::GetColorU32(activeColor)
        );

        ImVec2 labelPos = ImVec2(pos.x, pos.y - height + y_offset);
        draw_list->AddText(labelPos, ImGui::GetColorU32(ImVec4(1.f, 1.f, 1.f, labelAlpha)), label);

        ImGui::SetCursorScreenPos(ImVec2(pos.x + x_offset, pos.y + height + style.ItemSpacing.y + y_offset));
        ImGui::InvisibleButton(label, ImVec2(width, height));
        bool is_active = ImGui::IsItemActive();
        bool is_hovered = ImGui::IsItemHovered();

        if (is_active) {
            ImVec2 mousePos = ImGui::GetIO().MousePos;
            t = (mousePos.x - (pos.x + x_offset)) / width;
            t = ImClamp(t, 0.0f, 1.0f);
            if (no_decimals) { *value = (int)(min + t * (max - min)); }
            else { *value = (min + t * (max - min)); }
        }

        if (is_hovered || is_active) {
            labelAlpha = ImLerp(labelAlpha, 1.0f, 0.1f);
        }
        else {
            labelAlpha = ImLerp(labelAlpha, 0.5f, 0.1f);
        }

        if (is_hovered || is_active) {
            valueTextAlpha = ImLerp(valueTextAlpha, 1.0f, 0.1f);
        }
        else {
            valueTextAlpha = ImLerp(valueTextAlpha, 0.0f, 0.1f);
        }

        std::string text;
        if (no_decimals) { text = std::to_string((int)*value); }
        else { text = std::to_string(*value); }

        ImVec4 valueColor = ImVec4(1.0f, 1.0f, 1.0f, valueTextAlpha);
        ImVec2 valuePos = ImVec2(sliderX - ImGui::CalcTextSize(text.c_str()).x / 2, pos.y + 10 + y_offset);
        draw_list->AddText(valuePos, ImGui::GetColorU32(valueColor), text.c_str());

        return is_active || is_hovered;
    }

    void color_picker(const char* label, ImVec4& color) {
        static std::unordered_map<std::string, std::string> id_map;
        std::string unique_label = std::string(label) + "##" + std::to_string(reinterpret_cast<uintptr_t>(&color));
        std::string& id = id_map[unique_label];
        static std::unordered_map<std::string, bool> status_map;
        bool& status = status_map[unique_label];

        if (!status) {
            id = utils.generate_id((200));
            status = true;
        }

        ImGui::SetCursorPosX(10);
        ImGui::Text(label);
        ImGui::SetCursorPos({ ImGui::GetCursorPos().x + 220, ImGui::GetCursorPos().y - ImGui::CalcTextSize(label).y - 5 });
        ImGui::ColorEdit4(id.c_str(), (float*)&color, (ImGuiColorEditFlags_NoInputs) | (ImGuiColorEditFlags_NoOptions));
    }

    void begin_section(const char* label, ImVec2 size, bool outline, bool hovered) {
        auto* window = ImGui::GetCurrentWindow();
        ImVec2 pos = window->DC.CursorPos;

        static std::unordered_map<ImGuiID, float> alpha_map;
        ImGuiID section_id = window->GetID(label);
        float& alpha = alpha_map[section_id];

        ImGui::PushStyleColor(ImGuiCol_ChildBg, utils.rgb_to_imvec4(8, 8, 8, 1.f));

        ImGui::BeginChild(section_id, size, outline);

        alpha = ImLerp(alpha, hovered ? 1.0f : 0.5f, 0.01f);

        ImGui::PushStyleColor(ImGuiCol_Separator, utils.rgb_to_imvec4(10, 10, 10, alpha));
        ImGui::PushStyleColor(ImGuiCol_Text, utils.rgb_to_imvec4(255, 255, 255, alpha));

        ImVec2 text_size = ImGui::CalcTextSize(label);
        ImGui::SetCursorPosX((size.x - text_size.x) / 2);
        ImGui::SetCursorPosY(10);
        ImGui::Text(label);
        ImGui::SetCursorPosX(pos.x);
        ImGui::Separator();

        ImGui::PopStyleColor(3);
    } void end_section() { ImGui::EndChild(); }
}; custom_widgets widgets;
