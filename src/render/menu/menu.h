#pragma once
#include "../include/includes.h"

class handle_menu
{
public:
	void fade_in() {
		float alpha = 0.0f;
		float targetAlpha = 1.0f;
		float fadeSpeed = 0.01f;

		while (alpha < targetAlpha) {
			alpha += fadeSpeed;
			if (alpha > targetAlpha) {
				alpha = targetAlpha;
			}

			ImGui::GetStyle().Alpha = alpha;

			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
	}

	void loop() {
		aimbot.aimbot_loop();
		visuals.draw_esp();

		std::string water_mark_text = ("Relapse-Private | ") + std::to_string((int)ImGui::GetIO().Framerate);
		ImGui::GetBackgroundDrawList()->AddText(ImVec2((10), (10)), ImGui::GetColorU32(ImVec4((1.f), (1.f), (1.f), (1.f))), water_mark_text.c_str());
	}

	void key_loop() {
		while (true) {
			if (get_async_key_state_spoofed(VK_INSERT)) {
				strings.b_draw = !strings.b_draw;
				while (get_async_key_state_spoofed(VK_INSERT));
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}

	void style() {
		ImGuiStyle& style = ImGui::GetStyle();

		style.Colors[ImGuiCol_WindowBg] = utils.rgb_to_imvec4(0, 0, 0, 0);
		style.Colors[ImGuiCol_ChildBg] = utils.rgb_to_imvec4(10, 10, 10, 255);
		style.Colors[ImGuiCol_Border] = utils.rgb_to_imvec4(0, 0, 0, 0);

		style.Colors[ImGuiCol_PopupBg] = utils.rgb_to_imvec4(13, 13, 13, 255);

		style.Colors[ImGuiCol_SliderGrab] = { 10 / 255.0f, 10 / 255.0f, 10 / 255.0f, 1.f };
		style.Colors[ImGuiCol_SliderGrabActive] = ImColor(0, 0, 255, 255);
		style.Colors[ImGuiCol_ScrollbarBg] = ImColor(0, 0, 0, 0);
		style.Colors[ImGuiCol_ScrollbarGrab] = ImColor(5 / 255.0f, 5 / 255.0f, 5 / 255.0f, 1.0f);
		style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImColor(5 / 255.0f, 5 / 255.0f, 5 / 255.0f, 1.0f);
		style.Colors[ImGuiCol_ScrollbarGrabActive] = ImColor(5 / 255.0f, 5 / 255.0f, 5 / 255.0f, 1.0f);

		style.WindowBorderSize = 0.f;
		style.WindowRounding = 3.f;

		style.ChildBorderSize = 0.f;
		style.ChildRounding = 3.f;
	}

	void draw() {
		if (!strings.b_init) {
			ImGui::SetNextWindowSize({ 850, 500 });
			ImGui::SetNextWindowPos({ screen_width / 2 - 850 / 2, screen_height / 2 - 500 / 2 });

			strings.b_init = true;
		}

		if (strings.b_draw) {
			ImGui::PushFont(strings.roboto_bold);
			ImGui::Begin(("Relapse-Overlay"), &strings.b_draw, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse);

			if (strings.animation < 1.f) { strings.animation += 0.1; }

			{
				ImGui::SetCursorPos({ 0,0 });

				ImGui::BeginChild(("#main"), ImGui::GetWindowSize(), false);
				
				// tabs
				{
					ImGui::PushStyleColor(ImGuiCol_ChildBg, utils.rgb_to_imvec4(8, 8, 8, 255));

					ImGui::SetCursorPos({ 0,0 });
					ImGui::BeginChild(("#tabs"), { 200, ImGui::GetWindowSize().y }, false);

					ImGui::PopStyleColor();

					ImGui::PushFont(strings.roboto_bold);

					ImGui::SetCursorPos({ 200 / 2 - 200 / 2, -50 });
					ImGui::Image(strings.logo_icon_texture, { 200,200 });

					ImGui::SetCursorPosX(10);

					if (widgets.tab(reinterpret_cast<const char*>(ICON_FA_CROSSHAIRS), strings.icons_font, ("Aimbot"), strings.selected_tab == 0) && strings.selected_tab != 0) {
						strings.selected_tab = 0; strings.animation = 0.0f;
					}

					ImGui::Spacing();
					ImGui::SetCursorPosX(10);

					if (widgets.tab(reinterpret_cast<const char*>(ICON_FA_EYE), strings.icons_font, ("Visuals"), strings.selected_tab == 1) && strings.selected_tab != 1) {
						strings.selected_tab = 1; strings.animation = 0.0f;
					}

					ImGui::Spacing();
					ImGui::SetCursorPosX(10);

					if (widgets.tab(reinterpret_cast<const char*>(ICON_FA_PALETTE), strings.icons_font, ("Colors"), strings.selected_tab == 2) && strings.selected_tab != 2) {
						strings.selected_tab = 2; strings.animation = 0.f;
					}

					ImGui::Spacing();
					ImGui::SetCursorPosX(10);

					if (widgets.tab(reinterpret_cast<const char*>(ICON_FA_COG), strings.icons_font, ("Misc"), strings.selected_tab == 3) && strings.selected_tab != 3) {
						strings.selected_tab = 3; strings.animation = 0.0f;
					}

					ImGui::PopFont();

					ImGui::EndChild();
				}

				ImGui::EndChild();
			}

			ImGui::SetCursorPos({ 200, 5.f * strings.animation });

			ImGui::BeginChild(("#animation"), ImVec2(ImGui::GetWindowSize().x - 200, ImGui::GetWindowSize().y), false);

			{
				if (strings.selected_tab == 0) {
					ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
					
					{
						ImGui::SetCursorPos({ 10,20 });

						static std::unordered_map<ImGuiID, bool> hovered_map;
						ImGuiID hovered_id = ImGui::GetID((""));
						bool& hovered = hovered_map[hovered_id];

						widgets.begin_section(("Aimbot Setttings"), ImVec2(250, 250), false, hovered);

						ImGui::PushFont(strings.roboto_regular);

						ImGui::SetCursorPosX(10);

						ImGui::Spacing();
						ImGui::Checkbox(("enable"), &strings.aimbot.enable, ImVec2(20, 0));
						ImGui::Spacing();
						widgets.slider_float(("aimbot fov"), &strings.aimbot.fov, 1, 360, true, 108);
						ImGui::Spacing();
						widgets.slider_float(("Smooth"), &strings.aimbot.smoothness, 1, 100, true, 108);
						ImGui::Spacing();

						if (strings.aimbot.enable) {
							ImGui::SetCursorPosX(10);

							ImGui::Checkbox(("show fov"), &strings.aimbot.show_fov, ImVec2(20, 0));

							ImGui::PushFont(strings.roboto_regular_small);

							ImGui::SameLine(-45, 0);
							static const char* items[] = { "normal", "filled" };
							if (ImGui::BeginCombo((""), items[strings.aimbot.selected_fov])) {
								for (int i = 0; i < IM_ARRAYSIZE(items); i++) {
									bool selected = (strings.aimbot.selected_fov == i);
									if (ImGui::Selectable(items[i], selected)) strings.aimbot.selected_fov = i;
									if (selected) ImGui::SetItemDefaultFocus();
								} ImGui::EndCombo();
							}

							ImGui::PopFont();
						}

						ImGui::PopFont();

						widgets.end_section();

						hovered = ImGui::IsItemHovered();
					}

					{
						ImGui::SetCursorPos({ 270,20 });

						static std::unordered_map<ImGuiID, bool> hovered_map;
						ImGuiID hovered_id = ImGui::GetID(("3463432472"));
						bool& hovered = hovered_map[hovered_id];

						widgets.begin_section(("Style Settings"), ImVec2(250, 250), false, hovered);

						ImGui::PushFont(strings.roboto_regular);

						{
							ImGui::SetCursorPos({ 10 , 40 });
							widgets.slider_float(("fov thickness"), &strings.styles.aimbot.fov_thickness, 1, 10, true, 108);
							ImGui::SetCursorPosX(10);
							widgets.slider_float(("outline thickness"), &strings.styles.aimbot.fov_outline_thickness, 2, 15, true, 108);
							ImGui::SetCursorPosX(10);
							ImGui::Checkbox(("fov outline"), &strings.styles.aimbot.fov_outline, ImVec2(20, 0));
						}

						ImGui::PopFont();

						widgets.end_section();

						hovered = ImGui::IsItemHovered();
					}

					ImGui::PopStyleColor(1);
				}
				else if (strings.selected_tab == 1) {
					ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));

					{
						ImGui::SetCursorPos({ 10,20 });

						static std::unordered_map<ImGuiID, bool> hovered_map;
						ImGuiID hovered_id = ImGui::GetID(("3246234524"));
						bool& hovered = hovered_map[hovered_id];

						widgets.begin_section(("Visuals"), ImVec2(250, 250), false, hovered);

						ImGui::PushFont(strings.roboto_regular);
						{
							ImGui::Checkbox(("Enable Viauals"), &strings.visuals.enable, ImVec2(20, 0));

							ImGui::Spacing();	

							ImGui::Checkbox(("Skeleton"), &strings.visuals.skeleton, ImVec2(20, 0));
							ImGui::Checkbox(("Box"), &strings.visuals.box, ImVec2(20, 0));
							ImGui::Checkbox(("Radar"), &strings.visuals.radar, ImVec2(20, 0));
							ImGui::Checkbox(("UserName"), &strings.visuals.username, ImVec2(20, 0));
						}

						ImGui::PopFont();

						widgets.end_section();

						hovered = ImGui::IsItemHovered();
					}

					{
						ImGui::SetCursorPos({ 270,20 });

						static std::unordered_map<ImGuiID, bool> hovered_map;
						ImGuiID hovered_id = ImGui::GetID(("3463432472"));
						bool& hovered = hovered_map[hovered_id];

						widgets.begin_section(("Visuals Colors"), ImVec2(250, 250), false, hovered);

						ImGui::PushFont(strings.roboto_regular);
						{

						}

						ImGui::PopFont();

						widgets.end_section();

						hovered = ImGui::IsItemHovered();
					}

					ImGui::PopStyleColor(1);
				}
				else if (strings.selected_tab == 2) {
					ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
					
					{
						ImGui::SetCursorPos({ 10,20 });

						static std::unordered_map<ImGuiID, bool> hovered_map;
						ImGuiID hovered_id = ImGui::GetID(("3246234524"));
						bool& hovered = hovered_map[hovered_id];
						
						widgets.begin_section(("Aimbot Colors"), ImVec2(250, 250), false, hovered);

						ImGui::PushFont(strings.roboto_regular);

						{
							widgets.color_picker(("fov color"), strings.colors.aimbot.fov);
							widgets.color_picker(("fov filled color"), strings.colors.aimbot.fov_filled);
							widgets.color_picker(("fov outline color"), strings.colors.aimbot.fov_outline);
						}

						ImGui::PopFont();

						widgets.end_section();

						hovered = ImGui::IsItemHovered();
					}

					{
						ImGui::SetCursorPos({ 270,20 });

						static std::unordered_map<ImGuiID, bool> hovered_map;
						ImGuiID hovered_id = ImGui::GetID(("3463432472"));
						bool& hovered = hovered_map[hovered_id];

						widgets.begin_section(("Visuals Colors"), ImVec2(250, 250), false, hovered);

						ImGui::PushFont(strings.roboto_regular);

						{

						}

						ImGui::PopFont();

						widgets.end_section();

						hovered = ImGui::IsItemHovered();
					}

					
					ImGui::PopStyleColor(1);
				}
			}

			ImGui::EndChild();

			ImGui::PopStyleVar();
		
			ImGui::End();
			ImGui::PopFont();
		}
	}
}; handle_menu menu;