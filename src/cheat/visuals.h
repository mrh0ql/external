#pragma once
#include "../include/includes.h"

class handle_visuals
{
public:
	void actor_loop() {
		while (true) {
            pointers.temporary_entity_list.clear();

            pointers.u_world = read<DWORD_PTR>(kernel->ProcessBase + offsets::u_world);
            if (strings.debug.enable) { std::cout << ("uworld -> ") << pointers.u_world << std::endl; }

            pointers.game_instance = read<DWORD_PTR>(pointers.u_world + offsets::game_instance);
            if (strings.debug.enable) { std::cout << ("game_instance -> ") << pointers.game_instance << std::endl; }

            pointers.game_state = read<DWORD_PTR>(pointers.u_world + offsets::game_state);
            if (strings.debug.enable) { std::cout << ("game_state -> ") << pointers.game_state << std::endl; }

            pointers.local_players = read<DWORD_PTR>(pointers.game_instance + offsets::local_player);
            if (strings.debug.enable) { std::cout << ("local_players -> ") << pointers.local_players << std::endl; }

            pointers.local_player = read<DWORD_PTR>(pointers.local_players);
            if (strings.debug.enable) { std::cout << ("local_player -> ") << pointers.local_player << std::endl; }

            pointers.player_controller = read<DWORD_PTR>(pointers.local_player + offsets::player_controller);
            if (strings.debug.enable) { std::cout << ("player_controller -> ") << pointers.player_controller << std::endl; }

            pointers.local_pawn = read<DWORD_PTR>(pointers.player_controller + offsets::acknowledged_pawn);
            if (strings.debug.enable) { std::cout << ("local_pawn -> ") << pointers.local_pawn << std::endl; }

            pointers.root_component = read<DWORD_PTR>(pointers.local_pawn + offsets::root_component);
            if (strings.debug.enable) { std::cout << ("root_component -> ") << pointers.root_component << std::endl; }

            pointers.mesh = read<DWORD_PTR>(pointers.local_pawn + offsets::mesh);
            if (strings.debug.enable) { std::cout << ("mesh -> ") << pointers.mesh << std::endl; }

            pointers.player_state = read<DWORD_PTR>(pointers.local_pawn + offsets::player_state);
            if (strings.debug.enable) { std::cout << ("player_state -> ") << pointers.player_state << std::endl; }

            pointers.local_team_index = read<int>(pointers.player_state + offsets::team_index);
            if (strings.debug.enable) { std::cout << ("local_team_index -> ") << pointers.local_team_index << std::endl; }

            pointers.player_array = read<DWORD_PTR>(pointers.game_state + offsets::player_array);
            if (strings.debug.enable) { std::cout << ("player_array -> ") << pointers.player_array << std::endl; }

            pointers.player_array_size = read<int>(pointers.game_state + (offsets::player_array + sizeof(uintptr_t)));
            if (strings.debug.enable) { std::cout << ("player_array_size -> ") << pointers.player_array_size << std::endl; }

            if (pointers.player_array_size > 190) { pointers.player_array_size = 0; continue; }



            for (int i = 0; i < pointers.player_array_size; ++i) {
                auto player_state = read<uintptr_t>(pointers.player_array + (i * sizeof(uintptr_t)));
                auto current_actor = read<uintptr_t>(player_state + offsets::pawn_private);
                auto skeleton_mesh = read<uintptr_t>(current_actor + offsets::mesh);
                auto head_3d = utils.get_bone_location(skeleton_mesh, player_bones::head);
                auto actor_distance = camera.location.Distance(head_3d) / 100;

                if (current_actor == pointers.local_pawn) continue;
                if (!skeleton_mesh) continue;
                if (head_3d.x == 0 && head_3d.y == 0 && head_3d.z == 0) continue;
                if (actor_distance < 5000) {
                    pointers.cached_actors.actor = current_actor;
                    pointers.cached_actors.mesh = read<uintptr_t>(current_actor + offsets::mesh);
                    pointers.cached_actors.root_component = read<uintptr_t>(current_actor + offsets::root_component);
                    pointers.cached_actors.player_state = read<uintptr_t>(current_actor + offsets::player_state);
                    pointers.cached_actors.user_name = utils.GetPlayerName((uintptr_t)pointers.cached_actors.player_state);
                    pointers.cached_actors.platform = utils.GetPlatformName((uintptr_t)pointers.cached_actors.player_state);
                    pointers.cached_actors.bounds = utils.get_bounding((uintptr_t)pointers.cached_actors.mesh);

                    pointers.temporary_entity_list.push_back(pointers.cached_actors);
                }
            }
            pointers.entity_list.clear();
            pointers.entity_list = pointers.temporary_entity_list;

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
	}

    void draw_esp() {
        Vector3 head_3d;
        Vector3 foot_3d;
        Vector2 head_2d;
        Vector2 foot_2d;
        int rendered_players = 0; 

        if (strings.visuals.radar) {
            ImGui::SetNextWindowPos({ 10.0f, 60.0f });
            ImGui::SetNextWindowSize({ 250.0f, 250.0f });
            ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(64.0f / 255.0f, 64.0f / 255.0f, 64.0f / 255.0f, 242.0f / 255.0f));
            ImGui::Begin(("##radar"), nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoResize);

            ImVec2 winpos = ImGui::GetWindowPos();
            ImVec2 winsize = ImGui::GetWindowSize();
            ImGui::GetWindowDrawList()->AddLine(ImVec2(winpos.x + winsize.x * 0.5f, winpos.y),
                ImVec2(winpos.x + winsize.x * 0.5f, winpos.y + winsize.y), ImColor(0, 0, 0, 255), 1.0f);
            ImGui::GetWindowDrawList()->AddLine(ImVec2(winpos.x, winpos.y + winsize.y * 0.5f),
                ImVec2(winpos.x + winsize.x, winpos.y + winsize.y * 0.5f), ImColor(0, 0, 0, 255), 1.0f);
            ImGui::GetWindowDrawList()->AddCircleFilled(
                ImVec2(winpos.x + winsize.x * 0.5f, winpos.y + winsize.y * 0.5f),
                2.0f, ImColor(255, 255, 255, 255), 64);
        }

        for (auto& cached_entity : pointers.entity_list) {
            head_3d = utils.get_bone_location(cached_entity.mesh, player_bones::head);
            foot_3d = utils.get_bone_location(cached_entity.mesh, player_bones::r_foot);

            head_2d = utils.world_to_screen(head_3d);
            foot_2d = utils.world_to_screen(foot_3d);

            auto pelvis_2d = utils.world_to_screen(utils.get_bone_location(cached_entity.mesh, player_bones::pelvis));

            if (strings.visuals.radar) {
                int ScreenX, ScreenY = 0;
                utils.project_world_to_radar(foot_3d, ScreenX, ScreenY);
                ImGui::GetWindowDrawList()->AddCircleFilled(
                    ImVec2(static_cast<float>(ScreenX), static_cast<float>(ScreenY)),
                    2.0f, ImColor(255, 50, 50, 255), 64);

                if (!cached_entity.user_name.empty()) {
                    ImFont* font = ImGui::GetFont();
                    float fontSize = 10.0f;

                    ImGui::GetWindowDrawList()->AddText(
                        font,
                        fontSize,
                        ImVec2(static_cast<float>(ScreenX) + 4.0f,
                            static_cast<float>(ScreenY) - fontSize / 2),
                        ImColor(255, 255, 255, 255),
                        cached_entity.user_name.c_str()
                    );
                }
            }
            rendered_players++;

            if (utils.in_screen(pelvis_2d) && utils.in_screen(head_2d)) {
                int box_height = pelvis_2d.y - head_2d.y;
                int box_width = box_height / 2;
                int box_x = head_2d.x - (box_width / 2);
                int box_y = head_2d.y;

                if (strings.visuals.enable) {
                    if (strings.visuals.skeleton) {
                        utils.draw_skeleton(cached_entity.mesh, ImVec4(1.f, 1.f, 1.f, 1.f));
                    }
                }

                std::string nameText;
                float Txt = head_2d.y - 50;

                if (strings.visuals.username) {
                    nameText = cached_entity.user_name;
                    if (!nameText.empty()) {
                        float textWidth = ImGui::CalcTextSize(nameText.c_str()).x;
                        float xCentered = static_cast<float>(head_2d.x) - static_cast<float>(textWidth) / 2.0f;
                        ImGui::GetBackgroundDrawList()->AddText(ImVec2(xCentered, Txt), ImColor(255, 0, 0), nameText.c_str());
                        Txt += ImGui::GetFontSize() + 2;
                    }
                }
                std::string platformText;

                if (strings.visuals.platform) {
                    platformText = cached_entity.platform;

                    if (!platformText.empty()) {
                        float textWidth = ImGui::CalcTextSize(platformText.c_str()).x;
                        float xCentered = static_cast<float>(head_2d.x) - static_cast<float>(textWidth) / 2.0f;

                        ImGui::GetBackgroundDrawList()->AddText(ImVec2(xCentered, Txt), ImColor(255, 0, 0), platformText.c_str());
                        Txt += ImGui::GetFontSize() + 2;
                    }
                }

                if (strings.visuals.box) {
                    utils.bounding_box(cached_entity.bounds.max, cached_entity.bounds.size, ImColor(255, 0, 0), 1);
                }

                if (strings.aimbot.enable) {
                    auto dx = head_2d.x - (screen_width / 2);
                    auto dy = head_2d.y - (screen_height / 2);
                    auto dist = sqrtf(dx * dx + dy * dy);

                    if (dist < strings.aimbot.fov && dist < pointers.target_dist) {
                        if (dist < pointers.target_dist || (dist == pointers.target_dist)) {
                            pointers.target_dist = dist;
                            pointers.target_entity = cached_entity;
                        }
                    }
                }
            }
        }

        if (strings.visuals.radar) {
            ImGui::End();

            ImGui::SetNextWindowPos(ImVec2(10.0f, 320.0f));
            ImGui::SetNextWindowSize(ImVec2(250.0f, 30.0f));
            ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(64.0f / 255.0f, 64.0f / 255.0f, 64.0f / 255.0f, 242.0f / 255.0f));
            ImGui::Begin(("##players"), nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoResize);

            ImGui::Text("Players on radar: %d", rendered_players);

            ImGui::End();
            ImGui::PopStyleColor();
        }

        if (strings.aimbot.enable && strings.aimbot.show_fov) {
            if (strings.styles.aimbot.fov_outline) {
                ImGui::GetBackgroundDrawList()->AddCircle(
                    ImVec2(screen_width / 2, screen_height / 2),
                    strings.aimbot.fov,
                    ImGui::GetColorU32(strings.colors.aimbot.fov_outline),
                    100,
                    strings.styles.aimbot.fov_outline_thickness
                );
            }

            ImGui::GetBackgroundDrawList()->AddCircle(
                ImVec2(screen_width / 2, screen_height / 2),
                strings.aimbot.fov,
                ImGui::GetColorU32(strings.colors.aimbot.fov),
                100,
                strings.styles.aimbot.fov_thickness
            );

            if (strings.aimbot.selected_fov == 1) {
                ImGui::GetBackgroundDrawList()->AddCircleFilled(
                    ImVec2(screen_width / 2, screen_height / 2),
                    strings.aimbot.fov,
                    ImGui::GetColorU32(strings.colors.aimbot.fov_filled),
                    100
                );
            }
        }
    }
}; handle_visuals visuals;