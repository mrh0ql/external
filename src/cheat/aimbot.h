#pragma once
#include "../include/includes.h"

class handle_aimbot
{
public:
	void aimbot_loop() {
		if (strings.aimbot.enable && pointers.local_pawn && pointers.target_entity.actor) {
			if (get_async_key_state_spoofed(VK_SHIFT)) {
				auto head_3d = utils.get_bone_location(pointers.target_entity.mesh, player_bones::head);
				auto head_2D = utils.world_to_screen(head_3d);

				//mouse.move(head_2D);
			}
			else {
				pointers.target_entity.actor = NULL;
				pointers.target_entity.mesh = NULL;
				pointers.target_entity.root_component = NULL;
				pointers.target_entity.player_state = NULL;
				pointers.target_dist = FLT_MAX;
			}
		}
	}
}; handle_aimbot aimbot;
