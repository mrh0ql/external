#pragma once
#include "../include/includes.h"

namespace offsets {
	inline uintptr_t
		u_world = 0x185565C8, // Engine.World
		viewport_client = 0x78, // Engine.LocalPlayer.ViewportClient
		game_instance = 0x248, // Engine.World.OwningGameInstance
		game_state = 0x1D0, // Engine.World.GameState
		local_player = 0x38, // Engine.GameInstance.LocalPlayers
		player_controller = 0x30, // Engine.Player.PlayerController
		acknowledged_pawn = 0x350, // Engine.PlayerController.AcknowledgedPawn
		player_array = 0x2C0, // Engine.GameStateBase.PlayerArray
		pawn_private = 0x320, // Engine.PlayerState.PawnPrivate
		mesh = 0x328, // Engine.Character.Mesh
		root_component = 0x1b0, // Engine.Actor.RootComponent
		velocity = 0x180, // Engine.MovementComponent.Velocity
		player_state = 0x2c8, // Engine.Controller.PlayerState
		team_index = 0x1261, // FortniteGame.FortPlayerStateAthena.TeamIndex
		current_weapon = 0xa80, // FortniteGame.FortPawn.CurrentWeapon
		weapon_data = 0x548, // FortniteGame.FortWeapon.WeaponData
		ammo_count = 0x109c, // ?
		item_name = 0x40, // ?
		component_to_world = 0x1E0, // NOT SDK / NOT FOUND
		player_name = 0xAF8, // NOT SDK / NOT FOUND
		platform = 0x430, // NOT SDK / NOT FOUND
		habanero_component = 0xa38, // NOT SDK / NOT FOUND
		rank_progress = 0xd0, // NOT SDK / NOT FOUND
		bounds = 0x100, // ?
		levels = 0x1a0,
		a_actors = 0x1a0,
		relative_location = 0x138,
		primary_pickup_item_entry = 0x360,
		rarity = 0xa2,
		b_already_searched = 0xe0a,
		active_transforms = 0x48,

		location_pointer = 0x178,
		rotation_pointer = 0x188,
		yaw = 0x20,
		roll = 0x1d0,
		fov = 0x4AC,

		projectile_speed = 0x1A24, // GA_Athena_Consumable_Throw_Parent.GA_Athena_Consumable_Throw_Parent_C.ProjectileSpeed
		projectile_gravity = 0x1DF0, // GA_Athena_Consumable_Throw_Parent.GA_Athena_Consumable_Throw_Parent_C.ProjectileGravityScale

		seconds = 0x198, // NOT SDK / NOT FOUND
		last_render_time = 0x30C, // NOT SDK / NOT FOUND

		targeted_fort_pawn = 0x1920, // FortniteGame.FortPlayerController.TargetedFortPawn

		bone_array = 0x5E8, // NOT SDK / NOT FOUND
		bone_cache = 0x5D8, // NOT SDK / NOT FOUND
		is_dbno = 0x962; // FortniteGame.FortPawn.bIsDBNO
}

class cache_pointers
{
public:
	DWORD_PTR
		u_world,
		game_instance,
		local_players,
		local_player,
		viewport_client,
		player_controller,
		local_pawn,
		root_component,
		mesh,
		player_state;

	uintptr_t
		game_state,
		player_array,
		current_weapon;

	int
		player_array_size,
		local_team_index;

	float
		projectile_speed,
		projectile_gravity,
		target_dist = FLT_MAX;

	std::vector<entity>
		entity_list,
		temporary_entity_list;

	entity
		cached_actors{},
		target_entity;
}; cache_pointers pointers;

enum player_bones : int {
	base = 0,
	pelvis = 2,
	l_thigh_1 = 71,
	l_thigh_2 = 77,
	l_thigh_3 = 72,
	l_calf = 74,
	l_foot_2 = 75,
	l_foot = 76,
	l_toe = 76,
	r_thigh_1 = 78,
	r_thigh_2 = 84,
	r_thigh_3 = 79,
	r_calf = 81,
	r_foot_2 = 82,
	r_foot = 82,
	r_toe = 83,
	spine_1 = 7,
	spine_2 = 5,
	spine_3 = 2,
	l_collarbone = 9,
	l_upperarm = 35,
	l_forearm_1 = 36,
	l_forearm_23 = 10,
	l_forearm_2 = 34,
	l_forearm_3 = 33,
	l_palm = 32,
	l_hand = 11,
	r_collarbone = 38,
	r_upperarm = 64,
	r_forearm_1 = 65,
	r_forearm_23 = 39,
	r_forearm_2 = 63,
	r_forearm_3 = 62,
	r_hand = 40,
	r_palm = 58,
	neck = 66,
	head = 110,
	lower_head = 106,
	chest = 65
};

inline D3DMATRIX MatrixMultiplication(D3DMATRIX pM1, D3DMATRIX pM2)
{
	D3DMATRIX pOut;
	pOut._11 = pM1._11 * pM2._11 + pM1._12 * pM2._21 + pM1._13 * pM2._31 + pM1._14 * pM2._41;
	pOut._12 = pM1._11 * pM2._12 + pM1._12 * pM2._22 + pM1._13 * pM2._32 + pM1._14 * pM2._42;
	pOut._13 = pM1._11 * pM2._13 + pM1._12 * pM2._23 + pM1._13 * pM2._33 + pM1._14 * pM2._43;
	pOut._14 = pM1._11 * pM2._14 + pM1._12 * pM2._24 + pM1._13 * pM2._34 + pM1._14 * pM2._44;
	pOut._21 = pM1._21 * pM2._11 + pM1._22 * pM2._21 + pM1._23 * pM2._31 + pM1._24 * pM2._41;
	pOut._22 = pM1._21 * pM2._12 + pM1._22 * pM2._22 + pM1._23 * pM2._32 + pM1._24 * pM2._42;
	pOut._23 = pM1._21 * pM2._13 + pM1._22 * pM2._23 + pM1._23 * pM2._33 + pM1._24 * pM2._43;
	pOut._24 = pM1._21 * pM2._14 + pM1._22 * pM2._24 + pM1._23 * pM2._34 + pM1._24 * pM2._44;
	pOut._31 = pM1._31 * pM2._11 + pM1._32 * pM2._21 + pM1._33 * pM2._31 + pM1._34 * pM2._41;
	pOut._32 = pM1._31 * pM2._12 + pM1._32 * pM2._22 + pM1._33 * pM2._32 + pM1._34 * pM2._42;
	pOut._33 = pM1._31 * pM2._13 + pM1._32 * pM2._23 + pM1._33 * pM2._33 + pM1._34 * pM2._43;
	pOut._34 = pM1._31 * pM2._14 + pM1._32 * pM2._24 + pM1._33 * pM2._34 + pM1._34 * pM2._44;
	pOut._41 = pM1._41 * pM2._11 + pM1._42 * pM2._21 + pM1._43 * pM2._31 + pM1._44 * pM2._41;
	pOut._42 = pM1._41 * pM2._12 + pM1._42 * pM2._22 + pM1._43 * pM2._32 + pM1._44 * pM2._42;
	pOut._43 = pM1._41 * pM2._13 + pM1._42 * pM2._23 + pM1._43 * pM2._33 + pM1._44 * pM2._43;
	pOut._44 = pM1._41 * pM2._14 + pM1._42 * pM2._24 + pM1._43 * pM2._34 + pM1._44 * pM2._44;

	return pOut;
}

inline D3DMATRIX Matrix(Vector3 rot, Vector3 origin = Vector3(0, 0, 0))
{
	float radPitch = (rot.x * float(PI) / 180.f);
	float radYaw = (rot.y * float(PI) / 180.f);
	float radRoll = (rot.z * float(PI) / 180.f);

	float SP = sinf(radPitch);
	float CP = cosf(radPitch);
	float SY = sinf(radYaw);
	float CY = cosf(radYaw);
	float SR = sinf(radRoll);
	float CR = cosf(radRoll);

	D3DMATRIX matrix;
	matrix.m[0][0] = CP * CY;
	matrix.m[0][1] = CP * SY;
	matrix.m[0][2] = SP;
	matrix.m[0][3] = 0.f;

	matrix.m[1][0] = SR * SP * CY - CR * SY;
	matrix.m[1][1] = SR * SP * SY + CR * CY;
	matrix.m[1][2] = -SR * CP;
	matrix.m[1][3] = 0.f;

	matrix.m[2][0] = -(CR * SP * CY + SR * SY);
	matrix.m[2][1] = CY * SR - CR * SP * SY;
	matrix.m[2][2] = CR * CP;
	matrix.m[2][3] = 0.f;

	matrix.m[3][0] = origin.x;
	matrix.m[3][1] = origin.y;
	matrix.m[3][2] = origin.z;
	matrix.m[3][3] = 1.f;

	return matrix;
}

//static auto update_camera() -> void
//{
//	for (;;) {
//		auto location_pointer = read<uintptr_t>(pointers.u_world + offsets::location_pointer);
//		auto rotation_pointer = read<uintptr_t>(pointers.u_world + offsets::rotation_pointer);
//
//		double pitch = read<double>(rotation_pointer);
//		double yaw = read<double>(rotation_pointer + offsets::yaw);
//		double roll = read<double>(rotation_pointer + offsets::roll);
//
//		camera.rotation.x = asin(roll) * (180.0 / PI);
//		camera.rotation.y = ((atan2(pitch * -1, yaw) * (180.0 / PI)) * -1) * -1;
//		camera.rotation.z = 0;
//		camera.location = read<Vector3>(location_pointer);
//		camera.fov = read<float>(pointers.local_player + offsets::fov);
//
//		std::this_thread::sleep_for(std::chrono::milliseconds(1));
//	}
//}

void get_camera_info() {
	while (true) {
		// camera_info camera;
		auto location_pointer = read<uintptr_t>(pointers.u_world + offsets::location_pointer);
		auto rotation_pointer = read<uintptr_t>(pointers.u_world + offsets::rotation_pointer);

		struct rotation_info_struct
		{
			double pitch;
			char pad_0008[24];
			double yaw;
			char pad_0028[424];
			double roll;
		} rotation_info;

		rotation_info.pitch = read<double>(rotation_pointer);
		rotation_info.yaw = read<double>(rotation_pointer + offsets::yaw);
		rotation_info.roll = read<double>(rotation_pointer + offsets::roll);

		camera.location = read<Vector3>(location_pointer);
		camera.rotation.x = asin(rotation_info.roll) * (180.0 / PI);
		camera.rotation.y = ((atan2(rotation_info.pitch * -1, rotation_info.yaw) * (180.0 / PI)) * -1) * -1;
		camera.fov = read<float>((uintptr_t)pointers.local_player + offsets::fov); //  * 90.f

		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}