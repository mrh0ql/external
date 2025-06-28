#pragma once
#include "../include/includes.h"


constexpr float M_PI_F = 3.14159265358979323846f;

class utilities
{
public:
	bool is_fortnite_open() {
		

		HANDLE window = FindWindowA(("UnrealWindow"), ("Fortnite  "));
		if (!window) return false;
		return true;
		
		
	}

	bool windows_23h2_or_lower() {
		

		typedef LONG(WINAPI* RtlGetVersionFunc)(OSVERSIONINFOEXW*);

		HMODULE hNtDll = GetModuleHandleW((L"ntdll.dll"));
		if (!hNtDll) return false;

		auto RtlGetVersion = reinterpret_cast<RtlGetVersionFunc>(
			GetProcAddress(hNtDll, ("RtlGetVersion")));
		if (!RtlGetVersion) return false;

		OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
		RtlGetVersion(&osInfo);

		if (osInfo.dwMajorVersion < (10)) return true;

		if (osInfo.dwMinorVersion > (0)) return false;

		if (osInfo.dwBuildNumber >= (25915)) return false;

		return true;

		
	}

	bool bytes_to_file(const std::wstring& path, LPCVOID bytes, DWORD size) {
		

		HANDLE h_file;
		BOOL b_status = FALSE;
		DWORD bytes_written = 0;

		h_file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (h_file == INVALID_HANDLE_VALUE) {
			return false;
		}

		b_status = WriteFile(h_file, bytes, size, &bytes_written, NULL);
		if (!b_status || bytes_written != size) {
			CloseHandle(h_file);
			return false;
		}

		CloseHandle(h_file);
		return true;
		
		
	}

	D3DMATRIX fmatrix_to_d3dmatrix(const FMatrix& matrix) {
		D3DMATRIX d3dMatrix = {};

		d3dMatrix._11 = matrix.XPlane.x; d3dMatrix._12 = matrix.XPlane.y; d3dMatrix._13 = matrix.XPlane.z; d3dMatrix._14 = matrix.XPlane.W;
		d3dMatrix._21 = matrix.YPlane.x; d3dMatrix._22 = matrix.YPlane.y; d3dMatrix._23 = matrix.YPlane.z; d3dMatrix._24 = matrix.YPlane.W;
		d3dMatrix._31 = matrix.ZPlane.x; d3dMatrix._32 = matrix.ZPlane.y; d3dMatrix._33 = matrix.ZPlane.z; d3dMatrix._34 = matrix.ZPlane.W;
		d3dMatrix._41 = matrix.WPlane.x; d3dMatrix._42 = matrix.WPlane.y; d3dMatrix._43 = matrix.WPlane.z; d3dMatrix._44 = matrix.WPlane.W;

		return d3dMatrix;
	}

	Vector3 get_bone_location(uintptr_t mesh, int index) {
		int32_t active_transforms = (read<int32_t>((uintptr_t)mesh + (offsets::bone_array + offsets::active_transforms)) * std::size_t(0x10));

		auto bone_array = read<TArray<FTransform>>((uintptr_t)mesh + offsets::bone_array + active_transforms);
		auto bone_transform = read<FTransform>(bone_array.Array + (index * 0x60));
		FTransform component_to_world = read<FTransform>((uintptr_t)mesh + offsets::component_to_world);
		
		D3DMATRIX matrix = MatrixMultiplication(fmatrix_to_d3dmatrix(bone_transform.ToMatrixWithScale()), fmatrix_to_d3dmatrix(component_to_world.ToMatrixWithScale()));
		return Vector3(matrix._41, matrix._42, matrix._43);
	}

	//Vector3 get_bone_location(uintptr_t mesh, int bone_id)
	//{
	//	uintptr_t bone_array = read<uintptr_t>(mesh + offsets::bone_array);
	//	if (bone_array == NULL)
	//	{
	//		bone_array = read<uintptr_t>(mesh + 0x5b8); // cache
	//	}

	//	FTransform bone = read<FTransform>(bone_array + (bone_id * 0x60));
	//	if (bone_id == NULL)
	//	{
	//		bone_array = read<uintptr_t>(mesh + 0x5b8); // cache
	//	}
	//	FTransform component_to_world = read<FTransform>(mesh + offsets::component_to_world);
	//	D3DMATRIX matrix = MatrixMultiplication(bone.ToMatrixWithScale(), component_to_world.ToMatrixWithScale());

	//	return Vector3(matrix._41, matrix._42, matrix._43);
	//}

	std::string GetPlayerName(uintptr_t playerState) {
		__int64 FString = read<__int64>(playerState + offsets::player_name);

		int length = static_cast<int>(read<__int64>(FString + 16));
		if (length == 0) return std::string(" AI ");

		uintptr_t FText = read<__int64>(FString + 8);

		wchar_t* nameBuffer = new wchar_t[length];

		kernel->ReadPhysical(reinterpret_cast<void*>(FText), nameBuffer, static_cast<size_t>(length) * sizeof(wchar_t));

		char v21 = static_cast<char>(length - 1);
		if (length == 0) {
			v21 = 0;
		}

		int v22 = 0;
		WORD* v23 = reinterpret_cast<WORD*>(nameBuffer);
		for (int i = (v21 & 3); ; *v23++ += i & 7) {
			int v25 = length - 1;
			if (length == 0) {
				v25 = 0;
			}
			if (v22 >= v25) {
				break;
			}
			i += 3;
			++v22;
		}

		std::wstring wbuffer{ nameBuffer };

		delete[] nameBuffer;

		return std::string(wbuffer.begin(), wbuffer.end());
	}

	Vector2 world_to_screen(Vector3 world_location) {
		D3DMATRIX tempMatrix = Matrix(camera.rotation);
		Vector3 vAxisX = Vector3(tempMatrix.m[0][0], tempMatrix.m[0][1], tempMatrix.m[0][2]);
		Vector3 vAxisY = Vector3(tempMatrix.m[1][0], tempMatrix.m[1][1], tempMatrix.m[1][2]);
		Vector3 vAxisZ = Vector3(tempMatrix.m[2][0], tempMatrix.m[2][1], tempMatrix.m[2][2]);

		Vector3 vDelta = world_location - camera.location;
		Vector3 vTransformed = Vector3(vDelta.Dot(vAxisY), vDelta.Dot(vAxisZ), vDelta.Dot(vAxisX));

		if (vTransformed.z < 1.f)
			vTransformed.z = 1.f;

		return Vector2((screen_width / 2.0f) + vTransformed.x * (((screen_width / 2.0f) / tanf(camera.fov * (float)PI / 360.f))) / vTransformed.z, (screen_height / 2.0f) - vTransformed.y * (((screen_width / 2.0f) / tanf(camera.fov * (float)PI / 360.f))) / vTransformed.z);
	}


	bool in_screen(Vector2 screen_position) {
		if (screen_position.x > 0 && screen_position.x < screen_width && screen_position.y > 0 && screen_position.y < screen_height) { return true; }
		else { return false; }
	}

	ImVec4 rgb_to_imvec4(int r, int g, int b, float a = 1.0f) {
		return ImVec4(r / 255.0f, g / 255.0f, b / 255.0f, a);
	}

	void draw_line(Vector2 start, Vector2 end, ImU32 color, float thickness, ImU32 shadowColor, float shadowOffset) {
		ImDrawList* drawList = ImGui::GetBackgroundDrawList();

		drawList->AddLine(
			ImVec2(static_cast<float>(start.x + shadowOffset), static_cast<float>(start.y + shadowOffset)),
			ImVec2(static_cast<float>(end.x + shadowOffset), static_cast<float>(end.y + shadowOffset)),
			shadowColor, thickness
		);

		drawList->AddLine(
			ImVec2(static_cast<float>(start.x), static_cast<float>(start.y)),
			ImVec2(static_cast<float>(end.x), static_cast<float>(end.y)),
			color, thickness
		);
	}

	void draw_box(int X, int Y, int W, int H, const ImColor color, int thickness) {
		ImU32 shadowColor = ImColor(0, 0, 0, 255);
		float shadowOffset = 1.0f;

		float fThickness = static_cast<float>(thickness);

		draw_line(Vector2{ static_cast<float>(X), static_cast<float>(Y) },
			Vector2{ static_cast<float>(X + W), static_cast<float>(Y) },
			color, fThickness, shadowColor, shadowOffset);

		draw_line(Vector2{ static_cast<float>(X + W), static_cast<float>(Y) },
			Vector2{ static_cast<float>(X + W), static_cast<float>(Y + H) },
			color, fThickness, shadowColor, shadowOffset);

		draw_line(Vector2{ static_cast<float>(X), static_cast<float>(Y + H) },
			Vector2{ static_cast<float>(X + W), static_cast<float>(Y + H) },
			color, fThickness, shadowColor, shadowOffset);

		draw_line(Vector2{ static_cast<float>(X), static_cast<float>(Y) },
			Vector2{ static_cast<float>(X), static_cast<float>(Y + H) },
			color, fThickness, shadowColor, shadowOffset);
	}

	std::string GetPlatformName(uintptr_t playerState) {
		uintptr_t platformAddr = read<uintptr_t>(playerState + offsets::platform);
		wchar_t platformBuffer[64];
		kernel->ReadPhysical((void*)platformAddr, platformBuffer, sizeof(platformBuffer));

		std::string platformStr(platformBuffer, platformBuffer + wcslen(platformBuffer));
		if (platformStr == std::string(("XBL"))) return std::string((" Xbox "));
		if (platformStr == std::string(("PSN"))) return std::string((" PlayStation 4 "));
		if (platformStr == std::string(("PS5"))) return std::string((" PlayStation 5 "));
		if (platformStr == std::string(("XSX"))) return std::string((" Xbox "));
		if (platformStr == std::string(("SWT"))) return std::string((" Nintendo "));
		if (platformStr == std::string(("WIN"))) return std::string((" Windows "));
		if (platformStr == std::string(("IOS"))) return std::string((" IPhone  "));
		if (platformStr == std::string(("LNX"))) return std::string((" Linux  "));
		if (platformStr == std::string(("MAC"))) return std::string((" Macbook  "));
		if (platformStr == std::string(("AND"))) return std::string((" Android  "));

		return std::string((" B O T "));
	}

	void draw_skeleton(uintptr_t mesh, ImVec4 color) {
		struct bone_connection {
			int start;
			int end;
		};

		bone_connection connections[] = {
			{player_bones::neck, player_bones::r_collarbone},
			{player_bones::neck, player_bones::l_collarbone},
			{player_bones::l_collarbone, player_bones::l_forearm_23},
			{player_bones::l_forearm_23, player_bones::l_hand},
			{player_bones::r_collarbone, player_bones::r_forearm_23},
			{player_bones::r_forearm_23, player_bones::r_hand},
			{player_bones::neck, player_bones::pelvis},
			{player_bones::pelvis, player_bones::l_thigh_1},
			{player_bones::l_thigh_1, player_bones::l_thigh_3},
			{player_bones::l_thigh_3, player_bones::l_foot_2},
			{player_bones::pelvis, player_bones::r_thigh_1},
			{player_bones::r_thigh_1, player_bones::r_thigh_3},
			{player_bones::r_thigh_3, player_bones::r_foot_2},
		};

		for (const auto& connection : connections) {
			Vector2 start = world_to_screen(get_bone_location(mesh, connection.start));
			Vector2 end = world_to_screen(get_bone_location(mesh, connection.end));

			ImGui::GetBackgroundDrawList()->AddLine(
				ImVec2(start.x, start.y),
				ImVec2(end.x, end.y),
				ImGui::GetColorU32(color),
				2.f
			);
		}
	}


	void radar_range(float* x, float* y, float range)
	{
		if (fabs((*x)) > range || fabs((*y)) > range)
		{
			if ((*y) > (*x))
			{
				if ((*y) > -(*x))
				{
					(*x) = range * (*x) / (*y);
					(*y) = range;
				}
				else
				{
					(*y) = -range * (*y) / (*x);
					(*x) = -range;
				}
			}
			else
			{
				if ((*y) > -(*x))
				{
					(*y) = range * (*y) / (*x);
					(*x) = range;
				}
				else
				{
					(*x) = -range * (*x) / (*y);
					(*y) = -range;
				}
			}
		}
	}

	box_t get_bounding(uintptr_t mesh) {
		box_t box;
		auto bounds = read<fbox_sphere_bounds>(mesh + offsets::bounds);

		if (!bounds.box_extent.x && !bounds.box_extent.y && !bounds.box_extent.z) {
			bounds = read<fbox_sphere_bounds>(mesh + offsets::bounds);
		}

		bounds.box_extent *= 2.0f;
		bounds.orgin -= bounds.box_extent / 2.f;

		std::array<Vector3, 8> points = {
			Vector3(bounds.orgin.x, bounds.orgin.y, bounds.orgin.z),
			Vector3(bounds.orgin.x, bounds.orgin.y, bounds.orgin.z + bounds.box_extent.z),
			Vector3(bounds.orgin.x + bounds.box_extent.x, bounds.orgin.y, bounds.orgin.z + bounds.box_extent.z),
			Vector3(bounds.orgin.x + bounds.box_extent.x, bounds.orgin.y, bounds.orgin.z),
			Vector3(bounds.orgin.x + bounds.box_extent.x, bounds.orgin.y + bounds.box_extent.y, bounds.orgin.z),
			Vector3(bounds.orgin.x, bounds.orgin.y + bounds.box_extent.y, bounds.orgin.z),
			Vector3(bounds.orgin.x, bounds.orgin.y + bounds.box_extent.y, bounds.orgin.z + bounds.box_extent.z),
			Vector3(bounds.orgin.x + bounds.box_extent.x, bounds.orgin.y + bounds.box_extent.y, bounds.orgin.z + bounds.box_extent.z)
		};

		box.min = { DBL_MAX, DBL_MAX, DBL_MAX };
		box.max = { -DBL_MAX, -DBL_MAX, -DBL_MAX };

		std::array<Vector2, 8> screen{};

		auto custom_min = [](double a, double b) { return a < b ? a : b; };
		auto custom_max = [](double a, double b) { return a > b ? a : b; };

		for (auto i = 0; i < points.size(); i++) {
			screen.at(i) = world_to_screen(points.at(i));
			box.min.x = custom_min(box.min.x, screen.at(i).x);
			box.min.y = custom_min(box.min.y, screen.at(i).y);
			box.max.x = custom_max(box.max.x, screen.at(i).x);
			box.max.y = custom_max(box.max.y, screen.at(i).y);
		}

		box.size = box.min - box.max;
		return box;
	}

	void project_world_to_radar(Vector3 vOrigin, int& screenx, int& screeny)
	{
		Vector3 vAngle = camera.rotation;

		float fYaw = static_cast<float>(vAngle.y) * M_PI_F / 180.0f;

		float dx = static_cast<float>(vOrigin.x - camera.location.x);
		float dy = static_cast<float>(vOrigin.y - camera.location.y);

		float fsin_yaw = sinf(fYaw);
		float fminus_cos_yaw = -cosf(fYaw);

		float x = dy * fminus_cos_yaw + dx * fsin_yaw;
		x = -x;
		float y = dx * fminus_cos_yaw - dy * fsin_yaw;

		float range = (250.0f / 5.0f) * 1000.0f;

		radar_range(&x, &y, range);

		ImVec2 DrawPos = ImVec2(10.0f, 60.0f);
		ImVec2 DrawSize = ImVec2(250.0f, 250.0f);
		float radarRadius = 250.0f / 2.0f;

		float distance = sqrtf(powf(screenx - DrawPos.x, 2.0f) + powf(screeny - DrawPos.y, 2.0f));

		if (distance > radarRadius)
		{
			float angle = atan2f(screeny - DrawPos.y, screenx - DrawPos.x);
			screenx = static_cast<int>(DrawPos.x + radarRadius * cosf(angle));
			screeny = static_cast<int>(DrawPos.y + radarRadius * sinf(angle));
		}

		int rad_x = static_cast<int>(DrawPos.x);
		int rad_y = static_cast<int>(DrawPos.y);
		float r_siz_x = DrawSize.x;
		float r_siz_y = DrawSize.y;
		int x_max = static_cast<int>(r_siz_x + rad_x - 5);
		int y_max = static_cast<int>(r_siz_y + rad_y - 5);

		screenx = rad_x + (static_cast<int>(r_siz_x / 2.0f) + static_cast<int>(x / range * r_siz_x));
		screeny = rad_y + (static_cast<int>(r_siz_y / 2.0f) + static_cast<int>(y / range * r_siz_y));

		if (screenx > x_max) screenx = x_max;
		if (screenx < rad_x) screenx = rad_x;
		if (screeny > y_max) screeny = y_max;
		if (screeny < rad_y) screeny = rad_y;
	}

	void bounding_box(const Vector3& position, const Vector3& size, ImColor color, float thickness) {
		ImDrawList* drawList = ImGui::GetBackgroundDrawList();

		drawList->AddRect(ImVec2(static_cast<float>(position.x), static_cast<float>(position.y)),
			ImVec2(static_cast<float>(size.x + position.x), static_cast<float>(size.y + position.y)),
			color, 0.0f, 0, static_cast<float>(thickness + 0.1f));
	}

	std::unordered_set<std::string> used_ids;

	std::string generate_id(int length) {
		const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+:<>?{}[]|\\~`"; // characters to choose from
		std::random_device rd;
		std::mt19937 gen(rd());
		std::uniform_int_distribution<> dis(0, chars.size() - 1);

		std::string result;
		do {
			result.clear();
			result.reserve(length);
			for (int i = 0; i < length; ++i) {
				result += chars[dis(gen)];
			}
		} while (used_ids.find(result) != used_ids.end()); // Ensure ID is unique

		used_ids.insert(result); // Mark this ID as used
		return result;
	}

}; utilities utils;