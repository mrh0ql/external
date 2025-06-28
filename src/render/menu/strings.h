#pragma once
#include "../include/includes.h"

class menu_strings
{
public:
	bool b_draw = true;
	bool b_init = false;
	int selected_tab = 1;
	bool b_animation = true;
	float anim = 0.f;

	float animation = 0.f;

	class colors_string
	{
	public:
		class aimbot_colors
		{
		public:
			ImVec4 fov = { 1.f, 1.f, 1.f, 1.f };
			ImVec4 fov_filled = { 0.f, 0.f, 0.f, 0.7 };
			ImVec4 fov_outline = { 1.f, 1.f, 1.f, 1.0 };


		}; aimbot_colors aimbot;

		class visuals_colors
		{
		public:

		}; visuals_colors visuals;


	}; colors_string colors;

	class styles_string
	{
	public:
		class styles_colors
		{
		public:
			float fov_thickness = 1.f;
			bool fov_outline = false;
			float fov_outline_thickness = fov_thickness + 1.f;

		}; styles_colors aimbot;

		class visuals_colors
		{
		public:

		}; styles_colors visuals;
	}; styles_string styles;

	class aimbot_strings
	{
	public:
		bool enable = true;
		bool show_fov = true;
		float fov = 150;
		int selected_fov;
		float smoothness = 1;
	}; aimbot_strings aimbot;

	class visuals_strings
	{
	public:
		bool enable = true;
		bool box = true;
		bool platform = true;
		bool radar = true;
		bool username = true;
		int boxtype = false;

		bool skeleton = false;
		int box_thickness = 1;

		ImColor yasss = ImColor(0, 255, 0, 255);

	}; visuals_strings visuals;

	class misc_strings
	{
	public:
		bool vsync = true;
	}; misc_strings misc;

	class debug_strings
	{
	public:
		bool enable = false;
	}; debug_strings debug;

	ImFont* roboto_bold;
	ImFont* roboto_regular;
	ImFont* roboto_regular_small;
	ImFont* proggy_clean;
	ImFont* icons_font;

	PDIRECT3DTEXTURE9 logo_icon_texture = nullptr;
}; menu_strings strings;