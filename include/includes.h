#pragma once
#include <Windows.h>
#include <iostream>
#include <thread>
#include <vector>
#include <TlHelp32.h>
#include <d3d9.h>
#include <dwmapi.h>
#include <mutex>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <random>
#include <array>

#define CALL(funcPtr, ...) (*funcPtr)(__VA_ARGS__)

#define PI 3.14159265358979323846f

float screen_width;
float screen_height;

// local
#include <render/imgui/imgui.h>
#include <render/imgui/imgui_internal.h>
#include <render/imgui/imgui_impl_dx9.h>
#include <render/imgui/imgui_impl_win32.h>
#include <render/imgui/hashes.hpp>
#include <render/imgui/blur.hpp>
#include <render/menu/strings.h>

// protection

#include <main/protection/encryption/spoof.h>

// console
#include <main/console/console.h>

// kernel
#include <kernel/kernel.h>

// cheat utils
#include <cheat/hooks/hooks.h>
#include <cheat/sdk/structs.h>
#include <cheat/sdk/sdk.h>
#include <cheat/mouse/mouse.h>

// utils
#include <main/utils/utils.h>

// cheat
#include <cheat/aimbot.h>
#include <cheat/visuals.h>

// overlay
#include <render/menu/memory.h>
#include <render/menu/widgets.h>
#include <render/menu/font.h>
#include <render/imgui/bBlur.hpp>
#include <render/menu/menu.h>
#include <render/render.h>