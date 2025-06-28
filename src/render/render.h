#pragma once
#include "../include/includes.h"

IDirect3D9Ex* p_Object = NULL;
IDirect3DDevice9Ex* p_Device = NULL;
D3DPRESENT_PARAMETERS p_Params = { NULL };

HWND fn_hwnd = NULL;
HWND user_hwnd = NULL;
MSG Message = { NULL };

class overlay
{
public:
	void clean_directx() {
		if (p_Device != NULL) {

			p_Device->EndScene();

			p_Device->Release();

		}
		if (p_Object != NULL) {

			p_Object->Release();
		}
	}

	WPARAM init() {
		static RECT old_rc;
		ZeroMemory(&Message, sizeof(MSG));

		while (Message.message != WM_QUIT) {
			if (PeekMessage(&Message, user_hwnd, 0, 0, PM_REMOVE)) {
				translate_message_spoofed(&Message);
				DispatchMessage(&Message);
			}

			HWND hwnd_active = get_foreground_window_spoofed();

			set_window_pos_spoofed(user_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

			if (hwnd_active == fn_hwnd) {
				HWND hwndtest = GetWindow(hwnd_active, GW_HWNDPREV);
				set_window_pos_spoofed(user_hwnd, hwndtest, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			}

			if (!strings.b_draw) {
				set_window_long_a_spoofed(user_hwnd, GWL_EXSTYLE,WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED);
			}
			else {
				set_window_long_a_spoofed(user_hwnd, GWL_EXSTYLE, WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED);
			}

			RECT rc;
			POINT xy;
			ZeroMemory(&rc, sizeof(RECT));
			ZeroMemory(&xy, sizeof(POINT));
			get_client_rect_spoofed(fn_hwnd, &rc);
			client_to_screen_spoofed(fn_hwnd, &xy);
			rc.left = xy.x;
			rc.top = xy.y;

			ImGuiIO& io = ImGui::GetIO();
			io.ImeWindowHandle = fn_hwnd;
			io.DeltaTime = 1.0f / 60.0f;

			POINT p;
			GetCursorPos(&p);

			io.MousePos.x = static_cast<float>(p.x - xy.x);
			io.MousePos.y = static_cast<float>(p.y - xy.y);

			if (get_async_key_state_spoofed(VK_LBUTTON) & 0x8000) {
				io.MouseDown[0] = true;
				io.MouseClicked[0] = true;
				io.MouseClickedPos[0].x = io.MousePos.x;
				io.MouseClickedPos[0].y = io.MousePos.y;
			}
			else {
				io.MouseDown[0] = false;
			}

			if (rc.left != old_rc.left || rc.right != old_rc.right || rc.top != old_rc.top || rc.bottom != old_rc.bottom) {
				old_rc = rc;
				screen_width = rc.right - rc.left;
				screen_height = rc.bottom - rc.top;

				p_Params.BackBufferWidth = screen_width;
				p_Params.BackBufferHeight = screen_height;

				set_window_pos_spoofed(user_hwnd, HWND_TOP, xy.x, xy.y, screen_width, screen_height, SWP_NOREDRAW);
				p_Device->Reset(&p_Params);
			}

			static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
			ImFontConfig icons_config;
			icons_config.MergeMode = true;
			icons_config.PixelSnapH = true;

			bBlur->device = p_Device;

			if (!strings.b_init) { ImGui::GetStyle().Alpha = 0; }

			ImGui_ImplDX9_NewFrame();
			ImGui_ImplWin32_NewFrame();
			ImGui::NewFrame();

			if (!strings.b_init) {
				std::thread([]() { menu.fade_in(); }).detach();
				menu.style();
				D3DXCreateTextureFromFileInMemory(p_Device, logo_icon, sizeof(logo_icon), &strings.logo_icon_texture);
			}

			menu.loop();
			menu.draw();
			
			ImGui::EndFrame();

			p_Device->SetRenderState(D3DRS_ZENABLE, false);
			p_Device->SetRenderState(D3DRS_ALPHABLENDENABLE, true);
			p_Device->SetRenderState(D3DRS_SCISSORTESTENABLE, false);
			p_Device->Clear(0, NULL, D3DCLEAR_TARGET, D3DCOLOR_ARGB(0, 0, 0, 0), 1.0f, 0);

			if (p_Device->BeginScene() >= 0) {
				ImGui::Render();
				ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
				p_Device->EndScene();
			}

			HRESULT result = p_Device->Present(NULL, NULL, NULL, NULL);

			if (result == D3DERR_DEVICELOST && p_Device->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
				ImGui_ImplDX9_InvalidateDeviceObjects();
				p_Device->Reset(&p_Params);
				ImGui_ImplDX9_CreateDeviceObjects();
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}

		ImGui_ImplDX9_Shutdown();
		ImGui_ImplWin32_Shutdown();
		ImGui::DestroyContext();
		clean_directx();
		DestroyWindow(user_hwnd);

		return Message.wParam;
	}

	HRESULT start_directx() {
		WNDCLASSEXA wcex = {
			sizeof(WNDCLASSEXA), 0, def_window_proc_a_spoofed, 0, 0, nullptr,
			LoadIcon(nullptr, IDI_APPLICATION) , LoadCursor(nullptr, IDC_ARROW) ,
			nullptr, nullptr, ("Relapse"), LoadIcon(nullptr , IDI_APPLICATION)
		};

		RECT Rect;
		GetWindowRect(GetDesktopWindow(), &Rect);

		if (!register_class_ex_a_spoofed(&wcex)) {
			return E_FAIL;
		}

		user_hwnd = create_window_ex_a_spoofed(
			NULL, ("Relapse"), ("RelapseOverlay"), WS_POPUP,
			0, 0, screen_width, screen_height, NULL, NULL, wcex.hInstance, NULL
		);

		if (!user_hwnd) {

			return E_FAIL;
		}

		set_window_long_a_spoofed(user_hwnd, GWL_EXSTYLE,
			WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_LAYERED
		);

		MARGINS margin = { -1 };
		dwm_extend_frame_into_client_area_spoofed(user_hwnd, &margin);
		show_window_spoofed(user_hwnd, SW_SHOW);

		set_layered_window_attributes_spoofed(user_hwnd, RGB(0, 0, 0), 255, LWA_ALPHA);
		update_window_spoofed(user_hwnd);

		if (FAILED(Direct3DCreate9Ex(D3D_SDK_VERSION, &p_Object))) {

			return E_FAIL;
		}

		ZeroMemory(&p_Params, sizeof(p_Params));
		p_Params.Windowed = TRUE;
		p_Params.SwapEffect = D3DSWAPEFFECT_DISCARD;
		p_Params.hDeviceWindow = user_hwnd;
		p_Params.MultiSampleQuality = D3DMULTISAMPLE_NONE;
		p_Params.BackBufferFormat = D3DFMT_A8R8G8B8;
		p_Params.BackBufferWidth = screen_width;
		p_Params.BackBufferHeight = screen_height;
		p_Params.EnableAutoDepthStencil = TRUE;
		p_Params.AutoDepthStencilFormat = D3DFMT_D16;
		p_Params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

		if (FAILED(p_Object->CreateDeviceEx(
			D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, user_hwnd,
			D3DCREATE_HARDWARE_VERTEXPROCESSING, &p_Params, 0, &p_Device
		))) {
			p_Object->Release();
			return E_FAIL;
		}

		IMGUI_CHECKVERSION();
		ImGui::CreateContext();

		if (!ImGui_ImplWin32_Init(user_hwnd) || !ImGui_ImplDX9_Init(p_Device)) {

			p_Object->Release();

			return E_FAIL;
		}

		ImGui::GetStyle();
		ImGuiIO& io = ImGui::GetIO();

		static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
		ImFontConfig icons_config;
		icons_config.MergeMode = true;
		icons_config.PixelSnapH = true;

		strings.roboto_bold = io.Fonts->AddFontFromMemoryTTF(font_memory, sizeof(font_memory), 17.0f);
		strings.roboto_regular = io.Fonts->AddFontFromMemoryTTF(roboto_regular_memory, sizeof(roboto_regular_memory), 15.0f);
		strings.roboto_regular_small = io.Fonts->AddFontFromMemoryTTF(roboto_regular_memory, sizeof(roboto_regular_memory), 13.0f);
		strings.proggy_clean = io.Fonts->AddFontFromMemoryTTF(default_font_memory, sizeof(default_font_memory), 17.0f);
		strings.icons_font = io.Fonts->AddFontFromMemoryTTF(&font_awesome_memory, sizeof font_awesome_memory, 13, &icons_config, icon_ranges);

		p_Object->Release();
		return S_OK;
	}
}; overlay render;