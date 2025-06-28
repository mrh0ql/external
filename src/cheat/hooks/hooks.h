#include "../include/includes.h"

BOOL get_cursor_pos_a_spoofed(LPPOINT lp_point)
{
	overwrite_return_address;

	return CALL(&GetCursorPos, lp_point);
}

BOOL set_layered_window_attributes_spoofed(HWND hwnd, COLORREF cr_key, BYTE b_alpha, DWORD dw_flags)
{
	overwrite_return_address;

	return CALL(&SetLayeredWindowAttributes, hwnd, cr_key, b_alpha, dw_flags);
}

HRESULT __stdcall dwm_extend_frame_into_client_area_spoofed(HWND hwnd, const MARGINS* p_mar_inset)
{
	overwrite_return_address;

	return DwmExtendFrameIntoClientArea(hwnd, p_mar_inset);
}

LRESULT __stdcall def_window_proc_a_spoofed(HWND hwnd, UINT msg, WPARAM w_param, LPARAM l_param)
{
	overwrite_return_address;

	return CALL(&DefWindowProc, hwnd, msg, w_param, l_param);
}

HWND __stdcall create_window_ex_a_spoofed(DWORD dw_ex_style, LPCSTR lp_class_name, LPCSTR lp_window_name, DWORD dw_style, int x, int y, int n_width, int n_height, HWND hwnd_parent, HMENU h_menu, HINSTANCE h_instance, LPVOID lp_param)
{
	overwrite_return_address;

	return CALL(&CreateWindowExA, dw_ex_style, lp_class_name, lp_window_name, dw_style, x, y, n_width, n_height, hwnd_parent, h_menu, h_instance, lp_param);
}

LONG __stdcall set_window_long_a_spoofed(HWND hwnd, int n_index, LONG dw_new_long)
{
	overwrite_return_address;

	return CALL(&SetWindowLongA, hwnd, n_index, dw_new_long);
}

LONG __stdcall get_window_long_a_spoofed(HWND hwnd, int n_index)
{
	overwrite_return_address;

	return CALL(&GetWindowLongA, hwnd, n_index);
}

ATOM __stdcall register_class_ex_a_spoofed(const WNDCLASSEXA* softaim)
{
	overwrite_return_address;

	return CALL(&RegisterClassExA, softaim);
}

int __stdcall get_system_metrics_spoofed(int n_index)
{
	overwrite_return_address;

	return CALL(&GetSystemMetrics, n_index);
}

HWND __stdcall find_window_a_spoofed(LPCSTR lp_class_name, LPCSTR lp_window_name)
{
	overwrite_return_address;

	return CALL(&FindWindowA, lp_class_name, lp_window_name);
}

HWND __stdcall get_foreground_window_spoofed()
{
	overwrite_return_address;

	return CALL(&GetForegroundWindow);
}

SHORT get_async_key_state_spoofed(int v_key)
{
	overwrite_return_address;

	return CALL(&GetAsyncKeyState, v_key);
}

SHORT move_window_spoofed(HWND hwnd, int x, int y, int n_width, int n_height, bool b_repaint)
{
	overwrite_return_address;

	return CALL(&MoveWindow, hwnd, x, y, n_width, n_height, b_repaint);
}

BOOL __stdcall peek_message_a_spoofed(LPMSG lp_msg, HWND hwnd, UINT w_msg_filter_min, UINT w_msg_filter_max, UINT w_remove_msg)
{
	overwrite_return_address;

	return CALL(&PeekMessageA, lp_msg, hwnd, w_msg_filter_min, w_msg_filter_max, w_remove_msg);
}

BOOL __stdcall translate_message_spoofed(const MSG* lp_msg)
{
	overwrite_return_address;

	return CALL(&TranslateMessage, lp_msg);
}

LRESULT __stdcall dispatch_message_a_spoofed(const MSG* lp_msg)
{
	overwrite_return_address;

	return CALL(&DispatchMessageA, lp_msg);
}

HANDLE __stdcall create_thread_spoofed(LPSECURITY_ATTRIBUTES lp_thread_attributes, SIZE_T dw_stack_size, LPTHREAD_START_ROUTINE lp_start_address, LPVOID lp_parameter, DWORD dw_creation_flags, LPDWORD lp_thread_id)
{
	overwrite_return_address;

	return CALL(&CreateThread, lp_thread_attributes, dw_stack_size, lp_start_address, lp_parameter, dw_creation_flags, lp_thread_id);
}

BOOL __stdcall close_handle_spoofed(HANDLE h_object)
{
	overwrite_return_address;

	return CALL(&CloseHandle, h_object);
}

BOOL __stdcall set_window_pos_spoofed(HWND hwnd, HWND hwnd_insert_after, int x, int y, int cx, int cy, UINT u_flags)
{
	overwrite_return_address;

	return CALL(&SetWindowPos, hwnd, hwnd_insert_after, x, y, cx, cy, u_flags);
}

BOOL __stdcall show_window_spoofed(HWND hwnd, int n_cmd_show)
{
	overwrite_return_address;

	return CALL(&ShowWindow, hwnd, n_cmd_show);
}

BOOL __stdcall set_window_display_affinity_spoofed(HWND hwnd, DWORD dw_affinity)
{
	overwrite_return_address;

	return CALL(&SetWindowDisplayAffinity, hwnd, dw_affinity);
}

void __stdcall mouse_event_spoofed(DWORD dw_flags, DWORD dx, DWORD dy, DWORD dw_data, ULONG_PTR dw_extra_info)
{
	overwrite_return_address;

	return CALL(&mouse_event, dw_flags, dx, dy, dw_data, dw_extra_info);
}

BOOL __stdcall update_window_spoofed(HWND hwnd)
{
	overwrite_return_address;

	return CALL(&UpdateWindow, hwnd);
}

BOOL __stdcall get_client_rect_spoofed(HWND hwnd, LPRECT lp_rect)
{
	overwrite_return_address;

	return CALL(&GetClientRect, hwnd, lp_rect);
}

BOOL __stdcall client_to_screen_spoofed(HWND hwnd, LPPOINT lp_rect)
{
	overwrite_return_address;

	return CALL(&ClientToScreen, hwnd, lp_rect);
}
