#include "../include/includes.h"

//#define menu_debug

inline DWORD dwMode;
auto main() -> int {

#ifdef menu_debug
    screen_width = CALL(&get_system_metrics_spoofed, (SM_CXSCREEN));
    screen_height = CALL(&get_system_metrics_spoofed, (SM_CYSCREEN));
    //SonyDriverHelper::api::Init();

    std::thread([]() { menu.key_loop(); }).detach();

    render.start_directx();
    render.init();
#else

    CALL(&SetConsoleTitleA, ("Relapse-Private"));

    //if (utils.is_fortnite_open()) {
    //    console.clear();
    //    std::cout << std::endl;
    //    console.print_slow("Fortnite is open please close before opening loader...", 30, true, true, 2);
    //    Sleep(5000);
    //    __fastfail(0x4c);
    //}


    screen_width = CALL(&get_system_metrics_spoofed, SM_CXSCREEN);
    screen_height = CALL(&get_system_metrics_spoofed, SM_CYSCREEN);

    //SonyDriverHelper::api::Init();

    CALL(&MessageBoxA, nullptr, ("Click 'ok' in lobby..."), ("Waiting..."), MB_OK);
    Sleep(1000);

    if (!utils.is_fortnite_open()) {
        console.clear();
        std::cout << std::endl;
        console.print_slow(("Fortnite not open..."), 30, true, true, 2);
        Sleep(5000);
        __fastfail(0x4c);
    }
    kernel->Base();
    kernel->Init( );
    kernel->Attach(("FortniteClient-Win64-Shipping.exe"));
    kernel->Base();
    kernel->Cr3( );


    if (!strings.debug.enable) {
        CALL(&show_window_spoofed, CALL(&GetConsoleWindow), SW_HIDE);
    }

    std::thread([]() { visuals.actor_loop(); }).detach();
    std::thread([]() { get_camera_info(); }).detach();
    std::thread([]() { menu.key_loop(); }).detach();

    render.start_directx();
    render.init();

    return 0;
#endif
}