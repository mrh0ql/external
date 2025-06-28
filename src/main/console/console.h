#pragma once
#include "../include/includes.h"

class console_print
{
public:
    void clear() {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        COORD coord = { 0, 0 };
        DWORD written;
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        FillConsoleOutputCharacter(hConsole, ' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &written);
        SetConsoleCursorPosition(hConsole, coord);
    }

    void print_slow(const std::string& text, int delay = 30, bool endl = true, bool arrow = true, int arrow_color = 1) {
        if (arrow) {
            if (arrow_color == 1) printf((" \033[34m->\033[0m ")); // BLUE
            if (arrow_color == 2) printf((" \033[31m->\033[0m ")); // RED
            if (arrow_color == 3) printf((" \033[32m->\033[0m ")); // GREEN
            if (arrow_color == 4) printf((" \033[33m->\033[0m ")); // YELLOW
            if (arrow_color == 4) printf((" \033[35m->\033[0m ")); // MAGENTA
            if (arrow_color == 5) printf((" \033[36m->\033[0m ")); // CYAN
        }
        for (char c : text) {
            printf("%s", std::string(1, c).c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        }
        if (endl) { std::cout << std::endl; }
    }

}; console_print console;

