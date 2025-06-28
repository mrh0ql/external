#include "../include/includes.h"

namespace SonyDriverHelper {
    class api {
    public:
        static void Init();
        static void MouseMove(float x, float y);
        static bool GetKey(int id);
    };

}

class handle_mouse
{
public:
    auto move(Vector2 target_2d) -> void {
        float screen_center_x = (screen_width / 2);
        float screen_center_y = (screen_height / 2);
        auto aim_speed = strings.aimbot.smoothness;
        float target_x = 0;
        float target_y = 0;
        float x = target_2d.x;
        float y = target_2d.y;

        if (x != 0)
        {
            if (x > screen_center_x)
            {
                target_x = -(screen_center_x - x);
                target_x /= aim_speed;
                if (target_x + screen_center_x > screen_center_x * 2) target_x = 0;
            }

            if (x < screen_center_x)
            {
                target_x = x - screen_center_x;
                target_x /= aim_speed;
                if (target_x + screen_center_x < 0) target_x = 0;
            }
        }

        if (y != 0)
        {
            if (y > screen_center_y)
            {
                target_y = -(screen_center_y - y);
                target_y /= aim_speed;
                if (target_y + screen_center_y > screen_center_y * 2) target_y = 0;
            }

            if (y < screen_center_y)
            {
                target_y = y - screen_center_y;
                target_y /= aim_speed;
                if (target_y + screen_center_y < 0) target_y = 0;
            }
        }

        //SonyDriverHelper::api::MouseMove(target_x, target_y);
    }
}; handle_mouse mouse;