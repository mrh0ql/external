#pragma once
#include "../include/includes.h"

class Vector2 {
public:
    Vector2() : x(0.0), y(0.0) {}

    Vector2(double _x, double _y) : x(_x), y(_y) {}

    ~Vector2() {}

    Vector2 operator+(const Vector2& other) const {
        return Vector2(x + other.x, y + other.y);
    }

    Vector2 operator-(const Vector2& other) const {
        return Vector2(x - other.x, y - other.y);
    }

    Vector2 operator*(double scalar) const {
        return Vector2(x * scalar, y * scalar);
    }

    double Length() const {
        return std::sqrt(x * x + y * y);
    }

    double x;
    double y;
};

class Vector3 {
public:
    Vector3() : x(0.f), y(0.f), z(0.f) {}

    Vector3(double _x, double _y, double _z) : x(_x), y(_y), z(_z) {}

    ~Vector3() {}

    double x;
    double y;
    double z;

    inline double Dot(Vector3 v) {
        return x * v.x + y * v.y + z * v.z;
    }

    inline bool isValid() const {
        return std::isfinite(x) && std::isfinite(y) && std::isfinite(z);
    }

    inline double Distance(Vector3 v) {
        return std::sqrt(std::pow(v.x - x, 2.0) + std::pow(v.y - y, 2.0) + std::pow(v.z - z, 2.0));
    }

    inline double Length() const {
        return std::sqrt(x * x + y * y + z * z);
    }

    Vector3 operator+(Vector3 v) const {
        return Vector3(x + v.x, y + v.y, z + v.z);
    }

    Vector3 operator-(Vector3 v) const {
        return Vector3(x - v.x, y - v.y, z - v.z);
    }

    Vector3& operator+=(const Vector3& v) {
        x += v.x;
        y += v.y;
        z += v.z;
        return *this;
    }

    Vector3& operator-=(const Vector3& v) {
        x -= v.x;
        y -= v.y;
        z -= v.z;
        return *this;
    }

    Vector3& operator*=(double flNum) {
        x *= flNum;
        y *= flNum;
        z *= flNum;
        return *this;
    }

    Vector3& operator=(const Vector3& other) {
        if (this != &other) {
            x = other.x;
            y = other.y;
            z = other.z;
        }
        return *this;
    }

    Vector3 operator/(double flNum) const {
        return Vector3(x / flNum, y / flNum, z / flNum);
    }

    Vector3 operator*(double flNum) const {
        return Vector3(x * flNum, y * flNum, z * flNum);
    }
};

struct FPlane : Vector3
{
    double W = 0;

    Vector3 ToVector3()
    {
        Vector3 value;
        value.x = this->x;
        value.y = this->y;
        value.z = this->y;

        return value;
    }
};

struct FQuat { double x, y, z, w; };

class FMatrix
{
public:
    double m[4][4];
    FPlane XPlane, YPlane, ZPlane, WPlane;

    FMatrix() : XPlane(), YPlane(), ZPlane(), WPlane() { }
    FMatrix(FPlane XPlane, FPlane YPlane, FPlane ZPlane, FPlane WPlane)
        : XPlane(XPlane), YPlane(YPlane), ZPlane(ZPlane), WPlane(WPlane) { }
};

struct FTransform
{
    FQuat   Rotation;
    Vector3 Translation;
    uint8_t Pad_1C[0x8];
    Vector3 Scale3D;
    uint8_t Pad_2C[0x8];

    FMatrix ToMatrixWithScale()
    {
        const Vector3 Scale
        (
            (Scale3D.x == 0.0) ? 1.0 : Scale3D.x,
            (Scale3D.y == 0.0) ? 1.0 : Scale3D.y,
            (Scale3D.z == 0.0) ? 1.0 : Scale3D.z
        );

        const double x2 = Rotation.x + Rotation.x;
        const double y2 = Rotation.y + Rotation.y;
        const double z2 = Rotation.z + Rotation.z;
        const double xx2 = Rotation.x * x2;
        const double yy2 = Rotation.y * y2;
        const double zz2 = Rotation.z * z2;
        const double yz2 = Rotation.y * z2;
        const double wx2 = Rotation.w * x2;
        const double xy2 = Rotation.x * y2;
        const double wz2 = Rotation.w * z2;
        const double xz2 = Rotation.x * z2;
        const double wy2 = Rotation.w * y2;

        FMatrix Matrix = FMatrix();

        Matrix.WPlane.x = Translation.x;
        Matrix.WPlane.y = Translation.y;
        Matrix.WPlane.z = Translation.z;

        Matrix.XPlane.x = (1.0 - (yy2 + zz2)) * Scale.x;
        Matrix.YPlane.y = (1.0 - (xx2 + zz2)) * Scale.y;
        Matrix.ZPlane.z = (1.0 - (xx2 + yy2)) * Scale.z;

        Matrix.ZPlane.y = (yz2 - wx2) * Scale.z;
        Matrix.YPlane.z = (yz2 + wx2) * Scale.y;

        Matrix.YPlane.x = (xy2 - wz2) * Scale.y;
        Matrix.XPlane.y = (xy2 + wz2) * Scale.x;

        Matrix.ZPlane.x = (xz2 + wy2) * Scale.z;
        Matrix.XPlane.z = (xz2 - wy2) * Scale.x;

        Matrix.XPlane.W = 0.0f;
        Matrix.YPlane.W = 0.0f;
        Matrix.ZPlane.W = 0.0f;
        Matrix.WPlane.W = 1.0f;

        return Matrix;
    }
};

template <typename T>
struct TArray {
    std::uintptr_t Array;
    std::uint32_t Count;
    std::uint32_t MaxCount;

    T Get(std::uint32_t Index) const {
        if (Index >= Count) {
            return T();
        }
        return tRead<T>(Array + (Index * sizeof(T)));
    }

    T operator[](std::uint32_t Index) const {
        return Get(Index);
    }

    std::uint32_t size() const {
        return Count;
    }

    bool isValid() const {
        return Array && Count <= MaxCount && MaxCount <= 1000000;
    }

    std::uintptr_t getAddress() const {
        return Array;
    }
};

//class player_camera
//{
//public:
//    Vector3
//        location,
//        rotation;
//    float fov;
//}; player_camera camera;

//struct player_bone {
//    Vector3 bone_3d;
//    Vector2 bone_2d;
//};
//
//class cached_players_bones {
//public:
//    player_bone
//        base,
//        pelvis,
//        l_thigh_1,
//        l_thigh_2,
//        l_thigh_3,
//        l_calf,
//        l_foot_2,
//        l_foot,
//        l_toe,
//        r_thigh_1,
//        r_thigh_2,
//        r_thigh_3,
//        r_calf,
//        r_foot_2,
//        r_foot,
//        r_toe,
//        spine_1,
//        spine_2,
//        spine_3,
//        l_collarbone,
//        l_upperarm,
//        l_forearm_1,
//        l_forearm_23,
//        l_forearm_2,
//        l_forearm_3,
//        l_palm,
//        l_hand,
//        r_collarbone,
//        r_upperarm,
//        r_forearm_1,
//        r_forearm_23,
//        r_forearm_2,
//        r_forearm_3,
//        r_palm,
//        r_hand,
//        neck,
//        head,
//        lower_head,
//        chest;
//};

struct CachedBones {
    Vector2 head;
    Vector2 neck;
    Vector2 chest;
    Vector2 right_shoulder;
    Vector2 left_shoulder;
    Vector2 right_elbow;
    Vector2 left_elbow;
    Vector2 right_hand;
    Vector2 left_hand;
    Vector2 pelvis;
    Vector2 right_hip;
    Vector2 left_hip;
    Vector2 right_knee;
    Vector2 left_knee;
    Vector2 right_foot;
    Vector2 left_foot;
};


struct box_t {
    Vector3 min, max, size;
};

class entity {
public:
    uintptr_t
        actor,
        mesh,
        root_component,
        player_state;
    std::string user_name;
    std::string platform;
    box_t bounds;
};


struct fbox_sphere_bounds final
{
public:
    Vector3 orgin;
    Vector3 box_extent;
    double sphere_radius;
};


struct camera_info {
    Vector3 location;
    Vector3 rotation;
    float fov;
};camera_info camera;

