#include "Config.h"

#include <Windows.h>

namespace {
std::string readStringValue(const std::string& path, const char* section, const char* key, const char* fallback) {
    char buffer[MAX_PATH] = {};
    GetPrivateProfileStringA(section, key, fallback, buffer, static_cast<DWORD>(sizeof(buffer)), path.c_str());
    return buffer;
}
}

Config Config::load(const std::string& gameDirectory) {
    const std::string iniPath = gameDirectory + "\\wkWall2Wall.ini";

    Config config;
    config.enabled = GetPrivateProfileIntA("General", "EnableModule", 1, iniPath.c_str()) != 0;
    config.ignoreVersionCheck = GetPrivateProfileIntA("General", "IgnoreVersionCheck", 0, iniPath.c_str()) != 0;
    config.enableOfflineMode = GetPrivateProfileIntA("General", "EnableOfflineMode", 1, iniPath.c_str()) != 0;
    config.enableOnlineSync = GetPrivateProfileIntA("General", "EnableOnlineSync", 1, iniPath.c_str()) != 0;
    config.requireAllPlayersOnline = GetPrivateProfileIntA("General", "RequireAllPlayersOnline", 1, iniPath.c_str()) != 0;
    config.enableVisualOverlay = GetPrivateProfileIntA("General", "EnableVisualOverlay", 1, iniPath.c_str()) != 0;
    config.enableHooks = GetPrivateProfileIntA("Hooks", "EnableHooks", 1, iniPath.c_str()) != 0;
    config.hookProbeOnly = GetPrivateProfileIntA("Hooks", "ProbeOnly", 1, iniPath.c_str()) != 0;
    config.enableMessagePumpProbe = GetPrivateProfileIntA("Hooks", "EnableMessagePumpProbe", 0, iniPath.c_str()) != 0;
    config.enableRenderProbe = GetPrivateProfileIntA("Hooks", "EnableRenderProbe", 0, iniPath.c_str()) != 0;
    config.enableRendererModuleProbe = GetPrivateProfileIntA("Hooks", "EnableRendererModuleProbe", 0, iniPath.c_str()) != 0;
    config.enableRendererApiProbe = GetPrivateProfileIntA("Hooks", "EnableRendererApiProbe", 0, iniPath.c_str()) != 0;
    config.enableCameraProbe = GetPrivateProfileIntA("Hooks", "EnableCameraProbe", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9Probe = GetPrivateProfileIntA("Hooks", "EnableDirect3D9Probe", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9DeviceSlotProbe = GetPrivateProfileIntA("Hooks", "EnableDirect3D9DeviceSlotProbe", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9OverlaySmokeTest = GetPrivateProfileIntA("Hooks", "EnableDirect3D9OverlaySmokeTest", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9MetadataOverlayTest = GetPrivateProfileIntA("Hooks", "EnableDirect3D9MetadataOverlayTest", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9TrackingTargetOverlayTest = GetPrivateProfileIntA("Hooks", "EnableDirect3D9TrackingTargetOverlayTest", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9MetadataOverlayAutoViewportX = GetPrivateProfileIntA("Hooks", "EnableDirect3D9MetadataOverlayAutoViewportX", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9MetadataOverlayAutoViewportY = GetPrivateProfileIntA("Hooks", "EnableDirect3D9MetadataOverlayAutoViewportY", 0, iniPath.c_str()) != 0;
    config.enableDirect3D9MetadataOverlayCameraFollow = GetPrivateProfileIntA("Hooks", "EnableDirect3D9MetadataOverlayCameraFollow", 0, iniPath.c_str()) != 0;
    config.direct3D9MetadataOverlayCameraSlot = GetPrivateProfileIntA("Hooks", "Direct3D9MetadataOverlayCameraSlot", 0, iniPath.c_str());
    config.direct3D9MetadataOverlayMapIndex = GetPrivateProfileIntA("Hooks", "Direct3D9MetadataOverlayMapIndex", 0, iniPath.c_str());
    config.direct3D9MetadataOverlayOffsetX = GetPrivateProfileIntA("Hooks", "Direct3D9MetadataOverlayOffsetX", 0, iniPath.c_str());
    config.direct3D9MetadataOverlayOffsetY = GetPrivateProfileIntA("Hooks", "Direct3D9MetadataOverlayOffsetY", 0, iniPath.c_str());
    config.direct3D9MetadataOverlayBottomUiPixels = GetPrivateProfileIntA("Hooks", "Direct3D9MetadataOverlayBottomUiPixels", 160, iniPath.c_str());
    config.direct3D9MetadataOverlayScalePercent = GetPrivateProfileIntA("Hooks", "Direct3D9MetadataOverlayScalePercent", 100, iniPath.c_str());
    config.wallMetadataDirectory = readStringValue(iniPath, "Walls", "MetadataDirectory", "User\\Walls");
    config.touchRadiusPixels = GetPrivateProfileIntA("Detection", "TouchRadiusPixels", 8, iniPath.c_str());

    if (config.touchRadiusPixels < 1) {
        config.touchRadiusPixels = 1;
    }

    if (config.touchRadiusPixels > 64) {
        config.touchRadiusPixels = 64;
    }

    if (config.direct3D9MetadataOverlayMapIndex < 0) {
        config.direct3D9MetadataOverlayMapIndex = 0;
    }

    if (config.direct3D9MetadataOverlayScalePercent < 1) {
        config.direct3D9MetadataOverlayScalePercent = 1;
    }

    if (config.direct3D9MetadataOverlayScalePercent > 400) {
        config.direct3D9MetadataOverlayScalePercent = 400;
    }

    if (config.direct3D9MetadataOverlayBottomUiPixels < 0) {
        config.direct3D9MetadataOverlayBottomUiPixels = 0;
    }

    if (config.direct3D9MetadataOverlayBottomUiPixels > 1024) {
        config.direct3D9MetadataOverlayBottomUiPixels = 1024;
    }

    if (config.direct3D9MetadataOverlayCameraSlot < 0) {
        config.direct3D9MetadataOverlayCameraSlot = 0;
    }

    if (config.direct3D9MetadataOverlayCameraSlot > 4) {
        config.direct3D9MetadataOverlayCameraSlot = 4;
    }

    return config;
}
