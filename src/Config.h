#pragma once

#include <string>

struct Config {
    bool enabled = true;
    bool ignoreVersionCheck = false;
    bool enableOfflineMode = true;
    bool enableOnlineSync = true;
    bool requireAllPlayersOnline = true;
    bool enableVisualOverlay = true;
    bool enableHooks = true;
    bool hookProbeOnly = true;
    bool enableMessagePumpProbe = false;
    bool enableRenderProbe = false;
    bool enableRendererModuleProbe = false;
    bool enableRendererApiProbe = false;
    bool enableCameraProbe = false;
    bool enableDirect3D9Probe = false;
    bool enableDirect3D9DeviceSlotProbe = false;
    bool enableDirect3D9OverlaySmokeTest = false;
    bool enableDirect3D9MetadataOverlayTest = false;
    bool enableDirect3D9TrackingTargetOverlayTest = false;
    bool enableDirect3D9MetadataOverlayAutoViewportX = false;
    bool enableDirect3D9MetadataOverlayAutoViewportY = false;
    bool enableDirect3D9MetadataOverlayCameraFollow = false;
    int direct3D9MetadataOverlayCameraSlot = 0;
    int direct3D9MetadataOverlayMapIndex = 0;
    int direct3D9MetadataOverlayOffsetX = 0;
    int direct3D9MetadataOverlayOffsetY = 0;
    int direct3D9MetadataOverlayBottomUiPixels = 160;
    int direct3D9MetadataOverlayScalePercent = 100;
    std::string wallMetadataDirectory = "User\\Walls";
    int touchRadiusPixels = 8;

    static Config load(const std::string& gameDirectory);
};
