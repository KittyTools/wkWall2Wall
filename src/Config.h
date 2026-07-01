#pragma once

#include <array>
#include <string>

struct Config {
    bool enabled = true;
    bool ignoreVersionCheck = false;
    bool enableOfflineMode = true;
    bool enableOnlineSync = true;
    bool requireAllPlayersOnline = true;
    bool enableVisualOverlay = true;
    bool enableHooks = true;
    bool hookProbeOnly = false;
    bool enableMessagePumpProbe = false;
    bool enableRenderProbe = false;
    bool enableRendererModuleProbe = false;
    bool enableRendererApiProbe = true;
    bool enableCameraProbe = true;
    bool enableDirect3D9Probe = true;
    bool enableDirect3D9DeviceSlotProbe = true;
    bool enableDirect3D9OverlaySmokeTest = false;
    bool enableDirect3D9MetadataOverlayTest = true;
    bool enableDirect3D9TrackingTargetOverlayTest = false;
    bool enableDirect3D9MetadataOverlayAutoViewportX = true;
    bool enableDirect3D9MetadataOverlayAutoViewportY = true;
    bool enableDirect3D9MetadataOverlayCameraFollow = true;
    int direct3D9MetadataOverlayCameraSlot = 4;
    int direct3D9MetadataOverlayMapIndex = 0;
    int direct3D9MetadataOverlayOffsetX = 0;
    int direct3D9MetadataOverlayOffsetY = 0;
    int direct3D9MetadataOverlayBottomUiPixels = 160;
    int direct3D9MetadataOverlayScalePercent = 100;
    std::string wallMetadataDirectory = "User\\Walls";
    int touchRadiusPixels = 8;
    bool enableSounds = true;
    int soundVolumePercent = 100;
    std::array<std::string, 5> wallTouchedSoundPaths;
    std::string wallTouchedExtraSoundPath = "User\\Speech\\wall_touch_x.wav";
    std::string allWallsTouchedSoundPath = "User\\Speech\\all_walls_touched.wav";
    std::string warningWallsSoundPath = "User\\Speech\\warning_walls.wav";
    std::string warningCrateSoundPath = "User\\Speech\\warning_crate.wav";
    std::string warningRopeSoundPath = "User\\Speech\\warning_afr.wav";

    static Config load(const std::string& gameDirectory);
};
