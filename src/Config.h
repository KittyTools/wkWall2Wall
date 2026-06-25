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
    bool enableSounds = true;
    int soundVolumePercent = 100;
    std::array<std::string, 5> wallTouchedSoundPaths;
    std::string wallTouchedExtraSoundPath = "User\\Walls\\Sounds\\wall_touch_x.wav";
    std::string allWallsTouchedSoundPath = "User\\Walls\\Sounds\\all_walls_touched.wav";
    std::string warningWallsSoundPath = "User\\Walls\\Sounds\\warning_walls.wav";
    std::string warningCrateSoundPath = "User\\Walls\\Sounds\\warning_crate.wav";
    std::string warningRopeSoundPath = "User\\Walls\\Sounds\\warning_afr.wav";

    static Config load(const std::string& gameDirectory);
};
