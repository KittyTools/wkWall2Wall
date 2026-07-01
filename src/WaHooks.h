#pragma once

#include "Logger.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct WaOverlayRect {
    int left = 0;
    int top = 0;
    int right = 0;
    int bottom = 0;
    std::uint32_t argb = 0;
    std::uint32_t touchedArgb = 0;
    std::size_t wallIndex = 0;
};

struct WaOverlayTransform {
    int mapWidth = 0;
    int mapHeight = 0;
    int offsetX = 0;
    int offsetY = 0;
    int scalePercent = 100;
    bool autoViewportX = false;
    bool autoViewportY = false;
    int bottomUiPixels = 160;
    bool cameraFollow = false;
    int cameraSlot = 0;
    bool trackingTargetOverlayTest = false;
    int touchRadiusPixels = 8;
    std::string mapCachePath;
    std::string customDatPath;
    std::string cachedMapPath;
    std::uint64_t cachedMapCustomDatWriteTime = 0;
    std::string cachedMapCustomDatSha256;
};

struct WaOverlayMap {
    std::string name;
    std::string fileName;
    std::string sha256;
    int width = 0;
    int height = 0;
    std::vector<WaOverlayRect> rects;
};

struct WaSoundConfig {
    bool enabled = true;
    int volumePercent = 100;
    std::array<std::string, 5> wallTouchedSoundPaths;
    std::string wallTouchedExtraSoundPath;
    std::string allWallsTouchedSoundPath;
    std::string warningWallsSoundPath;
    std::string warningCrateSoundPath;
    std::string warningRopeSoundPath;
};

class X86DetourHook {
public:
    X86DetourHook() = default;
    ~X86DetourHook();

    X86DetourHook(const X86DetourHook&) = delete;
    X86DetourHook& operator=(const X86DetourHook&) = delete;

    bool install(void* target, void* detour, std::size_t patchLength, std::string& error);
    bool uninstall(std::string& error);

    bool installed() const;
    void* trampoline() const;

private:
    void* target_ = nullptr;
    void* detour_ = nullptr;
    void* trampoline_ = nullptr;
    std::size_t patchLength_ = 0;
    std::vector<std::uint8_t> originalBytes_;
    bool installed_ = false;
};

class IatHook {
public:
    IatHook() = default;
    ~IatHook();

    IatHook(const IatHook&) = delete;
    IatHook& operator=(const IatHook&) = delete;

    bool install(
        const char* importedModuleName,
        const char* importedFunctionName,
        void* detour,
        void*& original,
        std::string& error);
    bool uninstall(std::string& error);

    bool installed() const;

private:
    std::uintptr_t* slot_ = nullptr;
    std::uintptr_t original_ = 0;
    bool installed_ = false;
};

class WaHookManager {
public:
    bool initialize(
        Logger& logger,
        bool probeOnly,
        bool enableMessagePumpProbe,
        bool enableRenderProbe,
        bool enableRendererModuleProbe,
        bool enableRendererApiProbe,
        bool enableCameraProbe,
        bool enableDirect3D9Probe,
        bool enableDirect3D9DeviceSlotProbe,
        bool enableDirect3D9OverlaySmokeTest,
        const std::vector<WaOverlayRect>& direct3D9OverlayTestRects,
        const std::vector<WaOverlayMap>& direct3D9OverlayMaps,
        const WaOverlayTransform& direct3D9OverlayTransform,
        const WaSoundConfig& soundConfig,
        bool enableOnlineSync,
        bool requireAllPlayersOnline,
        std::string& error);

    bool ensureGameplayHooks(Logger& logger, const char* reason);
    void disableGameplayHooks(Logger& logger, const char* reason);

private:
    IatHook getMessageHook_;
    IatHook peekMessageHook_;
    IatHook getAsyncKeyStateHook_;
    IatHook getKeyStateHook_;
    IatHook getKeyboardStateHook_;
    IatHook swapBuffersHook_;
    IatHook bitBltHook_;
    IatHook stretchBltHook_;
    IatHook loadLibraryAHook_;
    IatHook getProcAddressHook_;
    IatHook createFileAHook_;
    IatHook createFileWHook_;
    X86DetourHook cameraTrackingHook_;
    X86DetourHook cameraRenderCopyHook_;
    X86DetourHook cameraTargetAggregateHook_;
    X86DetourHook turnGameHandleMessageHook_;
    X86DetourHook wormMotionCandidateHook_;
    X86DetourHook movementCollisionResultHook_;
    X86DetourHook movementCollisionBranchHook_;
    X86DetourHook movementCollisionPathHook_;
    X86DetourHook collisionQueryCommonHook_;
    X86DetourHook jumpTerrainCollisionResultHook_;
    X86DetourHook movementResolutionSecondaryResultHook_;
    X86DetourHook direct3DCreate9ExportHook_;
    X86DetourHook hostLobbyPacketHandlerHook_;
    X86DetourHook clientLobbyPacketHandlerHook_;
    X86DetourHook constructLobbyHostScreenHook_;
    X86DetourHook constructLobbyClientScreenHook_;
    std::uintptr_t moduleBase_ = 0;
    std::size_t moduleSize_ = 0;
    bool gameplayHookSupportEnabled_ = false;
    bool initialized_ = false;
};
