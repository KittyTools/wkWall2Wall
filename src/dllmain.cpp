#include "Config.h"
#include "Logger.h"
#include "Version.h"
#include "WaHooks.h"
#include "WallMetadata.h"

#include <Windows.h>

#include <cctype>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <memory>
#include <sstream>
#include <string>

namespace {
std::unique_ptr<Logger> g_logger;
std::unique_ptr<WaHookManager> g_hookManager;

std::string getGameDirectory() {
    char modulePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, modulePath, MAX_PATH);

    std::string path(modulePath);
    const std::string::size_type slash = path.find_last_of("\\/");
    if (slash == std::string::npos) {
        return ".";
    }

    return path.substr(0, slash);
}

bool isAbsolutePath(const std::string& path) {
    if (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
        return true;
    }

    return path.size() >= 2 && ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'));
}

std::string joinPath(const std::string& directory, const std::string& child) {
    if (directory.empty()) {
        return child;
    }

    const char last = directory.back();
    if (last == '\\' || last == '/') {
        return directory + child;
    }

    return directory + "\\" + child;
}

bool lockCurrentProcessInstance() {
    char mutexName[128] = {};
    sprintf_s(mutexName, "Local\\wkWall2Wall_%lu", GetCurrentProcessId());

    HANDLE mutex = CreateMutexA(nullptr, FALSE, mutexName);
    if (mutex == nullptr) {
        return false;
    }

    return GetLastError() != ERROR_ALREADY_EXISTS;
}

std::uint32_t wallOverlayArgb(std::uint32_t rgb) {
    return 0xFF000000 | (rgb & 0x00FFFFFF);
}

std::vector<WaOverlayRect> buildMetadataOverlayTestRects(const WallMapMetadata& map) {
    std::vector<WaOverlayRect> rects;
    rects.reserve(map.walls.size());

    for (std::size_t index = 0; index < map.walls.size(); ++index) {
        const WallRect& wall = map.walls[index];

        if (wall.width <= 0 || wall.height <= 0) {
            continue;
        }

        rects.push_back(WaOverlayRect{
            wall.x,
            wall.y,
            wall.x + wall.width,
            wall.y + wall.height,
            0xFFFF00FF,
            wallOverlayArgb(wall.color),
            index,
        });
    }

    return rects;
}

DWORD WINAPI initializeModule(LPVOID) {
    const std::string gameDirectory = getGameDirectory();
    g_logger = std::make_unique<Logger>(gameDirectory);
    Logger& logger = *g_logger;

    try {
        logger.info("wkWall2Wall initialization started");

        if (!lockCurrentProcessInstance()) {
            logger.info("wkWall2Wall is already initialized in this process");
            return 0;
        }

        const Config config = Config::load(gameDirectory);
        if (!config.enabled) {
            logger.info("module disabled by configuration");
            return 0;
        }

        const WaVersion version = getCurrentWaVersion();
        logger.info("detected W:A version " + version.toString());

        if (!config.ignoreVersionCheck && !isSupportedWaVersion(version)) {
            std::ostringstream message;
            message << "wkWall2Wall currently supports W:A 3.8.x only. Detected version: " << version.toString();
            logger.error(message.str());
            MessageBoxA(nullptr, message.str().c_str(), "wkWall2Wall", MB_OK | MB_ICONERROR);
            return 0;
        }

        logger.info(config.enableOfflineMode ? "offline mode flag enabled" : "offline mode flag disabled");
        logger.info(config.enableOnlineSync ? "online sync flag enabled" : "online sync flag disabled");
        logger.info(config.requireAllPlayersOnline ? "online sync requires every player to run wkWall2Wall" : "online sync may run with partial module presence");
        logger.info(config.enableVisualOverlay ? "visual overlay flag enabled" : "visual overlay flag disabled");
        logger.info(config.enableHooks ? "hook subsystem enabled" : "hook subsystem disabled");
        logger.info(config.hookProbeOnly ? "hook probe-only flag enabled" : "hook probe-only flag disabled");
        logger.info(config.enableMessagePumpProbe ? "message pump runtime probe enabled" : "message pump runtime probe disabled");
        logger.info(config.enableRenderProbe ? "render runtime probe enabled" : "render runtime probe disabled");
        logger.info(config.enableRendererModuleProbe ? "renderer module runtime probe enabled" : "renderer module runtime probe disabled");
        logger.info(config.enableRendererApiProbe ? "renderer API runtime probe enabled" : "renderer API runtime probe disabled");
        logger.info(config.enableCameraProbe ? "camera runtime probe enabled" : "camera runtime probe disabled");
        logger.info(config.enableDirect3D9Probe ? "Direct3D9 runtime probe enabled" : "Direct3D9 runtime probe disabled");
        logger.info(config.enableDirect3D9DeviceSlotProbe ? "Direct3D9 device slot runtime probe enabled" : "Direct3D9 device slot runtime probe disabled");
        logger.info(config.enableDirect3D9OverlaySmokeTest ? "Direct3D9 overlay smoke test enabled" : "Direct3D9 overlay smoke test disabled");
        logger.info(config.enableDirect3D9TrackingTargetOverlayTest ? "Direct3D9 tracking target overlay test enabled" : "Direct3D9 tracking target overlay test disabled");

        const std::string wallMetadataDirectory = isAbsolutePath(config.wallMetadataDirectory)
            ? config.wallMetadataDirectory
            : joinPath(gameDirectory, config.wallMetadataDirectory);
        const WallMetadataCatalog wallMetadata = loadWallMetadataCatalog(wallMetadataDirectory);

        std::ostringstream metadataMessage;
        metadataMessage << "loaded " << wallMetadata.maps.size() << " wall metadata map(s), "
                        << wallMetadata.wallCount() << " wall rectangle(s) from "
                        << wallMetadata.fileCount << " file(s)";
        logger.info(metadataMessage.str());

        for (const std::string& warning : wallMetadata.warnings) {
            logger.warn("wall metadata warning: " + warning);
        }

        std::vector<WaOverlayRect> direct3D9OverlayTestRects;
        WaOverlayTransform direct3D9OverlayTransform;
        if (config.enableDirect3D9MetadataOverlayTest) {
            if (wallMetadata.maps.empty()) {
                logger.warn("Direct3D9 metadata overlay test enabled, but no wall metadata map is loaded");
            } else {
                const std::size_t mapIndex = static_cast<std::size_t>(config.direct3D9MetadataOverlayMapIndex);
                const WallMapMetadata& overlayMap = wallMetadata.maps[mapIndex < wallMetadata.maps.size() ? mapIndex : 0];
                direct3D9OverlayTestRects = buildMetadataOverlayTestRects(overlayMap);
                direct3D9OverlayTransform.mapWidth = overlayMap.width;
                direct3D9OverlayTransform.mapHeight = overlayMap.height;
                direct3D9OverlayTransform.offsetX = config.direct3D9MetadataOverlayOffsetX;
                direct3D9OverlayTransform.offsetY = config.direct3D9MetadataOverlayOffsetY;
                direct3D9OverlayTransform.scalePercent = config.direct3D9MetadataOverlayScalePercent;
                direct3D9OverlayTransform.autoViewportX = config.enableDirect3D9MetadataOverlayAutoViewportX;
                direct3D9OverlayTransform.autoViewportY = config.enableDirect3D9MetadataOverlayAutoViewportY;
                direct3D9OverlayTransform.bottomUiPixels = config.direct3D9MetadataOverlayBottomUiPixels;
                direct3D9OverlayTransform.cameraFollow = config.enableDirect3D9MetadataOverlayCameraFollow;
                direct3D9OverlayTransform.cameraSlot = config.direct3D9MetadataOverlayCameraSlot;
                direct3D9OverlayTransform.trackingTargetOverlayTest = config.enableDirect3D9TrackingTargetOverlayTest;
                direct3D9OverlayTransform.touchRadiusPixels = config.touchRadiusPixels;

                std::ostringstream overlayMessage;
                overlayMessage << "Direct3D9 metadata overlay test prepared "
                               << direct3D9OverlayTestRects.size()
                               << " rect(s) from metadata map \""
                               << overlayMap.name
                               << "\" using offset "
                               << config.direct3D9MetadataOverlayOffsetX
                               << ","
                               << config.direct3D9MetadataOverlayOffsetY
                               << " and scale "
                               << config.direct3D9MetadataOverlayScalePercent
                               << "%, autoViewportX "
                               << (config.enableDirect3D9MetadataOverlayAutoViewportX ? "true" : "false")
                               << ", autoViewportY "
                               << (config.enableDirect3D9MetadataOverlayAutoViewportY ? "true" : "false")
                               << ", bottomUi "
                               << config.direct3D9MetadataOverlayBottomUiPixels
                               << ", cameraFollow "
                               << (config.enableDirect3D9MetadataOverlayCameraFollow ? "true" : "false")
                               << ", cameraSlot "
                               << config.direct3D9MetadataOverlayCameraSlot
                               << ", trackingTargetOverlay "
                               << (config.enableDirect3D9TrackingTargetOverlayTest ? "true" : "false");
                logger.info(overlayMessage.str());
            }
        }

        if (config.enableHooks) {
            g_hookManager = std::make_unique<WaHookManager>();
            std::string hookError;
            if (!g_hookManager->initialize(
                    logger,
                    config.hookProbeOnly,
                    config.enableMessagePumpProbe,
                    config.enableRenderProbe,
                    config.enableRendererModuleProbe,
                    config.enableRendererApiProbe,
                    config.enableCameraProbe,
                    config.enableDirect3D9Probe,
                    config.enableDirect3D9DeviceSlotProbe,
                    config.enableDirect3D9OverlaySmokeTest,
                    direct3D9OverlayTestRects,
                    direct3D9OverlayTransform,
                    hookError)) {
                g_hookManager.reset();
                logger.warn("hook initialization skipped: " + hookError);
            }
        }

        logger.info("wkWall2Wall skeleton loaded successfully");
    } catch (const std::exception& exception) {
        logger.error(exception.what());
        MessageBoxA(nullptr, exception.what(), "wkWall2Wall", MB_OK | MB_ICONERROR);
    } catch (...) {
        logger.error("unknown initialization error");
        MessageBoxA(nullptr, "Unknown initialization error", "wkWall2Wall", MB_OK | MB_ICONERROR);
    }

    return 0;
}
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        HANDLE thread = CreateThread(nullptr, 0, initializeModule, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
