#include "Config.h"
#include "Logger.h"
#include "Version.h"
#include "WaHooks.h"
#include "WallMetadata.h"

#include <Windows.h>
#include <wincrypt.h>

#include <array>
#include <cctype>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iomanip>
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

std::string readStringValue(const std::string& path, const char* section, const char* key, const char* fallback = "") {
    char buffer[1024] = {};
    GetPrivateProfileStringA(section, key, fallback, buffer, static_cast<DWORD>(sizeof(buffer)), path.c_str());
    return buffer;
}

std::string lowerAscii(const std::string& value) {
    std::string output;
    output.reserve(value.size());
    for (const char character : value) {
        output.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }
    return output;
}

std::string fileNameOnlyFromPath(const std::string& path) {
    const std::string::size_type slash = path.find_last_of("\\/");
    if (slash == std::string::npos) {
        return path;
    }

    return path.substr(slash + 1);
}

bool sameAsciiText(const std::string& left, const std::string& right) {
    return !left.empty() && !right.empty() && lowerAscii(left) == lowerAscii(right);
}

bool fileExists(const std::string& path) {
    if (path.empty()) {
        return false;
    }

    const DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string sha256FileHex(const std::string& path) {
    if (!fileExists(path)) {
        return {};
    }

    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return {};
    }

    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    std::string result;
    if (CryptAcquireContextA(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)
        && CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        std::array<BYTE, 32768> buffer = {};
        DWORD bytesRead = 0;
        bool ok = true;
        while (true) {
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)) {
                ok = false;
                break;
            }
            if (bytesRead == 0) {
                break;
            }
            if (!CryptHashData(hash, buffer.data(), bytesRead, 0)) {
                ok = false;
                break;
            }
        }

        if (ok) {
            std::array<BYTE, 32> digest = {};
            DWORD digestSize = static_cast<DWORD>(digest.size());
            if (CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &digestSize, 0)) {
                std::ostringstream stream;
                stream << std::hex << std::setfill('0');
                for (DWORD index = 0; index < digestSize; ++index) {
                    stream << std::setw(2) << static_cast<unsigned int>(digest[index]);
                }
                result = stream.str();
            }
        }
    }

    if (hash != 0) {
        CryptDestroyHash(hash);
    }
    if (provider != 0) {
        CryptReleaseContext(provider, 0);
    }
    CloseHandle(file);
    return result;
}

bool overlayCatalogHasFileName(const std::vector<WaOverlayMap>& maps, const std::string& fileName) {
    const std::string candidateFileName = fileNameOnlyFromPath(fileName);
    const std::string candidateHash = sha256FileHex(fileName);
    bool hasHashConstrainedCandidate = false;
    for (const WaOverlayMap& map : maps) {
        if (!sameAsciiText(fileNameOnlyFromPath(map.fileName), candidateFileName)) {
            continue;
        }

        if (!map.sha256.empty()) {
            hasHashConstrainedCandidate = true;
            if (!candidateHash.empty() && sameAsciiText(map.sha256, candidateHash)) {
                return true;
            }
            continue;
        }

        if (candidateHash.empty()) {
            return true;
        }
    }

    (void)hasHashConstrainedCandidate;
    return false;
}

std::uint64_t fileWriteTimeUtc(const std::string& path) {
    if (path.empty()) {
        return 0;
    }

    WIN32_FILE_ATTRIBUTE_DATA attributes = {};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &attributes)) {
        return 0;
    }

    return (static_cast<std::uint64_t>(attributes.ftLastWriteTime.dwHighDateTime) << 32)
        | static_cast<std::uint64_t>(attributes.ftLastWriteTime.dwLowDateTime);
}

std::uint64_t parseUnsigned64(const std::string& value) {
    if (value.empty()) {
        return 0;
    }

    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (end == value.c_str()) {
        return 0;
    }

    return static_cast<std::uint64_t>(parsed);
}

std::string readCachedMapPath(
    const std::string& cachePath,
    const std::string& customDatPath,
    const std::vector<WaOverlayMap>& overlayMaps,
    Logger& logger,
    std::uint64_t& cachedCustomDatWriteTime) {
    cachedCustomDatWriteTime = 0;
    if (cachePath.empty() || overlayMaps.empty()) {
        return {};
    }

    const int hasMetadata = GetPrivateProfileIntA("Map", "LastHasMetadata", 0, cachePath.c_str());
    if (hasMetadata == 0) {
        return {};
    }

    const int cacheFormatVersion = GetPrivateProfileIntA("Map", "CacheFormatVersion", 0, cachePath.c_str());
    if (cacheFormatVersion < 2) {
        logger.info("cached default wall map ignored because cache format is obsolete");
        return {};
    }

    const std::string cachedPath = readStringValue(cachePath, "Map", "LastPath");
    const std::string cachedFile = readStringValue(cachePath, "Map", "LastFile");
    const std::string candidate = !cachedPath.empty() ? cachedPath : cachedFile;
    if (candidate.empty() || !overlayCatalogHasFileName(overlayMaps, candidate)) {
        return {};
    }

    const std::string cachedSourceMapSha256 = readStringValue(cachePath, "Map", "SourceMapSha256");
    const std::string currentSourceMapSha256 = sha256FileHex(candidate);
    if (cachedSourceMapSha256.empty()
        || currentSourceMapSha256.empty()
        || !sameAsciiText(cachedSourceMapSha256, currentSourceMapSha256)) {
        logger.info("cached default wall map ignored because source map SHA-256 does not match");
        return {};
    }

    const std::string cachedCustomDatSha256 = readStringValue(cachePath, "Map", "CustomDatSha256");
    if (cachedCustomDatSha256.empty()) {
        logger.info("cached default wall map ignored because custom.dat SHA-256 was not recorded");
        return {};
    }

    const std::string currentCustomDatSha256 = sha256FileHex(customDatPath);
    if (currentCustomDatSha256.empty() || !sameAsciiText(cachedCustomDatSha256, currentCustomDatSha256)) {
        logger.info("cached default wall map ignored because current custom.dat SHA-256 does not match the recorded map");
        return {};
    }

    const std::uint64_t cachedTime = parseUnsigned64(
        readStringValue(cachePath, "Map", "CustomDatWriteTimeUtc"));
    const std::uint64_t currentTime = fileWriteTimeUtc(customDatPath);

    cachedCustomDatWriteTime = currentTime != 0 ? currentTime : cachedTime;
    return candidate;
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

WaOverlayMap buildMetadataOverlayMap(const WallMapMetadata& map) {
    WaOverlayMap overlayMap;
    overlayMap.name = map.name;
    overlayMap.fileName = map.fileName;
    overlayMap.sha256 = map.sha256;
    overlayMap.width = map.width;
    overlayMap.height = map.height;
    overlayMap.rects = buildMetadataOverlayTestRects(map);
    return overlayMap;
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
        std::vector<WaOverlayMap> direct3D9OverlayMaps;
        WaOverlayTransform direct3D9OverlayTransform;
        if (config.enableDirect3D9MetadataOverlayTest) {
            if (wallMetadata.maps.empty()) {
                logger.warn("Direct3D9 metadata overlay test enabled, but no wall metadata map is loaded");
            } else {
                direct3D9OverlayMaps.reserve(wallMetadata.maps.size());
                for (const WallMapMetadata& map : wallMetadata.maps) {
                    WaOverlayMap overlayMap = buildMetadataOverlayMap(map);
                    if (!overlayMap.rects.empty()) {
                        direct3D9OverlayMaps.push_back(overlayMap);
                    }
                }
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
                direct3D9OverlayTransform.mapCachePath = joinPath(gameDirectory, "wkWall2Wall.cache");
                direct3D9OverlayTransform.customDatPath = joinPath(gameDirectory, "custom.dat");
                direct3D9OverlayTransform.cachedMapPath = readCachedMapPath(
                    direct3D9OverlayTransform.mapCachePath,
                    direct3D9OverlayTransform.customDatPath,
                    direct3D9OverlayMaps,
                    logger,
                    direct3D9OverlayTransform.cachedMapCustomDatWriteTime);
                direct3D9OverlayTransform.cachedMapCustomDatSha256 = readStringValue(
                    direct3D9OverlayTransform.mapCachePath,
                    "Map",
                    "CustomDatSha256");

                std::ostringstream overlayMessage;
                overlayMessage << "Direct3D9 metadata overlay test prepared "
                               << direct3D9OverlayMaps.size()
                               << " metadata map(s) for dynamic activation using offset "
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

                if (!direct3D9OverlayTransform.cachedMapPath.empty()) {
                    logger.info("cached default wall map candidate: " + direct3D9OverlayTransform.cachedMapPath);
                }
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
                    direct3D9OverlayMaps,
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
