#include "WaHooks.h"

#include "WaMemory.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <d3d9.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <new>
#include <sstream>
#include <string>
#include <vector>

namespace {
constexpr std::size_t kX86JumpBytes = 5;
constexpr std::uint32_t kSupportedWa381Timestamp = 0x5FA8504C;
constexpr std::uint32_t kSupportedWa381Checksum = 0x003775F1;
constexpr std::uint32_t kSupportedWa381EntryPointRva = 0x001D8B6C;
constexpr std::size_t kSupportedWa381ImageSize = 0x00584000;
constexpr std::uintptr_t kWa381CameraTrackingFunctionRva = 0x00142F70;
constexpr std::uintptr_t kWa381CameraRenderCopyRva = 0x00134676;
constexpr std::uintptr_t kWa381CameraTargetAggregateRva = 0x00147E70;
constexpr std::uintptr_t kWa381WormMotionCandidateRva = 0x0010D450;
constexpr std::size_t kWaCameraTrackingPatchLength = 5;
constexpr std::size_t kWaCameraRenderCopyPatchLength = 6;
constexpr std::size_t kWaCameraTargetAggregatePatchLength = 5;
constexpr std::size_t kWaWormMotionCandidatePatchLength = 7;
constexpr std::uintptr_t kWaCameraPointStructOffset = 0x8CBC;
constexpr LONG kFixedPointOne = 0x10000;
constexpr std::size_t kCameraTargetCallSampleSlots = 12;
constexpr std::size_t kWormLiveSampleSlots = 32;
constexpr LONG kWaObjectKindWorm = 100;
constexpr std::uintptr_t kWaObjectStateOffset = 0x2C;
constexpr std::uintptr_t kWaObjectKindOffset = 0x44;
constexpr std::uintptr_t kWaObjectTeamOffset = 0xFC;
constexpr std::uintptr_t kWaObjectWormOffset = 0x100;
constexpr std::uintptr_t kWaObjectAliveOffset = 0x104;
constexpr std::uintptr_t kWaObjectPrimaryXOffset = 0x84;
constexpr std::uintptr_t kWaObjectPrimaryYOffset = 0x88;
constexpr std::uintptr_t kWaObjectLiveXOffset = 0x2E0;
constexpr std::uintptr_t kWaObjectLiveYOffset = 0x2E4;
constexpr std::uintptr_t kWaTeamStride = 0x51C;
constexpr std::uintptr_t kWaWormStride = 0x9C;
constexpr std::uintptr_t kWaWormDataBaseOffset = 0x4000;
constexpr std::uintptr_t kWaWormDataScanBytes = 0x180;
constexpr std::uintptr_t kWaTeamNameStride = 0xBB8;
constexpr std::uintptr_t kWaCurrentTeamByteOffset = 0xD9DC;
constexpr std::intptr_t kWaTeamByteListOffset = -0x768;
constexpr int kMaxWallTouchSweepPixels = 384;
constexpr int kWallTouchBounceRadiusPixels = 36;
constexpr int kMinWallTouchBounceVelocityPixels = 2;
constexpr int kActiveWormReferenceKeepDistancePixels = 512;
constexpr DWORD kActiveWormRefreshIntervalMilliseconds = 50;
constexpr LONG kUnknownWallTouchTurnTeamByte = -1;

bool waObjectKindLooksLikeWorm(LONG objectKind) {
    return objectKind == kWaObjectKindWorm || objectKind == 101;
}

bool relativeJumpFits(std::uintptr_t source, std::uintptr_t destination) {
    const std::intptr_t relative = static_cast<std::intptr_t>(destination - (source + kX86JumpBytes));
    return relative >= INT32_MIN && relative <= INT32_MAX;
}

void writeRelativeJump(std::uint8_t* source, std::uintptr_t destination) {
    const std::uintptr_t sourceAddress = reinterpret_cast<std::uintptr_t>(source);
    const std::int32_t relative = static_cast<std::int32_t>(destination - (sourceAddress + kX86JumpBytes));
    source[0] = 0xE9;
    std::memcpy(source + 1, &relative, sizeof(relative));
}

void writeRelativeCall(std::uint8_t* source, std::uintptr_t destination) {
    const std::uintptr_t sourceAddress = reinterpret_cast<std::uintptr_t>(source);
    const std::int32_t relative = static_cast<std::int32_t>(destination - (sourceAddress + kX86JumpBytes));
    source[0] = 0xE8;
    std::memcpy(source + 1, &relative, sizeof(relative));
}

void fillNops(std::uint8_t* target, std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
        target[index] = 0x90;
    }
}

struct WaPeFingerprint {
    std::uint32_t timestamp = 0;
    std::uint32_t checksum = 0;
    std::uint32_t entryPointRva = 0;
    std::size_t imageSize = 0;
};

struct WaProbeSignature {
    const char* name;
    const char* purpose;
    const char* pattern;
    std::uintptr_t expectedRva;
    std::size_t maxMatches;
};

bool readPeFingerprint(const ProcessModuleView& module, WaPeFingerprint& fingerprint) {
    fingerprint = WaPeFingerprint{};
    if (!module) {
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const std::uint8_t*>(module.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    fingerprint.timestamp = nt->FileHeader.TimeDateStamp;
    fingerprint.checksum = nt->OptionalHeader.CheckSum;
    fingerprint.entryPointRva = nt->OptionalHeader.AddressOfEntryPoint;
    fingerprint.imageSize = nt->OptionalHeader.SizeOfImage;
    return true;
}

bool isKnownWa381SteamImage(const WaPeFingerprint& fingerprint) {
    return fingerprint.timestamp == kSupportedWa381Timestamp
        && fingerprint.checksum == kSupportedWa381Checksum
        && fingerprint.entryPointRva == kSupportedWa381EntryPointRva
        && fingerprint.imageSize == kSupportedWa381ImageSize;
}

std::string formatRva(std::uintptr_t address, std::uintptr_t base) {
    if (address < base) {
        return formatAddress(address);
    }

    return formatAddress(address - base);
}

const std::array<WaProbeSignature, 5> kWa381ProbeSignatures = {{
    {
        "main message pump",
        "safe first hook candidate; confirms W:A runtime message dispatch",
        "56 57 E8 97 F6 FF FF 8B F8 33 C0 50 50 50 8D 77 30 56 FF 15 ?? ?? ?? ?? "
        "85 C0 74 25 81 7F 34 6A 03 00 00",
        0x001C8812,
        2
    },
    {
        "window message fallback",
        "message pump virtual-dispatch fallback used when no owner object handles messages",
        "56 E8 7F FB FF FF 80 78 14 00 8B 74 24 08 75 24 85 F6 7D 08 "
        "81 FE 01 80 00 00 75 18",
        0x001C886C,
        2
    },
    {
        "OpenGL init/render path",
        "rendering path probe; candidate area for later overlay work",
        "68 03 1F 00 00 FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? "
        "83 C4 08 85 C0 74 1A",
        0x0019F308,
        2
    },
    {
        "OpenGL texture blit helper",
        "render helper candidates with texture upload and draw setup",
        "81 EC 04 04 00 00 53 55 8B 2D ?? ?? ?? ?? 57 8B DA 8B F9 FF D5 "
        "85 C0 74 57",
        0x0019FAE0,
        4
    },
    {
        "WinMM timer transition",
        "timer state transition candidate; useful for later game loop correlation",
        "A1 ?? ?? ?? ?? 83 EC 1C 83 F8 02 0F 84 ?? ?? ?? ?? 83 F8 01 56 "
        "8B F0 75 2E",
        0x000ED4F0,
        3
    }
}};

void logProbeSignatureMatches(Logger& logger, const ProcessModuleView& module) {
    for (const WaProbeSignature& signature : kWa381ProbeSignatures) {
        BytePattern pattern;
        std::string patternError;
        if (!parseBytePattern(signature.pattern, pattern, patternError)) {
            logger.warn(std::string("hook probe signature parse failed for ") + signature.name + ": " + patternError);
            continue;
        }

        const std::vector<std::uintptr_t> matches = findBytePattern(module, pattern, signature.maxMatches);
        if (matches.empty()) {
            logger.warn(std::string("hook probe: missing signature: ") + signature.name + " (" + signature.purpose + ")");
            continue;
        }

        std::ostringstream message;
        message << "hook probe: " << signature.name << " matched " << matches.size()
                << " time(s); expected RVA " << formatAddress(signature.expectedRva)
                << "; purpose: " << signature.purpose;
        logger.info(message.str());

        for (std::uintptr_t match : matches) {
            std::ostringstream matchMessage;
            matchMessage << "hook probe:   " << signature.name
                         << " at " << formatAddress(match)
                         << " (RVA " << formatRva(match, module.base) << ")";
            logger.info(matchMessage.str());
        }
    }
}

using GetMessageAFunction = BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT);
using SwapBuffersFunction = BOOL(WINAPI*)(HDC);
using BitBltFunction = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, DWORD);
using StretchBltFunction = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
using LoadLibraryAFunction = HMODULE(WINAPI*)(LPCSTR);
using GetProcAddressFunction = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using Direct3DCreate9Function = IDirect3D9*(WINAPI*)(UINT);

GetMessageAFunction g_originalGetMessageA = nullptr;
SwapBuffersFunction g_originalSwapBuffers = nullptr;
BitBltFunction g_originalBitBlt = nullptr;
StretchBltFunction g_originalStretchBlt = nullptr;
LoadLibraryAFunction g_originalLoadLibraryA = nullptr;
GetProcAddressFunction g_originalGetProcAddress = nullptr;
Direct3DCreate9Function g_originalDirect3DCreate9 = nullptr;
Logger* g_runtimeProbeLogger = nullptr;
volatile LONG g_getMessageProbeHits = 0;
volatile LONG g_swapBuffersProbeHits = 0;
volatile LONG g_bitBltProbeHits = 0;
volatile LONG g_stretchBltProbeHits = 0;
volatile LONG g_rendererModuleProbeStarted = 0;
volatile LONG g_rendererApiProbeLoadHits = 0;
volatile LONG g_rendererApiProbeProcHits = 0;
volatile LONG g_cameraTrackingProbeHits = 0;
volatile LONG g_cameraTrackingPointAddress = 0;
volatile LONG g_cameraTrackingXFixed = 0;
volatile LONG g_cameraTrackingYFixed = 0;
volatile LONG g_cameraRenderProbeHits = 0;
volatile LONG g_cameraRenderPointAddress = 0;
volatile LONG g_cameraRenderXFixed = 0;
volatile LONG g_cameraRenderYFixed = 0;
volatile LONG g_cameraRenderSampleValid = 0;
volatile LONG g_cameraTrackingBaselineValid = 0;
volatile LONG g_cameraTrackingBaselineXFixed = 0;
volatile LONG g_cameraTrackingBaselineYFixed = 0;
volatile LONG g_cameraTrackingZeroSampleLogHits = 0;
volatile LONG g_direct3D9ProbeHits = 0;
volatile LONG g_direct3D9CreateDeviceProbeHits = 0;
volatile LONG g_direct3D9DeviceProbeInstallLock = 0;
volatile LONG g_direct3D9DeviceProbeSkippedHits = 0;
volatile LONG g_direct3D9OverlaySmokeDrawHits = 0;
volatile LONG g_direct3D9OverlaySmokeFailureHits = 0;
volatile LONG g_direct3D9MetadataOverlayDrawHits = 0;
volatile LONG g_direct3D9MetadataOverlayFailureHits = 0;
volatile LONG g_direct3D9MetadataOverlayTransformLogHits = 0;
volatile LONG g_direct3D9MetadataOverlayLastBackBufferWidth = 0;
volatile LONG g_direct3D9MetadataOverlayLastBackBufferHeight = 0;
volatile LONG g_direct3D9MetadataOverlayLastCameraDeltaX = 0;
volatile LONG g_direct3D9MetadataOverlayLastCameraDeltaY = 0;
volatile LONG g_direct3D9MetadataOverlayLastCameraDeltaValid = 0;
volatile LONG g_direct3D9MetadataOverlayCameraDeltaLogCount = 0;
volatile LONG g_direct3D9WallTouchLogCount = 0;
volatile LONG g_direct3D9TrackingTargetOverlayDrawHits = 0;
volatile LONG g_direct3D9TrackingTargetOverlayLastCenterX = 0;
volatile LONG g_direct3D9TrackingTargetOverlayLastCenterY = 0;
volatile LONG g_direct3D9TrackingTargetOverlayLastCenterValid = 0;
volatile LONG g_direct3D9TrackingTargetOverlayLogCount = 0;
volatile LONG g_trackingTargetReferenceCenterX = 0;
volatile LONG g_trackingTargetReferenceCenterY = 0;
volatile LONG g_trackingTargetReferenceTick = 0;
volatile LONG g_trackingTargetReferenceValid = 0;
volatile LONG g_cameraTargetAggregateProbeHits = 0;
volatile LONG g_cameraTargetAggregateProbeLogCount = 0;
volatile LONG g_cameraTargetAggregateProbeMissedSlots = 0;
volatile LONG g_cameraTargetAggregateProbeSequence = 0;
volatile LONG g_activeWormCandidateOwnerAddress = 0;
volatile LONG g_activeWormCandidateBaseAddress = 0;
volatile LONG g_activeWormCandidateXOffset = 0;
volatile LONG g_activeWormCandidateYOffset = 0;
volatile LONG g_activeWormCandidateOffsetValid = 0;
volatile LONG g_activeWormCandidateSourceKind = 0;
volatile LONG g_activeWormCandidateSourceOffset = 0;
volatile LONG g_activeWormCandidateLastXFixed = 0;
volatile LONG g_activeWormCandidateLastYFixed = 0;
volatile LONG g_activeWormCandidateLogCount = 0;
volatile LONG g_activeWormCandidatePollLogCount = 0;
volatile LONG g_activeWormCandidateRefreshTick = 0;
volatile LONG g_activeWormCandidateScanTick = 0;
volatile LONG g_activeWormCandidateScanMissLogCount = 0;
volatile LONG g_activeWormMovementLogCount = 0;
volatile LONG g_wallTouchTurnOwnerAddress = 0;
volatile LONG g_wallTouchTurnTeamByte = kUnknownWallTouchTurnTeamByte;
volatile LONG g_wallTouchResetLogCount = 0;
volatile LONG g_wormMotionCandidateProbeHits = 0;
volatile LONG g_wormMotionCandidateProbeLogCount = 0;
volatile LONG g_wormMotionCandidateLastOwnerAddress = 0;
bool g_direct3D9ProbeEnabled = false;
bool g_direct3D9DeviceSlotProbeEnabled = false;
bool g_direct3D9OverlaySmokeTestEnabled = false;
void* g_cameraTrackingProbeStub = nullptr;
void* g_cameraTargetAggregateProbeStub = nullptr;
void* g_wormMotionCandidateProbeStub = nullptr;
std::uintptr_t g_waModuleBase = 0;

constexpr GUID kIUnknownGuid = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
constexpr GUID kIDirect3D9Guid = {0x81BDCBCA, 0x64D4, 0x426D, {0xAE, 0x8D, 0xAD, 0x01, 0x47, 0xF4, 0x27, 0x5C}};
constexpr std::size_t kD3D9DeviceVtableSize = 119;
constexpr std::size_t kD3D9DeviceReleaseIndex = 2;
constexpr std::size_t kD3D9DeviceResetIndex = 16;
constexpr std::size_t kD3D9DevicePresentIndex = 17;
constexpr std::size_t kD3D9DeviceBeginSceneIndex = 41;
constexpr std::size_t kD3D9DeviceEndSceneIndex = 42;
constexpr bool kEnableUnsafeD3D9DeviceShadowVtableProbe = false;

using D3D9DeviceReleaseFunction = ULONG(STDMETHODCALLTYPE*)(IDirect3DDevice9*);
using D3D9DeviceResetFunction = HRESULT(STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
using D3D9DevicePresentFunction = HRESULT(STDMETHODCALLTYPE*)(
    IDirect3DDevice9*,
    const RECT*,
    const RECT*,
    HWND,
    const RGNDATA*);
using D3D9DeviceEndSceneFunction = HRESULT(STDMETHODCALLTYPE*)(IDirect3DDevice9*);

struct Direct3D9DeviceProbeState {
    IDirect3DDevice9* device = nullptr;
    std::uintptr_t* originalVtable = nullptr;
    std::uintptr_t* probeVtable = nullptr;
    D3D9DeviceReleaseFunction originalRelease = nullptr;
    D3D9DeviceResetFunction originalReset = nullptr;
    D3D9DevicePresentFunction originalPresent = nullptr;
    D3D9DeviceEndSceneFunction originalEndScene = nullptr;
    volatile LONG presentHits = 0;
    volatile LONG endSceneHits = 0;
    volatile LONG resetHits = 0;
    volatile LONG releaseHits = 0;
};

struct Direct3D9OverlayRect {
    LONG left = 0;
    LONG top = 0;
    LONG right = 0;
    LONG bottom = 0;
    D3DCOLOR color = 0;
    D3DCOLOR touchedColor = 0;
    std::size_t wallIndex = 0;
    bool touched = false;
};

struct CameraTrackingSnapshot {
    bool available = false;
    int slot = 0;
    std::uintptr_t pointAddress = 0;
    LONG xFixed = 0;
    LONG yFixed = 0;
    int xPixels = 0;
    int yPixels = 0;
    int deltaX = 0;
    int deltaY = 0;
};

struct TrackingTargetSnapshot {
    bool available = false;
    int slot = -1;
    LONG leftFixed = 0;
    LONG topFixed = 0;
    LONG rightFixed = 0;
    LONG bottomFixed = 0;
    int centerX = 0;
    int centerY = 0;
};

struct CameraTargetCallSample {
    volatile LONG callerRva = 0;
    volatile LONG ownerAddress = 0;
    volatile LONG xFixed = 0;
    volatile LONG yFixed = 0;
    volatile LONG xPixels = 0;
    volatile LONG yPixels = 0;
    volatile LONG objectKind = 0;
    volatile LONG teamIndex = 0;
    volatile LONG wormIndex = 0;
    volatile LONG state330 = 0;
    volatile LONG state394 = 0;
    volatile LONG hits = 0;
    volatile LONG sequence = 0;
    volatile LONG tick = 0;
};

struct WormLiveSample {
    volatile LONG ownerAddress = 0;
    volatile LONG xFixed = 0;
    volatile LONG yFixed = 0;
    volatile LONG xPixels = 0;
    volatile LONG yPixels = 0;
    volatile LONG teamIndex = 0;
    volatile LONG wormIndex = 0;
    volatile LONG aliveFlag = 0;
    volatile LONG hits = 0;
    volatile LONG tick = 0;
    volatile LONG primaryXFixed = 0;
    volatile LONG primaryYFixed = 0;
    volatile LONG primaryXPixels = 0;
    volatile LONG primaryYPixels = 0;
    volatile LONG primaryValid = 0;
    volatile LONG olderPrimaryXFixed = 0;
    volatile LONG olderPrimaryYFixed = 0;
    volatile LONG olderPrimaryXPixels = 0;
    volatile LONG olderPrimaryYPixels = 0;
    volatile LONG previousPrimaryXFixed = 0;
    volatile LONG previousPrimaryYFixed = 0;
    volatile LONG previousPrimaryXPixels = 0;
    volatile LONG previousPrimaryYPixels = 0;
    volatile LONG primaryHistoryCount = 0;
    volatile LONG lastMotionTick = 0;
    volatile LONG lastPollTick = 0;
    volatile LONG motionScore = 0;
};

std::array<CameraTargetCallSample, kCameraTargetCallSampleSlots> g_cameraTargetCallSamples;
std::array<WormLiveSample, kWormLiveSampleSlots> g_wormLiveSamples;

Direct3D9DeviceProbeState g_direct3D9DeviceProbe;
std::vector<Direct3D9OverlayRect> g_direct3D9OverlayTestRects;
WaOverlayTransform g_direct3D9OverlayTransform;

TrackingTargetSnapshot currentTrackingTargetSnapshot();
bool waObjectCurrentTeamMatches(void* owner);

ULONG STDMETHODCALLTYPE hookedD3D9DeviceRelease(IDirect3DDevice9* device) noexcept;
HRESULT STDMETHODCALLTYPE hookedD3D9DeviceReset(IDirect3DDevice9* device, D3DPRESENT_PARAMETERS* presentationParameters) noexcept;
HRESULT STDMETHODCALLTYPE hookedD3D9DevicePresent(
    IDirect3DDevice9* device,
    const RECT* sourceRect,
    const RECT* destinationRect,
    HWND destinationWindowOverride,
    const RGNDATA* dirtyRegion) noexcept;
HRESULT STDMETHODCALLTYPE hookedD3D9DeviceEndScene(IDirect3DDevice9* device) noexcept;

std::string lowerAscii(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

bool isRendererModuleName(const std::string& moduleName) {
    const std::string lowerName = lowerAscii(moduleName);
    return lowerName == "ddraw.dll"
        || lowerName == "opengl32.dll"
        || lowerName == "glu32.dll"
        || lowerName == "d3d9.dll"
        || lowerName == "d3d8.dll"
        || lowerName == "d3dim.dll"
        || lowerName == "d3dim700.dll"
        || lowerName == "d3d11.dll"
        || lowerName == "dxgi.dll"
        || lowerName == "dwmapi.dll"
        || lowerName == "cnc-ddraw.dll"
        || lowerName == "ddrawcompat.dll"
        || lowerName == "dgvoodoo.dll"
        || lowerName == "wined3d.dll";
}

bool isInterestingRendererLibraryName(const char* libraryName) {
    if (libraryName == nullptr || libraryName[0] == '\0') {
        return false;
    }

    const std::string lowerName = lowerAscii(libraryName);
    return lowerName.find("ddraw") != std::string::npos
        || lowerName.find("opengl") != std::string::npos
        || lowerName.find("d3d") != std::string::npos
        || lowerName.find("dxgi") != std::string::npos
        || lowerName.find("dwmapi") != std::string::npos;
}

bool isInterestingRendererProcName(const char* procName) {
    if (procName == nullptr || reinterpret_cast<std::uintptr_t>(procName) <= 0xFFFF) {
        return false;
    }

    const std::string name = procName;
    return name == "Direct3DCreate9"
        || name == "Direct3DCreate9Ex"
        || name == "DirectDrawCreate"
        || name == "DirectDrawCreateEx"
        || name == "DirectDrawEnumerateExA"
        || name == "wglCreateContext"
        || name == "wglMakeCurrent"
        || name == "wglSwapBuffers"
        || name == "glBegin"
        || name == "glEnd"
        || name == "glBindTexture"
        || name == "glTexImage2D"
        || name == "glTexSubImage2D";
}

bool isNamedProc(const char* procName, const char* expectedName) {
    return procName != nullptr
        && reinterpret_cast<std::uintptr_t>(procName) > 0xFFFF
        && std::strcmp(procName, expectedName) == 0;
}

bool sameGuid(REFIID left, const GUID& right) {
    return std::memcmp(&left, &right, sizeof(GUID)) == 0;
}

std::string formatHex32(std::uint32_t value) {
    return formatAddress(static_cast<std::uintptr_t>(value));
}

std::string formatCodeBytes(const std::uint8_t* bytes, std::size_t count) {
    std::ostringstream message;
    for (std::size_t index = 0; index < count; ++index) {
        if (index != 0) {
            message << ' ';
        }
        message << formatAddress(static_cast<std::uintptr_t>(bytes[index]));
    }
    return message.str();
}

const char* d3dDeviceTypeName(D3DDEVTYPE deviceType) {
    switch (deviceType) {
    case D3DDEVTYPE_HAL:
        return "HAL";
    case D3DDEVTYPE_REF:
        return "REF";
    case D3DDEVTYPE_SW:
        return "SW";
    case D3DDEVTYPE_NULLREF:
        return "NULLREF";
    default:
        return "unknown";
    }
}

const char* d3dSwapEffectName(D3DSWAPEFFECT swapEffect) {
    switch (swapEffect) {
    case D3DSWAPEFFECT_DISCARD:
        return "DISCARD";
    case D3DSWAPEFFECT_FLIP:
        return "FLIP";
    case D3DSWAPEFFECT_COPY:
        return "COPY";
    case D3DSWAPEFFECT_OVERLAY:
        return "OVERLAY";
    case D3DSWAPEFFECT_FLIPEX:
        return "FLIPEX";
    default:
        return "unknown";
    }
}

std::string formatRectPointer(const RECT* rect) {
    if (rect == nullptr) {
        return "null";
    }

    std::ostringstream message;
    message << "[" << rect->left << "," << rect->top << "," << rect->right << "," << rect->bottom << "]";
    return message.str();
}

void appendVtableEntry(std::ostringstream& message, const char* name, std::uintptr_t* vtable, std::size_t index) {
    message << ", " << name << "[" << index << "]=";
    if (vtable == nullptr) {
        message << "null";
        return;
    }

    message << formatAddress(vtable[index]);
}

void appendPresentParametersSummary(std::ostringstream& message, const D3DPRESENT_PARAMETERS* presentationParameters) {
    if (presentationParameters == nullptr) {
        message << ", presentationParameters null";
        return;
    }

    message << ", backBuffer " << presentationParameters->BackBufferWidth
            << "x" << presentationParameters->BackBufferHeight
            << ", format " << static_cast<int>(presentationParameters->BackBufferFormat)
            << ", windowed " << (presentationParameters->Windowed ? "true" : "false")
            << ", swapEffect " << d3dSwapEffectName(presentationParameters->SwapEffect)
            << "(" << static_cast<int>(presentationParameters->SwapEffect) << ")"
            << ", deviceWindow "
            << formatAddress(reinterpret_cast<std::uintptr_t>(presentationParameters->hDeviceWindow))
            << ", interval " << presentationParameters->PresentationInterval;
}

int fixedDeltaToPixels(LONG fixedDelta) {
    return static_cast<int>(fixedDelta / kFixedPointOne);
}

bool isReadableMemoryRange(std::uintptr_t address, std::size_t bytes) {
    if (address < 0x10000 || bytes == 0) {
        return false;
    }

    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) != sizeof(info)) {
        return false;
    }

    if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
        return false;
    }

    const DWORD protect = info.Protect & 0xFF;
    const bool readable = protect == PAGE_READONLY
        || protect == PAGE_READWRITE
        || protect == PAGE_WRITECOPY
        || protect == PAGE_EXECUTE_READ
        || protect == PAGE_EXECUTE_READWRITE
        || protect == PAGE_EXECUTE_WRITECOPY;
    if (!readable) {
        return false;
    }

    const std::uintptr_t regionStart = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    const std::uintptr_t regionEnd = regionStart + info.RegionSize;
    return address >= regionStart && address < regionEnd && bytes <= regionEnd - address;
}

bool tryReadLong(std::uintptr_t address, LONG& value) {
    if (!isReadableMemoryRange(address, sizeof(LONG))) {
        return false;
    }

    value = *reinterpret_cast<volatile LONG*>(address);
    return true;
}

LONG readWaObjectLong(void* owner, std::uintptr_t offset) {
    if (owner == nullptr) {
        return 0;
    }

    const auto address = reinterpret_cast<std::uintptr_t>(owner) + offset;
    LONG value = 0;
    return tryReadLong(address, value) ? value : 0;
}

bool tryReadByte(std::uintptr_t address, BYTE& value) {
    if (!isReadableMemoryRange(address, sizeof(BYTE))) {
        return false;
    }

    value = *reinterpret_cast<volatile BYTE*>(address);
    return true;
}

bool isPlausibleMapFixedPoint(LONG xFixed, LONG yFixed) {
    const int x = fixedDeltaToPixels(xFixed);
    const int y = fixedDeltaToPixels(yFixed);
    return x >= -256 && x <= 4096 && y >= -1024 && y <= 4096;
}

bool closeFixedPoint(LONG left, LONG right, LONG tolerancePixels) {
    const LONG tolerance = tolerancePixels * kFixedPointOne;
    return std::abs(left - right) <= tolerance;
}

struct ActiveWormCoordinateCandidate {
    std::uintptr_t baseAddress = 0;
    LONG xOffset = -1;
    LONG yOffset = -1;
    LONG xFixed = 0;
    LONG yFixed = 0;
    LONG score = INT32_MAX;
    LONG sourceKind = 0;
    LONG sourceOffset = 0;
};

const char* activeWormCandidateSourceName(LONG sourceKind) {
    switch (sourceKind) {
    case 1:
        return "owner";
    case 2:
        return "worm-data";
    case 3:
        return "owner-pointer";
    case 4:
        return "worm-motion";
    default:
        return "unknown";
    }
}

bool candidateLooksLikeMapCoordinate(LONG xFixed, LONG yFixed) {
    if (!isPlausibleMapFixedPoint(xFixed, yFixed)) {
        return false;
    }

    const int xPixels = fixedDeltaToPixels(xFixed);
    const int yPixels = fixedDeltaToPixels(yFixed);
    if (std::abs(xPixels) < 8 && std::abs(yPixels) < 8) {
        return false;
    }

    return true;
}

std::size_t resetTouchedOverlayWallsForNewTurn() {
    std::size_t resetCount = 0;
    for (Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (!rect.touched) {
            continue;
        }

        rect.touched = false;
        ++resetCount;
    }

    return resetCount;
}

bool tryReadCurrentActiveTeamByteFromOwner(std::uintptr_t ownerAddress, BYTE& activeTeamByte) {
    if (ownerAddress == 0) {
        return false;
    }

    LONG stateAddressLong = 0;
    if (!tryReadLong(ownerAddress + kWaObjectStateOffset, stateAddressLong)) {
        return false;
    }

    const auto stateAddress = static_cast<std::uintptr_t>(stateAddressLong);
    LONG stateUiAddressLong = 0;
    if (!tryReadLong(stateAddress + 0x24, stateUiAddressLong)) {
        return false;
    }

    const auto stateUiAddress = static_cast<std::uintptr_t>(stateUiAddressLong);
    return tryReadByte(stateUiAddress + kWaCurrentTeamByteOffset, activeTeamByte);
}

bool currentActiveTeamByteFromKnownWormSamples(BYTE& activeTeamByte) {
    const DWORD now = GetTickCount();

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddressLong = sample.ownerAddress;
        if (ownerAddressLong == 0) {
            continue;
        }

        const DWORD sampleTick = static_cast<DWORD>(
            sample.lastPollTick != 0 ? sample.lastPollTick : sample.tick);
        if (sampleTick != 0 && now - sampleTick > 30000) {
            continue;
        }

        const auto ownerAddress = static_cast<std::uintptr_t>(ownerAddressLong);
        if (tryReadCurrentActiveTeamByteFromOwner(ownerAddress, activeTeamByte)) {
            return true;
        }
    }

    return false;
}

void clearActiveWormCandidateForTurnChange() {
    InterlockedExchange(&g_activeWormCandidateOwnerAddress, 0);
    InterlockedExchange(&g_activeWormCandidateBaseAddress, 0);
    InterlockedExchange(&g_activeWormCandidateXOffset, 0);
    InterlockedExchange(&g_activeWormCandidateYOffset, 0);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 0);
    InterlockedExchange(&g_activeWormCandidateSourceKind, 0);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, 0);
    InterlockedExchange(&g_activeWormCandidateRefreshTick, 0);
    InterlockedExchange(&g_wallTouchTurnOwnerAddress, 0);
}

void resetTouchedOverlayWallsWhenActiveTeamChanges() {
    BYTE activeTeamByte = 0;
    if (!currentActiveTeamByteFromKnownWormSamples(activeTeamByte)) {
        return;
    }

    const LONG activeTeamLong = static_cast<LONG>(activeTeamByte);
    const LONG previousTeamLong = InterlockedExchange(&g_wallTouchTurnTeamByte, activeTeamLong);
    if (previousTeamLong == kUnknownWallTouchTurnTeamByte || previousTeamLong == activeTeamLong) {
        return;
    }

    clearActiveWormCandidateForTurnChange();
    const std::size_t resetCount = resetTouchedOverlayWallsForNewTurn();
    if (resetCount == 0) {
        return;
    }

    if (g_runtimeProbeLogger != nullptr && g_wallTouchResetLogCount < 32) {
        InterlockedIncrement(&g_wallTouchResetLogCount);

        std::ostringstream message;
        message << "runtime probe: wall touch state reset for active team change from "
                << previousTeamLong
                << " to "
                << activeTeamLong
                << ", reset "
                << resetCount
                << " touched wall(s)";
        g_runtimeProbeLogger->info(message.str());
    }
}

void resetTouchedOverlayWallsWhenActiveOwnerChanges(std::uintptr_t ownerAddress) {
    if (ownerAddress == 0) {
        return;
    }

    BYTE activeTeamByte = 0;
    if (tryReadCurrentActiveTeamByteFromOwner(ownerAddress, activeTeamByte)) {
        InterlockedExchange(&g_wallTouchTurnTeamByte, static_cast<LONG>(activeTeamByte));
    }

    const LONG ownerAddressLong = static_cast<LONG>(ownerAddress);
    const LONG previousOwnerAddress = InterlockedExchange(&g_wallTouchTurnOwnerAddress, ownerAddressLong);
    if (previousOwnerAddress == 0 || previousOwnerAddress == ownerAddressLong) {
        return;
    }

    const std::size_t resetCount = resetTouchedOverlayWallsForNewTurn();
    if (resetCount == 0) {
        return;
    }

    if (g_runtimeProbeLogger != nullptr && g_wallTouchResetLogCount < 32) {
        InterlockedIncrement(&g_wallTouchResetLogCount);

        std::ostringstream message;
        message << "runtime probe: wall touch state reset for active worm change from "
                << formatAddress(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(previousOwnerAddress)))
                << " to "
                << formatAddress(ownerAddress)
                << ", reset "
                << resetCount
                << " touched wall(s)";
        g_runtimeProbeLogger->info(message.str());
    }
}

void publishActiveWormCoordinateCandidate(
    void* owner,
    std::uintptr_t baseAddress,
    LONG xOffset,
    LONG yOffset,
    LONG xFixed,
    LONG yFixed,
    LONG sourceKind,
    LONG sourceOffset) {
    const std::uintptr_t ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    resetTouchedOverlayWallsWhenActiveOwnerChanges(ownerAddress);

    InterlockedExchange(&g_activeWormCandidateOwnerAddress, static_cast<LONG>(ownerAddress));
    InterlockedExchange(&g_activeWormCandidateBaseAddress, static_cast<LONG>(baseAddress));
    InterlockedExchange(&g_activeWormCandidateXOffset, xOffset);
    InterlockedExchange(&g_activeWormCandidateYOffset, yOffset);
    InterlockedExchange(&g_activeWormCandidateSourceKind, sourceKind);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, sourceOffset);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 1);
    InterlockedExchange(&g_activeWormCandidateLastXFixed, xFixed);
    InterlockedExchange(&g_activeWormCandidateLastYFixed, yFixed);
}

WormLiveSample* wormLiveSampleSlotForOwner(std::uintptr_t ownerAddress) {
    WormLiveSample* emptySlot = nullptr;
    WormLiveSample* oldestSlot = &g_wormLiveSamples[0];
    DWORD oldestTick = static_cast<DWORD>(oldestSlot->tick);

    for (WormLiveSample& sample : g_wormLiveSamples) {
        const LONG sampleOwner = sample.ownerAddress;
        if (sampleOwner == static_cast<LONG>(ownerAddress)) {
            return &sample;
        }

        if (sampleOwner == 0 && emptySlot == nullptr) {
            emptySlot = &sample;
        }

        const DWORD sampleTick = static_cast<DWORD>(sample.tick);
        if (sampleTick < oldestTick) {
            oldestTick = sampleTick;
            oldestSlot = &sample;
        }
    }

    return emptySlot != nullptr ? emptySlot : oldestSlot;
}

const WormLiveSample* findWormLiveSampleByOwner(std::uintptr_t ownerAddress) {
    if (ownerAddress == 0) {
        return nullptr;
    }

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        if (sample.ownerAddress == static_cast<LONG>(ownerAddress)) {
            return &sample;
        }
    }

    return nullptr;
}

void resetWormLiveSampleTransientHistory(WormLiveSample& sample) {
    if (sample.ownerAddress == 0) {
        return;
    }

    InterlockedExchange(&sample.xFixed, 0);
    InterlockedExchange(&sample.yFixed, 0);
    InterlockedExchange(&sample.xPixels, 0);
    InterlockedExchange(&sample.yPixels, 0);
    InterlockedExchange(&sample.hits, 0);
    InterlockedExchange(&sample.tick, 0);
    InterlockedExchange(&sample.primaryXFixed, 0);
    InterlockedExchange(&sample.primaryYFixed, 0);
    InterlockedExchange(&sample.primaryXPixels, 0);
    InterlockedExchange(&sample.primaryYPixels, 0);
    InterlockedExchange(&sample.primaryValid, 0);
    InterlockedExchange(&sample.olderPrimaryXFixed, 0);
    InterlockedExchange(&sample.olderPrimaryYFixed, 0);
    InterlockedExchange(&sample.olderPrimaryXPixels, 0);
    InterlockedExchange(&sample.olderPrimaryYPixels, 0);
    InterlockedExchange(&sample.previousPrimaryXFixed, 0);
    InterlockedExchange(&sample.previousPrimaryYFixed, 0);
    InterlockedExchange(&sample.previousPrimaryXPixels, 0);
    InterlockedExchange(&sample.previousPrimaryYPixels, 0);
    InterlockedExchange(&sample.primaryHistoryCount, 0);
    InterlockedExchange(&sample.lastMotionTick, 0);
    InterlockedExchange(&sample.lastPollTick, 0);
    InterlockedExchange(&sample.motionScore, 0);
}

void resetTransientGameplayTrackingState() {
    const std::size_t resetWallCount = resetTouchedOverlayWallsForNewTurn();
    if (resetWallCount != 0 && g_runtimeProbeLogger != nullptr && g_wallTouchResetLogCount < 32) {
        InterlockedIncrement(&g_wallTouchResetLogCount);

        std::ostringstream message;
        message << "runtime probe: wall touch state reset for D3D context transition, reset "
                << resetWallCount
                << " touched wall(s)";
        g_runtimeProbeLogger->info(message.str());
    }

    InterlockedExchange(&g_cameraTrackingPointAddress, 0);
    InterlockedExchange(&g_cameraTrackingXFixed, 0);
    InterlockedExchange(&g_cameraTrackingYFixed, 0);
    InterlockedExchange(&g_cameraRenderPointAddress, 0);
    InterlockedExchange(&g_cameraRenderXFixed, 0);
    InterlockedExchange(&g_cameraRenderYFixed, 0);
    InterlockedExchange(&g_cameraRenderSampleValid, 0);
    InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
    InterlockedExchange(&g_cameraTrackingBaselineXFixed, 0);
    InterlockedExchange(&g_cameraTrackingBaselineYFixed, 0);
    InterlockedExchange(&g_cameraTrackingZeroSampleLogHits, 0);

    InterlockedExchange(&g_trackingTargetReferenceCenterX, 0);
    InterlockedExchange(&g_trackingTargetReferenceCenterY, 0);
    InterlockedExchange(&g_trackingTargetReferenceTick, 0);
    InterlockedExchange(&g_trackingTargetReferenceValid, 0);

    InterlockedExchange(&g_activeWormCandidateOwnerAddress, 0);
    InterlockedExchange(&g_activeWormCandidateBaseAddress, 0);
    InterlockedExchange(&g_activeWormCandidateXOffset, 0);
    InterlockedExchange(&g_activeWormCandidateYOffset, 0);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 0);
    InterlockedExchange(&g_activeWormCandidateSourceKind, 0);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, 0);
    InterlockedExchange(&g_activeWormCandidateLastXFixed, 0);
    InterlockedExchange(&g_activeWormCandidateLastYFixed, 0);
    InterlockedExchange(&g_activeWormCandidateRefreshTick, 0);
    InterlockedExchange(&g_activeWormCandidateScanTick, 0);
    InterlockedExchange(&g_wallTouchTurnOwnerAddress, 0);
    InterlockedExchange(&g_wallTouchTurnTeamByte, kUnknownWallTouchTurnTeamByte);
    InterlockedExchange(&g_activeWormCandidateLogCount, 0);
    InterlockedExchange(&g_activeWormCandidatePollLogCount, 0);
    InterlockedExchange(&g_activeWormCandidateScanMissLogCount, 0);
    InterlockedExchange(&g_activeWormMovementLogCount, 0);
    InterlockedExchange(&g_wormMotionCandidateProbeLogCount, 0);

    for (WormLiveSample& sample : g_wormLiveSamples) {
        resetWormLiveSampleTransientHistory(sample);
    }
}

void rememberWormLiveSample(
    std::uintptr_t ownerAddress,
    LONG teamIndex,
    LONG wormIndex,
    LONG aliveFlag,
    LONG xFixed,
    LONG yFixed) {
    if (ownerAddress == 0 || !candidateLooksLikeMapCoordinate(xFixed, yFixed)) {
        return;
    }

    WormLiveSample* sample = wormLiveSampleSlotForOwner(ownerAddress);
    if (sample == nullptr) {
        return;
    }

    if (sample->ownerAddress != static_cast<LONG>(ownerAddress)) {
        InterlockedExchange(&sample->hits, 0);
        InterlockedExchange(&sample->primaryXFixed, 0);
        InterlockedExchange(&sample->primaryYFixed, 0);
        InterlockedExchange(&sample->primaryXPixels, 0);
        InterlockedExchange(&sample->primaryYPixels, 0);
        InterlockedExchange(&sample->primaryValid, 0);
        InterlockedExchange(&sample->olderPrimaryXFixed, 0);
        InterlockedExchange(&sample->olderPrimaryYFixed, 0);
        InterlockedExchange(&sample->olderPrimaryXPixels, 0);
        InterlockedExchange(&sample->olderPrimaryYPixels, 0);
        InterlockedExchange(&sample->previousPrimaryXFixed, 0);
        InterlockedExchange(&sample->previousPrimaryYFixed, 0);
        InterlockedExchange(&sample->previousPrimaryXPixels, 0);
        InterlockedExchange(&sample->previousPrimaryYPixels, 0);
        InterlockedExchange(&sample->primaryHistoryCount, 0);
        InterlockedExchange(&sample->lastMotionTick, 0);
        InterlockedExchange(&sample->lastPollTick, 0);
        InterlockedExchange(&sample->motionScore, 0);
    }

    InterlockedExchange(&sample->ownerAddress, static_cast<LONG>(ownerAddress));
    InterlockedExchange(&sample->xFixed, xFixed);
    InterlockedExchange(&sample->yFixed, yFixed);
    InterlockedExchange(&sample->xPixels, fixedDeltaToPixels(xFixed));
    InterlockedExchange(&sample->yPixels, fixedDeltaToPixels(yFixed));
    InterlockedExchange(&sample->teamIndex, teamIndex);
    InterlockedExchange(&sample->wormIndex, wormIndex);
    InterlockedExchange(&sample->aliveFlag, aliveFlag);
    InterlockedIncrement(&sample->hits);
    InterlockedExchange(&sample->tick, static_cast<LONG>(GetTickCount()));
}

bool readWormOwnerPrimaryFixed(std::uintptr_t ownerAddress, LONG& xFixed, LONG& yFixed) {
    if (ownerAddress == 0) {
        return false;
    }

    if (!tryReadLong(ownerAddress + kWaObjectPrimaryXOffset, xFixed)
        || !tryReadLong(ownerAddress + kWaObjectPrimaryYOffset, yFixed)
        || !candidateLooksLikeMapCoordinate(xFixed, yFixed)) {
        return false;
    }

    return true;
}

bool readWormOwnerLiveFixed(std::uintptr_t ownerAddress, LONG& xFixed, LONG& yFixed) {
    if (ownerAddress == 0) {
        return false;
    }

    if (!tryReadLong(ownerAddress + kWaObjectLiveXOffset, xFixed)
        || !tryReadLong(ownerAddress + kWaObjectLiveYOffset, yFixed)
        || !candidateLooksLikeMapCoordinate(xFixed, yFixed)) {
        return false;
    }

    return true;
}

bool rememberWormLiveSampleFromOwner(std::uintptr_t ownerAddress) {
    if (ownerAddress == 0) {
        return false;
    }

    LONG objectKind = 0;
    LONG teamIndex = 0;
    LONG wormIndex = 0;
    LONG aliveFlag = 0;
    if (!tryReadLong(ownerAddress + kWaObjectKindOffset, objectKind)
        || !waObjectKindLooksLikeWorm(objectKind)
        || !tryReadLong(ownerAddress + kWaObjectTeamOffset, teamIndex)
        || !tryReadLong(ownerAddress + kWaObjectWormOffset, wormIndex)
        || !tryReadLong(ownerAddress + kWaObjectAliveOffset, aliveFlag)) {
        return false;
    }

    LONG primaryXFixed = 0;
    LONG primaryYFixed = 0;
    LONG liveXFixed = 0;
    LONG liveYFixed = 0;
    const bool primaryCoordinatesValid = readWormOwnerPrimaryFixed(ownerAddress, primaryXFixed, primaryYFixed);
    const bool liveCoordinatesValid = readWormOwnerLiveFixed(ownerAddress, liveXFixed, liveYFixed);
    if (!primaryCoordinatesValid && !liveCoordinatesValid) {
        return false;
    }

    rememberWormLiveSample(
        ownerAddress,
        teamIndex,
        wormIndex,
        aliveFlag,
        primaryCoordinatesValid ? primaryXFixed : liveXFixed,
        primaryCoordinatesValid ? primaryYFixed : liveYFixed);
    return true;
}

bool wormSampleRecentCachedPrimaryFixed(const WormLiveSample& sample, LONG& xFixed, LONG& yFixed) {
    if (sample.primaryValid == 0) {
        return false;
    }

    const DWORD pollTick = static_cast<DWORD>(sample.lastPollTick);
    const DWORD now = GetTickCount();
    if (pollTick == 0 || now - pollTick > 3000) {
        return false;
    }

    xFixed = sample.primaryXFixed;
    yFixed = sample.primaryYFixed;
    return candidateLooksLikeMapCoordinate(xFixed, yFixed);
}

bool wormSampleBestKnownFixed(
    const WormLiveSample& sample,
    LONG& xFixed,
    LONG& yFixed,
    LONG& xOffset,
    LONG& yOffset) {
    const auto ownerAddress = static_cast<std::uintptr_t>(sample.ownerAddress);
    if (readWormOwnerPrimaryFixed(ownerAddress, xFixed, yFixed)) {
        xOffset = static_cast<LONG>(kWaObjectPrimaryXOffset);
        yOffset = static_cast<LONG>(kWaObjectPrimaryYOffset);
        return true;
    }

    if (wormSampleRecentCachedPrimaryFixed(sample, xFixed, yFixed)) {
        xOffset = static_cast<LONG>(kWaObjectPrimaryXOffset);
        yOffset = static_cast<LONG>(kWaObjectPrimaryYOffset);
        return true;
    }

    if (readWormOwnerLiveFixed(ownerAddress, xFixed, yFixed)) {
        xOffset = static_cast<LONG>(kWaObjectLiveXOffset);
        yOffset = static_cast<LONG>(kWaObjectLiveYOffset);
        return true;
    }

    xFixed = sample.xFixed;
    yFixed = sample.yFixed;
    xOffset = static_cast<LONG>(kWaObjectLiveXOffset);
    yOffset = static_cast<LONG>(kWaObjectLiveYOffset);
    return candidateLooksLikeMapCoordinate(xFixed, yFixed);
}

bool publishActiveWormCandidateFromLiveSample(const WormLiveSample& sample, const char* selectionReason) {
    const LONG ownerAddressLong = sample.ownerAddress;
    if (ownerAddressLong == 0) {
        return false;
    }

    LONG xFixed = 0;
    LONG yFixed = 0;
    LONG xOffset = -1;
    LONG yOffset = -1;
    if (!wormSampleBestKnownFixed(sample, xFixed, yFixed, xOffset, yOffset)) {
        return false;
    }

    const auto ownerAddress = static_cast<std::uintptr_t>(ownerAddressLong);
    const LONG previousActiveOwner = g_activeWormCandidateOwnerAddress;
    publishActiveWormCoordinateCandidate(
        reinterpret_cast<void*>(ownerAddress),
        ownerAddress,
        xOffset,
        yOffset,
        xFixed,
        yFixed,
        4,
        xOffset);

    if (g_runtimeProbeLogger != nullptr
        && g_activeWormMovementLogCount < 64
        && previousActiveOwner != ownerAddressLong) {
        InterlockedIncrement(&g_activeWormMovementLogCount);

        std::ostringstream message;
        message << "runtime probe: active worm selected from "
                << selectionReason
                << " owner "
                << formatAddress(ownerAddress)
                << " team "
                << sample.teamIndex
                << " worm "
                << sample.wormIndex
                << " pixels "
                << fixedDeltaToPixels(xFixed)
                << ","
                << fixedDeltaToPixels(yFixed)
                << " source +"
                << formatAddress(static_cast<std::uintptr_t>(xOffset));
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

bool selectActiveWormCandidateFromCurrentTeamSamples() {
    const DWORD now = GetTickCount();
    const WormLiveSample* bestSample = nullptr;
    LONG bestScore = INT32_MAX;
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddressLong = sample.ownerAddress;
        const DWORD sampleTick = static_cast<DWORD>(
            sample.lastPollTick != 0 ? sample.lastPollTick : sample.tick);
        if (ownerAddressLong == 0 || sampleTick == 0 || now - sampleTick > 3000 || sample.aliveFlag == 0) {
            continue;
        }

        const auto ownerAddress = static_cast<std::uintptr_t>(ownerAddressLong);
        if (!waObjectCurrentTeamMatches(reinterpret_cast<void*>(ownerAddress))) {
            continue;
        }

        LONG xFixed = 0;
        LONG yFixed = 0;
        LONG xOffset = -1;
        LONG yOffset = -1;
        if (!wormSampleBestKnownFixed(sample, xFixed, yFixed, xOffset, yOffset)) {
            continue;
        }

        const DWORD motionTick = static_cast<DWORD>(sample.lastMotionTick);
        const bool hasRecentMotion = motionTick != 0 && now - motionTick <= 3000;
        LONG score = static_cast<LONG>(std::min<DWORD>(now - sampleTick, 3000));
        if (hasRecentMotion) {
            score -= 200000;
            score += static_cast<LONG>(std::min<DWORD>(now - motionTick, 3000));
        } else {
            score += 50000;
        }

        if (ownerAddressLong == activeOwnerAddress && g_activeWormCandidateSourceKind == 4) {
            score -= 100000;
        }

        const LONG motionScore = sample.motionScore;
        score -= std::min<LONG>(motionScore, 10000);

        if (bestSample == nullptr || score < bestScore) {
            bestSample = &sample;
            bestScore = score;
        }
    }

    if (bestSample == nullptr) {
        return false;
    }

    return publishActiveWormCandidateFromLiveSample(*bestSample, "current-team live sample");
}

bool selectActiveWormCandidateFromRecentMotionSamples(const char* selectionReason) {
    const DWORD now = GetTickCount();
    const WormLiveSample* bestSample = nullptr;
    LONG bestScore = INT32_MAX;

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddressLong = sample.ownerAddress;
        const DWORD sampleTick = static_cast<DWORD>(
            sample.lastPollTick != 0 ? sample.lastPollTick : sample.tick);
        const DWORD motionTick = static_cast<DWORD>(sample.lastMotionTick);
        if (ownerAddressLong == 0
            || sampleTick == 0
            || motionTick == 0
            || now - sampleTick > 3000
            || now - motionTick > 1500
            || sample.aliveFlag == 0
            || sample.motionScore <= 0) {
            continue;
        }

        LONG xFixed = 0;
        LONG yFixed = 0;
        LONG xOffset = -1;
        LONG yOffset = -1;
        if (!wormSampleBestKnownFixed(sample, xFixed, yFixed, xOffset, yOffset)) {
            continue;
        }

        LONG score = static_cast<LONG>(std::min<DWORD>(now - motionTick, 1500));
        const LONG motionScore = sample.motionScore;
        score -= std::min<LONG>(motionScore, 10000);
        if (ownerAddressLong == g_activeWormCandidateOwnerAddress && g_activeWormCandidateSourceKind == 4) {
            score -= 200000;
        }

        if (bestSample == nullptr || score < bestScore) {
            bestSample = &sample;
            bestScore = score;
        }
    }

    if (bestSample == nullptr) {
        return false;
    }

    return publishActiveWormCandidateFromLiveSample(*bestSample, selectionReason);
}

void pollWormLiveSamplesFromMemory() {
    const DWORD now = GetTickCount();

    for (WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddressLong = sample.ownerAddress;
        if (ownerAddressLong == 0) {
            continue;
        }

        const auto ownerAddress = static_cast<std::uintptr_t>(ownerAddressLong);
        LONG aliveFlag = sample.aliveFlag;
        LONG memoryAliveFlag = aliveFlag;
        if (tryReadLong(ownerAddress + kWaObjectAliveOffset, memoryAliveFlag)) {
            InterlockedExchange(&sample.aliveFlag, memoryAliveFlag);
            aliveFlag = memoryAliveFlag;
        }

        if (aliveFlag == 0) {
            continue;
        }

        LONG xFixed = 0;
        LONG yFixed = 0;
        if (!readWormOwnerPrimaryFixed(ownerAddress, xFixed, yFixed)) {
            continue;
        }

        const bool hadPrimary = sample.primaryValid != 0;
        const LONG previousXFixed = sample.primaryXFixed;
        const LONG previousYFixed = sample.primaryYFixed;
        const int previousXPixels = static_cast<int>(sample.primaryXPixels);
        const int previousYPixels = static_cast<int>(sample.primaryYPixels);
        const int xPixels = fixedDeltaToPixels(xFixed);
        const int yPixels = fixedDeltaToPixels(yFixed);

        if (!hadPrimary) {
            InterlockedExchange(&sample.olderPrimaryXFixed, xFixed);
            InterlockedExchange(&sample.olderPrimaryYFixed, yFixed);
            InterlockedExchange(&sample.olderPrimaryXPixels, xPixels);
            InterlockedExchange(&sample.olderPrimaryYPixels, yPixels);
            InterlockedExchange(&sample.previousPrimaryXFixed, xFixed);
            InterlockedExchange(&sample.previousPrimaryYFixed, yFixed);
            InterlockedExchange(&sample.previousPrimaryXPixels, xPixels);
            InterlockedExchange(&sample.previousPrimaryYPixels, yPixels);
            InterlockedExchange(&sample.primaryHistoryCount, 1);
        } else if (xPixels != previousXPixels || yPixels != previousYPixels) {
            const LONG previousDistinctXFixed = sample.previousPrimaryXFixed;
            const LONG previousDistinctYFixed = sample.previousPrimaryYFixed;
            const LONG previousDistinctXPixels = sample.previousPrimaryXPixels;
            const LONG previousDistinctYPixels = sample.previousPrimaryYPixels;
            const LONG historyCount = sample.primaryHistoryCount;

            InterlockedExchange(
                &sample.olderPrimaryXFixed,
                historyCount >= 2 ? previousDistinctXFixed : previousXFixed);
            InterlockedExchange(
                &sample.olderPrimaryYFixed,
                historyCount >= 2 ? previousDistinctYFixed : previousYFixed);
            InterlockedExchange(
                &sample.olderPrimaryXPixels,
                historyCount >= 2 ? previousDistinctXPixels : previousXPixels);
            InterlockedExchange(
                &sample.olderPrimaryYPixels,
                historyCount >= 2 ? previousDistinctYPixels : previousYPixels);
            InterlockedExchange(&sample.previousPrimaryXFixed, previousXFixed);
            InterlockedExchange(&sample.previousPrimaryYFixed, previousYFixed);
            InterlockedExchange(&sample.previousPrimaryXPixels, previousXPixels);
            InterlockedExchange(&sample.previousPrimaryYPixels, previousYPixels);
            InterlockedExchange(&sample.primaryHistoryCount, std::min<LONG>(historyCount + 1, 3));
        }

        InterlockedExchange(&sample.primaryXFixed, xFixed);
        InterlockedExchange(&sample.primaryYFixed, yFixed);
        InterlockedExchange(&sample.primaryXPixels, xPixels);
        InterlockedExchange(&sample.primaryYPixels, yPixels);
        InterlockedExchange(&sample.primaryValid, 1);
        InterlockedExchange(&sample.lastPollTick, static_cast<LONG>(now));
        InterlockedExchange(&sample.tick, static_cast<LONG>(now));

        if (!hadPrimary) {
            continue;
        }

        const int movementPixels = std::abs(xPixels - previousXPixels) + std::abs(yPixels - previousYPixels);
        if (movementPixels <= 0 || movementPixels > 4096) {
            continue;
        }

        const LONG oldScore = sample.motionScore;
        const LONG newScore = oldScore < 1000000000 - movementPixels
            ? oldScore + movementPixels
            : oldScore;
        InterlockedExchange(&sample.motionScore, newScore);
        InterlockedExchange(&sample.lastMotionTick, static_cast<LONG>(now));

        const bool currentTeamMatches = waObjectCurrentTeamMatches(reinterpret_cast<void*>(ownerAddress));
        const bool alreadyActiveWorm = ownerAddressLong == g_activeWormCandidateOwnerAddress
            && g_activeWormCandidateSourceKind == 4;
        const bool noActiveWormCandidate = g_activeWormCandidateOffsetValid == 0
            || g_activeWormCandidateOwnerAddress == 0;
        const bool movementFallback = noActiveWormCandidate && movementPixels >= 2;
        if (!currentTeamMatches && !alreadyActiveWorm && !movementFallback) {
            continue;
        }

        const LONG previousActiveOwner = g_activeWormCandidateOwnerAddress;
        publishActiveWormCandidateFromLiveSample(
            sample,
            currentTeamMatches
                ? "current-team primary movement"
                : (alreadyActiveWorm ? "active primary movement" : "fallback primary movement"));

        if (g_runtimeProbeLogger != nullptr
            && g_activeWormMovementLogCount < 64
            && (previousActiveOwner != ownerAddressLong || movementPixels >= 8)) {
            InterlockedIncrement(&g_activeWormMovementLogCount);

            std::ostringstream message;
            message << "runtime probe: active worm selected from primary movement owner "
                    << formatAddress(ownerAddress)
                    << " team "
                    << sample.teamIndex
                    << " worm "
                    << sample.wormIndex
                    << " pixels "
                    << xPixels
                    << ","
                    << yPixels
                    << " movement "
                    << movementPixels
                    << " previous "
                    << previousXPixels
                    << ","
                    << previousYPixels
                    << " score "
                    << newScore
                    << " currentTeam "
                    << (currentTeamMatches ? "yes" : "no");
            g_runtimeProbeLogger->info(message.str());
        }
    }
}

bool selectActiveWormCandidateFromLiveSamples(int referenceX, int referenceY) {
    const DWORD now = GetTickCount();
    const WormLiveSample* bestSample = nullptr;
    LONG bestXFixed = 0;
    LONG bestYFixed = 0;
    LONG bestXOffset = -1;
    LONG bestYOffset = -1;
    int bestDistance = INT32_MAX;

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddress = sample.ownerAddress;
        const DWORD tick = static_cast<DWORD>(sample.tick);
        if (ownerAddress == 0 || tick == 0 || now - tick > 120000 || sample.aliveFlag == 0) {
            continue;
        }

        LONG xFixed = 0;
        LONG yFixed = 0;
        LONG xOffset = -1;
        LONG yOffset = -1;
        if (!wormSampleBestKnownFixed(sample, xFixed, yFixed, xOffset, yOffset)) {
            continue;
        }

        const int xPixels = fixedDeltaToPixels(xFixed);
        const int yPixels = fixedDeltaToPixels(yFixed);
        const int distance = std::abs(xPixels - referenceX) + std::abs(yPixels - referenceY);
        if (distance < bestDistance) {
            bestDistance = distance;
            bestSample = &sample;
            bestXFixed = xFixed;
            bestYFixed = yFixed;
            bestXOffset = xOffset;
            bestYOffset = yOffset;
        }
    }

    if (bestSample == nullptr || bestDistance > 384) {
        if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateScanMissLogCount < 32) {
            InterlockedIncrement(&g_activeWormCandidateScanMissLogCount);
            std::ostringstream message;
            message << "runtime probe: active worm live sample selection failed near tracking reference "
                    << referenceX
                    << ","
                    << referenceY;
            if (bestSample != nullptr) {
                message << ", closest "
                        << fixedDeltaToPixels(bestXFixed)
                        << ","
                        << fixedDeltaToPixels(bestYFixed)
                        << " distance "
                        << bestDistance
                        << " owner "
                        << formatAddress(static_cast<std::uintptr_t>(bestSample->ownerAddress));
            }
            g_runtimeProbeLogger->info(message.str());
        }
        return false;
    }

    publishActiveWormCoordinateCandidate(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(bestSample->ownerAddress)),
        static_cast<std::uintptr_t>(bestSample->ownerAddress),
        bestXOffset,
        bestYOffset,
        bestXFixed,
        bestYFixed,
        4,
        bestXOffset);

    if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateLogCount < 32) {
        InterlockedIncrement(&g_activeWormCandidateLogCount);
        std::ostringstream message;
        message << "runtime probe: active worm selected from live samples owner "
                << formatAddress(static_cast<std::uintptr_t>(bestSample->ownerAddress))
                << " team "
                << bestSample->teamIndex
                << " worm "
                << bestSample->wormIndex
                << " pixels "
                << fixedDeltaToPixels(bestXFixed)
                << ","
                << fixedDeltaToPixels(bestYFixed)
                << " offsets "
                << formatAddress(static_cast<std::uintptr_t>(bestXOffset))
                << ","
                << formatAddress(static_cast<std::uintptr_t>(bestYOffset))
                << " reference "
                << referenceX
                << ","
                << referenceY
                << " distance "
                << bestDistance;
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

bool waObjectCurrentTeamMatches(void* owner) {
    if (owner == nullptr) {
        return false;
    }

    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    LONG stateAddressLong = 0;
    LONG teamIndex = 0;
    if (!tryReadLong(ownerAddress + kWaObjectStateOffset, stateAddressLong)
        || !tryReadLong(ownerAddress + kWaObjectTeamOffset, teamIndex)
        || teamIndex < 0
        || teamIndex >= 8) {
        return false;
    }

    const auto stateAddress = static_cast<std::uintptr_t>(stateAddressLong);
    LONG stateUiAddressLong = 0;
    if (!tryReadLong(stateAddress + 0x24, stateUiAddressLong)) {
        return false;
    }

    const auto stateUiAddress = static_cast<std::uintptr_t>(stateUiAddressLong);
    BYTE activeTeamByte = 0;
    BYTE objectTeamByte = 0;
    const auto objectTeamByteAddress = static_cast<std::uintptr_t>(
        static_cast<std::intptr_t>(stateUiAddress)
        + (static_cast<std::intptr_t>(teamIndex) * static_cast<std::intptr_t>(kWaTeamNameStride))
        + kWaTeamByteListOffset);
    if (!tryReadByte(stateUiAddress + kWaCurrentTeamByteOffset, activeTeamByte)
        || !tryReadByte(objectTeamByteAddress, objectTeamByte)) {
        return false;
    }

    return activeTeamByte == objectTeamByte;
}

void considerActiveWormCoordinateCandidate(
    ActiveWormCoordinateCandidate& best,
    std::uintptr_t baseAddress,
    LONG xOffset,
    LONG yOffset,
    LONG xFixed,
    LONG yFixed,
    LONG sourceKind,
    LONG sourceOffset,
    bool hasReference,
    int referenceX,
    int referenceY) {
    if (!candidateLooksLikeMapCoordinate(xFixed, yFixed)) {
        return;
    }

    const int xPixels = fixedDeltaToPixels(xFixed);
    const int yPixels = fixedDeltaToPixels(yFixed);
    LONG score = std::abs(yOffset - xOffset - 4) * 4;
    if (hasReference) {
        score += (std::abs(xPixels - referenceX) + std::abs(yPixels - referenceY)) * 32;
    } else {
        score += std::abs(xPixels - 960) + std::abs(yPixels - 350);
    }

    if (sourceKind == 2) {
        score += 128;
    } else if (sourceKind == 3) {
        score += 64;
    }

    if (score >= best.score) {
        return;
    }

    best.baseAddress = baseAddress;
    best.xOffset = xOffset;
    best.yOffset = yOffset;
    best.xFixed = xFixed;
    best.yFixed = yFixed;
    best.score = score;
    best.sourceKind = sourceKind;
    best.sourceOffset = sourceOffset;
}

void scanCoordinatePairs(
    ActiveWormCoordinateCandidate& best,
    std::uintptr_t baseAddress,
    LONG firstOffset,
    LONG bytesToScan,
    LONG sourceKind,
    LONG sourceOffset,
    bool hasReference,
    int referenceX,
    int referenceY) {
    if (!isReadableMemoryRange(baseAddress + static_cast<std::uintptr_t>(firstOffset), sizeof(LONG) * 2)) {
        return;
    }

    for (LONG offset = firstOffset; offset <= firstOffset + bytesToScan - 8; offset += 4) {
        LONG xFixed = 0;
        LONG yFixed = 0;
        if (!tryReadLong(baseAddress + static_cast<std::uintptr_t>(offset), xFixed)
            || !tryReadLong(baseAddress + static_cast<std::uintptr_t>(offset + 4), yFixed)) {
            continue;
        }

        considerActiveWormCoordinateCandidate(
            best,
            baseAddress,
            offset,
            offset + 4,
            xFixed,
            yFixed,
            sourceKind,
            sourceOffset,
            hasReference,
            referenceX,
            referenceY);
    }
}

bool trackingTargetReferenceLooksUsable(int xPixels, int yPixels) {
    return xPixels >= -256
        && xPixels <= 4096
        && yPixels >= -1024
        && yPixels <= 4096;
}

void rememberTrackingTargetReference(const TrackingTargetSnapshot& reference) {
    if (!reference.available
        || !trackingTargetReferenceLooksUsable(reference.centerX, reference.centerY)) {
        return;
    }

    InterlockedExchange(&g_trackingTargetReferenceCenterX, reference.centerX);
    InterlockedExchange(&g_trackingTargetReferenceCenterY, reference.centerY);
    InterlockedExchange(&g_trackingTargetReferenceTick, static_cast<LONG>(GetTickCount()));
    InterlockedExchange(&g_trackingTargetReferenceValid, 1);
}

bool currentTrackingReference(int& referenceX, int& referenceY) {
    const TrackingTargetSnapshot current = currentTrackingTargetSnapshot();
    if (current.available
        && trackingTargetReferenceLooksUsable(current.centerX, current.centerY)) {
        rememberTrackingTargetReference(current);
        referenceX = current.centerX;
        referenceY = current.centerY;
        return true;
    }

    if (g_trackingTargetReferenceValid == 0) {
        return false;
    }

    const DWORD tick = static_cast<DWORD>(g_trackingTargetReferenceTick);
    if (tick == 0 || GetTickCount() - tick > 1000) {
        return false;
    }

    const int cachedX = static_cast<int>(g_trackingTargetReferenceCenterX);
    const int cachedY = static_cast<int>(g_trackingTargetReferenceCenterY);
    if (!trackingTargetReferenceLooksUsable(cachedX, cachedY)) {
        return false;
    }

    referenceX = cachedX;
    referenceY = cachedY;
    return true;
}

bool discoverActiveWormCoordinateOffsetsFromOwner(void* owner) {
    if (owner == nullptr) {
        return false;
    }

    const std::uintptr_t ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    if (!isReadableMemoryRange(ownerAddress, 0x120)) {
        return false;
    }

    int referenceX = 0;
    int referenceY = 0;
    const bool hasReference = currentTrackingReference(referenceX, referenceY);
    if (!hasReference) {
        if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateScanMissLogCount < 16) {
            InterlockedIncrement(&g_activeWormCandidateScanMissLogCount);
            std::ostringstream message;
            message << "runtime probe: active worm memory scan skipped for owner "
                    << formatAddress(ownerAddress)
                    << " because no recent tracking target reference is available";
            g_runtimeProbeLogger->info(message.str());
        }
        return false;
    }

    ActiveWormCoordinateCandidate best;
    scanCoordinatePairs(best, ownerAddress, 0, 0x800, 1, 0, hasReference, referenceX, referenceY);

    LONG stateAddressLong = 0;
    LONG teamIndex = 0;
    LONG wormIndex = 0;
    if (tryReadLong(ownerAddress + kWaObjectStateOffset, stateAddressLong)
        && tryReadLong(ownerAddress + kWaObjectTeamOffset, teamIndex)
        && tryReadLong(ownerAddress + kWaObjectWormOffset, wormIndex)
        && teamIndex >= 0
        && teamIndex < 8
        && wormIndex >= 0
        && wormIndex < 8) {
        const auto stateAddress = static_cast<std::uintptr_t>(stateAddressLong);
        const std::uintptr_t wormDataBase = stateAddress
            + (static_cast<std::uintptr_t>(teamIndex) * kWaTeamStride)
            + (static_cast<std::uintptr_t>(wormIndex) * kWaWormStride);
        scanCoordinatePairs(
            best,
            wormDataBase,
            static_cast<LONG>(kWaWormDataBaseOffset),
            static_cast<LONG>(kWaWormDataScanBytes),
            2,
            0,
            hasReference,
            referenceX,
            referenceY);
    }

    for (LONG pointerOffset = 0; pointerOffset <= 0x800; pointerOffset += 4) {
        LONG pointerValue = 0;
        if (!tryReadLong(ownerAddress + static_cast<std::uintptr_t>(pointerOffset), pointerValue)) {
            continue;
        }

        const auto pointerAddress = static_cast<std::uintptr_t>(pointerValue);
        if (pointerAddress == ownerAddress || !isReadableMemoryRange(pointerAddress, 0x80)) {
            continue;
        }

        scanCoordinatePairs(
            best,
            pointerAddress,
            0,
            0x1000,
            3,
            pointerOffset,
            hasReference,
            referenceX,
            referenceY);
    }

    if (best.baseAddress == 0 || best.xOffset < 0 || best.yOffset < 0) {
        if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateScanMissLogCount < 16) {
            InterlockedIncrement(&g_activeWormCandidateScanMissLogCount);
            std::ostringstream message;
            message << "runtime probe: active worm memory scan found no plausible coordinate pair for owner "
                    << formatAddress(ownerAddress)
                    << " near reference "
                    << referenceX
                    << ","
                    << referenceY
                    << " (reference "
                    << (hasReference ? "yes" : "no")
                    << ")";
            g_runtimeProbeLogger->info(message.str());
        }
        return false;
    }

    const int bestXPixels = fixedDeltaToPixels(best.xFixed);
    const int bestYPixels = fixedDeltaToPixels(best.yFixed);
    const int referenceDistance = std::abs(bestXPixels - referenceX) + std::abs(bestYPixels - referenceY);
    if (hasReference && referenceDistance > 96) {
        if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateScanMissLogCount < 32) {
            InterlockedIncrement(&g_activeWormCandidateScanMissLogCount);
            std::ostringstream message;
            message << "runtime probe: active worm memory scan closest coordinate for owner "
                    << formatAddress(ownerAddress)
                    << " is too far from tracking target, closest "
                    << bestXPixels
                    << ","
                    << bestYPixels
                    << " reference "
                    << referenceX
                    << ","
                    << referenceY
                    << " distance "
                    << referenceDistance
                    << " source "
                    << activeWormCandidateSourceName(best.sourceKind)
                    << "+"
                    << formatAddress(static_cast<std::uintptr_t>(best.sourceOffset))
                    << " offsets "
                    << formatAddress(static_cast<std::uintptr_t>(best.xOffset))
                    << ","
                    << formatAddress(static_cast<std::uintptr_t>(best.yOffset));
            g_runtimeProbeLogger->info(message.str());
        }
        return false;
    }

    InterlockedExchange(&g_activeWormCandidateBaseAddress, static_cast<LONG>(best.baseAddress));
    InterlockedExchange(&g_activeWormCandidateXOffset, best.xOffset);
    InterlockedExchange(&g_activeWormCandidateYOffset, best.yOffset);
    InterlockedExchange(&g_activeWormCandidateSourceKind, best.sourceKind);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, best.sourceOffset);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 1);
    InterlockedExchange(&g_activeWormCandidateLastXFixed, best.xFixed);
    InterlockedExchange(&g_activeWormCandidateLastYFixed, best.yFixed);

    if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateLogCount < 24) {
        InterlockedIncrement(&g_activeWormCandidateLogCount);
        std::ostringstream message;
        message << "runtime probe: active worm memory coordinate candidate "
                << activeWormCandidateSourceName(best.sourceKind)
                << " owner "
                << formatAddress(ownerAddress)
                << " base "
                << formatAddress(best.baseAddress)
                << " sourceOffset "
                << formatAddress(static_cast<std::uintptr_t>(best.sourceOffset))
                << " offsets "
                << formatAddress(static_cast<std::uintptr_t>(best.xOffset))
                << ","
                << formatAddress(static_cast<std::uintptr_t>(best.yOffset))
                << " fixed "
                << best.xFixed
                << ","
                << best.yFixed
                << " pixels "
                << fixedDeltaToPixels(best.xFixed)
                << ","
                << fixedDeltaToPixels(best.yFixed)
                << " score "
                << best.score
                << " reference "
                << referenceX
                << ","
                << referenceY
                << " ("
                << (hasReference ? "target" : "fallback")
                << ")";
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

bool readActiveWormCandidateFixed(LONG& xFixed, LONG& yFixed) {
    if (g_activeWormCandidateOffsetValid == 0) {
        return false;
    }

    const LONG baseAddress = g_activeWormCandidateBaseAddress;
    const LONG xOffset = g_activeWormCandidateXOffset;
    const LONG yOffset = g_activeWormCandidateYOffset;
    if (baseAddress == 0 || xOffset < 0 || yOffset < 0) {
        return false;
    }

    const auto base = static_cast<std::uintptr_t>(baseAddress);
    const bool wormMotionCandidate = g_activeWormCandidateSourceKind == 4;
    if (wormMotionCandidate && readWormOwnerPrimaryFixed(base, xFixed, yFixed)) {
        return true;
    }

    if (wormMotionCandidate) {
        const WormLiveSample* sample = findWormLiveSampleByOwner(base);
        if (sample != nullptr && wormSampleRecentCachedPrimaryFixed(*sample, xFixed, yFixed)) {
            return true;
        }
    }

    if (tryReadLong(base + static_cast<std::uintptr_t>(xOffset), xFixed)
        && tryReadLong(base + static_cast<std::uintptr_t>(yOffset), yFixed)
        && candidateLooksLikeMapCoordinate(xFixed, yFixed)) {
        return true;
    }

    if (wormMotionCandidate) {
        xFixed = g_activeWormCandidateLastXFixed;
        yFixed = g_activeWormCandidateLastYFixed;
        if (candidateLooksLikeMapCoordinate(xFixed, yFixed)) {
            return true;
        }

        if (readWormOwnerLiveFixed(base, xFixed, yFixed)) {
            return true;
        }

        const WormLiveSample* sample = findWormLiveSampleByOwner(base);
        if (sample != nullptr && candidateLooksLikeMapCoordinate(sample->xFixed, sample->yFixed)) {
            xFixed = sample->xFixed;
            yFixed = sample->yFixed;
            return true;
        }
    }

    return false;
}

bool readActiveWormCandidatePixels(int& xPixels, int& yPixels) {
    LONG xFixed = 0;
    LONG yFixed = 0;
    if (!readActiveWormCandidateFixed(xFixed, yFixed)) {
        return false;
    }

    xPixels = fixedDeltaToPixels(xFixed);
    yPixels = fixedDeltaToPixels(yFixed);
    return true;
}

bool readActiveWormCandidateSweepPixels(
    int& olderX,
    int& olderY,
    int& previousX,
    int& previousY,
    int& currentX,
    int& currentY,
    bool& hasOlder) {
    if (!readActiveWormCandidatePixels(currentX, currentY)) {
        return false;
    }

    olderX = currentX;
    olderY = currentY;
    previousX = currentX;
    previousY = currentY;
    hasOlder = false;

    const auto ownerAddress = static_cast<std::uintptr_t>(g_activeWormCandidateOwnerAddress);
    const WormLiveSample* sample = findWormLiveSampleByOwner(ownerAddress);
    if (sample == nullptr || sample->primaryValid == 0) {
        return true;
    }

    const DWORD pollTick = static_cast<DWORD>(sample->lastPollTick);
    const DWORD now = GetTickCount();
    if (pollTick == 0 || now - pollTick > 3000) {
        return true;
    }

    const LONG historyCount = sample->primaryHistoryCount;
    if (historyCount <= 0) {
        return true;
    }

    currentX = static_cast<int>(sample->primaryXPixels);
    currentY = static_cast<int>(sample->primaryYPixels);

    if (historyCount >= 2) {
        previousX = static_cast<int>(sample->previousPrimaryXPixels);
        previousY = static_cast<int>(sample->previousPrimaryYPixels);
    } else {
        previousX = currentX;
        previousY = currentY;
    }

    if (historyCount >= 3) {
        olderX = static_cast<int>(sample->olderPrimaryXPixels);
        olderY = static_cast<int>(sample->olderPrimaryYPixels);
        hasOlder = true;
    } else {
        olderX = previousX;
        olderY = previousY;
    }

    return true;
}

void invalidateActiveWormCoordinateCandidate() {
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 0);
    InterlockedExchange(&g_activeWormCandidateBaseAddress, 0);
    InterlockedExchange(&g_activeWormCandidateSourceKind, 0);
}

void refreshActiveWormCandidateFromTrackingTarget() {
    const DWORD now = GetTickCount();
    const DWORD previousRefresh = static_cast<DWORD>(g_activeWormCandidateRefreshTick);
    if (previousRefresh != 0 && now - previousRefresh < kActiveWormRefreshIntervalMilliseconds) {
        return;
    }
    InterlockedExchange(&g_activeWormCandidateRefreshTick, static_cast<LONG>(now));

    int candidateX = 0;
    int candidateY = 0;
    if (readActiveWormCandidatePixels(candidateX, candidateY)) {
        if (g_activeWormCandidateSourceKind == 4) {
            const auto ownerAddress = static_cast<std::uintptr_t>(g_activeWormCandidateOwnerAddress);
            if (ownerAddress != 0
                && waObjectCurrentTeamMatches(reinterpret_cast<void*>(ownerAddress))) {
                return;
            }

            clearActiveWormCandidateForTurnChange();
        }
    }

    if (selectActiveWormCandidateFromCurrentTeamSamples()) {
        return;
    }

    if (selectActiveWormCandidateFromRecentMotionSamples("recent motion fallback")) {
        return;
    }

    int referenceX = 0;
    int referenceY = 0;
    if (!currentTrackingReference(referenceX, referenceY)) {
        return;
    }

    if (readActiveWormCandidatePixels(candidateX, candidateY)) {
        if (g_activeWormCandidateSourceKind == 4) {
            return;
        }

        const int distance = std::abs(candidateX - referenceX) + std::abs(candidateY - referenceY);
        if (distance <= 64) {
            return;
        }
    }

    if (selectActiveWormCandidateFromLiveSamples(referenceX, referenceY)) {
        return;
    }

    if (g_activeWormCandidateSourceKind != 4
        && readActiveWormCandidatePixels(candidateX, candidateY)) {
        const int distance = std::abs(candidateX - referenceX) + std::abs(candidateY - referenceY);
        if (distance > kActiveWormReferenceKeepDistancePixels) {
            invalidateActiveWormCoordinateCandidate();
        }
    }
}

void maybeUpdateActiveWormCoordinateOffsets(void* owner, LONG xFixed, LONG yFixed, LONG objectKind) {
    if (owner == nullptr || !waObjectKindLooksLikeWorm(objectKind)) {
        return;
    }

    if (g_activeWormCandidateOffsetValid != 0
        && g_activeWormCandidateSourceKind == 4) {
        return;
    }

    const LONG previousOwner = g_activeWormCandidateOwnerAddress;
    if (previousOwner != 0 && previousOwner != static_cast<LONG>(reinterpret_cast<std::uintptr_t>(owner))) {
        InterlockedExchange(&g_activeWormCandidateOffsetValid, 0);
        InterlockedExchange(&g_activeWormCandidateBaseAddress, 0);
        InterlockedExchange(&g_activeWormCandidateSourceKind, 0);
    }
    InterlockedExchange(&g_activeWormCandidateOwnerAddress, static_cast<LONG>(reinterpret_cast<std::uintptr_t>(owner)));
    InterlockedExchange(&g_activeWormCandidateLastXFixed, xFixed);
    InterlockedExchange(&g_activeWormCandidateLastYFixed, yFixed);

    if (!isPlausibleMapFixedPoint(xFixed, yFixed)) {
        if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateLogCount < 24) {
            InterlockedIncrement(&g_activeWormCandidateLogCount);
            std::ostringstream message;
            message << "runtime probe: active worm owner observed with non-map aggregate fixed "
                    << xFixed
                    << ","
                    << yFixed
                    << " pixels "
                    << fixedDeltaToPixels(xFixed)
                    << ","
                    << fixedDeltaToPixels(yFixed)
                    << " owner "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(owner))
                    << "; will scan owner memory for live coordinates";
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }

    if (g_activeWormCandidateOffsetValid != 0) {
        return;
    }

    LONG bestXOffset = -1;
    LONG bestYOffset = -1;
    LONG bestScore = INT32_MAX;

    for (LONG offset = 0; offset <= 0x420; offset += 4) {
        const LONG candidateX = readWaObjectLong(owner, static_cast<std::uintptr_t>(offset));
        const LONG candidateY = readWaObjectLong(owner, static_cast<std::uintptr_t>(offset + 4));
        if (!closeFixedPoint(candidateX, xFixed, 4) || !closeFixedPoint(candidateY, yFixed, 4)) {
            continue;
        }

        const LONG score = std::abs(candidateX - xFixed) + std::abs(candidateY - yFixed);
        if (score < bestScore) {
            bestScore = score;
            bestXOffset = offset;
            bestYOffset = offset + 4;
        }
    }

    if (bestXOffset < 0 || bestYOffset < 0) {
        for (LONG xOffset = 0; xOffset <= 0x420; xOffset += 4) {
            const LONG candidateX = readWaObjectLong(owner, static_cast<std::uintptr_t>(xOffset));
            if (!closeFixedPoint(candidateX, xFixed, 2)) {
                continue;
            }

            for (LONG yOffset = 0; yOffset <= 0x420; yOffset += 4) {
                const LONG candidateY = readWaObjectLong(owner, static_cast<std::uintptr_t>(yOffset));
                if (!closeFixedPoint(candidateY, yFixed, 2)) {
                    continue;
                }

                const LONG score = std::abs(candidateX - xFixed)
                    + std::abs(candidateY - yFixed)
                    + std::abs(yOffset - xOffset - 4) * kFixedPointOne;
                if (score < bestScore) {
                    bestScore = score;
                    bestXOffset = xOffset;
                    bestYOffset = yOffset;
                }
            }
        }
    }

    if (bestXOffset < 0 || bestYOffset < 0) {
        if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateLogCount < 16) {
            InterlockedIncrement(&g_activeWormCandidateLogCount);
            std::ostringstream message;
            message << "runtime probe: active worm candidate owner "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(owner))
                    << " has no coordinate offset match for fixed "
                    << xFixed
                    << ","
                    << yFixed
                    << " pixels "
                    << fixedDeltaToPixels(xFixed)
                    << ","
                    << fixedDeltaToPixels(yFixed);
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }

    InterlockedExchange(&g_activeWormCandidateBaseAddress, static_cast<LONG>(reinterpret_cast<std::uintptr_t>(owner)));
    InterlockedExchange(&g_activeWormCandidateXOffset, bestXOffset);
    InterlockedExchange(&g_activeWormCandidateYOffset, bestYOffset);
    InterlockedExchange(&g_activeWormCandidateSourceKind, 1);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, 0);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 1);

    if (g_runtimeProbeLogger != nullptr && g_activeWormCandidateLogCount < 16) {
        InterlockedIncrement(&g_activeWormCandidateLogCount);
        std::ostringstream message;
        message << "runtime probe: active worm candidate owner "
                << formatAddress(reinterpret_cast<std::uintptr_t>(owner))
                << " coordinate offsets x+"
                << formatAddress(static_cast<std::uintptr_t>(bestXOffset))
                << " y+"
                << formatAddress(static_cast<std::uintptr_t>(bestYOffset))
                << " from fixed "
                << xFixed
                << ","
                << yFixed
                << " pixels "
                << fixedDeltaToPixels(xFixed)
                << ","
                << fixedDeltaToPixels(yFixed);
        g_runtimeProbeLogger->info(message.str());
    }
}

std::uintptr_t cameraSlotOffset(int slot) {
    switch (slot) {
    case 1:
        return 0x8CBC;
    case 2:
        return 0x8CCC;
    case 3:
        return 0x8CDC;
    case 4:
        return 0x8CEC;
    default:
        return 0;
    }
}

extern "C" void __cdecl recordWaCameraTrackingPoint(void* point) noexcept {
    if (point == nullptr) {
        return;
    }

    const std::uintptr_t pointAddress = reinterpret_cast<std::uintptr_t>(point);
    LONG xFixed = 0;
    LONG yFixed = 0;
    if (!tryReadLong(pointAddress, xFixed)
        || !tryReadLong(pointAddress + sizeof(LONG), yFixed)) {
        InterlockedExchange(&g_cameraTrackingPointAddress, 0);
        InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
        return;
    }

    const LONG previousPointAddress = InterlockedExchange(
        &g_cameraTrackingPointAddress,
        static_cast<LONG>(pointAddress));
    if (previousPointAddress != 0 && previousPointAddress != static_cast<LONG>(pointAddress)) {
        InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
    }

    InterlockedExchange(&g_cameraTrackingXFixed, xFixed);
    InterlockedExchange(&g_cameraTrackingYFixed, yFixed);

    const LONG hits = InterlockedIncrement(&g_cameraTrackingProbeHits);
    if ((hits <= 4 || previousPointAddress != static_cast<LONG>(pointAddress)) && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: W:A camera tracking point captured at "
                << formatAddress(pointAddress)
                << ", fixed "
                << xFixed
                << ","
                << yFixed
                << ", pixels "
                << fixedDeltaToPixels(xFixed)
                << ","
                << fixedDeltaToPixels(yFixed);
        g_runtimeProbeLogger->info(message.str());
    }
}

extern "C" void __cdecl recordWaCameraTargetAggregateCall(
    void* owner,
    LONG xFixed,
    LONG yFixed,
    void* returnAddress) noexcept {
    const LONG hits = InterlockedIncrement(&g_cameraTargetAggregateProbeHits);

    std::uintptr_t callerRva = 0;
    bool callerInsideWa = false;
    if (returnAddress != nullptr) {
        const auto callSite = reinterpret_cast<std::uintptr_t>(returnAddress) - kX86JumpBytes;
        if (g_waModuleBase != 0
            && callSite >= g_waModuleBase
            && callSite < g_waModuleBase + kSupportedWa381ImageSize) {
            callerRva = callSite - g_waModuleBase;
            callerInsideWa = true;
        } else {
            callerRva = callSite;
        }
    }

    if (callerRva == 0) {
        callerRva = 1;
    }

    std::uintptr_t sampleKey = callerRva;
    if (!callerInsideWa && owner != nullptr) {
        sampleKey = (reinterpret_cast<std::uintptr_t>(owner) & 0x3FFFFFFF) | 0x40000000;
    }

    CameraTargetCallSample* sample = nullptr;
    for (CameraTargetCallSample& candidate : g_cameraTargetCallSamples) {
        const LONG existingCaller = candidate.callerRva;
        if (existingCaller == static_cast<LONG>(sampleKey)) {
            sample = &candidate;
            break;
        }

        if (existingCaller == 0) {
            const LONG exchanged = InterlockedCompareExchange(
                &candidate.callerRva,
                static_cast<LONG>(sampleKey),
                0);
            if (exchanged == 0 || exchanged == static_cast<LONG>(sampleKey)) {
                sample = &candidate;
                break;
            }
        }
    }

    if (sample == nullptr) {
        InterlockedIncrement(&g_cameraTargetAggregateProbeMissedSlots);
        return;
    }

    LONG objectKind = 0;
    LONG teamIndex = 0;
    LONG wormIndex = 0;
    LONG state330 = 0;
    LONG state394 = 0;
    if (owner != nullptr) {
        objectKind = readWaObjectLong(owner, kWaObjectKindOffset);
        teamIndex = readWaObjectLong(owner, kWaObjectTeamOffset);
        wormIndex = readWaObjectLong(owner, kWaObjectWormOffset);
        state330 = readWaObjectLong(owner, 0x330);
        state394 = readWaObjectLong(owner, 0x394);
    }

    if (waObjectKindLooksLikeWorm(objectKind)) {
        rememberWormLiveSampleFromOwner(reinterpret_cast<std::uintptr_t>(owner));
    }

    maybeUpdateActiveWormCoordinateOffsets(owner, xFixed, yFixed, objectKind);

    const LONG sequence = InterlockedIncrement(&g_cameraTargetAggregateProbeSequence);
    InterlockedExchange(&sample->ownerAddress, static_cast<LONG>(reinterpret_cast<std::uintptr_t>(owner)));
    InterlockedExchange(&sample->xFixed, xFixed);
    InterlockedExchange(&sample->yFixed, yFixed);
    InterlockedExchange(&sample->xPixels, fixedDeltaToPixels(xFixed));
    InterlockedExchange(&sample->yPixels, fixedDeltaToPixels(yFixed));
    InterlockedExchange(&sample->objectKind, objectKind);
    InterlockedExchange(&sample->teamIndex, teamIndex);
    InterlockedExchange(&sample->wormIndex, wormIndex);
    InterlockedExchange(&sample->state330, state330);
    InterlockedExchange(&sample->state394, state394);
    InterlockedExchange(&sample->sequence, sequence);
    InterlockedExchange(&sample->tick, static_cast<LONG>(GetTickCount()));
    const LONG slotHits = InterlockedIncrement(&sample->hits);

    if (g_runtimeProbeLogger != nullptr && slotHits == 1 && g_cameraTargetAggregateProbeLogCount < 32) {
        InterlockedIncrement(&g_cameraTargetAggregateProbeLogCount);

        std::ostringstream message;
        message << "runtime probe: W:A camera target aggregate caller RVA "
                << formatAddress(callerRva)
                << " ("
                << (callerInsideWa ? "wa" : "external")
                << ", sample key "
                << formatAddress(sampleKey)
                << ")"
                << ", owner "
                << formatAddress(reinterpret_cast<std::uintptr_t>(owner))
                << ", objectKind "
                << objectKind
                << ", team "
                << teamIndex
                << ", worm "
                << wormIndex
                << ", state330 "
                << state330
                << ", state394 "
                << state394
                << ", fixed "
                << xFixed
                << ","
                << yFixed
                << ", pixels "
                << fixedDeltaToPixels(xFixed)
                << ","
                << fixedDeltaToPixels(yFixed)
                << ", total hits "
                << hits;
        g_runtimeProbeLogger->info(message.str());
    }
}

extern "C" void __cdecl recordWaWormMotionCandidateOwner(void* owner) noexcept {
    if (owner == nullptr) {
        return;
    }

    const LONG hits = InterlockedIncrement(&g_wormMotionCandidateProbeHits);
    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    LONG objectKind = 0;
    LONG teamIndex = 0;
    LONG wormIndex = 0;
    LONG aliveFlag = 0;
    LONG liveXFixed = 0;
    LONG liveYFixed = 0;
    LONG primaryXFixed = 0;
    LONG primaryYFixed = 0;
    if (!tryReadLong(ownerAddress + kWaObjectKindOffset, objectKind)
        || !waObjectKindLooksLikeWorm(objectKind)
        || !tryReadLong(ownerAddress + kWaObjectTeamOffset, teamIndex)
        || !tryReadLong(ownerAddress + kWaObjectWormOffset, wormIndex)
        || !tryReadLong(ownerAddress + kWaObjectAliveOffset, aliveFlag)
        || !tryReadLong(ownerAddress + kWaObjectLiveXOffset, liveXFixed)
        || !tryReadLong(ownerAddress + kWaObjectLiveYOffset, liveYFixed)
        || !tryReadLong(ownerAddress + kWaObjectPrimaryXOffset, primaryXFixed)
        || !tryReadLong(ownerAddress + kWaObjectPrimaryYOffset, primaryYFixed)) {
        return;
    }

    const bool currentTeamMatches = waObjectCurrentTeamMatches(owner);
    const bool liveCoordinatesValid = candidateLooksLikeMapCoordinate(liveXFixed, liveYFixed);
    const bool primaryCoordinatesValid = candidateLooksLikeMapCoordinate(primaryXFixed, primaryYFixed);
    if (primaryCoordinatesValid || liveCoordinatesValid) {
        rememberWormLiveSample(
            ownerAddress,
            teamIndex,
            wormIndex,
            aliveFlag,
            primaryCoordinatesValid ? primaryXFixed : liveXFixed,
            primaryCoordinatesValid ? primaryYFixed : liveYFixed);
    }

    int referenceX = 0;
    int referenceY = 0;
    const bool hasReference = currentTrackingReference(referenceX, referenceY);
    const int liveDistance = liveCoordinatesValid
        ? std::abs(fixedDeltaToPixels(liveXFixed) - referenceX) + std::abs(fixedDeltaToPixels(liveYFixed) - referenceY)
        : INT32_MAX;
    const int primaryDistance = primaryCoordinatesValid
        ? std::abs(fixedDeltaToPixels(primaryXFixed) - referenceX) + std::abs(fixedDeltaToPixels(primaryYFixed) - referenceY)
        : INT32_MAX;
    const bool liveMatchesReference = hasReference && liveCoordinatesValid && liveDistance <= 96;
    const bool primaryMatchesReference = hasReference && primaryCoordinatesValid && primaryDistance <= 96;
    const bool shouldPublishActiveWorm = currentTeamMatches || liveMatchesReference || primaryMatchesReference;
    if (shouldPublishActiveWorm && primaryCoordinatesValid) {
        publishActiveWormCoordinateCandidate(
            owner,
            ownerAddress,
            static_cast<LONG>(kWaObjectPrimaryXOffset),
            static_cast<LONG>(kWaObjectPrimaryYOffset),
            primaryXFixed,
            primaryYFixed,
            4,
            static_cast<LONG>(kWaObjectPrimaryXOffset));
    } else if (shouldPublishActiveWorm && liveCoordinatesValid) {
        publishActiveWormCoordinateCandidate(
            owner,
            ownerAddress,
            static_cast<LONG>(kWaObjectLiveXOffset),
            static_cast<LONG>(kWaObjectLiveYOffset),
            liveXFixed,
            liveYFixed,
            4,
            static_cast<LONG>(kWaObjectLiveXOffset));
    }

    const LONG previousOwner = g_wormMotionCandidateLastOwnerAddress;
    const bool ownerChanged = previousOwner != static_cast<LONG>(ownerAddress);
    if (ownerChanged) {
        InterlockedExchange(&g_wormMotionCandidateLastOwnerAddress, static_cast<LONG>(ownerAddress));
    }

    if (g_runtimeProbeLogger != nullptr
        && g_wormMotionCandidateProbeLogCount < 48
        && (hits <= 8 || ownerChanged || currentTeamMatches)) {
        InterlockedIncrement(&g_wormMotionCandidateProbeLogCount);

        std::ostringstream message;
        message << "runtime probe: worm motion candidate owner "
                << formatAddress(ownerAddress)
                << " team "
                << teamIndex
                << " worm "
                << wormIndex
                << " alive "
                << aliveFlag
                << " currentTeam "
                << (currentTeamMatches ? "yes" : "no")
                << " live "
                << fixedDeltaToPixels(liveXFixed)
                << ","
                << fixedDeltaToPixels(liveYFixed)
                << " primary "
                << fixedDeltaToPixels(primaryXFixed)
                << ","
                << fixedDeltaToPixels(primaryYFixed)
                << " trackingRef "
                << (hasReference ? "yes" : "no")
                << " "
                << referenceX
                << ","
                << referenceY
                << " total hits "
                << hits;
        g_runtimeProbeLogger->info(message.str());
    }
}

extern "C" void __cdecl recordWaCameraRenderOwner(void* owner) noexcept {
    if (owner == nullptr) {
        return;
    }

    const std::uintptr_t pointAddress =
        reinterpret_cast<std::uintptr_t>(owner) + kWaCameraPointStructOffset;
    LONG xFixed = 0;
    LONG yFixed = 0;
    if (!tryReadLong(pointAddress, xFixed)
        || !tryReadLong(pointAddress + sizeof(LONG), yFixed)) {
        InterlockedExchange(&g_cameraRenderSampleValid, 0);
        return;
    }

    const LONG previousPointAddress = InterlockedExchange(
        &g_cameraRenderPointAddress,
        static_cast<LONG>(pointAddress));
    if (previousPointAddress != 0 && previousPointAddress != static_cast<LONG>(pointAddress)) {
        InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
    }

    InterlockedExchange(&g_cameraRenderXFixed, xFixed);
    InterlockedExchange(&g_cameraRenderYFixed, yFixed);
    InterlockedExchange(&g_cameraRenderSampleValid, 1);

    const LONG hits = InterlockedIncrement(&g_cameraRenderProbeHits);
    if ((hits <= 4 || previousPointAddress != static_cast<LONG>(pointAddress)) && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: W:A render camera sample captured at "
                << formatAddress(pointAddress)
                << ", fixed "
                << xFixed
                << ","
                << yFixed
                << ", pixels "
                << fixedDeltaToPixels(xFixed)
                << ","
                << fixedDeltaToPixels(yFixed);
        g_runtimeProbeLogger->info(message.str());
    }
}

CameraTrackingSnapshot currentCameraTrackingSnapshot(int slot) {
    CameraTrackingSnapshot snapshot;
    snapshot.slot = slot;

    const std::uintptr_t slotOffset = cameraSlotOffset(slot);
    const LONG trackingPointAddress = g_cameraTrackingPointAddress;
    if (trackingPointAddress == 0 || slotOffset == 0) {
        return snapshot;
    }

    const std::uintptr_t stateBase =
        static_cast<std::uintptr_t>(trackingPointAddress) - kWaCameraPointStructOffset;
    snapshot.pointAddress = stateBase + slotOffset;

    if (slot == 1) {
        snapshot.xFixed = g_cameraTrackingXFixed;
        snapshot.yFixed = g_cameraTrackingYFixed;
    } else {
        if (!tryReadLong(snapshot.pointAddress, snapshot.xFixed)
            || !tryReadLong(snapshot.pointAddress + sizeof(LONG), snapshot.yFixed)) {
            InterlockedExchange(&g_cameraTrackingPointAddress, 0);
            InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
            return snapshot;
        }
    }

    if (snapshot.xFixed == 0 && snapshot.yFixed == 0) {
        const LONG hits = InterlockedIncrement(&g_cameraTrackingZeroSampleLogHits);
        if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: W:A camera slot "
                    << slot
                    << " sample is 0,0; waiting for a valid camera sample";
            g_runtimeProbeLogger->info(message.str());
        }
        return snapshot;
    }

    snapshot.xPixels = fixedDeltaToPixels(snapshot.xFixed);
    snapshot.yPixels = fixedDeltaToPixels(snapshot.yFixed);

    if (InterlockedCompareExchange(&g_cameraTrackingBaselineValid, 1, 0) == 0) {
        InterlockedExchange(&g_cameraTrackingBaselineXFixed, snapshot.xFixed);
        InterlockedExchange(&g_cameraTrackingBaselineYFixed, snapshot.yFixed);
        if (g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: W:A camera slot "
                    << slot
                    << " baseline set at "
                    << formatAddress(snapshot.pointAddress)
                    << ", fixed "
                    << snapshot.xFixed
                    << ","
                    << snapshot.yFixed
                    << ", pixels "
                    << snapshot.xPixels
                    << ","
                    << snapshot.yPixels;
            g_runtimeProbeLogger->info(message.str());
        }
    }

    snapshot.available = true;
    snapshot.deltaX = fixedDeltaToPixels(snapshot.xFixed - g_cameraTrackingBaselineXFixed);
    snapshot.deltaY = fixedDeltaToPixels(snapshot.yFixed - g_cameraTrackingBaselineYFixed);
    return snapshot;
}

bool readTrackingTargetFromEntry(std::uintptr_t entryAddress, int slot, TrackingTargetSnapshot& snapshot) {
    LONG entryFlag = 0;
    if (!tryReadLong(entryAddress, entryFlag) || entryFlag == 0) {
        return false;
    }

    LONG leftFixed = 0;
    LONG topFixed = 0;
    LONG rightFixed = 0;
    LONG bottomFixed = 0;
    if (!tryReadLong(entryAddress + sizeof(LONG), leftFixed)
        || !tryReadLong(entryAddress + (sizeof(LONG) * 2), topFixed)
        || !tryReadLong(entryAddress + (sizeof(LONG) * 3), rightFixed)
        || !tryReadLong(entryAddress + (sizeof(LONG) * 4), bottomFixed)) {
        return false;
    }

    if (leftFixed == rightFixed || topFixed == bottomFixed) {
        return false;
    }

    snapshot.available = true;
    snapshot.slot = slot;
    snapshot.leftFixed = leftFixed;
    snapshot.topFixed = topFixed;
    snapshot.rightFixed = rightFixed;
    snapshot.bottomFixed = bottomFixed;
    snapshot.centerX = fixedDeltaToPixels(leftFixed + ((rightFixed - leftFixed) / 2));
    snapshot.centerY = fixedDeltaToPixels(topFixed + ((bottomFixed - topFixed) / 2));
    return true;
}

TrackingTargetSnapshot currentTrackingTargetSnapshot() {
    TrackingTargetSnapshot snapshot;

    const LONG trackingPointAddress = g_cameraTrackingPointAddress;
    if (trackingPointAddress == 0) {
        return snapshot;
    }

    const std::uintptr_t stateBase =
        static_cast<std::uintptr_t>(trackingPointAddress) - kWaCameraPointStructOffset;
    if (!isReadableMemoryRange(stateBase + 0x72E4, 0x739C + sizeof(LONG) - 0x72E4)) {
        InterlockedExchange(&g_cameraTrackingPointAddress, 0);
        InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
        return snapshot;
    }

    LONG activeTargetFlag = 0;
    if (tryReadLong(stateBase + 0x739C, activeTargetFlag) && activeTargetFlag != 0) {
        LONG leftFixed = 0;
        LONG topFixed = 0;
        LONG rightFixed = 0;
        LONG bottomFixed = 0;
        const std::uintptr_t activeTargetAddress = stateBase + 0x73A0;
        if (!tryReadLong(activeTargetAddress, leftFixed)
            || !tryReadLong(activeTargetAddress + sizeof(LONG), topFixed)
            || !tryReadLong(activeTargetAddress + (sizeof(LONG) * 2), rightFixed)
            || !tryReadLong(activeTargetAddress + (sizeof(LONG) * 3), bottomFixed)) {
            InterlockedExchange(&g_cameraTrackingPointAddress, 0);
            InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
            return snapshot;
        }

        if (leftFixed != rightFixed && topFixed != bottomFixed) {
            snapshot.available = true;
            snapshot.slot = -1;
            snapshot.leftFixed = leftFixed;
            snapshot.topFixed = topFixed;
            snapshot.rightFixed = rightFixed;
            snapshot.bottomFixed = bottomFixed;
            snapshot.centerX = fixedDeltaToPixels(leftFixed + ((rightFixed - leftFixed) / 2));
            snapshot.centerY = fixedDeltaToPixels(topFixed + ((bottomFixed - topFixed) / 2));
            return snapshot;
        }
    }

    LONG queueLimit = 0;
    if (!tryReadLong(stateBase + 0x72E4, queueLimit)) {
        InterlockedExchange(&g_cameraTrackingPointAddress, 0);
        InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
        return snapshot;
    }

    if (queueLimit < 0) {
        return snapshot;
    }

    if (queueLimit > 13) {
        queueLimit = 13;
    }

    for (LONG index = 0; index <= queueLimit; ++index) {
        const std::uintptr_t entryAddress = stateBase + 0x73B0 + (static_cast<std::uintptr_t>(index) * 0x14);
        if (readTrackingTargetFromEntry(entryAddress, static_cast<int>(index), snapshot)) {
            return snapshot;
        }
    }

    return snapshot;
}

void logTrackingTargetOverlay(
    const TrackingTargetSnapshot& target,
    int screenX,
    int screenY) {
    if (g_runtimeProbeLogger == nullptr || !target.available) {
        return;
    }

    const LONG previousX = g_direct3D9TrackingTargetOverlayLastCenterX;
    const LONG previousY = g_direct3D9TrackingTargetOverlayLastCenterY;
    const bool hadPrevious = g_direct3D9TrackingTargetOverlayLastCenterValid != 0;
    const int distance =
        std::abs(target.centerX - static_cast<int>(previousX))
        + std::abs(target.centerY - static_cast<int>(previousY));
    if (hadPrevious && distance < 16) {
        return;
    }

    if (g_direct3D9TrackingTargetOverlayLogCount >= 64) {
        return;
    }

    InterlockedExchange(&g_direct3D9TrackingTargetOverlayLastCenterX, target.centerX);
    InterlockedExchange(&g_direct3D9TrackingTargetOverlayLastCenterY, target.centerY);
    InterlockedExchange(&g_direct3D9TrackingTargetOverlayLastCenterValid, 1);
    InterlockedIncrement(&g_direct3D9TrackingTargetOverlayLogCount);

    std::ostringstream message;
    message << "runtime probe: W:A tracking target candidate"
            << " slot " << target.slot
            << " center " << target.centerX << "," << target.centerY
            << " screen " << screenX << "," << screenY
            << " fixed rect "
            << target.leftFixed << "," << target.topFixed
            << "-" << target.rightFixed << "," << target.bottomFixed;
    g_runtimeProbeLogger->info(message.str());
}

void* buildWaCameraTrackingProbeStub(std::uint8_t* target, std::size_t stolenLength, std::string& error) {
    error.clear();
    if (target == nullptr || stolenLength < kX86JumpBytes) {
        error = "invalid camera tracking probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t jumpBackBytes = kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + stolenLength + jumpBackBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate camera tracking probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd
    stub[offset++] = 0x57; // push edi

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaCameraTrackingPoint))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera tracking probe record callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaCameraTrackingPoint));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x04; // add esp, 4
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::memcpy(stub + offset, target, stolenLength);
    offset += stolenLength;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination = reinterpret_cast<std::uintptr_t>(target + stolenLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera tracking probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaCameraRenderCopyProbeStub(std::uint8_t* target, std::size_t stolenLength, std::string& error) {
    error.clear();
    if (target == nullptr || stolenLength < kX86JumpBytes) {
        error = "invalid camera render copy probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t jumpBackBytes = kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + stolenLength + jumpBackBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate camera render copy probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd
    stub[offset++] = 0x50; // push eax

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaCameraRenderOwner))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera render copy probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaCameraRenderOwner));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x04; // add esp, 4
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::memcpy(stub + offset, target, stolenLength);
    offset += stolenLength;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination = reinterpret_cast<std::uintptr_t>(target + stolenLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera render copy probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaCameraTargetAggregateProbeStub(std::uint8_t* target, std::size_t stolenLength, std::string& error) {
    error.clear();
    if (target == nullptr || stolenLength < kX86JumpBytes) {
        error = "invalid camera target aggregate probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 4 + 1 + 1 + 1 + 4 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t jumpBackBytes = kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + stolenLength + jumpBackBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate camera target aggregate probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd
    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x24; // mov eax, [esp+0x24] - original return address
    stub[offset++] = 0x50; // push eax
    stub[offset++] = 0x52; // push edx
    stub[offset++] = 0x51; // push ecx
    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x34; // mov eax, [esp+0x34] - original first argument after three pushes
    stub[offset++] = 0x50; // push eax

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaCameraTargetAggregateCall))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera target aggregate probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaCameraTargetAggregateCall));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x10; // add esp, 16
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::memcpy(stub + offset, target, stolenLength);
    offset += stolenLength;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination = reinterpret_cast<std::uintptr_t>(target + stolenLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera target aggregate probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaWormMotionCandidateProbeStub(std::uint8_t* target, std::size_t stolenLength, std::string& error) {
    error.clear();
    if (target == nullptr || stolenLength < kX86JumpBytes) {
        error = "invalid worm motion candidate probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t jumpBackBytes = kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + stolenLength + jumpBackBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate worm motion candidate probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd
    stub[offset++] = 0x56; // push esi

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaWormMotionCandidateOwner))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "worm motion candidate probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaWormMotionCandidateOwner));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x04; // add esp, 4
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::memcpy(stub + offset, target, stolenLength);
    offset += stolenLength;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination = reinterpret_cast<std::uintptr_t>(target + stolenLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "worm motion candidate probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

bool installWaCameraTrackingProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381CameraTrackingFunctionRva);
    if (target[0] != 0x51 || target[1] != 0xC1 || target[2] != 0xE0 || target[4] != 0x99) {
        error = "W:A camera tracking function prologue did not match the expected 3.8.1 bytes";
        return false;
    }

    std::string stubError;
    void* stub = buildWaCameraTrackingProbeStub(target, kWaCameraTrackingPatchLength, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaCameraTrackingPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_cameraTrackingProbeStub = stub;
    InterlockedExchange(&g_cameraTrackingProbeHits, 0);
    InterlockedExchange(&g_cameraTrackingPointAddress, 0);
    InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
    InterlockedExchange(&g_cameraTrackingBaselineXFixed, 0);
    InterlockedExchange(&g_cameraTrackingBaselineYFixed, 0);

    std::ostringstream message;
    message << "runtime probe: W:A camera tracking hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (from wkTrackMeBetter381 RVA "
            << formatAddress(kWa381CameraTrackingFunctionRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaCameraRenderCopyProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381CameraRenderCopyRva);
    if (target[0] != 0x8B || target[1] != 0x88 || target[2] != 0xBC || target[3] != 0x8C || target[4] != 0x00 || target[5] != 0x00) {
        error = "W:A camera render copy instruction did not match the expected 3.8.1 bytes";
        return false;
    }

    std::string stubError;
    void* stub = buildWaCameraRenderCopyProbeStub(target, kWaCameraRenderCopyPatchLength, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaCameraRenderCopyPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    std::ostringstream message;
    message << "runtime probe: W:A camera render copy hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381CameraRenderCopyRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaCameraTargetAggregateProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381CameraTargetAggregateRva);
    if (target[0] != 0x8B || target[1] != 0x44 || target[2] != 0x24 || target[3] != 0x04 || target[4] != 0x56) {
        std::ostringstream message;
        message << "W:A camera target aggregate function prologue did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381CameraTargetAggregateRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaCameraTargetAggregateProbeStub(target, kWaCameraTargetAggregatePatchLength, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaCameraTargetAggregatePatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_cameraTargetAggregateProbeStub = stub;
    InterlockedExchange(&g_cameraTargetAggregateProbeHits, 0);
    InterlockedExchange(&g_cameraTargetAggregateProbeLogCount, 0);
    InterlockedExchange(&g_cameraTargetAggregateProbeMissedSlots, 0);
    InterlockedExchange(&g_cameraTargetAggregateProbeSequence, 0);
    InterlockedExchange(&g_trackingTargetReferenceCenterX, 0);
    InterlockedExchange(&g_trackingTargetReferenceCenterY, 0);
    InterlockedExchange(&g_trackingTargetReferenceTick, 0);
    InterlockedExchange(&g_trackingTargetReferenceValid, 0);
    InterlockedExchange(&g_activeWormCandidateOwnerAddress, 0);
    InterlockedExchange(&g_activeWormCandidateBaseAddress, 0);
    InterlockedExchange(&g_activeWormCandidateXOffset, 0);
    InterlockedExchange(&g_activeWormCandidateYOffset, 0);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 0);
    InterlockedExchange(&g_activeWormCandidateSourceKind, 0);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, 0);
    InterlockedExchange(&g_activeWormCandidateLastXFixed, 0);
    InterlockedExchange(&g_activeWormCandidateLastYFixed, 0);
    InterlockedExchange(&g_activeWormCandidateLogCount, 0);
    InterlockedExchange(&g_activeWormCandidatePollLogCount, 0);
    InterlockedExchange(&g_activeWormCandidateRefreshTick, 0);
    InterlockedExchange(&g_activeWormCandidateScanTick, 0);
    InterlockedExchange(&g_activeWormCandidateScanMissLogCount, 0);
    InterlockedExchange(&g_activeWormMovementLogCount, 0);
    for (CameraTargetCallSample& sample : g_cameraTargetCallSamples) {
        InterlockedExchange(&sample.callerRva, 0);
        InterlockedExchange(&sample.ownerAddress, 0);
        InterlockedExchange(&sample.xFixed, 0);
        InterlockedExchange(&sample.yFixed, 0);
        InterlockedExchange(&sample.xPixels, 0);
        InterlockedExchange(&sample.yPixels, 0);
        InterlockedExchange(&sample.objectKind, 0);
        InterlockedExchange(&sample.teamIndex, 0);
        InterlockedExchange(&sample.wormIndex, 0);
        InterlockedExchange(&sample.state330, 0);
        InterlockedExchange(&sample.state394, 0);
        InterlockedExchange(&sample.hits, 0);
        InterlockedExchange(&sample.sequence, 0);
        InterlockedExchange(&sample.tick, 0);
    }
    for (WormLiveSample& sample : g_wormLiveSamples) {
        InterlockedExchange(&sample.ownerAddress, 0);
        InterlockedExchange(&sample.xFixed, 0);
        InterlockedExchange(&sample.yFixed, 0);
        InterlockedExchange(&sample.xPixels, 0);
        InterlockedExchange(&sample.yPixels, 0);
        InterlockedExchange(&sample.teamIndex, 0);
        InterlockedExchange(&sample.wormIndex, 0);
        InterlockedExchange(&sample.aliveFlag, 0);
        InterlockedExchange(&sample.hits, 0);
        InterlockedExchange(&sample.tick, 0);
        InterlockedExchange(&sample.primaryXFixed, 0);
        InterlockedExchange(&sample.primaryYFixed, 0);
        InterlockedExchange(&sample.primaryXPixels, 0);
        InterlockedExchange(&sample.primaryYPixels, 0);
        InterlockedExchange(&sample.primaryValid, 0);
        InterlockedExchange(&sample.olderPrimaryXFixed, 0);
        InterlockedExchange(&sample.olderPrimaryYFixed, 0);
        InterlockedExchange(&sample.olderPrimaryXPixels, 0);
        InterlockedExchange(&sample.olderPrimaryYPixels, 0);
        InterlockedExchange(&sample.previousPrimaryXFixed, 0);
        InterlockedExchange(&sample.previousPrimaryYFixed, 0);
        InterlockedExchange(&sample.previousPrimaryXPixels, 0);
        InterlockedExchange(&sample.previousPrimaryYPixels, 0);
        InterlockedExchange(&sample.primaryHistoryCount, 0);
        InterlockedExchange(&sample.lastMotionTick, 0);
        InterlockedExchange(&sample.lastPollTick, 0);
        InterlockedExchange(&sample.motionScore, 0);
    }

    std::ostringstream message;
    message << "runtime probe: W:A camera target aggregate hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381CameraTargetAggregateRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaWormMotionCandidateProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381WormMotionCandidateRva);
    if (target[0] != 0x53
        || target[1] != 0x8B
        || target[2] != 0x9E
        || target[3] != 0x84
        || target[4] != 0x00
        || target[5] != 0x00
        || target[6] != 0x00) {
        std::ostringstream message;
        message << "W:A worm motion candidate function prologue did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381WormMotionCandidateRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaWormMotionCandidateProbeStub(target, kWaWormMotionCandidatePatchLength, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaWormMotionCandidatePatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_wormMotionCandidateProbeStub = stub;
    InterlockedExchange(&g_wormMotionCandidateProbeHits, 0);
    InterlockedExchange(&g_wormMotionCandidateProbeLogCount, 0);
    InterlockedExchange(&g_wormMotionCandidateLastOwnerAddress, 0);

    std::ostringstream message;
    message << "runtime probe: W:A worm motion candidate hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381WormMotionCandidateRva)
            << ")";
    logger.info(message.str());
    return true;
}

HRESULT drawDirect3D9OverlayRect(IDirect3DDevice9* device, const Direct3D9OverlayRect& rect) {
    if (device == nullptr || rect.right <= rect.left || rect.bottom <= rect.top) {
        return D3DERR_INVALIDCALL;
    }

    D3DRECT d3dRect = {rect.left, rect.top, rect.right, rect.bottom};
    return device->Clear(1, &d3dRect, D3DCLEAR_TARGET, rect.color, 1.0f, 0);
}

bool getDirect3D9RenderTargetSize(IDirect3DDevice9* device, UINT& width, UINT& height) {
    width = 0;
    height = 0;

    if (device == nullptr) {
        return false;
    }

    IDirect3DSurface9* renderTarget = nullptr;
    HRESULT result = device->GetRenderTarget(0, &renderTarget);
    if (FAILED(result) || renderTarget == nullptr) {
        return false;
    }

    D3DSURFACE_DESC description = {};
    result = renderTarget->GetDesc(&description);
    renderTarget->Release();
    if (FAILED(result)) {
        return false;
    }

    width = description.Width;
    height = description.Height;
    return width > 0 && height > 0;
}

int scaledOverlayCoordinate(int coordinate) {
    return (coordinate * g_direct3D9OverlayTransform.scalePercent) / 100;
}

int scaledOverlayMapHeight() {
    if (g_direct3D9OverlayTransform.mapHeight <= 0) {
        return 0;
    }

    return scaledOverlayCoordinate(g_direct3D9OverlayTransform.mapHeight);
}

int scaledOverlayMapWidth() {
    if (g_direct3D9OverlayTransform.mapWidth <= 0) {
        return 0;
    }

    return scaledOverlayCoordinate(g_direct3D9OverlayTransform.mapWidth);
}

int direct3D9OverlayBaseX(IDirect3DDevice9* device, UINT& renderTargetWidth, UINT& renderTargetHeight) {
    int baseX = g_direct3D9OverlayTransform.offsetX;
    if (!g_direct3D9OverlayTransform.autoViewportX) {
        return baseX;
    }

    if ((renderTargetWidth == 0 || renderTargetHeight == 0)
        && !getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return baseX;
    }

    const int mapWidth = scaledOverlayMapWidth();
    if (mapWidth <= 0) {
        return baseX;
    }

    return ((static_cast<int>(renderTargetWidth) - mapWidth) / 2) + baseX;
}

int direct3D9OverlayBaseY(IDirect3DDevice9* device, UINT& renderTargetWidth, UINT& renderTargetHeight) {
    renderTargetWidth = 0;
    renderTargetHeight = 0;

    int baseY = g_direct3D9OverlayTransform.offsetY;
    if (!g_direct3D9OverlayTransform.autoViewportY) {
        return baseY;
    }

    if (!getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return baseY;
    }

    const int mapHeight = scaledOverlayMapHeight();
    if (mapHeight <= 0) {
        return baseY;
    }

    const int renderHeight = static_cast<int>(renderTargetHeight);
    int autoBaseY = renderHeight - mapHeight - g_direct3D9OverlayTransform.bottomUiPixels;
    if (autoBaseY < g_direct3D9OverlayTransform.bottomUiPixels) {
        autoBaseY = (renderHeight - mapHeight) / 2;
    }

    return autoBaseY + baseY;
}

void logDirect3D9OverlayTransform(
    UINT renderTargetWidth,
    UINT renderTargetHeight,
    int baseX,
    int baseY,
    const CameraTrackingSnapshot& camera) {
    if (g_runtimeProbeLogger == nullptr) {
        return;
    }

    bool shouldLog = false;
    if (InterlockedIncrement(&g_direct3D9MetadataOverlayTransformLogHits) == 1) {
        shouldLog = true;
    }

    if (renderTargetWidth > 0 && renderTargetHeight > 0) {
        const LONG previousWidth = InterlockedExchange(
            &g_direct3D9MetadataOverlayLastBackBufferWidth,
            static_cast<LONG>(renderTargetWidth));
        const LONG previousHeight = InterlockedExchange(
            &g_direct3D9MetadataOverlayLastBackBufferHeight,
            static_cast<LONG>(renderTargetHeight));
        if (previousWidth != static_cast<LONG>(renderTargetWidth)
            || previousHeight != static_cast<LONG>(renderTargetHeight)) {
            shouldLog = true;
        }
    }

    if (camera.available) {
        const LONG previousDeltaX = g_direct3D9MetadataOverlayLastCameraDeltaX;
        const LONG previousDeltaY = g_direct3D9MetadataOverlayLastCameraDeltaY;
        const bool hadPreviousDelta = g_direct3D9MetadataOverlayLastCameraDeltaValid != 0;
        const int deltaDistance =
            std::abs(camera.deltaX - static_cast<int>(previousDeltaX))
            + std::abs(camera.deltaY - static_cast<int>(previousDeltaY));
        if ((!hadPreviousDelta || deltaDistance >= 64)
            && g_direct3D9MetadataOverlayCameraDeltaLogCount < 64) {
            InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaX, camera.deltaX);
            InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaY, camera.deltaY);
            InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaValid, 1);
            InterlockedIncrement(&g_direct3D9MetadataOverlayCameraDeltaLogCount);
            shouldLog = true;
        }
    }

    if (!shouldLog) {
        return;
    }

    std::ostringstream message;
    message << "runtime probe: Direct3D9 metadata overlay transform: renderTarget "
            << renderTargetWidth
            << "x"
            << renderTargetHeight
            << ", map "
            << g_direct3D9OverlayTransform.mapWidth
            << "x"
            << g_direct3D9OverlayTransform.mapHeight
            << ", base "
            << baseX
            << ","
            << baseY
            << ", scale "
            << g_direct3D9OverlayTransform.scalePercent
            << "%"
            << ", autoViewportX "
            << (g_direct3D9OverlayTransform.autoViewportX ? "true" : "false")
            << ", autoViewportY "
            << (g_direct3D9OverlayTransform.autoViewportY ? "true" : "false")
            << ", bottomUi "
            << g_direct3D9OverlayTransform.bottomUiPixels
            << ", cameraFollow "
            << (g_direct3D9OverlayTransform.cameraFollow ? "true" : "false")
            << ", cameraSlot "
            << g_direct3D9OverlayTransform.cameraSlot;
    if (camera.available) {
        message << ", camera slot "
                << camera.slot
                << " "
                << formatAddress(camera.pointAddress)
                << " fixed "
                << camera.xFixed
                << ","
                << camera.yFixed
                << " pixels "
                << camera.xPixels
                << ","
                << camera.yPixels
                << " delta "
                << camera.deltaX
                << ","
                << camera.deltaY;
    } else {
        message << ", camera unavailable";
    }
    g_runtimeProbeLogger->info(message.str());
}

void drawDirect3D9OverlaySmokeTest(IDirect3DDevice9* device) {
    const Direct3D9OverlayRect rect{8, 8, 72, 24, 0xFFFF3030};
    const HRESULT result = drawDirect3D9OverlayRect(device, rect);
    if (SUCCEEDED(result)) {
        const LONG hits = InterlockedIncrement(&g_direct3D9OverlaySmokeDrawHits);
        if (hits == 1 && g_runtimeProbeLogger != nullptr) {
            g_runtimeProbeLogger->info("runtime probe: Direct3D9 overlay smoke test draw succeeded");
        }
        return;
    }

    const LONG failures = InterlockedIncrement(&g_direct3D9OverlaySmokeFailureHits);
    if (failures == 1 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: Direct3D9 overlay smoke test draw failed with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result));
        g_runtimeProbeLogger->warn(message.str());
    }
}

void drawDirect3D9TrackingTargetOverlayTest(IDirect3DDevice9* device) {
    if (!g_direct3D9OverlayTransform.trackingTargetOverlayTest) {
        return;
    }

    const TrackingTargetSnapshot target = currentTrackingTargetSnapshot();
    if (!target.available) {
        return;
    }
    rememberTrackingTargetReference(target);

    const CameraTrackingSnapshot camera = currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot);
    if (!camera.available) {
        return;
    }

    UINT renderTargetWidth = 0;
    UINT renderTargetHeight = 0;
    if (!getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return;
    }

    const int screenX = (static_cast<int>(renderTargetWidth) / 2)
        - camera.xPixels
        + target.centerX
        + g_direct3D9OverlayTransform.offsetX;
    const int screenY = (static_cast<int>(renderTargetHeight) / 2)
        - camera.yPixels
        + target.centerY
        + g_direct3D9OverlayTransform.offsetY;

    constexpr LONG halfLength = 8;
    constexpr LONG halfThickness = 2;
    constexpr D3DCOLOR color = 0xFF00FFFF;

    const Direct3D9OverlayRect horizontal{
        static_cast<LONG>(screenX - halfLength),
        static_cast<LONG>(screenY - halfThickness),
        static_cast<LONG>(screenX + halfLength + 1),
        static_cast<LONG>(screenY + halfThickness + 1),
        color,
    };
    const Direct3D9OverlayRect vertical{
        static_cast<LONG>(screenX - halfThickness),
        static_cast<LONG>(screenY - halfLength),
        static_cast<LONG>(screenX + halfThickness + 1),
        static_cast<LONG>(screenY + halfLength + 1),
        color,
    };

    HRESULT firstFailure = drawDirect3D9OverlayRect(device, horizontal);
    const HRESULT secondResult = drawDirect3D9OverlayRect(device, vertical);
    if (SUCCEEDED(secondResult) && FAILED(firstFailure)) {
        firstFailure = secondResult;
    }

    if (SUCCEEDED(firstFailure) || SUCCEEDED(secondResult)) {
        InterlockedIncrement(&g_direct3D9TrackingTargetOverlayDrawHits);
        logTrackingTargetOverlay(target, screenX, screenY);
        return;
    }

    if (g_runtimeProbeLogger != nullptr && g_direct3D9TrackingTargetOverlayDrawHits == 0) {
        std::ostringstream message;
        message << "runtime probe: Direct3D9 tracking target overlay failed with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(firstFailure));
        g_runtimeProbeLogger->warn(message.str());
    }
}

void drawDirect3D9CameraTargetCallOverlayTest(IDirect3DDevice9* device) {
    if (!g_direct3D9OverlayTransform.trackingTargetOverlayTest) {
        return;
    }

    const CameraTrackingSnapshot camera = currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot);
    if (!camera.available) {
        return;
    }

    UINT renderTargetWidth = 0;
    UINT renderTargetHeight = 0;
    if (!getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return;
    }

    constexpr DWORD kSampleVisibleMilliseconds = 2000;
    const DWORD now = GetTickCount();
    const std::array<D3DCOLOR, 12> colors = {{
        D3DCOLOR_ARGB(255, 0, 255, 255),
        D3DCOLOR_ARGB(255, 255, 255, 0),
        D3DCOLOR_ARGB(255, 0, 255, 0),
        D3DCOLOR_ARGB(255, 255, 128, 0),
        D3DCOLOR_ARGB(255, 64, 160, 255),
        D3DCOLOR_ARGB(255, 255, 64, 192),
        D3DCOLOR_ARGB(255, 160, 255, 64),
        D3DCOLOR_ARGB(255, 255, 64, 64),
        D3DCOLOR_ARGB(255, 160, 96, 255),
        D3DCOLOR_ARGB(255, 64, 255, 192),
        D3DCOLOR_ARGB(255, 255, 192, 64),
        D3DCOLOR_ARGB(255, 192, 192, 192),
    }};

    for (std::size_t index = 0; index < g_cameraTargetCallSamples.size(); ++index) {
        const CameraTargetCallSample& sample = g_cameraTargetCallSamples[index];
        if (sample.callerRva == 0 || sample.tick == 0) {
            continue;
        }

        const DWORD age = now - static_cast<DWORD>(sample.tick);
        if (age > kSampleVisibleMilliseconds) {
            continue;
        }

        const int screenX = (static_cast<int>(renderTargetWidth) / 2)
            - camera.xPixels
            + static_cast<int>(sample.xPixels)
            + g_direct3D9OverlayTransform.offsetX;
        const int screenY = (static_cast<int>(renderTargetHeight) / 2)
            - camera.yPixels
            + static_cast<int>(sample.yPixels)
            + g_direct3D9OverlayTransform.offsetY;

        if (screenX < -32 || screenY < -32
            || screenX > static_cast<int>(renderTargetWidth) + 32
            || screenY > static_cast<int>(renderTargetHeight) + 32) {
            continue;
        }

        const D3DCOLOR color = colors[index % colors.size()];
        const Direct3D9OverlayRect horizontal = {
            static_cast<LONG>(screenX - 9),
            static_cast<LONG>(screenY - 2),
            static_cast<LONG>(screenX + 10),
            static_cast<LONG>(screenY + 3),
            color
        };
        const Direct3D9OverlayRect vertical = {
            static_cast<LONG>(screenX - 2),
            static_cast<LONG>(screenY - 9),
            static_cast<LONG>(screenX + 3),
            static_cast<LONG>(screenY + 10),
            color
        };

        drawDirect3D9OverlayRect(device, horizontal);
        drawDirect3D9OverlayRect(device, vertical);
    }
}

void drawDirect3D9WormLiveSamplesOverlayTest(IDirect3DDevice9* device) {
    if (!g_direct3D9OverlayTransform.trackingTargetOverlayTest) {
        return;
    }

    const CameraTrackingSnapshot camera = currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot);
    if (!camera.available) {
        return;
    }

    UINT renderTargetWidth = 0;
    UINT renderTargetHeight = 0;
    if (!getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return;
    }

    constexpr DWORD kSampleVisibleMilliseconds = 120000;
    constexpr D3DCOLOR color = D3DCOLOR_ARGB(180, 0, 255, 64);
    constexpr D3DCOLOR primaryColor = D3DCOLOR_ARGB(220, 255, 160, 0);
    const DWORD now = GetTickCount();
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddress = sample.ownerAddress;
        const DWORD sampleTick = static_cast<DWORD>(sample.lastPollTick != 0 ? sample.lastPollTick : sample.tick);
        const DWORD age = now - sampleTick;
        if (ownerAddress == 0 || sampleTick == 0 || age > kSampleVisibleMilliseconds || sample.aliveFlag == 0) {
            continue;
        }

        const int xPixels = static_cast<int>(sample.xPixels);
        const int yPixels = static_cast<int>(sample.yPixels);
        const int screenX = (static_cast<int>(renderTargetWidth) / 2)
            - camera.xPixels
            + xPixels
            + g_direct3D9OverlayTransform.offsetX;
        const int screenY = (static_cast<int>(renderTargetHeight) / 2)
            - camera.yPixels
            + yPixels
            + g_direct3D9OverlayTransform.offsetY;

        if (screenX < -32 || screenY < -32
            || screenX > static_cast<int>(renderTargetWidth) + 32
            || screenY > static_cast<int>(renderTargetHeight) + 32) {
            continue;
        }

        const Direct3D9OverlayRect horizontal = {
            static_cast<LONG>(screenX - 5),
            static_cast<LONG>(screenY - 1),
            static_cast<LONG>(screenX + 6),
            static_cast<LONG>(screenY + 2),
            color
        };
        const Direct3D9OverlayRect vertical = {
            static_cast<LONG>(screenX - 1),
            static_cast<LONG>(screenY - 5),
            static_cast<LONG>(screenX + 2),
            static_cast<LONG>(screenY + 6),
            color
        };

        drawDirect3D9OverlayRect(device, horizontal);
        drawDirect3D9OverlayRect(device, vertical);

        LONG primaryXFixed = 0;
        LONG primaryYFixed = 0;
        if (ownerAddress == activeOwnerAddress && g_activeWormCandidateOffsetValid != 0) {
            continue;
        }

        if (!readWormOwnerPrimaryFixed(static_cast<std::uintptr_t>(ownerAddress), primaryXFixed, primaryYFixed)
            && !wormSampleRecentCachedPrimaryFixed(sample, primaryXFixed, primaryYFixed)) {
            continue;
        }

        const int primaryScreenX = (static_cast<int>(renderTargetWidth) / 2)
            - camera.xPixels
            + fixedDeltaToPixels(primaryXFixed)
            + g_direct3D9OverlayTransform.offsetX;
        const int primaryScreenY = (static_cast<int>(renderTargetHeight) / 2)
            - camera.yPixels
            + fixedDeltaToPixels(primaryYFixed)
            + g_direct3D9OverlayTransform.offsetY;

        if (primaryScreenX < -32 || primaryScreenY < -32
            || primaryScreenX > static_cast<int>(renderTargetWidth) + 32
            || primaryScreenY > static_cast<int>(renderTargetHeight) + 32) {
            continue;
        }

        const Direct3D9OverlayRect primaryHorizontal = {
            static_cast<LONG>(primaryScreenX - 6),
            static_cast<LONG>(primaryScreenY - 2),
            static_cast<LONG>(primaryScreenX + 7),
            static_cast<LONG>(primaryScreenY + 3),
            primaryColor
        };
        const Direct3D9OverlayRect primaryVertical = {
            static_cast<LONG>(primaryScreenX - 2),
            static_cast<LONG>(primaryScreenY - 6),
            static_cast<LONG>(primaryScreenX + 3),
            static_cast<LONG>(primaryScreenY + 7),
            primaryColor
        };

        drawDirect3D9OverlayRect(device, primaryHorizontal);
        drawDirect3D9OverlayRect(device, primaryVertical);
    }
}

void drawDirect3D9ActiveWormCandidateOverlayTest(IDirect3DDevice9* device) {
    if (!g_direct3D9OverlayTransform.trackingTargetOverlayTest) {
        return;
    }

    refreshActiveWormCandidateFromTrackingTarget();

    const LONG ownerAddress = g_activeWormCandidateOwnerAddress;
    if (g_activeWormCandidateOffsetValid == 0) {
        const DWORD now = GetTickCount();
        const DWORD previousScan = static_cast<DWORD>(g_activeWormCandidateScanTick);
        if (ownerAddress != 0 && (previousScan == 0 || now - previousScan >= 250)) {
            InterlockedExchange(&g_activeWormCandidateScanTick, static_cast<LONG>(now));
            discoverActiveWormCoordinateOffsetsFromOwner(
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(ownerAddress)));
        }
    }

    if (g_activeWormCandidateOffsetValid == 0) {
        return;
    }

    const LONG baseAddress = g_activeWormCandidateBaseAddress;
    const LONG xOffset = g_activeWormCandidateXOffset;
    const LONG yOffset = g_activeWormCandidateYOffset;
    if (ownerAddress == 0 || baseAddress == 0 || xOffset < 0 || yOffset < 0) {
        return;
    }

    const CameraTrackingSnapshot camera = currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot);
    if (!camera.available) {
        return;
    }

    UINT renderTargetWidth = 0;
    UINT renderTargetHeight = 0;
    if (!getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return;
    }

    LONG xFixed = 0;
    LONG yFixed = 0;
    if (!readActiveWormCandidateFixed(xFixed, yFixed)) {
        if (g_activeWormCandidateSourceKind != 4) {
            invalidateActiveWormCoordinateCandidate();
        }
        return;
    }

    const int xPixels = fixedDeltaToPixels(xFixed);
    const int yPixels = fixedDeltaToPixels(yFixed);
    const int screenX = (static_cast<int>(renderTargetWidth) / 2)
        - camera.xPixels
        + xPixels
        + g_direct3D9OverlayTransform.offsetX;
    const int screenY = (static_cast<int>(renderTargetHeight) / 2)
        - camera.yPixels
        + yPixels
        + g_direct3D9OverlayTransform.offsetY;

    if (screenX < -64 || screenY < -64
        || screenX > static_cast<int>(renderTargetWidth) + 64
        || screenY > static_cast<int>(renderTargetHeight) + 64) {
        return;
    }

    constexpr D3DCOLOR color = D3DCOLOR_ARGB(255, 255, 255, 255);
    const Direct3D9OverlayRect horizontal = {
        static_cast<LONG>(screenX - 12),
        static_cast<LONG>(screenY - 3),
        static_cast<LONG>(screenX + 13),
        static_cast<LONG>(screenY + 4),
        color
    };
    const Direct3D9OverlayRect vertical = {
        static_cast<LONG>(screenX - 3),
        static_cast<LONG>(screenY - 12),
        static_cast<LONG>(screenX + 4),
        static_cast<LONG>(screenY + 13),
        color
    };

    drawDirect3D9OverlayRect(device, horizontal);
    drawDirect3D9OverlayRect(device, vertical);

    const LONG previousX = g_activeWormCandidateLastXFixed;
    const LONG previousY = g_activeWormCandidateLastYFixed;
    const int distance = std::abs(xPixels - fixedDeltaToPixels(previousX))
        + std::abs(yPixels - fixedDeltaToPixels(previousY));
    if (distance >= 16 && g_runtimeProbeLogger != nullptr && g_activeWormCandidatePollLogCount < 48) {
        InterlockedExchange(&g_activeWormCandidateLastXFixed, xFixed);
        InterlockedExchange(&g_activeWormCandidateLastYFixed, yFixed);
        InterlockedIncrement(&g_activeWormCandidatePollLogCount);

        std::ostringstream message;
        message << "runtime probe: active worm candidate polled owner "
                << formatAddress(static_cast<std::uintptr_t>(ownerAddress))
                << " base "
                << formatAddress(static_cast<std::uintptr_t>(baseAddress))
                << " source "
                << activeWormCandidateSourceName(g_activeWormCandidateSourceKind)
                << "+"
                << formatAddress(static_cast<std::uintptr_t>(g_activeWormCandidateSourceOffset))
                << " offsets "
                << formatAddress(static_cast<std::uintptr_t>(xOffset))
                << ","
                << formatAddress(static_cast<std::uintptr_t>(yOffset))
                << " fixed "
                << xFixed
                << ","
                << yFixed
                << " pixels "
                << xPixels
                << ","
                << yPixels
                << " screen "
                << screenX
                << ","
                << screenY;
        g_runtimeProbeLogger->info(message.str());
    }
}

bool pointInsideExpandedRect(int x, int y, const Direct3D9OverlayRect& rect, int radius) {
    return x >= rect.left - radius
        && x <= rect.right + radius
        && y >= rect.top - radius
        && y <= rect.bottom + radius;
}

bool clipSegmentAxis(double p, double q, double& t0, double& t1) {
    if (p == 0.0) {
        return q >= 0.0;
    }

    const double r = q / p;
    if (p < 0.0) {
        if (r > t1) {
            return false;
        }
        if (r > t0) {
            t0 = r;
        }
    } else {
        if (r < t0) {
            return false;
        }
        if (r < t1) {
            t1 = r;
        }
    }

    return true;
}

bool segmentIntersectsExpandedRect(
    int x0,
    int y0,
    int x1,
    int y1,
    const Direct3D9OverlayRect& rect,
    int radius) {
    if (pointInsideExpandedRect(x0, y0, rect, radius)
        || pointInsideExpandedRect(x1, y1, rect, radius)) {
        return true;
    }

    const double left = static_cast<double>(rect.left - radius);
    const double right = static_cast<double>(rect.right + radius);
    const double top = static_cast<double>(rect.top - radius);
    const double bottom = static_cast<double>(rect.bottom + radius);
    const double dx = static_cast<double>(x1 - x0);
    const double dy = static_cast<double>(y1 - y0);

    double t0 = 0.0;
    double t1 = 1.0;
    return clipSegmentAxis(-dx, static_cast<double>(x0) - left, t0, t1)
        && clipSegmentAxis(dx, right - static_cast<double>(x0), t0, t1)
        && clipSegmentAxis(-dy, static_cast<double>(y0) - top, t0, t1)
        && clipSegmentAxis(dy, bottom - static_cast<double>(y0), t0, t1);
}

bool rangesOverlap(int leftA, int rightA, int leftB, int rightB) {
    return leftA <= rightB && leftB <= rightA;
}

bool bounceNearExpandedRect(
    int olderX,
    int olderY,
    int previousX,
    int previousY,
    int currentX,
    int currentY,
    const Direct3D9OverlayRect& rect,
    int radius) {
    const int beforeX = previousX - olderX;
    const int afterX = currentX - previousX;
    const int beforeY = previousY - olderY;
    const int afterY = currentY - previousY;
    const int minVelocity = kMinWallTouchBounceVelocityPixels;

    const int minX = std::min(olderX, std::min(previousX, currentX));
    const int maxX = std::max(olderX, std::max(previousX, currentX));
    const int minY = std::min(olderY, std::min(previousY, currentY));
    const int maxY = std::max(olderY, std::max(previousY, currentY));

    const bool yOverlapsWall = rangesOverlap(
        minY,
        maxY,
        static_cast<int>(rect.top) - radius,
        static_cast<int>(rect.bottom) + radius);
    if (yOverlapsWall && beforeX > minVelocity && afterX < -minVelocity) {
        const int distance = static_cast<int>(rect.left) - maxX;
        if (distance >= 0 && distance <= radius) {
            return true;
        }
    }
    if (yOverlapsWall && beforeX < -minVelocity && afterX > minVelocity) {
        const int distance = minX - static_cast<int>(rect.right);
        if (distance >= 0 && distance <= radius) {
            return true;
        }
    }

    const bool xOverlapsWall = rangesOverlap(
        minX,
        maxX,
        static_cast<int>(rect.left) - radius,
        static_cast<int>(rect.right) + radius);
    if (xOverlapsWall && beforeY > minVelocity && afterY < -minVelocity) {
        const int distance = static_cast<int>(rect.top) - maxY;
        if (distance >= 0 && distance <= radius) {
            return true;
        }
    }
    if (xOverlapsWall && beforeY < -minVelocity && afterY > minVelocity) {
        const int distance = minY - static_cast<int>(rect.bottom);
        if (distance >= 0 && distance <= radius) {
            return true;
        }
    }

    return false;
}

void updateTouchedOverlayWallsFromActiveWorm() {
    if (g_direct3D9OverlayTestRects.empty()) {
        return;
    }

    resetTouchedOverlayWallsWhenActiveTeamChanges();
    refreshActiveWormCandidateFromTrackingTarget();

    int olderX = 0;
    int olderY = 0;
    int previousX = 0;
    int previousY = 0;
    int activeX = 0;
    int activeY = 0;
    bool hasOlder = false;
    if (!readActiveWormCandidateSweepPixels(
            olderX,
            olderY,
            previousX,
            previousY,
            activeX,
            activeY,
            hasOlder)) {
        return;
    }

    const int touchRadius = g_direct3D9OverlayTransform.touchRadiusPixels;
    const int bounceRadius = std::max(touchRadius, kWallTouchBounceRadiusPixels);
    const int movementDistance = std::abs(activeX - previousX) + std::abs(activeY - previousY);
    const bool canUseSweep = movementDistance > 0 && movementDistance <= kMaxWallTouchSweepPixels;
    const int olderMovementDistance = std::abs(previousX - olderX) + std::abs(previousY - olderY);
    const bool canUseBounce = hasOlder
        && movementDistance > 0
        && olderMovementDistance > 0
        && movementDistance <= kMaxWallTouchSweepPixels
        && olderMovementDistance <= kMaxWallTouchSweepPixels;
    for (Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (rect.touched) {
            continue;
        }

        const bool pointTouch = pointInsideExpandedRect(activeX, activeY, rect, touchRadius);
        const bool sweepTouch = !pointTouch
            && canUseSweep
            && segmentIntersectsExpandedRect(previousX, previousY, activeX, activeY, rect, touchRadius);
        const bool bounceTouch = !pointTouch
            && !sweepTouch
            && canUseBounce
            && bounceNearExpandedRect(olderX, olderY, previousX, previousY, activeX, activeY, rect, bounceRadius);
        if (!pointTouch && !sweepTouch && !bounceTouch) {
            continue;
        }

        rect.touched = true;
        if (g_runtimeProbeLogger != nullptr && g_direct3D9WallTouchLogCount < 64) {
            InterlockedIncrement(&g_direct3D9WallTouchLogCount);

            std::ostringstream message;
            message << "runtime probe: wall touched by active worm, wall "
                    << rect.wallIndex
                    << " method "
                    << (bounceTouch ? "bounce" : (sweepTouch ? "sweep" : "point"))
                    << " rect "
                    << rect.left
                    << ","
                    << rect.top
                    << "-"
                    << rect.right
                    << ","
                    << rect.bottom
                    << " active "
                    << activeX
                    << ","
                    << activeY
                    << " previous "
                    << previousX
                    << ","
                    << previousY
                    << " older "
                    << olderX
                    << ","
                    << olderY
                    << " movement "
                    << movementDistance
                    << " olderMovement "
                    << olderMovementDistance
                    << " radius "
                    << touchRadius
                    << " bounceRadius "
                    << bounceRadius;
            g_runtimeProbeLogger->info(message.str());
        }
    }
}

void drawDirect3D9OverlayTestRects(IDirect3DDevice9* device) {
    if (g_direct3D9OverlayTestRects.empty()) {
        return;
    }

    updateTouchedOverlayWallsFromActiveWorm();

    UINT renderTargetWidth = 0;
    UINT renderTargetHeight = 0;
    int baseY = direct3D9OverlayBaseY(device, renderTargetWidth, renderTargetHeight);
    int baseX = direct3D9OverlayBaseX(device, renderTargetWidth, renderTargetHeight);
    const CameraTrackingSnapshot camera = g_direct3D9OverlayTransform.cameraFollow
        ? currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot)
        : CameraTrackingSnapshot{};
    if (g_direct3D9OverlayTransform.cameraFollow && camera.available) {
        if ((renderTargetWidth == 0 || renderTargetHeight == 0)
            && !getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
            logDirect3D9OverlayTransform(renderTargetWidth, renderTargetHeight, baseX, baseY, camera);
            return;
        }

        baseX = (static_cast<int>(renderTargetWidth) / 2)
            - camera.xPixels
            + g_direct3D9OverlayTransform.offsetX;
        baseY = (static_cast<int>(renderTargetHeight) / 2)
            - camera.yPixels
            + g_direct3D9OverlayTransform.offsetY;
    }
    logDirect3D9OverlayTransform(renderTargetWidth, renderTargetHeight, baseX, baseY, camera);

    std::size_t drawn = 0;
    HRESULT firstFailure = S_OK;

    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        const D3DCOLOR color = rect.touched ? rect.touchedColor : rect.color;
        const Direct3D9OverlayRect transformedRect{
            static_cast<LONG>(scaledOverlayCoordinate(rect.left) + baseX),
            static_cast<LONG>(scaledOverlayCoordinate(rect.top) + baseY),
            static_cast<LONG>(scaledOverlayCoordinate(rect.right) + baseX),
            static_cast<LONG>(scaledOverlayCoordinate(rect.bottom) + baseY),
            color,
            rect.touchedColor,
            rect.wallIndex,
            rect.touched,
        };
        const HRESULT result = drawDirect3D9OverlayRect(device, transformedRect);
        if (SUCCEEDED(result)) {
            ++drawn;
        } else if (SUCCEEDED(firstFailure)) {
            firstFailure = result;
        }
    }

    if (drawn > 0) {
        const LONG hits = InterlockedIncrement(&g_direct3D9MetadataOverlayDrawHits);
        if (hits == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: Direct3D9 metadata overlay drew "
                    << drawn
                    << " rect(s)";
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }

    if (FAILED(firstFailure)) {
        const LONG failures = InterlockedIncrement(&g_direct3D9MetadataOverlayFailureHits);
        if (failures == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: Direct3D9 metadata overlay failed with HRESULT "
                    << formatHex32(static_cast<std::uint32_t>(firstFailure));
            g_runtimeProbeLogger->warn(message.str());
        }
    }
}

void resetDirect3D9DeviceProbeState() {
    g_direct3D9DeviceProbe.device = nullptr;
    g_direct3D9DeviceProbe.originalVtable = nullptr;
    g_direct3D9DeviceProbe.probeVtable = nullptr;
    g_direct3D9DeviceProbe.originalRelease = nullptr;
    g_direct3D9DeviceProbe.originalReset = nullptr;
    g_direct3D9DeviceProbe.originalPresent = nullptr;
    g_direct3D9DeviceProbe.originalEndScene = nullptr;
    InterlockedExchange(&g_direct3D9DeviceProbe.presentHits, 0);
    InterlockedExchange(&g_direct3D9DeviceProbe.endSceneHits, 0);
    InterlockedExchange(&g_direct3D9DeviceProbe.resetHits, 0);
    InterlockedExchange(&g_direct3D9DeviceProbe.releaseHits, 0);
}

bool writeDirect3D9DeviceVtableSlot(std::uintptr_t* vtable, std::size_t index, std::uintptr_t value) {
    if (vtable == nullptr) {
        return false;
    }

    std::uintptr_t* slot = &vtable[index];
    DWORD oldProtect = 0;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &oldProtect)) {
        return false;
    }

    *slot = value;

    DWORD ignoredProtect = 0;
    VirtualProtect(slot, sizeof(*slot), oldProtect, &ignoredProtect);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));
    return true;
}

bool installDirect3D9DeviceProbe(IDirect3DDevice9* device) {
    if (device == nullptr) {
        return false;
    }

    if (InterlockedCompareExchange(&g_direct3D9DeviceProbeInstallLock, 1, 0) != 0) {
        return false;
    }

    if (g_direct3D9DeviceProbe.device != nullptr) {
        const LONG skippedHits = InterlockedIncrement(&g_direct3D9DeviceProbeSkippedHits);
        if (skippedHits == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: IDirect3DDevice9 probe already installed for "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(g_direct3D9DeviceProbe.device))
                    << "; skipping device "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(device));
            g_runtimeProbeLogger->info(message.str());
        }

        InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);
        return false;
    }

    auto** objectVtableSlot = reinterpret_cast<std::uintptr_t**>(device);
    std::uintptr_t* originalVtable = *objectVtableSlot;
    if (originalVtable == nullptr) {
        if (g_runtimeProbeLogger != nullptr) {
            g_runtimeProbeLogger->warn("runtime probe: IDirect3DDevice9 probe failed; original vtable is null");
        }

        InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);
        return false;
    }

    if (g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9 vtable survey: device "
                << formatAddress(reinterpret_cast<std::uintptr_t>(device))
                << ", vtable "
                << formatAddress(reinterpret_cast<std::uintptr_t>(originalVtable));
        appendVtableEntry(message, "Reset", originalVtable, kD3D9DeviceResetIndex);
        appendVtableEntry(message, "Present", originalVtable, kD3D9DevicePresentIndex);
        appendVtableEntry(message, "BeginScene", originalVtable, kD3D9DeviceBeginSceneIndex);
        appendVtableEntry(message, "EndScene", originalVtable, kD3D9DeviceEndSceneIndex);
        g_runtimeProbeLogger->info(message.str());
    }

    g_direct3D9DeviceProbe.originalReset =
        reinterpret_cast<D3D9DeviceResetFunction>(originalVtable[kD3D9DeviceResetIndex]);
    g_direct3D9DeviceProbe.originalPresent =
        reinterpret_cast<D3D9DevicePresentFunction>(originalVtable[kD3D9DevicePresentIndex]);
    g_direct3D9DeviceProbe.originalEndScene =
        reinterpret_cast<D3D9DeviceEndSceneFunction>(originalVtable[kD3D9DeviceEndSceneIndex]);

    if (g_direct3D9DeviceSlotProbeEnabled) {
        const bool resetPatched = writeDirect3D9DeviceVtableSlot(
            originalVtable,
            kD3D9DeviceResetIndex,
            reinterpret_cast<std::uintptr_t>(&hookedD3D9DeviceReset));
        const bool presentPatched = resetPatched && writeDirect3D9DeviceVtableSlot(
            originalVtable,
            kD3D9DevicePresentIndex,
            reinterpret_cast<std::uintptr_t>(&hookedD3D9DevicePresent));
        const bool endScenePatched = presentPatched && writeDirect3D9DeviceVtableSlot(
            originalVtable,
            kD3D9DeviceEndSceneIndex,
            reinterpret_cast<std::uintptr_t>(&hookedD3D9DeviceEndScene));

        if (!endScenePatched) {
            if (presentPatched) {
                writeDirect3D9DeviceVtableSlot(
                    originalVtable,
                    kD3D9DevicePresentIndex,
                    reinterpret_cast<std::uintptr_t>(g_direct3D9DeviceProbe.originalPresent));
            }
            if (resetPatched) {
                writeDirect3D9DeviceVtableSlot(
                    originalVtable,
                    kD3D9DeviceResetIndex,
                    reinterpret_cast<std::uintptr_t>(g_direct3D9DeviceProbe.originalReset));
            }

            resetDirect3D9DeviceProbeState();
            if (g_runtimeProbeLogger != nullptr) {
                g_runtimeProbeLogger->warn("runtime probe: IDirect3DDevice9 vtable slot probe failed; no device patch installed");
            }

            InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);
            return false;
        }

        g_direct3D9DeviceProbe.device = device;
        g_direct3D9DeviceProbe.originalVtable = originalVtable;
        g_direct3D9DeviceProbe.probeVtable = nullptr;
        InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);

        if (g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: IDirect3DDevice9 vtable slot probe installed for "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(device))
                    << "; private vtable tail preserved";
            g_runtimeProbeLogger->info(message.str());
        }

        return true;
    }

    resetDirect3D9DeviceProbeState();

    if (!kEnableUnsafeD3D9DeviceShadowVtableProbe) {
        if (g_runtimeProbeLogger != nullptr) {
            g_runtimeProbeLogger->info("runtime probe: IDirect3DDevice9 device slot probe disabled; no device patch installed");
        }

        InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);
        return false;
    }

    std::uintptr_t* probeVtable = new (std::nothrow) std::uintptr_t[kD3D9DeviceVtableSize];
    if (probeVtable == nullptr) {
        if (g_runtimeProbeLogger != nullptr) {
            g_runtimeProbeLogger->warn("runtime probe: IDirect3DDevice9 probe failed; vtable allocation failed");
        }

        InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);
        return false;
    }

    std::memcpy(probeVtable, originalVtable, sizeof(std::uintptr_t) * kD3D9DeviceVtableSize);

    g_direct3D9DeviceProbe.originalRelease =
        reinterpret_cast<D3D9DeviceReleaseFunction>(originalVtable[kD3D9DeviceReleaseIndex]);
    g_direct3D9DeviceProbe.originalReset =
        reinterpret_cast<D3D9DeviceResetFunction>(originalVtable[kD3D9DeviceResetIndex]);
    g_direct3D9DeviceProbe.originalPresent =
        reinterpret_cast<D3D9DevicePresentFunction>(originalVtable[kD3D9DevicePresentIndex]);
    g_direct3D9DeviceProbe.originalEndScene =
        reinterpret_cast<D3D9DeviceEndSceneFunction>(originalVtable[kD3D9DeviceEndSceneIndex]);

    probeVtable[kD3D9DeviceReleaseIndex] = reinterpret_cast<std::uintptr_t>(&hookedD3D9DeviceRelease);
    probeVtable[kD3D9DeviceResetIndex] = reinterpret_cast<std::uintptr_t>(&hookedD3D9DeviceReset);
    probeVtable[kD3D9DevicePresentIndex] = reinterpret_cast<std::uintptr_t>(&hookedD3D9DevicePresent);
    probeVtable[kD3D9DeviceEndSceneIndex] = reinterpret_cast<std::uintptr_t>(&hookedD3D9DeviceEndScene);

    DWORD oldProtect = 0;
    if (!VirtualProtect(objectVtableSlot, sizeof(*objectVtableSlot), PAGE_READWRITE, &oldProtect)) {
        delete[] probeVtable;
        resetDirect3D9DeviceProbeState();
        if (g_runtimeProbeLogger != nullptr) {
            g_runtimeProbeLogger->warn("runtime probe: IDirect3DDevice9 probe failed; object vtable slot is not writable");
        }

        InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);
        return false;
    }

    *objectVtableSlot = probeVtable;

    DWORD ignoredProtect = 0;
    VirtualProtect(objectVtableSlot, sizeof(*objectVtableSlot), oldProtect, &ignoredProtect);

    g_direct3D9DeviceProbe.device = device;
    g_direct3D9DeviceProbe.originalVtable = originalVtable;
    g_direct3D9DeviceProbe.probeVtable = probeVtable;
    InterlockedExchange(&g_direct3D9DeviceProbeInstallLock, 0);

    if (g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9 vtable probe installed for "
                << formatAddress(reinterpret_cast<std::uintptr_t>(device))
                << "; original vtable "
                << formatAddress(reinterpret_cast<std::uintptr_t>(originalVtable))
                << ", probe vtable "
                << formatAddress(reinterpret_cast<std::uintptr_t>(probeVtable));
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

ULONG STDMETHODCALLTYPE hookedD3D9DeviceRelease(IDirect3DDevice9* device) noexcept {
    const LONG hits = InterlockedIncrement(&g_direct3D9DeviceProbe.releaseHits);
    D3D9DeviceReleaseFunction originalRelease = g_direct3D9DeviceProbe.originalRelease;
    if (originalRelease == nullptr) {
        return 0;
    }

    ULONG result = originalRelease(device);
    if ((hits <= 4 || result == 0) && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9::Release hook fired: device "
                << formatAddress(reinterpret_cast<std::uintptr_t>(device))
                << ", refCount " << result;
        g_runtimeProbeLogger->info(message.str());
    }

    if (result == 0 && device == g_direct3D9DeviceProbe.device) {
        std::uintptr_t* probeVtable = g_direct3D9DeviceProbe.probeVtable;
        resetDirect3D9DeviceProbeState();
        delete[] probeVtable;
        InterlockedExchange(&g_direct3D9DeviceProbeSkippedHits, 0);
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedD3D9DeviceReset(
    IDirect3DDevice9* device,
    D3DPRESENT_PARAMETERS* presentationParameters) noexcept {
    const LONG hits = InterlockedIncrement(&g_direct3D9DeviceProbe.resetHits);
    if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9::Reset hook fired: device "
                << formatAddress(reinterpret_cast<std::uintptr_t>(device));
        appendPresentParametersSummary(message, presentationParameters);
        g_runtimeProbeLogger->info(message.str());
    }

    D3D9DeviceResetFunction originalReset = g_direct3D9DeviceProbe.originalReset;
    if (originalReset == nullptr) {
        return D3DERR_INVALIDCALL;
    }

    resetTransientGameplayTrackingState();

    HRESULT result = originalReset(device, presentationParameters);
    if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9::Reset returned HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result));
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedD3D9DevicePresent(
    IDirect3DDevice9* device,
    const RECT* sourceRect,
    const RECT* destinationRect,
    HWND destinationWindowOverride,
    const RGNDATA* dirtyRegion) noexcept {
    const LONG hits = InterlockedIncrement(&g_direct3D9DeviceProbe.presentHits);
    if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9::Present hook fired: device "
                << formatAddress(reinterpret_cast<std::uintptr_t>(device))
                << ", sourceRect " << formatRectPointer(sourceRect)
                << ", destinationRect " << formatRectPointer(destinationRect)
                << ", destinationWindowOverride "
                << formatAddress(reinterpret_cast<std::uintptr_t>(destinationWindowOverride))
                << ", dirtyRegion "
                << formatAddress(reinterpret_cast<std::uintptr_t>(dirtyRegion));
        g_runtimeProbeLogger->info(message.str());
    }

    D3D9DevicePresentFunction originalPresent = g_direct3D9DeviceProbe.originalPresent;
    if (originalPresent == nullptr) {
        return D3DERR_INVALIDCALL;
    }

    return originalPresent(device, sourceRect, destinationRect, destinationWindowOverride, dirtyRegion);
}

HRESULT STDMETHODCALLTYPE hookedD3D9DeviceEndScene(IDirect3DDevice9* device) noexcept {
    const LONG hits = InterlockedIncrement(&g_direct3D9DeviceProbe.endSceneHits);
    if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirect3DDevice9::EndScene hook fired: device "
                << formatAddress(reinterpret_cast<std::uintptr_t>(device));
        g_runtimeProbeLogger->info(message.str());
    }

    D3D9DeviceEndSceneFunction originalEndScene = g_direct3D9DeviceProbe.originalEndScene;
    if (originalEndScene == nullptr) {
        return D3DERR_INVALIDCALL;
    }

    if (g_direct3D9OverlaySmokeTestEnabled) {
        drawDirect3D9OverlaySmokeTest(device);
    }

    pollWormLiveSamplesFromMemory();
    drawDirect3D9OverlayTestRects(device);
    drawDirect3D9TrackingTargetOverlayTest(device);
    drawDirect3D9CameraTargetCallOverlayTest(device);
    drawDirect3D9WormLiveSamplesOverlayTest(device);
    drawDirect3D9ActiveWormCandidateOverlayTest(device);

    return originalEndScene(device);
}

class Direct3D9ProbeProxy final : public IDirect3D9 {
public:
    explicit Direct3D9ProbeProxy(IDirect3D9* original)
        : original_(original) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** object) noexcept override {
        if (object == nullptr) {
            return E_POINTER;
        }

        if (sameGuid(riid, kIUnknownGuid) || sameGuid(riid, kIDirect3D9Guid)) {
            *object = static_cast<IDirect3D9*>(this);
            AddRef();
            return S_OK;
        }

        return original_->QueryInterface(riid, object);
    }

    ULONG STDMETHODCALLTYPE AddRef() noexcept override {
        return static_cast<ULONG>(InterlockedIncrement(&refCount_));
    }

    ULONG STDMETHODCALLTYPE Release() noexcept override {
        const LONG count = InterlockedDecrement(&refCount_);
        if (count == 0) {
            delete this;
            return 0;
        }
        return static_cast<ULONG>(count);
    }

    HRESULT STDMETHODCALLTYPE RegisterSoftwareDevice(void* initializeFunction) noexcept override {
        return original_->RegisterSoftwareDevice(initializeFunction);
    }

    UINT STDMETHODCALLTYPE GetAdapterCount() noexcept override {
        return original_->GetAdapterCount();
    }

    HRESULT STDMETHODCALLTYPE GetAdapterIdentifier(
        UINT adapter,
        DWORD flags,
        D3DADAPTER_IDENTIFIER9* identifier) noexcept override {
        return original_->GetAdapterIdentifier(adapter, flags, identifier);
    }

    UINT STDMETHODCALLTYPE GetAdapterModeCount(UINT adapter, D3DFORMAT format) noexcept override {
        return original_->GetAdapterModeCount(adapter, format);
    }

    HRESULT STDMETHODCALLTYPE EnumAdapterModes(
        UINT adapter,
        D3DFORMAT format,
        UINT mode,
        D3DDISPLAYMODE* displayMode) noexcept override {
        return original_->EnumAdapterModes(adapter, format, mode, displayMode);
    }

    HRESULT STDMETHODCALLTYPE GetAdapterDisplayMode(UINT adapter, D3DDISPLAYMODE* displayMode) noexcept override {
        return original_->GetAdapterDisplayMode(adapter, displayMode);
    }

    HRESULT STDMETHODCALLTYPE CheckDeviceType(
        UINT adapter,
        D3DDEVTYPE deviceType,
        D3DFORMAT displayFormat,
        D3DFORMAT backBufferFormat,
        WINBOOL windowed) noexcept override {
        return original_->CheckDeviceType(adapter, deviceType, displayFormat, backBufferFormat, windowed);
    }

    HRESULT STDMETHODCALLTYPE CheckDeviceFormat(
        UINT adapter,
        D3DDEVTYPE deviceType,
        D3DFORMAT adapterFormat,
        DWORD usage,
        D3DRESOURCETYPE resourceType,
        D3DFORMAT checkFormat) noexcept override {
        return original_->CheckDeviceFormat(adapter, deviceType, adapterFormat, usage, resourceType, checkFormat);
    }

    HRESULT STDMETHODCALLTYPE CheckDeviceMultiSampleType(
        UINT adapter,
        D3DDEVTYPE deviceType,
        D3DFORMAT surfaceFormat,
        WINBOOL windowed,
        D3DMULTISAMPLE_TYPE multiSampleType,
        DWORD* qualityLevels) noexcept override {
        return original_->CheckDeviceMultiSampleType(
            adapter,
            deviceType,
            surfaceFormat,
            windowed,
            multiSampleType,
            qualityLevels);
    }

    HRESULT STDMETHODCALLTYPE CheckDepthStencilMatch(
        UINT adapter,
        D3DDEVTYPE deviceType,
        D3DFORMAT adapterFormat,
        D3DFORMAT renderTargetFormat,
        D3DFORMAT depthStencilFormat) noexcept override {
        return original_->CheckDepthStencilMatch(
            adapter,
            deviceType,
            adapterFormat,
            renderTargetFormat,
            depthStencilFormat);
    }

    HRESULT STDMETHODCALLTYPE CheckDeviceFormatConversion(
        UINT adapter,
        D3DDEVTYPE deviceType,
        D3DFORMAT sourceFormat,
        D3DFORMAT targetFormat) noexcept override {
        return original_->CheckDeviceFormatConversion(adapter, deviceType, sourceFormat, targetFormat);
    }

    HRESULT STDMETHODCALLTYPE GetDeviceCaps(UINT adapter, D3DDEVTYPE deviceType, D3DCAPS9* caps) noexcept override {
        return original_->GetDeviceCaps(adapter, deviceType, caps);
    }

    HMONITOR STDMETHODCALLTYPE GetAdapterMonitor(UINT adapter) noexcept override {
        return original_->GetAdapterMonitor(adapter);
    }

    HRESULT STDMETHODCALLTYPE CreateDevice(
        UINT adapter,
        D3DDEVTYPE deviceType,
        HWND focusWindow,
        DWORD behaviorFlags,
        D3DPRESENT_PARAMETERS* presentationParameters,
        IDirect3DDevice9** returnedDeviceInterface) noexcept override {
        const LONG hits = InterlockedIncrement(&g_direct3D9CreateDeviceProbeHits);
        if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: IDirect3D9::CreateDevice hook fired: adapter " << adapter
                    << ", deviceType " << d3dDeviceTypeName(deviceType) << "(" << static_cast<int>(deviceType) << ")"
                    << ", focusWindow " << formatAddress(reinterpret_cast<std::uintptr_t>(focusWindow))
                    << ", behaviorFlags " << formatHex32(static_cast<std::uint32_t>(behaviorFlags));

            appendPresentParametersSummary(message, presentationParameters);
            g_runtimeProbeLogger->info(message.str());
        }

        HRESULT result = original_->CreateDevice(
            adapter,
            deviceType,
            focusWindow,
            behaviorFlags,
            presentationParameters,
            returnedDeviceInterface);

        if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
            IDirect3DDevice9* device = returnedDeviceInterface != nullptr ? *returnedDeviceInterface : nullptr;

            std::ostringstream message;
            message << "runtime probe: IDirect3D9::CreateDevice returned HRESULT "
                    << formatHex32(static_cast<std::uint32_t>(result))
                    << ", IDirect3DDevice9 "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(device));
            g_runtimeProbeLogger->info(message.str());
        }

        if (SUCCEEDED(result) && returnedDeviceInterface != nullptr && *returnedDeviceInterface != nullptr) {
            installDirect3D9DeviceProbe(*returnedDeviceInterface);
        }

        return result;
    }

private:
    ~Direct3D9ProbeProxy() {
        if (original_ != nullptr) {
            original_->Release();
            original_ = nullptr;
        }
    }

    IDirect3D9* original_ = nullptr;
    volatile LONG refCount_ = 1;
};

std::string moduleNameFromHandle(HMODULE module) {
    if (module == nullptr) {
        return "null";
    }

    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, static_cast<DWORD>(sizeof(path)))) {
        return formatAddress(reinterpret_cast<std::uintptr_t>(module));
    }

    std::string value = path;
    const std::string::size_type slash = value.find_last_of("\\/");
    if (slash != std::string::npos) {
        value = value.substr(slash + 1);
    }

    return value + "@" + formatAddress(reinterpret_cast<std::uintptr_t>(module));
}

std::string rendererModuleSnapshot() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return "snapshot failed";
    }

    std::vector<std::string> modules;
    MODULEENTRY32 entry = {};
    entry.dwSize = sizeof(entry);
    if (Module32First(snapshot, &entry)) {
        do {
            const std::string moduleName = entry.szModule;
            if (!isRendererModuleName(moduleName)) {
                continue;
            }

            std::ostringstream module;
            module << moduleName << "@" << formatAddress(reinterpret_cast<std::uintptr_t>(entry.modBaseAddr));
            modules.push_back(module.str());
        } while (Module32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (modules.empty()) {
        return "none";
    }

    std::ostringstream result;
    for (std::size_t index = 0; index < modules.size(); ++index) {
        if (index != 0) {
            result << ", ";
        }
        result << modules[index];
    }
    return result.str();
}

DWORD WINAPI rendererModuleProbeThread(LPVOID) {
    if (g_runtimeProbeLogger == nullptr) {
        return 0;
    }

    std::string previousSnapshot;
    for (int sample = 0; sample < 20; ++sample) {
        if (sample != 0) {
            Sleep(1500);
        }

        const std::string snapshot = rendererModuleSnapshot();
        if (snapshot == previousSnapshot) {
            continue;
        }

        previousSnapshot = snapshot;

        std::ostringstream message;
        message << "runtime probe: renderer modules sample " << sample << ": " << snapshot;
        g_runtimeProbeLogger->info(message.str());
    }

    return 0;
}

void startRendererModuleProbe(Logger& logger) {
    if (InterlockedExchange(&g_rendererModuleProbeStarted, 1) != 0) {
        return;
    }

    g_runtimeProbeLogger = &logger;

    HANDLE thread = CreateThread(nullptr, 0, rendererModuleProbeThread, nullptr, 0, nullptr);
    if (thread == nullptr) {
        logger.warn("runtime probe: failed to start renderer module sampler thread");
        return;
    }

    CloseHandle(thread);
    logger.info("runtime probe: renderer module sampler started");
}

BOOL WINAPI hookedGetMessageA(LPMSG message, HWND window, UINT messageFilterMin, UINT messageFilterMax) {
    const LONG hits = InterlockedIncrement(&g_getMessageProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: USER32!GetMessageA IAT hook fired");
    }

    if (g_originalGetMessageA == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return -1;
    }

    return g_originalGetMessageA(message, window, messageFilterMin, messageFilterMax);
}

BOOL WINAPI hookedSwapBuffers(HDC deviceContext) {
    const LONG hits = InterlockedIncrement(&g_swapBuffersProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: GDI32!SwapBuffers IAT hook fired");
    }

    if (g_originalSwapBuffers == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return g_originalSwapBuffers(deviceContext);
}

BOOL WINAPI hookedBitBlt(
    HDC destination,
    int x,
    int y,
    int width,
    int height,
    HDC source,
    int sourceX,
    int sourceY,
    DWORD rasterOperation) {
    const LONG hits = InterlockedIncrement(&g_bitBltProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: GDI32!BitBlt IAT hook fired");
    }

    if (g_originalBitBlt == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return g_originalBitBlt(destination, x, y, width, height, source, sourceX, sourceY, rasterOperation);
}

BOOL WINAPI hookedStretchBlt(
    HDC destination,
    int x,
    int y,
    int width,
    int height,
    HDC source,
    int sourceX,
    int sourceY,
    int sourceWidth,
    int sourceHeight,
    DWORD rasterOperation) {
    const LONG hits = InterlockedIncrement(&g_stretchBltProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: GDI32!StretchBlt IAT hook fired");
    }

    if (g_originalStretchBlt == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    return g_originalStretchBlt(
        destination,
        x,
        y,
        width,
        height,
        source,
        sourceX,
        sourceY,
        sourceWidth,
        sourceHeight,
        rasterOperation);
}

HMODULE WINAPI hookedLoadLibraryA(LPCSTR libraryName) {
    if (g_originalLoadLibraryA == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return nullptr;
    }

    HMODULE module = g_originalLoadLibraryA(libraryName);
    if (g_runtimeProbeLogger != nullptr && isInterestingRendererLibraryName(libraryName)) {
        const LONG hits = InterlockedIncrement(&g_rendererApiProbeLoadHits);
        if (hits <= 32) {
            std::ostringstream message;
            message << "runtime probe: LoadLibraryA(\"" << libraryName << "\") -> "
                    << moduleNameFromHandle(module);
            g_runtimeProbeLogger->info(message.str());
        }
    }

    return module;
}

IDirect3D9* WINAPI hookedDirect3DCreate9(UINT sdkVersion) {
    const LONG hits = InterlockedIncrement(&g_direct3D9ProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: Direct3DCreate9 hook fired with SDKVersion " << sdkVersion;
        g_runtimeProbeLogger->info(message.str());
    }

    if (g_originalDirect3DCreate9 == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return nullptr;
    }

    IDirect3D9* direct3D = g_originalDirect3DCreate9(sdkVersion);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: Direct3DCreate9 returned IDirect3D9 "
                << formatAddress(reinterpret_cast<std::uintptr_t>(direct3D));
        g_runtimeProbeLogger->info(message.str());
    }

    if (direct3D == nullptr) {
        return nullptr;
    }

    Direct3D9ProbeProxy* proxy = new (std::nothrow) Direct3D9ProbeProxy(direct3D);
    if (proxy == nullptr) {
        if (g_runtimeProbeLogger != nullptr) {
            g_runtimeProbeLogger->warn("runtime probe: failed to allocate IDirect3D9 probe proxy; returning original object");
        }
        return direct3D;
    }

    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: Direct3DCreate9 returning IDirect3D9 probe proxy "
                << formatAddress(reinterpret_cast<std::uintptr_t>(proxy));
        g_runtimeProbeLogger->info(message.str());
    }

    return proxy;
}

FARPROC direct3DCreate9DetourAsFarproc() {
    Direct3DCreate9Function detour = &hookedDirect3DCreate9;
    FARPROC result = nullptr;
    static_assert(sizeof(result) == sizeof(detour));
    std::memcpy(&result, &detour, sizeof(result));
    return result;
}

FARPROC WINAPI hookedGetProcAddress(HMODULE module, LPCSTR procName) {
    if (g_originalGetProcAddress == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return nullptr;
    }

    FARPROC proc = g_originalGetProcAddress(module, procName);
    if (g_runtimeProbeLogger != nullptr && isInterestingRendererProcName(procName)) {
        const LONG hits = InterlockedIncrement(&g_rendererApiProbeProcHits);
        if (hits <= 64) {
            std::ostringstream message;
            message << "runtime probe: GetProcAddress("
                    << moduleNameFromHandle(module)
                    << ", \"" << procName << "\") -> "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(proc));
            g_runtimeProbeLogger->info(message.str());
        }
    }

    if (g_direct3D9ProbeEnabled && proc != nullptr && isNamedProc(procName, "Direct3DCreate9")) {
        g_originalDirect3DCreate9 = reinterpret_cast<Direct3DCreate9Function>(proc);
        InterlockedExchange(&g_direct3D9ProbeHits, 0);
        InterlockedExchange(&g_direct3D9CreateDeviceProbeHits, 0);
        if (g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: replacing GetProcAddress Direct3DCreate9 result with detour "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedDirect3DCreate9));
            g_runtimeProbeLogger->info(message.str());
        }
        return direct3DCreate9DetourAsFarproc();
    }

    return proc;
}
}

X86DetourHook::~X86DetourHook() {
    std::string ignored;
    uninstall(ignored);
}

bool X86DetourHook::install(void* target, void* detour, std::size_t patchLength, std::string& error) {
    error.clear();

    if (installed_) {
        error = "detour hook is already installed";
        return false;
    }

    if (target == nullptr || detour == nullptr) {
        error = "detour hook target or detour is null";
        return false;
    }

    if (patchLength < kX86JumpBytes) {
        error = "detour hook patch length must be at least 5 bytes";
        return false;
    }

    const auto targetAddress = reinterpret_cast<std::uintptr_t>(target);
    const auto detourAddress = reinterpret_cast<std::uintptr_t>(detour);
    if (!relativeJumpFits(targetAddress, detourAddress)) {
        error = "detour target is outside x86 relative jump range";
        return false;
    }

    const std::size_t trampolineSize = patchLength + kX86JumpBytes;
    void* trampoline = VirtualAlloc(nullptr, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (trampoline == nullptr) {
        error = "failed to allocate detour trampoline";
        return false;
    }

    const auto trampolineAddress = reinterpret_cast<std::uintptr_t>(trampoline);
    if (!relativeJumpFits(trampolineAddress + patchLength, targetAddress + patchLength)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        error = "detour trampoline is outside x86 relative jump range";
        return false;
    }

    originalBytes_.assign(
        reinterpret_cast<std::uint8_t*>(target),
        reinterpret_cast<std::uint8_t*>(target) + patchLength);

    std::memcpy(trampoline, target, patchLength);
    writeRelativeJump(
        reinterpret_cast<std::uint8_t*>(trampoline) + patchLength,
        targetAddress + patchLength);

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, patchLength, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        originalBytes_.clear();
        error = "failed to make detour target writable";
        return false;
    }

    auto* writableTarget = reinterpret_cast<std::uint8_t*>(target);
    writeRelativeJump(writableTarget, detourAddress);
    if (patchLength > kX86JumpBytes) {
        fillNops(writableTarget + kX86JumpBytes, patchLength - kX86JumpBytes);
    }

    FlushInstructionCache(GetCurrentProcess(), target, patchLength);

    DWORD ignoredProtect = 0;
    VirtualProtect(target, patchLength, oldProtect, &ignoredProtect);

    target_ = target;
    detour_ = detour;
    trampoline_ = trampoline;
    patchLength_ = patchLength;
    installed_ = true;
    return true;
}

bool X86DetourHook::uninstall(std::string& error) {
    error.clear();

    if (!installed_) {
        return true;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(target_, patchLength_, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        error = "failed to make detour target writable for restore";
        return false;
    }

    std::memcpy(target_, originalBytes_.data(), originalBytes_.size());
    FlushInstructionCache(GetCurrentProcess(), target_, patchLength_);

    DWORD ignoredProtect = 0;
    VirtualProtect(target_, patchLength_, oldProtect, &ignoredProtect);

    if (trampoline_ != nullptr) {
        VirtualFree(trampoline_, 0, MEM_RELEASE);
    }

    target_ = nullptr;
    detour_ = nullptr;
    trampoline_ = nullptr;
    patchLength_ = 0;
    originalBytes_.clear();
    installed_ = false;
    return true;
}

bool X86DetourHook::installed() const {
    return installed_;
}

void* X86DetourHook::trampoline() const {
    return trampoline_;
}

IatHook::~IatHook() {
    std::string ignored;
    uninstall(ignored);
}

bool IatHook::install(
    const char* importedModuleName,
    const char* importedFunctionName,
    void* detour,
    void*& original,
    std::string& error) {
    error.clear();
    original = nullptr;

    if (installed_) {
        error = "IAT hook is already installed";
        return false;
    }

    if (importedModuleName == nullptr || importedFunctionName == nullptr || detour == nullptr) {
        error = "IAT hook input is null";
        return false;
    }

    const ProcessModuleView module = currentProcessMainModule();
    if (!module) {
        error = "failed to resolve main module for IAT hook";
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module.base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = "main module has invalid DOS header";
        return false;
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const std::uint8_t*>(module.base) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error = "main module has invalid NT header";
        return false;
    }

    const IMAGE_DATA_DIRECTORY& importDirectory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0) {
        error = "main module has no import directory";
        return false;
    }

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        module.base + importDirectory.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor) {
        const char* moduleName = reinterpret_cast<const char*>(module.base + descriptor->Name);
        if (lstrcmpiA(moduleName, importedModuleName) != 0) {
            continue;
        }

        auto* lookupThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            module.base + (descriptor->OriginalFirstThunk != 0 ? descriptor->OriginalFirstThunk : descriptor->FirstThunk));
        auto* addressThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
            module.base + descriptor->FirstThunk);

        for (; lookupThunk->u1.AddressOfData != 0; ++lookupThunk, ++addressThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(lookupThunk->u1.Ordinal)) {
                continue;
            }

            const auto* importByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                module.base + lookupThunk->u1.AddressOfData);
            const char* functionName = reinterpret_cast<const char*>(importByName->Name);
            if (std::strcmp(functionName, importedFunctionName) != 0) {
                continue;
            }

            slot_ = reinterpret_cast<std::uintptr_t*>(&addressThunk->u1.Function);
            original_ = *slot_;

            DWORD oldProtect = 0;
            if (!VirtualProtect(slot_, sizeof(*slot_), PAGE_READWRITE, &oldProtect)) {
                slot_ = nullptr;
                original_ = 0;
                error = "failed to make IAT slot writable";
                return false;
            }

            *slot_ = reinterpret_cast<std::uintptr_t>(detour);

            DWORD ignoredProtect = 0;
            VirtualProtect(slot_, sizeof(*slot_), oldProtect, &ignoredProtect);
            FlushInstructionCache(GetCurrentProcess(), slot_, sizeof(*slot_));

            original = reinterpret_cast<void*>(original_);
            installed_ = true;
            return true;
        }
    }

    error = std::string("failed to find import ") + importedModuleName + "!" + importedFunctionName;
    return false;
}

bool IatHook::uninstall(std::string& error) {
    error.clear();

    if (!installed_) {
        return true;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(slot_, sizeof(*slot_), PAGE_READWRITE, &oldProtect)) {
        error = "failed to make IAT slot writable for restore";
        return false;
    }

    *slot_ = original_;

    DWORD ignoredProtect = 0;
    VirtualProtect(slot_, sizeof(*slot_), oldProtect, &ignoredProtect);
    FlushInstructionCache(GetCurrentProcess(), slot_, sizeof(*slot_));

    slot_ = nullptr;
    original_ = 0;
    installed_ = false;
    return true;
}

bool IatHook::installed() const {
    return installed_;
}

bool WaHookManager::initialize(
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
    const WaOverlayTransform& direct3D9OverlayTransform,
    std::string& error) {
    error.clear();

    if (initialized_) {
        error = "hook manager is already initialized";
        return false;
    }

    const ProcessModuleView module = currentProcessMainModule();
    if (!module) {
        error = "failed to resolve W:A main module image";
        return false;
    }
    g_waModuleBase = module.base;

    std::ostringstream moduleMessage;
    moduleMessage << "hook probe: main module base " << formatAddress(module.base)
                  << ", image size " << module.size << " bytes";
    logger.info(moduleMessage.str());

    WaPeFingerprint fingerprint;
    if (readPeFingerprint(module, fingerprint)) {
        std::ostringstream fingerprintMessage;
        fingerprintMessage << "hook probe: PE timestamp " << formatAddress(fingerprint.timestamp)
                           << ", checksum " << formatAddress(fingerprint.checksum)
                           << ", entry RVA " << formatAddress(fingerprint.entryPointRva)
                           << ", image size " << fingerprint.imageSize << " bytes";
        logger.info(fingerprintMessage.str());

        logger.info(isKnownWa381SteamImage(fingerprint)
            ? "hook probe: recognized W:A 3.8.1 Steam executable fingerprint"
            : "hook probe: W:A executable fingerprint is not in the current signature catalog");
    } else {
        logger.warn("hook probe: failed to read PE fingerprint from main module");
    }

    logger.info("hook probe: pattern scanner initialized");
    logProbeSignatureMatches(logger, module);

    logger.info("hook plan: game tick / turn transition hook pending runtime validation");
    logger.info("hook plan: active map discovery hook pending runtime validation");
    logger.info("hook plan: render overlay hook pending runtime validation");
    logger.info("hook plan: TaskMessage serializer/deserializer hooks pending signatures");

    if (enableRendererModuleProbe) {
        startRendererModuleProbe(logger);
    }

    if (probeOnly) {
        logger.info("hook probe-only mode enabled; no W:A code patches were applied");
        initialized_ = true;
        return true;
    }

    if (!readPeFingerprint(module, fingerprint) || !isKnownWa381SteamImage(fingerprint)) {
        error = "runtime hook probes require the recognized W:A 3.8.1 Steam executable fingerprint";
        logger.warn(error);
        return false;
    }

    if (!enableMessagePumpProbe && !enableRenderProbe && !enableRendererApiProbe && !enableCameraProbe && !enableDirect3D9Probe) {
        logger.info("hook runtime mode enabled, but no runtime probe hook is enabled in configuration");
        initialized_ = true;
        return true;
    }

    g_runtimeProbeLogger = &logger;
    g_direct3D9ProbeEnabled = enableDirect3D9Probe;
    g_direct3D9DeviceSlotProbeEnabled = enableDirect3D9DeviceSlotProbe;
    g_direct3D9OverlaySmokeTestEnabled = enableDirect3D9OverlaySmokeTest;
    g_direct3D9OverlayTransform = direct3D9OverlayTransform;
    g_direct3D9OverlayTestRects.clear();
    g_direct3D9OverlayTestRects.reserve(direct3D9OverlayTestRects.size());
    for (const WaOverlayRect& rect : direct3D9OverlayTestRects) {
        g_direct3D9OverlayTestRects.push_back(Direct3D9OverlayRect{
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            static_cast<D3DCOLOR>(rect.argb),
            static_cast<D3DCOLOR>(rect.touchedArgb),
            rect.wallIndex,
            false,
        });
    }
    InterlockedExchange(&g_getMessageProbeHits, 0);
    InterlockedExchange(&g_cameraTrackingProbeHits, 0);
    InterlockedExchange(&g_cameraTrackingPointAddress, 0);
    InterlockedExchange(&g_cameraTrackingXFixed, 0);
    InterlockedExchange(&g_cameraTrackingYFixed, 0);
    InterlockedExchange(&g_cameraRenderProbeHits, 0);
    InterlockedExchange(&g_cameraRenderPointAddress, 0);
    InterlockedExchange(&g_cameraRenderXFixed, 0);
    InterlockedExchange(&g_cameraRenderYFixed, 0);
    InterlockedExchange(&g_cameraRenderSampleValid, 0);
    InterlockedExchange(&g_cameraTrackingBaselineValid, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayDrawHits, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayFailureHits, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayTransformLogHits, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastBackBufferWidth, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastBackBufferHeight, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaX, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaY, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaValid, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayCameraDeltaLogCount, 0);
    InterlockedExchange(&g_direct3D9WallTouchLogCount, 0);
    InterlockedExchange(&g_wallTouchTurnOwnerAddress, 0);
    InterlockedExchange(&g_wallTouchTurnTeamByte, kUnknownWallTouchTurnTeamByte);
    InterlockedExchange(&g_wallTouchResetLogCount, 0);

    if (enableDirect3D9Probe && !enableRendererApiProbe) {
        error = "Direct3D9 probe requires EnableRendererApiProbe=1";
        logger.warn("runtime probe: " + error);
        return false;
    }

    if (enableDirect3D9DeviceSlotProbe && !enableDirect3D9Probe) {
        error = "Direct3D9 device slot probe requires EnableDirect3D9Probe=1";
        logger.warn("runtime probe: " + error);
        return false;
    }

    if (enableDirect3D9OverlaySmokeTest && !enableDirect3D9DeviceSlotProbe) {
        error = "Direct3D9 overlay smoke test requires EnableDirect3D9DeviceSlotProbe=1";
        logger.warn("runtime probe: " + error);
        return false;
    }

    if (enableCameraProbe) {
        std::string cameraError;
        if (!installWaCameraTrackingProbe(logger, module, cameraTrackingHook_, cameraError)) {
            logger.warn("runtime probe: failed to install W:A camera tracking hook: " + cameraError);
        }

        if (!installWaCameraRenderCopyProbe(logger, module, cameraRenderCopyHook_, cameraError)) {
            logger.warn("runtime probe: failed to install W:A camera render copy hook: " + cameraError);
        }

        if (!installWaCameraTargetAggregateProbe(logger, module, cameraTargetAggregateHook_, cameraError)) {
            logger.warn("runtime probe: failed to install W:A camera target aggregate hook: " + cameraError);
        }

        if (!installWaWormMotionCandidateProbe(logger, module, wormMotionCandidateHook_, cameraError)) {
            logger.warn("runtime probe: failed to install W:A worm motion candidate hook: " + cameraError);
        }
    }

    if (enableMessagePumpProbe) {
        void* originalGetMessageA = nullptr;
        if (!getMessageHook_.install("USER32.dll", "GetMessageA", reinterpret_cast<void*>(&hookedGetMessageA), originalGetMessageA, error)) {
            g_runtimeProbeLogger = nullptr;
            logger.warn("runtime probe: failed to install USER32!GetMessageA IAT hook: " + error);
            return false;
        }

        g_originalGetMessageA = reinterpret_cast<GetMessageAFunction>(originalGetMessageA);

        std::ostringstream hookMessage;
        hookMessage << "runtime probe: USER32!GetMessageA IAT hook installed; original "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetMessageA))
                    << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetMessageA));
        logger.info(hookMessage.str());
    }

    if (enableRendererApiProbe) {
        InterlockedExchange(&g_rendererApiProbeLoadHits, 0);
        InterlockedExchange(&g_rendererApiProbeProcHits, 0);

        void* originalLoadLibraryA = nullptr;
        if (!loadLibraryAHook_.install("KERNEL32.dll", "LoadLibraryA", reinterpret_cast<void*>(&hookedLoadLibraryA), originalLoadLibraryA, error)) {
            logger.warn("runtime probe: failed to install KERNEL32!LoadLibraryA IAT hook: " + error);
        } else {
            g_originalLoadLibraryA = reinterpret_cast<LoadLibraryAFunction>(originalLoadLibraryA);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: KERNEL32!LoadLibraryA IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalLoadLibraryA))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedLoadLibraryA));
            logger.info(hookMessage.str());
        }

        void* originalGetProcAddress = nullptr;
        if (!getProcAddressHook_.install("KERNEL32.dll", "GetProcAddress", reinterpret_cast<void*>(&hookedGetProcAddress), originalGetProcAddress, error)) {
            logger.warn("runtime probe: failed to install KERNEL32!GetProcAddress IAT hook: " + error);
        } else {
            g_originalGetProcAddress = reinterpret_cast<GetProcAddressFunction>(originalGetProcAddress);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: KERNEL32!GetProcAddress IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetProcAddress))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetProcAddress));
            logger.info(hookMessage.str());
        }

        if (!loadLibraryAHook_.installed() && !getProcAddressHook_.installed()) {
            g_runtimeProbeLogger = nullptr;
            error = "failed to install every renderer API runtime probe hook";
            logger.warn("runtime probe: " + error);
            return false;
        }
    }

    if (enableRenderProbe) {
        InterlockedExchange(&g_swapBuffersProbeHits, 0);
        InterlockedExchange(&g_bitBltProbeHits, 0);
        InterlockedExchange(&g_stretchBltProbeHits, 0);

        void* originalSwapBuffers = nullptr;
        if (!swapBuffersHook_.install("GDI32.dll", "SwapBuffers", reinterpret_cast<void*>(&hookedSwapBuffers), originalSwapBuffers, error)) {
            logger.warn("runtime probe: failed to install GDI32!SwapBuffers IAT hook: " + error);
        } else {
            g_originalSwapBuffers = reinterpret_cast<SwapBuffersFunction>(originalSwapBuffers);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: GDI32!SwapBuffers IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalSwapBuffers))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedSwapBuffers));
            logger.info(hookMessage.str());
        }

        void* originalBitBlt = nullptr;
        if (!bitBltHook_.install("GDI32.dll", "BitBlt", reinterpret_cast<void*>(&hookedBitBlt), originalBitBlt, error)) {
            logger.warn("runtime probe: failed to install GDI32!BitBlt IAT hook: " + error);
        } else {
            g_originalBitBlt = reinterpret_cast<BitBltFunction>(originalBitBlt);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: GDI32!BitBlt IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalBitBlt))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedBitBlt));
            logger.info(hookMessage.str());
        }

        void* originalStretchBlt = nullptr;
        if (!stretchBltHook_.install("GDI32.dll", "StretchBlt", reinterpret_cast<void*>(&hookedStretchBlt), originalStretchBlt, error)) {
            logger.warn("runtime probe: failed to install GDI32!StretchBlt IAT hook: " + error);
        } else {
            g_originalStretchBlt = reinterpret_cast<StretchBltFunction>(originalStretchBlt);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: GDI32!StretchBlt IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalStretchBlt))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedStretchBlt));
            logger.info(hookMessage.str());
        }

        if (!swapBuffersHook_.installed() && !bitBltHook_.installed() && !stretchBltHook_.installed()) {
            g_runtimeProbeLogger = nullptr;
            error = "failed to install every render runtime probe hook";
            logger.warn("runtime probe: " + error);
            return false;
        }
    }

    initialized_ = true;
    return true;
}
