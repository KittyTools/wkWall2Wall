#include "WaHooks.h"

#include "WaMemory.h"
#include "WallGameMessage.h"
#include "WallProtocol.h"
#include "WallTransport.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <d3d9.h>
#include <ddraw.h>
#include <gl/GL.h>
#include <mmsystem.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <new>
#include <sstream>
#include <iomanip>
#include <limits>
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
constexpr std::uintptr_t kWa381TurnGameHandleMessageRva = 0x0015DC00;
constexpr std::uintptr_t kWa381WormMotionCandidateRva = 0x0010D450;
constexpr std::uintptr_t kWa381MovementCollisionResultRva = 0x000FE092;
constexpr std::uintptr_t kWa381MovementCollisionBranchRva = 0x000FDBCB;
constexpr std::uintptr_t kWa381MovementCollisionPathRva = 0x000FF520;
constexpr std::uintptr_t kWa381CollisionQueryCommonRva = 0x000FB9D0;
constexpr std::uintptr_t kWa381JumpTerrainCollisionResultRva = 0x0010DD4A;
constexpr std::uintptr_t kWa381MovementResolutionSecondaryResultRva = 0x000FD0A4;
constexpr std::size_t kWaCameraTrackingPatchLength = 5;
constexpr std::size_t kWaCameraRenderCopyPatchLength = 6;
constexpr std::size_t kWaCameraTargetAggregatePatchLength = 5;
constexpr std::size_t kWaTurnGameHandleMessagePatchLength = 6;
constexpr std::size_t kWaWormMotionCandidatePatchLength = 7;
constexpr std::size_t kWaMovementCollisionResultPatchLength = 6;
constexpr std::size_t kWaMovementCollisionBranchPatchLength = 6;
constexpr std::size_t kWaMovementCollisionPathPatchLength = 5;
constexpr std::size_t kWaCollisionQueryCommonPatchLength = 8;
constexpr std::size_t kWaJumpTerrainCollisionResultPatchLength = 8;
constexpr std::size_t kWaMovementResolutionResultPatchLength = 8;
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
constexpr int kActiveWormReferenceKeepDistancePixels = 512;
constexpr DWORD kActiveWormRefreshIntervalMilliseconds = 50;
constexpr DWORD kActiveOwnerRecentMotionKeepMilliseconds = 750;
constexpr DWORD kRecentMotionHandoffMilliseconds = 1500;
constexpr DWORD kTurnGameFinishTurnResetDebounceMilliseconds = 1000;
constexpr DWORD kOverlayWormEvidenceKeepMilliseconds = 1000;
constexpr DWORD kOverlayGameplayGraceMilliseconds = 250;
constexpr DWORD kDetectedMapCacheRefreshPollMilliseconds = 2500;
constexpr DWORD kDetectedMapCacheRefreshWindowMilliseconds = 15000;
constexpr DWORD kDirectDrawSurfaceTransitionDebounceMilliseconds = 750;
constexpr DWORD kDirectDrawSurfaceTransitionDrawCooldownMilliseconds = 1000;
constexpr DWORD kBlockedAttackWarningSoundCooldownMilliseconds = 1200;
constexpr DWORD kUtilityActionSelectionGraceMilliseconds = 5000;
constexpr bool kVerboseRuntimeDiagnostics = false;
constexpr std::uint16_t kWallLobbyPacketMagic = 0x6666;
constexpr std::uint16_t kWallLobbyChatPacketType = 0x0000;
constexpr std::uint8_t kWallLobbyMessageVersionQuery = 1;
constexpr std::uint8_t kWallLobbyMessageVersionInfo = 2;
constexpr std::uint8_t kWallLobbyMessageMetadataFrame = 3;
constexpr const char* kWallLobbyJsonNamespace = "wkWall2Wall";
constexpr std::size_t kWaHostLobbyPacketHandlerPatchLength = 7;
constexpr std::size_t kWaClientLobbyPacketHandlerPatchLength = 6;
constexpr std::size_t kWaLobbyScreenConstructorPatchLength = 7;
constexpr DWORD kOnlineLobbyBroadcastCooldownMilliseconds = 1000;
constexpr DWORD kOnlineLobbyCompatibilityTimeoutMilliseconds = 3000;
constexpr bool kOnlineLobbyHostUnicastEnabled = true;
constexpr std::uintptr_t kWaHostSlotStride = 0x19118;
constexpr std::uintptr_t kWaHostSlotDataOffset = 0x1A4;
constexpr std::uintptr_t kWaHostSlotConnectionStateOffset = 0xB8;
constexpr std::uintptr_t kWaHostSlotNicknameOffset = 0xD0;
constexpr LONG kWaHostSlotConnectedState = 3;

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

const std::array<WaProbeSignature, 6> kWa381ProbeSignatures = {{
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
        "CTaskTurnGame::HandleMessage",
        "turn-game task message dispatcher; candidate for true game turn boundaries",
        "55 8B EC 83 E4 F8 81 EC ?? ?? ?? ?? 53 8B 5D 0C 56 8D 43 FE "
        "83 F8 7B 57 8B F1 0F 87 ?? ?? ?? ?? 0F B6 80 ?? ?? ?? ?? "
        "FF 24 85 ?? ?? ?? ?? 8B 86 ?? ?? ?? ??",
        kWa381TurnGameHandleMessageRva,
        2
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
using PeekMessageAFunction = BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT, UINT);
using GetAsyncKeyStateFunction = SHORT(WINAPI*)(int);
using GetKeyStateFunction = SHORT(WINAPI*)(int);
using GetKeyboardStateFunction = BOOL(WINAPI*)(PBYTE);
using SwapBuffersFunction = BOOL(WINAPI*)(HDC);
using BitBltFunction = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, DWORD);
using StretchBltFunction = BOOL(WINAPI*)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
using CreateFileAFunction = HANDLE(WINAPI*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using CreateFileWFunction = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using LoadLibraryAFunction = HMODULE(WINAPI*)(LPCSTR);
using GetProcAddressFunction = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using Direct3DCreate9Function = IDirect3D9*(WINAPI*)(UINT);
using DirectDrawCreateFunction = HRESULT(WINAPI*)(GUID*, LPDIRECTDRAW*, IUnknown*);
using DirectDrawCreateExFunction = HRESULT(WINAPI*)(GUID*, LPVOID*, REFIID, IUnknown*);
using OpenGLEndFunction = void(APIENTRY*)();
using WaTurnGameHandleMessageFunction =
    int(__fastcall*)(void*, void*, void*, std::uint32_t, std::size_t, void*);
using WaHostLobbyPacketHandlerFunction =
    int(__fastcall*)(void*, void*, int, unsigned char*, std::size_t);
using WaClientLobbyPacketHandlerFunction =
    int(__fastcall*)(void*, void*, unsigned char*, std::size_t);
using WaConstructLobbyScreenFunction = int(__stdcall*)(int, int);
using WaLobbyDisplayMessageFunction = int(__stdcall*)(int, char*);
using WaClientSendPacketFunction = int(__thiscall*)(void*, unsigned char*, std::size_t);

GetMessageAFunction g_originalGetMessageA = nullptr;
PeekMessageAFunction g_originalPeekMessageA = nullptr;
GetAsyncKeyStateFunction g_originalGetAsyncKeyState = nullptr;
GetKeyStateFunction g_originalGetKeyState = nullptr;
GetKeyboardStateFunction g_originalGetKeyboardState = nullptr;
SwapBuffersFunction g_originalSwapBuffers = nullptr;
BitBltFunction g_originalBitBlt = nullptr;
StretchBltFunction g_originalStretchBlt = nullptr;
CreateFileAFunction g_originalCreateFileA = nullptr;
CreateFileWFunction g_originalCreateFileW = nullptr;
LoadLibraryAFunction g_originalLoadLibraryA = nullptr;
GetProcAddressFunction g_originalGetProcAddress = nullptr;
Direct3DCreate9Function g_originalDirect3DCreate9 = nullptr;
DirectDrawCreateFunction g_originalDirectDrawCreate = nullptr;
DirectDrawCreateExFunction g_originalDirectDrawCreateEx = nullptr;
OpenGLEndFunction g_originalOpenGLEnd = nullptr;
WaTurnGameHandleMessageFunction g_originalWaTurnGameHandleMessage = nullptr;
WaHostLobbyPacketHandlerFunction g_originalWaHostLobbyPacketHandler = nullptr;
WaClientLobbyPacketHandlerFunction g_originalWaClientLobbyPacketHandler = nullptr;
WaConstructLobbyScreenFunction g_originalWaConstructLobbyHostScreen = nullptr;
WaConstructLobbyScreenFunction g_originalWaConstructLobbyClientScreen = nullptr;
WaLobbyDisplayMessageFunction g_waLobbyDisplayMessage = nullptr;
Logger* g_runtimeProbeLogger = nullptr;
volatile LONG g_getMessageProbeHits = 0;
volatile LONG g_peekMessageProbeHits = 0;
volatile LONG g_weaponInputBlockLogCount = 0;
volatile LONG g_blockedWeaponInputKeyMask = 0;
volatile LONG g_blockedWeaponInputSuppressUntilTick = 0;
volatile LONG g_utilityActionSelectionGraceUntilTick = 0;
volatile LONG g_recentRopeContextTick = 0;
volatile LONG g_swapBuffersProbeHits = 0;
volatile LONG g_bitBltProbeHits = 0;
volatile LONG g_stretchBltProbeHits = 0;
volatile LONG g_rendererModuleProbeStarted = 0;
volatile LONG g_rendererApiProbeLoadHits = 0;
volatile LONG g_rendererApiProbeProcHits = 0;
volatile LONG g_directDrawCreateProbeHits = 0;
volatile LONG g_directDrawCreateExProbeHits = 0;
volatile LONG g_directDrawQueryInterfaceProbeHits = 0;
volatile LONG g_directDrawCreateSurfaceProbeHits = 0;
volatile LONG g_directDrawSurfaceBltProbeHits = 0;
volatile LONG g_directDrawSurfaceBltFastProbeHits = 0;
volatile LONG g_directDrawSurfaceFlipProbeHits = 0;
volatile LONG g_directDrawSurfaceUnlockProbeHits = 0;
volatile LONG g_directDrawOverlayDrawHits = 0;
volatile LONG g_directDrawOverlayFailureHits = 0;
volatile LONG g_directDrawOverlayNoDrawHits = 0;
volatile LONG g_directDrawOverlayDrawing = 0;
volatile LONG g_directDrawSurfaceTransitionTick = 0;
volatile LONG g_directDrawSurfaceTransitionLogCount = 0;
volatile LONG g_openGLEndProbeHits = 0;
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
volatile LONG g_openGLMetadataOverlayDrawHits = 0;
volatile LONG g_openGLMetadataOverlayFailureHits = 0;
volatile LONG g_openGLMetadataOverlayContextLogHits = 0;
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
volatile LONG g_trackingTargetReferencePreviousX = 0;
volatile LONG g_trackingTargetReferencePreviousY = 0;
volatile LONG g_trackingTargetReferenceOlderX = 0;
volatile LONG g_trackingTargetReferenceOlderY = 0;
volatile LONG g_trackingTargetReferenceHistoryCount = 0;
volatile LONG g_trackingTargetFallbackLogCount = 0;
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
volatile LONG g_wallTouchResetLogCount = 0;
volatile LONG g_wallTouchLastTouchTick = 0;
volatile LONG g_wallTouchLastResetTick = 0;
volatile LONG g_waStateUiAddress = 0;
volatile LONG g_waStateUiLogCount = 0;
volatile LONG g_wormMotionCandidateProbeHits = 0;
volatile LONG g_wormMotionCandidateProbeLogCount = 0;
volatile LONG g_wormMotionCandidateLastOwnerAddress = 0;
volatile LONG g_movementCollisionResultProbeHits = 0;
volatile LONG g_movementCollisionBranchProbeHits = 0;
volatile LONG g_movementCollisionPathProbeHits = 0;
volatile LONG g_collisionQueryCommonProbeHits = 0;
volatile LONG g_jumpTerrainCollisionResultProbeHits = 0;
volatile LONG g_jumpTerrainCollisionResultLogCount = 0;
volatile LONG g_jumpTerrainCollisionResultNearWallLogCount = 0;
volatile LONG g_movementResolutionResultProbeHits = 0;
volatile LONG g_movementResolutionResultLogCount = 0;
volatile LONG g_movementResolutionResultNearWallLogCount = 0;
volatile LONG g_turnGameHandleMessageProbeHits = 0;
volatile LONG g_turnGameHandleMessageLogCount = 0;
volatile LONG g_turnGameFinishTurnLastResetTick = 0;
volatile LONG g_wallGameplayTaskActive = 0;
volatile LONG g_wallGameplayTaskLastTick = 0;
volatile LONG g_direct3D9OverlayLastGameplayEvidenceTick = 0;
bool g_direct3D9ProbeEnabled = false;
bool g_direct3D9DeviceSlotProbeEnabled = false;
bool g_direct3D9OverlaySmokeTestEnabled = false;
bool g_onlineSyncEnabled = false;
bool g_onlineRequireAllPlayers = true;
volatile LONG g_onlineMetadataBroadcastMapIndex = -1;
volatile LONG g_onlineMetadataSendLogCount = 0;
volatile LONG g_onlineMetadataReceiveLogCount = 0;
volatile LONG g_onlineMetadataErrorLogCount = 0;
volatile LONG g_onlineLobbyHookLogCount = 0;
volatile LONG g_onlineLobbyPacketLogCount = 0;
volatile LONG g_onlineLobbyMessageLogCount = 0;
volatile LONG g_onlineLobbyLastBroadcastTick = 0;
volatile LONG g_onlineLobbySeenSlotMask = 0;
volatile LONG g_onlineLobbyCompatibleSlotMask = 0;
volatile LONG g_onlineLobbyBroadcastSlotMask = 0;
volatile LONG g_onlineLobbyQuerySlotMask = 0;
volatile LONG g_onlineLobbyLastConnectedSlotMask = 0;
volatile LONG g_onlineLobbyCompatibilityDeadlineTick = 0;
volatile LONG g_onlineLobbyCompatibilityReported = 0;
volatile LONG g_onlineMetadataTrustedOverlayMapIndex = -1;
WaHookManager* g_activeHookManager = nullptr;
std::mutex g_gameplayHookLifecycleMutex;
void* g_cameraTrackingProbeStub = nullptr;
void* g_cameraRenderCopyProbeStub = nullptr;
void* g_cameraTargetAggregateProbeStub = nullptr;
void* g_wormMotionCandidateProbeStub = nullptr;
void* g_movementCollisionResultProbeStub = nullptr;
void* g_movementCollisionBranchProbeStub = nullptr;
void* g_movementCollisionPathProbeStub = nullptr;
void* g_collisionQueryCommonProbeStub = nullptr;
void* g_jumpTerrainCollisionResultProbeStub = nullptr;
void* g_movementResolutionSecondaryResultProbeStub = nullptr;
std::uintptr_t g_waModuleBase = 0;
std::uintptr_t g_lobbyHostScreenAddress = 0;
std::uintptr_t g_lobbyClientScreenAddress = 0;
std::uintptr_t g_lobbyHostSlotAddress = 0;
std::uintptr_t g_lobbyClientSlotAddress = 0;
std::uintptr_t g_lobbyHostUnicastAddress = 0;
std::uintptr_t g_lobbyHostIncomingConnectionAddress = 0;
std::uintptr_t g_direct3DCreate9ExportTarget = 0;

constexpr GUID kIUnknownGuid = {0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
constexpr GUID kIDirect3D9Guid = {0x81BDCBCA, 0x64D4, 0x426D, {0xAE, 0x8D, 0xAD, 0x01, 0x47, 0xF4, 0x27, 0x5C}};
constexpr GUID kIDirectDrawGuid = {0x6C14DB80, 0xA733, 0x11CE, {0xA5, 0x21, 0x00, 0x20, 0xAF, 0x0B, 0xE5, 0x60}};
constexpr GUID kIDirectDraw2Guid = {0xB3A6F3E0, 0x2B43, 0x11CF, {0xA2, 0xDE, 0x00, 0xAA, 0x00, 0xB9, 0x33, 0x56}};
constexpr GUID kIDirectDraw4Guid = {0x9C59509A, 0x39BD, 0x11D1, {0x8C, 0x4A, 0x00, 0xC0, 0x4F, 0xD9, 0x30, 0xC5}};
constexpr GUID kIDirectDraw7Guid = {0x15E65EC0, 0x3B9C, 0x11D2, {0xB9, 0x2F, 0x00, 0x60, 0x97, 0x97, 0xEA, 0x5B}};
constexpr std::size_t kD3D9DeviceVtableSize = 119;
constexpr std::size_t kD3D9DeviceReleaseIndex = 2;
constexpr std::size_t kD3D9DeviceResetIndex = 16;
constexpr std::size_t kD3D9DevicePresentIndex = 17;
constexpr std::size_t kD3D9DeviceBeginSceneIndex = 41;
constexpr std::size_t kD3D9DeviceEndSceneIndex = 42;
constexpr bool kEnableUnsafeD3D9DeviceShadowVtableProbe = false;
constexpr std::size_t kDirectDrawQueryInterfaceIndex = 0;
constexpr std::size_t kDirectDrawCreateSurfaceIndex = 6;
constexpr std::size_t kDirectDrawSurfaceBltIndex = 5;
constexpr std::size_t kDirectDrawSurfaceBltFastIndex = 7;
constexpr std::size_t kDirectDrawSurfaceFlipIndex = 11;
constexpr std::size_t kDirectDrawSurfaceUnlockIndex = 32;

using D3D9DeviceReleaseFunction = ULONG(STDMETHODCALLTYPE*)(IDirect3DDevice9*);
using D3D9DeviceResetFunction = HRESULT(STDMETHODCALLTYPE*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);
using D3D9DevicePresentFunction = HRESULT(STDMETHODCALLTYPE*)(
    IDirect3DDevice9*,
    const RECT*,
    const RECT*,
    HWND,
    const RGNDATA*);
using D3D9DeviceEndSceneFunction = HRESULT(STDMETHODCALLTYPE*)(IDirect3DDevice9*);
using DirectDrawQueryInterfaceFunction = HRESULT(STDMETHODCALLTYPE*)(void*, REFIID, void**);
using DirectDrawCreateSurfaceFunction = HRESULT(STDMETHODCALLTYPE*)(
    IDirectDraw*,
    LPDDSURFACEDESC,
    LPDIRECTDRAWSURFACE*,
    IUnknown*);
using DirectDraw7CreateSurfaceFunction = HRESULT(STDMETHODCALLTYPE*)(
    IDirectDraw7*,
    LPDDSURFACEDESC2,
    LPDIRECTDRAWSURFACE7*,
    IUnknown*);
using DirectDrawSurfaceBltFunction = HRESULT(STDMETHODCALLTYPE*)(
    void*,
    LPRECT,
    void*,
    LPRECT,
    DWORD,
    LPDDBLTFX);
using DirectDrawSurfaceBltFastFunction = HRESULT(STDMETHODCALLTYPE*)(
    void*,
    DWORD,
    DWORD,
    void*,
    LPRECT,
    DWORD);
using DirectDrawSurfaceFlipFunction = HRESULT(STDMETHODCALLTYPE*)(void*, void*, DWORD);
using DirectDrawSurfaceUnlockFunction = HRESULT(STDMETHODCALLTYPE*)(void*, void*);

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

struct DirectDrawObjectVtableHook {
    std::uintptr_t* vtable = nullptr;
    bool usesSurfaceDesc2 = false;
    DirectDrawQueryInterfaceFunction originalQueryInterface = nullptr;
    DirectDrawCreateSurfaceFunction originalCreateSurface = nullptr;
    DirectDraw7CreateSurfaceFunction originalCreateSurface7 = nullptr;
};

struct DirectDrawSurfaceVtableHook {
    std::uintptr_t* vtable = nullptr;
    bool usesSurfaceDesc2 = false;
    DirectDrawSurfaceBltFunction originalBlt = nullptr;
    DirectDrawSurfaceBltFastFunction originalBltFast = nullptr;
    DirectDrawSurfaceFlipFunction originalFlip = nullptr;
    DirectDrawSurfaceUnlockFunction originalUnlock = nullptr;
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

struct ScreenOverlayRect {
    LONG left = 0;
    LONG top = 0;
    LONG right = 0;
    LONG bottom = 0;
    DWORD color = 0;
};

void appendTouchedWallVisualRects(
    std::vector<ScreenOverlayRect>& screenRects,
    LONG left,
    LONG top,
    LONG right,
    LONG bottom,
    std::size_t wallIndex) {
    (void)wallIndex;
    if (right <= left || bottom <= top) {
        return;
    }

    screenRects.push_back(ScreenOverlayRect{
        left,
        top,
        right,
        bottom,
        0x8000FF40,
    });
}

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
std::mutex g_directDrawProbeMutex;
std::vector<DirectDrawObjectVtableHook> g_directDrawObjectVtableHooks;
std::vector<DirectDrawSurfaceVtableHook> g_directDrawSurfaceVtableHooks;
std::vector<Direct3D9OverlayRect> g_direct3D9OverlayTestRects;
std::vector<WaOverlayMap> g_direct3D9OverlayMaps;
WaOverlayTransform g_direct3D9OverlayTransform;
WaSoundConfig g_soundConfig;
std::mutex g_detectedMapMutex;
std::string g_detectedMapPath;
std::string g_detectedMapFileName;
std::string g_detectedMapCachePath;
std::string g_customDatPath;
std::string g_cachedDefaultMapPath;
std::uint64_t g_cachedDefaultMapCustomDatWriteTime = 0;
std::string g_cachedDefaultMapCustomDatSha256;
std::uint64_t g_detectedMapCachedCustomDatWriteTime = 0;
std::string g_detectedMapCachedCustomDatSha256;
volatile LONG g_detectedMapSequence = 0;
volatile LONG g_consumedMapSequence = 0;
volatile LONG g_detectedMapTick = 0;
volatile LONG g_detectedMapFromCacheSeed = 0;
volatile LONG g_detectedMapCacheAssociationPending = 0;
volatile LONG g_direct3D9ActiveOverlayMapIndex = -1;
volatile LONG g_detectedMapLogCount = 0;
volatile LONG g_detectedMapCacheRefreshTick = 0;
volatile LONG g_detectedMapCacheRefreshLogCount = 0;
volatile LONG g_cachedDefaultMapSeedAttemptTick = 0;
volatile LONG g_cachedDefaultMapSeedLogCount = 0;
volatile LONG g_direct3D9OverlayActivationLogCount = 0;
volatile LONG g_direct3D9OverlayGameplayActive = 0;
volatile LONG g_direct3D9OverlayGameplayLogCount = 0;
volatile LONG g_wallSoundLogCount = 0;
volatile LONG g_wallSoundMissingLogCount = 0;
volatile LONG g_wallWarningSoundLastTick = 0;
volatile LONG g_crateCollectedThisTurn = 0;
volatile LONG g_crateCollectionLogCount = 0;
volatile LONG g_chatOverlayActive = 0;
volatile LONG g_chatOverlayHiddenLogCount = 0;
volatile LONG g_chatInputLogCount = 0;
volatile LONG g_chatOverlayScanPendingTick = 0;
volatile LONG g_chatOverlayDetectedOffsetY = 0;
volatile LONG g_chatOverlayDetectedOffsetValid = 0;
volatile LONG g_chatOverlayScanLogCount = 0;
volatile LONG g_chatOverlayScanSampleCount = 0;
volatile LONG g_chatOverlayControlKeyActive = 0;
volatile LONG g_chatOverlayPinnedMode = 0;
volatile LONG g_chatOverlayPinnedPending = 0;
volatile LONG g_chatOverlayPinnedActivationTick = 0;
volatile LONG g_chatOverlayPinnedAutoProbeTick = 0;
volatile LONG g_chatOverlayLastUnpinnedCameraYPixels = 0;
volatile LONG g_chatOverlayPinnedCameraOffsetY = LONG_MIN;
volatile LONG g_chatOverlayPinnedBaselineBaseY = LONG_MIN;
volatile LONG g_chatOverlayLastUnpinnedBaseY = LONG_MIN;
std::array<LONG, 5> g_chatOverlayScanSamples = {};
std::mutex g_onlineSyncMutex;
std::vector<std::vector<std::uint8_t>> g_onlineOutgoingFrames;
WallTransportReassembler g_onlineIncomingMetadata;

TrackingTargetSnapshot currentTrackingTargetSnapshot();
bool waObjectCurrentTeamMatches(void* owner);
void activateChatOverlayPinnedMode();
void activatePendingChatOverlayPinnedModeIfReady();

ULONG STDMETHODCALLTYPE hookedD3D9DeviceRelease(IDirect3DDevice9* device) noexcept;
HRESULT STDMETHODCALLTYPE hookedD3D9DeviceReset(IDirect3DDevice9* device, D3DPRESENT_PARAMETERS* presentationParameters) noexcept;
HRESULT STDMETHODCALLTYPE hookedD3D9DevicePresent(
    IDirect3DDevice9* device,
    const RECT* sourceRect,
    const RECT* destinationRect,
    HWND destinationWindowOverride,
    const RGNDATA* dirtyRegion) noexcept;
HRESULT STDMETHODCALLTYPE hookedD3D9DeviceEndScene(IDirect3DDevice9* device) noexcept;
HRESULT STDMETHODCALLTYPE hookedDirectDrawQueryInterface(void* directDraw, REFIID iid, void** object);
HRESULT STDMETHODCALLTYPE hookedDirectDrawCreateSurface(
    IDirectDraw* directDraw,
    LPDDSURFACEDESC surfaceDescription,
    LPDIRECTDRAWSURFACE* surface,
    IUnknown* outer);
HRESULT STDMETHODCALLTYPE hookedDirectDraw7CreateSurface(
    IDirectDraw7* directDraw,
    LPDDSURFACEDESC2 surfaceDescription,
    LPDIRECTDRAWSURFACE7* surface,
    IUnknown* outer);
HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceBlt(
    void* surface,
    LPRECT destinationRect,
    void* sourceSurface,
    LPRECT sourceRect,
    DWORD flags,
    LPDDBLTFX effects);
HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceBltFast(
    void* surface,
    DWORD x,
    DWORD y,
    void* sourceSurface,
    LPRECT sourceRect,
    DWORD flags);
HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceFlip(void* surface, void* targetOverride, DWORD flags);
HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceUnlock(void* surface, void* surfaceData);
int __fastcall hookedWaHostLobbyPacketHandler(void* host, void* edx, int slot, unsigned char* packet, std::size_t size);
int __fastcall hookedWaClientLobbyPacketHandler(void* client, void* edx, unsigned char* packet, std::size_t size);
int __stdcall hookedWaConstructLobbyHostScreen(int screen, int arg);
int __stdcall hookedWaConstructLobbyClientScreen(int screen, int arg);
HANDLE WINAPI hookedCreateFileA(
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile) noexcept;
HANDLE WINAPI hookedCreateFileW(
    LPCWSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile) noexcept;
SHORT WINAPI hookedGetAsyncKeyState(int virtualKey) noexcept;
SHORT WINAPI hookedGetKeyState(int virtualKey) noexcept;
BOOL WINAPI hookedGetKeyboardState(PBYTE keyState) noexcept;

std::string lowerAscii(std::string value) {
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
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

bool sameFileName(const std::string& left, const std::string& right) {
    return sameAsciiText(fileNameOnlyFromPath(left), fileNameOnlyFromPath(right));
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

bool sameSha256(const std::string& left, const std::string& right) {
    return !left.empty() && !right.empty() && sameAsciiText(left, right);
}

bool endsWithAscii(const std::string& value, const char* suffix) {
    const std::string lowerValue = lowerAscii(value);
    const std::string lowerSuffix = lowerAscii(suffix);
    return lowerValue.size() >= lowerSuffix.size()
        && lowerValue.compare(lowerValue.size() - lowerSuffix.size(), lowerSuffix.size(), lowerSuffix) == 0;
}

bool hasSupportedWaMapExtension(const std::string& fileName) {
    return endsWithAscii(fileName, ".png")
        || endsWithAscii(fileName, ".bit")
        || endsWithAscii(fileName, ".bmp")
        || endsWithAscii(fileName, ".lev");
}

bool pathLooksLikeUserSavedLevel(const std::string& path) {
    const std::string normalized = lowerAscii(path);
    return normalized.find("\\user\\savedlevels\\") != std::string::npos
        || normalized.find("/user/savedlevels/") != std::string::npos;
}

bool direct3D9OverlayCatalogHasFileName(const std::string& mapPath) {
    const std::string candidateHash = sha256FileHex(mapPath);
    bool hasHashConstrainedCandidate = false;
    for (const WaOverlayMap& map : g_direct3D9OverlayMaps) {
        if (!sameFileName(map.fileName, mapPath)) {
            continue;
        }

        if (!map.sha256.empty()) {
            hasHashConstrainedCandidate = true;
            if (!candidateHash.empty() && sameSha256(map.sha256, candidateHash)) {
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

bool direct3D9OverlayMapIndexForFileName(const std::string& mapPath, std::size_t& index) {
    const std::string candidateHash = sha256FileHex(mapPath);
    bool hasHashConstrainedCandidate = false;
    for (std::size_t candidateIndex = 0; candidateIndex < g_direct3D9OverlayMaps.size(); ++candidateIndex) {
        const WaOverlayMap& map = g_direct3D9OverlayMaps[candidateIndex];
        if (!sameFileName(map.fileName, mapPath)) {
            continue;
        }

        if (!map.sha256.empty()) {
            hasHashConstrainedCandidate = true;
            if (!candidateHash.empty() && sameSha256(map.sha256, candidateHash)) {
                index = candidateIndex;
                return true;
            }
            continue;
        }

        if (candidateHash.empty()) {
            index = candidateIndex;
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

void writeDetectedMapCache(const std::string& path, const std::string& fileName, bool hasMetadata) {
    if (g_detectedMapCachePath.empty()) {
        return;
    }

    const std::string mapSha256 = hasMetadata ? sha256FileHex(path) : "";
    const bool canCacheMetadata = hasMetadata && !mapSha256.empty();
    WritePrivateProfileStringA(
        "Map",
        "LastHasMetadata",
        canCacheMetadata ? "1" : "0",
        g_detectedMapCachePath.c_str());
    WritePrivateProfileStringA(
        "Map",
        "CacheFormatVersion",
        canCacheMetadata ? "2" : "",
        g_detectedMapCachePath.c_str());
    WritePrivateProfileStringA(
        "Map",
        "LastPath",
        canCacheMetadata ? path.c_str() : "",
        g_detectedMapCachePath.c_str());
    WritePrivateProfileStringA(
        "Map",
        "LastFile",
        canCacheMetadata ? fileName.c_str() : "",
        g_detectedMapCachePath.c_str());
    WritePrivateProfileStringA(
        "Map",
        "SourceMapSha256",
        mapSha256.c_str(),
        g_detectedMapCachePath.c_str());

    const std::uint64_t customDatTime = canCacheMetadata ? fileWriteTimeUtc(g_customDatPath) : 0;
    const std::string customDatTimeText = customDatTime != 0 ? std::to_string(customDatTime) : "";
    const std::string customDatSha256 = canCacheMetadata ? sha256FileHex(g_customDatPath) : "";
    WritePrivateProfileStringA(
        "Map",
        "CustomDatWriteTimeUtc",
        customDatTimeText.c_str(),
        g_detectedMapCachePath.c_str());
    WritePrivateProfileStringA(
        "Map",
        "CustomDatSha256",
        customDatSha256.c_str(),
        g_detectedMapCachePath.c_str());
    g_detectedMapCachedCustomDatWriteTime = customDatTime;
    g_detectedMapCachedCustomDatSha256 = customDatSha256;
}

std::string wideToActiveCodePage(LPCWSTR value) {
    if (value == nullptr || value[0] == L'\0') {
        return {};
    }

    const int requiredBytes = WideCharToMultiByte(CP_ACP, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (requiredBytes <= 1) {
        return {};
    }

    std::string output(static_cast<std::size_t>(requiredBytes - 1), '\0');
    WideCharToMultiByte(CP_ACP, 0, value, -1, output.data(), requiredBytes, nullptr, nullptr);
    return output;
}

bool isOnlineLobbyHostContext();
void queueOnlineMetadataBroadcastForMap(std::size_t mapIndex);
void activateDirect3D9OverlayMap(std::size_t mapIndex, const std::string& detectedFileName, bool broadcastOnlineMetadata);
void clearDirect3D9OverlayMap(const char* reason);

void recordDetectedWaMapFilePath(const std::string& path) {
    if (path.empty() || g_direct3D9OverlayMaps.empty()) {
        return;
    }

    const std::string fileName = fileNameOnlyFromPath(path);
    if (!hasSupportedWaMapExtension(fileName)) {
        return;
    }

    if (!pathLooksLikeUserSavedLevel(path) && !direct3D9OverlayCatalogHasFileName(path)) {
        return;
    }

    std::size_t metadataMapIndex = 0;
    const bool hasWallMetadata = direct3D9OverlayMapIndexForFileName(path, metadataMapIndex);
    const DWORD now = GetTickCount();
    bool alreadyDetectedPath = false;
    {
        std::lock_guard<std::mutex> lock(g_detectedMapMutex);
        if (sameAsciiText(g_detectedMapPath, path)) {
            InterlockedExchange(&g_detectedMapTick, static_cast<LONG>(now));
            InterlockedExchange(&g_detectedMapFromCacheSeed, 0);
            alreadyDetectedPath = true;
        } else {
            g_detectedMapPath = path;
            g_detectedMapFileName = fileName;
            InterlockedExchange(&g_detectedMapTick, static_cast<LONG>(now));
            InterlockedExchange(&g_detectedMapFromCacheSeed, 0);
            InterlockedExchange(&g_detectedMapCacheAssociationPending, hasWallMetadata ? 1 : 0);
        }
    }

    if (alreadyDetectedPath) {
        if (hasWallMetadata) {
            activateDirect3D9OverlayMap(metadataMapIndex, fileName, true);
        } else {
            clearDirect3D9OverlayMap("detected map has no wall metadata");
        }
        return;
    }

    InterlockedIncrement(&g_detectedMapSequence);
    if (!hasWallMetadata) {
        writeDetectedMapCache("", "", false);
    }

    if (g_runtimeProbeLogger != nullptr && g_detectedMapLogCount < 32) {
        InterlockedIncrement(&g_detectedMapLogCount);

        std::ostringstream message;
        message << "runtime probe: detected W:A map file candidate \""
                << fileName
                << "\" from "
                << path
                << ", wall metadata "
                << (hasWallMetadata ? "yes" : "no");
        g_runtimeProbeLogger->info(message.str());
    }

    if (hasWallMetadata) {
        activateDirect3D9OverlayMap(metadataMapIndex, fileName, true);
    } else {
        clearDirect3D9OverlayMap("detected map has no wall metadata");
    }
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

bool isDirectDrawInterfaceGuid(REFIID guid) {
    return sameGuid(guid, kIDirectDrawGuid)
        || sameGuid(guid, kIDirectDraw2Guid)
        || sameGuid(guid, kIDirectDraw4Guid)
        || sameGuid(guid, kIDirectDraw7Guid);
}

bool directDrawInterfaceUsesSurfaceDesc2(REFIID guid) {
    return sameGuid(guid, kIDirectDraw4Guid)
        || sameGuid(guid, kIDirectDraw7Guid);
}

const char* directDrawInterfaceName(REFIID guid) {
    if (sameGuid(guid, kIDirectDrawGuid)) {
        return "IDirectDraw";
    }
    if (sameGuid(guid, kIDirectDraw2Guid)) {
        return "IDirectDraw2";
    }
    if (sameGuid(guid, kIDirectDraw4Guid)) {
        return "IDirectDraw4";
    }
    if (sameGuid(guid, kIDirectDraw7Guid)) {
        return "IDirectDraw7";
    }
    return "unknown";
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

void handleIncomingOnlineMetadataFrame(const void* data, std::size_t dataSize);

std::uint16_t readLittleEndian16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>(data[0])
        | static_cast<std::uint16_t>(data[1] << 8);
}

void appendLittleEndian16(std::vector<std::uint8_t>& data, std::uint16_t value) {
    data.push_back(static_cast<std::uint8_t>(value & 0xFF));
    data.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

std::string makeWallLobbyJsonText(
    std::uint8_t messageType,
    const std::uint8_t* payload,
    std::size_t payloadSize) {
    const char* messageTypeName = nullptr;
    switch (messageType) {
    case kWallLobbyMessageVersionQuery:
        messageTypeName = "VersionQuery";
        break;
    case kWallLobbyMessageVersionInfo:
        messageTypeName = "VersionInfo";
        break;
    case kWallLobbyMessageMetadataFrame:
        messageTypeName = "MetadataFrame";
        break;
    default:
        return "";
    }

    std::ostringstream json;
    json << "{\"module\":\""
         << kWallLobbyJsonNamespace
         << "\",\"type\":\""
         << messageTypeName
         << "\",\"protocol\":"
         << kWallProtocolVersion
         << ",\"transport\":"
         << kWallTransportVersion;

    if (messageType == kWallLobbyMessageMetadataFrame && payload != nullptr && payloadSize > 0) {
        static constexpr char kHexDigits[] = "0123456789ABCDEF";
        json << ",\"data\":\"";
        for (std::size_t index = 0; index < payloadSize; ++index) {
            const std::uint8_t value = payload[index];
            json << kHexDigits[(value >> 4) & 0x0F]
                 << kHexDigits[value & 0x0F];
        }
        json << "\"";
    }

    json << "}";
    return json.str();
}

std::vector<std::uint8_t> makeWallLobbyPacket(
    std::uint8_t messageType,
    const std::uint8_t* payload,
    std::size_t payloadSize) {
    const std::string text = makeWallLobbyJsonText(messageType, payload, payloadSize);
    if (text.empty()) {
        return {};
    }

    std::vector<std::uint8_t> packet;
    packet.reserve(sizeof(std::uint16_t) + text.size());
    appendLittleEndian16(packet, kWallLobbyPacketMagic);
    packet.insert(packet.end(), text.begin(), text.end());
    return packet;
}

std::vector<std::uint8_t> makeWallLobbyChatPacket(std::uint8_t messageType) {
    const std::string json = makeWallLobbyJsonText(messageType, nullptr, 0);
    if (json.empty()) {
        return {};
    }

    std::string message = "SYS:";
    message += kWallLobbyJsonNamespace;
    message += ":ALL:";
    message += kWallLobbyJsonNamespace;
    message += ": ";
    message += json;

    std::vector<std::uint8_t> packet;
    packet.reserve(sizeof(std::uint16_t) + message.size() + 1);
    appendLittleEndian16(packet, kWallLobbyChatPacketType);
    packet.insert(packet.end(), message.begin(), message.end());
    packet.push_back(0);
    return packet;
}

std::vector<std::uint8_t> makeWallLobbyPacket(
    std::uint8_t messageType,
    const std::vector<std::uint8_t>& payload) {
    return makeWallLobbyPacket(messageType, payload.data(), payload.size());
}

std::size_t findJsonFieldValueStart(const std::string& json, const char* fieldName) {
    std::string needle = "\"";
    needle += fieldName;
    needle += "\"";
    const std::size_t fieldPosition = json.find(needle);
    if (fieldPosition == std::string::npos) {
        return std::string::npos;
    }

    std::size_t colonPosition = json.find(':', fieldPosition + needle.size());
    if (colonPosition == std::string::npos) {
        return std::string::npos;
    }

    ++colonPosition;
    while (colonPosition < json.size()
        && std::isspace(static_cast<unsigned char>(json[colonPosition])) != 0) {
        ++colonPosition;
    }
    return colonPosition;
}

bool readJsonIntegerField(const std::string& json, const char* fieldName, int& value) {
    const std::size_t start = findJsonFieldValueStart(json, fieldName);
    if (start == std::string::npos || start >= json.size()) {
        return false;
    }

    std::size_t cursor = start;
    bool negative = false;
    if (json[cursor] == '-') {
        negative = true;
        ++cursor;
    }
    if (cursor >= json.size() || std::isdigit(static_cast<unsigned char>(json[cursor])) == 0) {
        return false;
    }

    int parsed = 0;
    while (cursor < json.size() && std::isdigit(static_cast<unsigned char>(json[cursor])) != 0) {
        parsed = (parsed * 10) + (json[cursor] - '0');
        ++cursor;
    }
    value = negative ? -parsed : parsed;
    return true;
}

bool readJsonStringField(const std::string& json, const char* fieldName, std::string& value) {
    const std::size_t start = findJsonFieldValueStart(json, fieldName);
    if (start == std::string::npos || start >= json.size() || json[start] != '"') {
        return false;
    }

    value.clear();
    for (std::size_t cursor = start + 1; cursor < json.size(); ++cursor) {
        const char ch = json[cursor];
        if (ch == '"') {
            return true;
        }
        if (ch == '\\') {
            if (++cursor >= json.size()) {
                return false;
            }
            value.push_back(json[cursor]);
        } else {
            value.push_back(ch);
        }
    }
    return false;
}

int hexValue(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

bool decodeHexPayload(const std::string& hex, std::vector<std::uint8_t>& payload) {
    if ((hex.size() % 2) != 0) {
        return false;
    }

    payload.clear();
    payload.reserve(hex.size() / 2);
    for (std::size_t index = 0; index < hex.size(); index += 2) {
        const int high = hexValue(hex[index]);
        const int low = hexValue(hex[index + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        payload.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return true;
}

bool parseWallLobbyPacket(
    const unsigned char* packet,
    std::size_t size,
    std::uint8_t& messageType,
    const std::uint8_t*& payload,
    std::size_t& payloadSize,
    std::uint16_t& protocolVersion) {
    payload = nullptr;
    payloadSize = 0;
    protocolVersion = 0;
    if (packet == nullptr || size == 0) {
        return false;
    }

    const auto* bytes = reinterpret_cast<const std::uint8_t*>(packet);
    if (size < sizeof(std::uint16_t)) {
        return false;
    }

    std::string json;
    const std::uint16_t packetType = readLittleEndian16(bytes);
    if (packetType == kWallLobbyPacketMagic) {
        json.assign(reinterpret_cast<const char*>(bytes + sizeof(std::uint16_t)), size - sizeof(std::uint16_t));
    } else if (packetType == kWallLobbyChatPacketType) {
        const char* message = reinterpret_cast<const char*>(bytes + sizeof(std::uint16_t));
        const std::size_t messageSize = size - sizeof(std::uint16_t);
        std::string chatText(message, messageSize);
        const std::size_t terminator = chatText.find('\0');
        if (terminator != std::string::npos) {
            chatText.resize(terminator);
        }
        const std::size_t jsonStart = chatText.find('{');
        if (jsonStart == std::string::npos) {
            return false;
        }
        json = chatText.substr(jsonStart);
    } else {
        return false;
    }

    std::size_t start = 0;
    while (start < json.size() && std::isspace(static_cast<unsigned char>(json[start])) != 0) {
        ++start;
    }
    if (start >= json.size() || json[start] != '{') {
        return false;
    }

    std::string module;
    if (!readJsonStringField(json, "module", module)
        || module != kWallLobbyJsonNamespace) {
        return false;
    }

    std::string type;
    if (!readJsonStringField(json, "type", type)) {
        return false;
    }

    int parsedProtocolVersion = 0;
    if (!readJsonIntegerField(json, "protocol", parsedProtocolVersion)) {
        return false;
    }
    protocolVersion = static_cast<std::uint16_t>(parsedProtocolVersion);

    static thread_local std::vector<std::uint8_t> parsedPayload;
    parsedPayload.clear();

    if (type == "query" || type == "VersionQuery") {
        messageType = kWallLobbyMessageVersionQuery;
    } else if (type == "version" || type == "VersionInfo") {
        int transportVersion = 0;
        if (!readJsonIntegerField(json, "transport", transportVersion)) {
            return false;
        }
        messageType = kWallLobbyMessageVersionInfo;
        appendLittleEndian16(parsedPayload, protocolVersion);
        appendLittleEndian16(parsedPayload, static_cast<std::uint16_t>(transportVersion));
    } else if (type == "metadata" || type == "MetadataFrame") {
        std::string data;
        if (!readJsonStringField(json, "data", data)
            || !decodeHexPayload(data, parsedPayload)) {
            return false;
        }
        messageType = kWallLobbyMessageMetadataFrame;
    } else {
        return false;
    }

    payload = parsedPayload.empty() ? nullptr : parsedPayload.data();
    payloadSize = parsedPayload.size();
    return true;
}

std::string describeWallLobbyVersionInfo(const std::uint8_t* payload, std::size_t payloadSize) {
    if (payload == nullptr || payloadSize < 4) {
        return "invalid version payload";
    }

    std::ostringstream message;
    message << "protocol "
            << readLittleEndian16(payload)
            << ", transport "
            << readLittleEndian16(payload + 2);
    return message.str();
}

bool isOnlineLobbyHost() {
    LONG value = 0;
    return g_lobbyHostSlotAddress != 0
        && tryReadLong(g_lobbyHostSlotAddress + 12, value)
        && value != 0;
}

bool isOnlineLobbyHostContext() {
    return g_lobbyHostScreenAddress != 0 && isOnlineLobbyHost();
}

bool isOnlineLobbyClient() {
    LONG value = 0;
    return g_lobbyClientSlotAddress != 0
        && tryReadLong(g_lobbyClientSlotAddress + 0xB8, value)
        && value == 3;
}

int onlineLobbyHostSlotCount() {
    if (!isOnlineLobbyHost()) {
        return 0;
    }

    if (g_lobbyHostIncomingConnectionAddress != 0
        && isReadableMemoryRange(g_lobbyHostIncomingConnectionAddress + 0x28, sizeof(std::uint8_t))) {
        const int slots = *reinterpret_cast<const std::uint8_t*>(g_lobbyHostIncomingConnectionAddress + 0x28);
        if (slots > 0 && slots <= 6) {
            return slots;
        }
    }

    return 1;
}

std::uintptr_t onlineLobbyHostSlotsBase() {
    if (!isOnlineLobbyHost()) {
        return 0;
    }

    const int slotCount = onlineLobbyHostSlotCount();
    if (slotCount != 6
        && g_lobbyHostIncomingConnectionAddress != 0
        && isReadableMemoryRange(g_lobbyHostIncomingConnectionAddress + 0xB, sizeof(std::uintptr_t))) {
        std::uintptr_t hostSlots = 0;
        std::memcpy(
            &hostSlots,
            reinterpret_cast<const void*>(g_lobbyHostIncomingConnectionAddress + 0xB),
            sizeof(hostSlots));
        if (hostSlots != 0) {
            return hostSlots;
        }
    }

    return g_lobbyHostSlotAddress;
}

std::uintptr_t onlineLobbyHostSlotAddressFromBase(std::uintptr_t hostSlots, int slot) {
    if (hostSlots == 0 || slot < 0 || slot >= 31) {
        return 0;
    }

    return hostSlots
        + kWaHostSlotDataOffset
        + (static_cast<std::uintptr_t>(slot) * kWaHostSlotStride);
}

bool onlineLobbyHostSlotConnected(int slot) {
    if (slot < 0 || slot >= 31) {
        return false;
    }

    const std::uintptr_t hostSlots = onlineLobbyHostSlotsBase();
    if (hostSlots == 0) {
        return false;
    }

    LONG state = 0;
    const std::uintptr_t slotAddress = onlineLobbyHostSlotAddressFromBase(hostSlots, slot);
    const std::uintptr_t stateAddress = slotAddress + kWaHostSlotConnectionStateOffset;
    return tryReadLong(stateAddress, state) && state == kWaHostSlotConnectedState;
}

std::uint32_t onlineLobbyConnectedSlotMask() {
    std::uint32_t mask = 0;
    const int slotCount = onlineLobbyHostSlotCount();
    for (int slot = 0; slot < slotCount && slot < 31; ++slot) {
        if (onlineLobbyHostSlotConnected(slot)) {
            mask |= (1u << slot);
        }
    }
    return mask;
}

std::uint32_t refreshOnlineLobbyConnectedSlots() {
    const std::uint32_t connected = onlineLobbyConnectedSlotMask();
    const LONG previous = g_onlineLobbyLastConnectedSlotMask;
    const LONG disconnected =
        previous & ~static_cast<LONG>(connected);

    if (disconnected != 0) {
        InterlockedAnd(&g_onlineLobbySeenSlotMask, ~disconnected);
        InterlockedAnd(&g_onlineLobbyCompatibleSlotMask, ~disconnected);
        InterlockedAnd(&g_onlineLobbyBroadcastSlotMask, ~disconnected);
        InterlockedAnd(&g_onlineLobbyQuerySlotMask, ~disconnected);
    }

    InterlockedExchange(&g_onlineLobbyLastConnectedSlotMask, static_cast<LONG>(connected));
    return connected;
}

bool tryReadLobbyAsciiString(std::uintptr_t address, std::string& value) {
    value.clear();
    if (address == 0 || !isReadableMemoryRange(address, 1)) {
        return false;
    }

    for (std::size_t index = 0; index < 31; ++index) {
        if (!isReadableMemoryRange(address + index, 1)) {
            return false;
        }

        const unsigned char ch = *reinterpret_cast<const unsigned char*>(address + index);
        if (ch == '\0') {
            break;
        }

        if (ch < 0x20 || ch == 0x7F) {
            value.clear();
            return false;
        }

        value.push_back(static_cast<char>(ch));
    }

    while (!value.empty() && value.back() == ' ') {
        value.pop_back();
    }
    return !value.empty();
}

std::string onlineLobbySlotName(int slot) {
    const std::uintptr_t hostSlots = onlineLobbyHostSlotsBase();
    if (hostSlots != 0 && slot >= 0 && slot < 31) {
        const std::uintptr_t slotAddress = onlineLobbyHostSlotAddressFromBase(hostSlots, slot);
        const std::uintptr_t compactSlotAddress = hostSlots
            + (static_cast<std::uintptr_t>(slot) * kWaHostSlotStride);
        const std::uintptr_t legacySlotAddress = g_lobbyHostSlotAddress
            + kWaHostSlotDataOffset
            + (static_cast<std::uintptr_t>(slot) * kWaHostSlotStride);
        const std::array<std::uintptr_t, 5> candidateAddresses = {
            slotAddress + kWaHostSlotNicknameOffset,
            compactSlotAddress + kWaHostSlotNicknameOffset,
            compactSlotAddress + kWaHostSlotDataOffset + kWaHostSlotNicknameOffset,
            legacySlotAddress + kWaHostSlotNicknameOffset,
            legacySlotAddress,
        };

        std::string name;
        for (std::uintptr_t candidate : candidateAddresses) {
            if (tryReadLobbyAsciiString(candidate, name)) {
                return name;
            }
        }

        if (g_runtimeProbeLogger != nullptr && g_onlineLobbyMessageLogCount < 24) {
            InterlockedIncrement(&g_onlineLobbyMessageLogCount);
            std::ostringstream message;
            message << "online lobby sync: failed to resolve nickname for slot "
                    << slot
                    << ", hostSlots "
                    << formatAddress(hostSlots)
                    << ", slotAddress "
                    << formatAddress(slotAddress);
            g_runtimeProbeLogger->info(message.str());
        }
    }

    std::ostringstream fallback;
    fallback << "slot " << slot;
    return fallback.str();
}

std::string describeOnlineLobbySlotMask(std::uint32_t mask) {
    std::ostringstream message;
    bool first = true;
    for (int slot = 0; slot < 31; ++slot) {
        if ((mask & (1u << slot)) == 0) {
            continue;
        }

        if (!first) {
            message << ", ";
        }
        first = false;
        message << onlineLobbySlotName(slot);
    }

    if (first) {
        return "none";
    }
    return message.str();
}

void wallLobbyPrint(const std::string& message) {
    if (g_waLobbyDisplayMessage == nullptr || message.empty()) {
        return;
    }

    std::uintptr_t screen = 0;
    if (isOnlineLobbyClient() && g_lobbyClientScreenAddress != 0) {
        screen = g_lobbyClientScreenAddress;
    } else if (isOnlineLobbyHostContext()) {
        screen = g_lobbyHostScreenAddress;
    }

    if (screen == 0 || !isReadableMemoryRange(screen + 0x10318, sizeof(void*))) {
        return;
    }

    std::string formatted = "SYS:wkWall2Wall:ALL:wkWall2Wall: ";
    formatted += message;
    g_waLobbyDisplayMessage(
        static_cast<int>(screen + 0x10318),
        const_cast<char*>(formatted.c_str()));
}

bool wallLobbyVersionPayloadCompatible(
    std::uint16_t protocolVersion,
    const std::uint8_t* payload,
    std::size_t payloadSize) {
    return protocolVersion == kWallProtocolVersion
        && payload != nullptr
        && payloadSize >= 4
        && readLittleEndian16(payload) == kWallProtocolVersion
        && readLittleEndian16(payload + 2) == kWallTransportVersion;
}

void resetOnlineLobbyCompatibilityState(DWORD now) {
    const std::uint32_t connected = refreshOnlineLobbyConnectedSlots();
    InterlockedExchange(&g_onlineLobbySeenSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyCompatibleSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyBroadcastSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyQuerySlotMask, 0);
    InterlockedExchange(&g_onlineLobbyLastConnectedSlotMask, static_cast<LONG>(connected));
    InterlockedExchange(
        &g_onlineLobbyCompatibilityDeadlineTick,
        static_cast<LONG>(now + kOnlineLobbyCompatibilityTimeoutMilliseconds));
    InterlockedExchange(&g_onlineLobbyCompatibilityReported, 0);
}

bool onlineLobbyTickReached(DWORD tick) {
    return tick != 0 && static_cast<LONG>(GetTickCount() - tick) >= 0;
}

void reportOnlineLobbyCompatibilityStatus(bool force) {
    if (!g_onlineSyncEnabled || !isOnlineLobbyHostContext()) {
        return;
    }

    const DWORD deadline = static_cast<DWORD>(g_onlineLobbyCompatibilityDeadlineTick);
    const bool deadlineReached = onlineLobbyTickReached(deadline);

    const std::uint32_t connected = refreshOnlineLobbyConnectedSlots();
    if (connected == 0) {
        return;
    }

    const std::uint32_t seen = static_cast<std::uint32_t>(g_onlineLobbySeenSlotMask);
    const std::uint32_t compatible = static_cast<std::uint32_t>(g_onlineLobbyCompatibleSlotMask);
    const std::uint32_t missing = connected & ~seen;
    const std::uint32_t incompatible = connected & seen & ~compatible;
    const bool allCompatible = missing == 0 && incompatible == 0;

    if (!allCompatible && !force && !deadlineReached) {
        return;
    }

    if (InterlockedCompareExchange(&g_onlineLobbyCompatibilityReported, 1, 0) != 0 && !allCompatible) {
        return;
    }

    if (allCompatible) {
        wallLobbyPrint("all connected players have a compatible wkWall2Wall.");
        return;
    }

    std::ostringstream message;
    if (missing != 0) {
        message << "missing wkWall2Wall response from: "
                << describeOnlineLobbySlotMask(missing);
    }
    if (incompatible != 0) {
        if (missing != 0) {
            message << "; ";
        }
        message << "incompatible wkWall2Wall version from: "
                << describeOnlineLobbySlotMask(incompatible);
    }
    wallLobbyPrint(message.str());
}

void checkOnlineLobbyCompatibilityTimeout() {
    const DWORD deadline = static_cast<DWORD>(g_onlineLobbyCompatibilityDeadlineTick);
    if (deadline == 0 || g_onlineLobbyCompatibilityReported != 0) {
        return;
    }

    if (onlineLobbyTickReached(deadline)) {
        reportOnlineLobbyCompatibilityStatus(true);
    }
}

bool onlineLobbySlotHasCompatibleVersion(int slot) {
    if (slot < 0 || slot >= 31) {
        return false;
    }

    const std::uint32_t slotMask = 1u << slot;
    const std::uint32_t seen = static_cast<std::uint32_t>(g_onlineLobbySeenSlotMask);
    const std::uint32_t compatible = static_cast<std::uint32_t>(g_onlineLobbyCompatibleSlotMask);
    return (seen & slotMask) != 0 && (compatible & slotMask) != 0;
}

bool onlineLobbyCompatibilityCompleteForCurrentPlayers() {
    if (!g_onlineSyncEnabled || !g_onlineRequireAllPlayers || !isOnlineLobbyHostContext()) {
        return true;
    }

    const std::uint32_t connected = refreshOnlineLobbyConnectedSlots();
    if (connected == 0) {
        return true;
    }

    const std::uint32_t seen = static_cast<std::uint32_t>(g_onlineLobbySeenSlotMask);
    const std::uint32_t compatible = static_cast<std::uint32_t>(g_onlineLobbyCompatibleSlotMask);
    return (connected & ~seen) == 0 && (connected & seen & ~compatible) == 0;
}

bool onlineWallModuleAllowedForCurrentContext() {
    if (!g_onlineSyncEnabled || !g_onlineRequireAllPlayers || !isOnlineLobbyHostContext()) {
        return true;
    }

    if (refreshOnlineLobbyConnectedSlots() == 0) {
        return true;
    }

    return onlineLobbyCompatibilityCompleteForCurrentPlayers();
}

bool sendWallLobbyPacketToClientSlot(int slot, const std::vector<std::uint8_t>& packet) {
    if (packet.empty()
        || g_lobbyHostUnicastAddress == 0
        || g_lobbyHostSlotAddress == 0
        || !isOnlineLobbyHostContext()) {
        return false;
    }

    const char* packetData = reinterpret_cast<const char*>(packet.data());
    const std::size_t packetSize = packet.size();
    const std::uintptr_t hostSlot = g_lobbyHostSlotAddress;
    const std::uintptr_t hostUnicast = g_lobbyHostUnicastAddress;
    int result = 0;

#if defined(__i386__) || defined(_M_IX86)
    // Load register arguments before pushing the stack argument. GCC may address
    // local operands relative to ESP, so a preceding push would shift them.
    asm volatile(
        "movl %[packetData], %%esi\n\t"
        "movl %[slot], %%ecx\n\t"
        "movl %[packetSize], %%edx\n\t"
        "pushl %[hostSlot]\n\t"
        "call *%[hostUnicast]\n\t"
        : "=a"(result)
        : [hostUnicast] "r"(hostUnicast),
          [hostSlot] "m"(hostSlot),
          [packetData] "m"(packetData),
          [slot] "m"(slot),
          [packetSize] "m"(packetSize)
        : "ecx", "edx", "esi", "memory", "cc");
#else
    (void)slot;
    (void)packetData;
    (void)packetSize;
    (void)hostSlot;
    (void)hostUnicast;
#endif

    return result != 0;
}

bool sendWallLobbyPacketToHost(const std::vector<std::uint8_t>& packet) {
    if (packet.empty()
        || g_lobbyClientSlotAddress == 0
        || !isOnlineLobbyClient()
        || !isReadableMemoryRange(g_lobbyClientSlotAddress, sizeof(std::uintptr_t))) {
        return false;
    }

    const std::uintptr_t vtable = *reinterpret_cast<std::uintptr_t*>(g_lobbyClientSlotAddress);
    if (!isReadableMemoryRange(vtable + 52, sizeof(std::uintptr_t))) {
        return false;
    }

    const auto sendFunction =
        reinterpret_cast<WaClientSendPacketFunction>(*reinterpret_cast<std::uintptr_t*>(vtable + 52));
    if (sendFunction == nullptr) {
        return false;
    }

    return sendFunction(
        reinterpret_cast<void*>(g_lobbyClientSlotAddress),
        const_cast<unsigned char*>(packet.data()),
        packet.size()) != 0;
}

void sendWallLobbyVersionInfoToHost() {
    sendWallLobbyPacketToHost(makeWallLobbyChatPacket(kWallLobbyMessageVersionInfo));
}

bool sendWallLobbyVersionQueryToClientSlot(int slot) {
    if (slot < 0 || slot >= 31) {
        return false;
    }

    const LONG slotMask = 1L << slot;
    const LONG previous = InterlockedOr(&g_onlineLobbyQuerySlotMask, slotMask);
    if ((previous & slotMask) != 0) {
        return false;
    }

    const bool sent =
        sendWallLobbyPacketToClientSlot(slot, makeWallLobbyChatPacket(kWallLobbyMessageVersionQuery));
    if (!sent) {
        InterlockedAnd(&g_onlineLobbyQuerySlotMask, ~slotMask);
    }
    return sent;
}

void broadcastWallLobbyVersionQuery() {
    const int slotCount = onlineLobbyHostSlotCount();
    const std::uint32_t connected = refreshOnlineLobbyConnectedSlots();
    for (int slot = 0; slot < slotCount && slot < 31; ++slot) {
        if ((connected & (1u << slot)) != 0) {
            sendWallLobbyVersionQueryToClientSlot(slot);
        }
    }
}

bool sendQueuedOnlineMetadataToLobbySlot(
    int slot,
    const std::vector<std::vector<std::uint8_t>>& frames) {
    if (!kOnlineLobbyHostUnicastEnabled
        || frames.empty()
        || !onlineLobbySlotHasCompatibleVersion(slot)) {
        return false;
    }

    bool sentAny = false;
    for (const std::vector<std::uint8_t>& frame : frames) {
        sentAny = sendWallLobbyPacketToClientSlot(
            slot,
            makeWallLobbyPacket(kWallLobbyMessageMetadataFrame, frame)) || sentAny;
    }

    if (sentAny && slot >= 0 && slot < 31) {
        InterlockedOr(&g_onlineLobbyBroadcastSlotMask, 1L << slot);
    }
    return sentAny;
}

int sendQueuedOnlineMetadataToCompatibleLobbySlots(
    const std::vector<std::vector<std::uint8_t>>& frames) {
    if (frames.empty()
        || !isOnlineLobbyHostContext()
        || (g_onlineRequireAllPlayers && !onlineLobbyCompatibilityCompleteForCurrentPlayers())) {
        return 0;
    }

    const int slotCount = onlineLobbyHostSlotCount();
    const std::uint32_t connected = refreshOnlineLobbyConnectedSlots();
    const std::uint32_t compatible = static_cast<std::uint32_t>(g_onlineLobbyCompatibleSlotMask);
    int sentSlots = 0;
    for (int slot = 0; slot < slotCount && slot < 31; ++slot) {
        const std::uint32_t slotMask = 1u << slot;
        if ((connected & slotMask) == 0 || (compatible & slotMask) == 0) {
            continue;
        }
        if ((g_onlineLobbyBroadcastSlotMask & static_cast<LONG>(slotMask)) != 0) {
            continue;
        }
        if (sendQueuedOnlineMetadataToLobbySlot(slot, frames)) {
            ++sentSlots;
        }
    }
    return sentSlots;
}

void broadcastQueuedOnlineMetadataToLobby() {
    if (!g_onlineSyncEnabled || !isOnlineLobbyHostContext()) {
        return;
    }

    const DWORD now = GetTickCount();
    const LONG lastTick = g_onlineLobbyLastBroadcastTick;
    if (lastTick != 0
        && now - static_cast<DWORD>(lastTick) < kOnlineLobbyBroadcastCooldownMilliseconds) {
        return;
    }

    std::vector<std::vector<std::uint8_t>> frames;
    {
        std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
        frames = g_onlineOutgoingFrames;
    }

    if (frames.empty()) {
        return;
    }

    if (refreshOnlineLobbyConnectedSlots() == 0) {
        return;
    }

    InterlockedExchange(&g_onlineLobbyLastBroadcastTick, static_cast<LONG>(now));

    if (!kOnlineLobbyHostUnicastEnabled) {
        wallLobbyPrint("wall metadata loaded; online compatibility handshake is paused in this build.");
        if (g_runtimeProbeLogger != nullptr && g_onlineLobbyMessageLogCount < 24) {
            InterlockedIncrement(&g_onlineLobbyMessageLogCount);
            g_runtimeProbeLogger->info("online lobby sync: host unicast disabled; skipped binary lobby compatibility packets");
        }
        return;
    }

    resetOnlineLobbyCompatibilityState(now);
    wallLobbyPrint("wall metadata loaded; checking wkWall2Wall clients.");
    broadcastWallLobbyVersionQuery();
    const int sentSlots = sendQueuedOnlineMetadataToCompatibleLobbySlots(frames);

    if (g_runtimeProbeLogger != nullptr && g_onlineLobbyMessageLogCount < 24) {
        InterlockedIncrement(&g_onlineLobbyMessageLogCount);
        std::ostringstream log;
        log << "online lobby sync: sent chat compatibility query and prepared "
            << frames.size()
            << " metadata frame(s)";
        if (sentSlots > 0) {
            log << "; sent to " << sentSlots << " compatible slot(s)";
        } else {
            log << "; waiting for compatible client responses";
        }
        g_runtimeProbeLogger->info(log.str());
    }
}

bool hasQueuedOnlineMetadataFrames() {
    std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
    return !g_onlineOutgoingFrames.empty();
}

void maybeBroadcastQueuedOnlineMetadataForLobbySlot(int slot) {
    if (!g_onlineSyncEnabled
        || slot < 0
        || slot >= 31
        || !isOnlineLobbyHostContext()
        || !hasQueuedOnlineMetadataFrames()) {
        return;
    }

    if (!kOnlineLobbyHostUnicastEnabled) {
        return;
    }

    const std::uint32_t connected = refreshOnlineLobbyConnectedSlots();
    if ((connected & (1u << slot)) == 0) {
        return;
    }

    const DWORD now = GetTickCount();
    const LONG lastTick = g_onlineLobbyLastBroadcastTick;
    if (lastTick != 0
        && now - static_cast<DWORD>(lastTick) < kOnlineLobbyBroadcastCooldownMilliseconds) {
        return;
    }

    bool sentSomething = false;

    if (!onlineLobbySlotHasCompatibleVersion(slot)) {
        sentSomething = sendWallLobbyVersionQueryToClientSlot(slot);
        if (sentSomething) {
            InterlockedExchange(
                &g_onlineLobbyCompatibilityDeadlineTick,
                static_cast<LONG>(now + kOnlineLobbyCompatibilityTimeoutMilliseconds));
            InterlockedExchange(&g_onlineLobbyCompatibilityReported, 0);
        }
    } else {
        std::vector<std::vector<std::uint8_t>> frames;
        {
            std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
            frames = g_onlineOutgoingFrames;
        }
        sentSomething = sendQueuedOnlineMetadataToCompatibleLobbySlots(frames) > 0;
    }

    if (!sentSomething) {
        return;
    }

    InterlockedExchange(&g_onlineLobbyLastBroadcastTick, static_cast<LONG>(now));

    if (g_runtimeProbeLogger != nullptr && g_onlineLobbyMessageLogCount < 24) {
        InterlockedIncrement(&g_onlineLobbyMessageLogCount);
        std::ostringstream message;
        message << "online lobby sync: refreshed compatibility check after activity from "
                << onlineLobbySlotName(slot);
        g_runtimeProbeLogger->info(message.str());
    }
}

void handleWallLobbyPacketAsHost(
    int slot,
    std::uint8_t messageType,
    std::uint16_t protocolVersion,
    const std::uint8_t* payload,
    std::size_t payloadSize) {
    if (messageType == kWallLobbyMessageVersionInfo) {
        const LONG slotMask = (slot >= 0 && slot < 31) ? (1L << slot) : 0;
        const bool compatible = wallLobbyVersionPayloadCompatible(protocolVersion, payload, payloadSize);
        if (slotMask != 0) {
            InterlockedOr(&g_onlineLobbySeenSlotMask, slotMask);
            if (compatible) {
                InterlockedOr(&g_onlineLobbyCompatibleSlotMask, slotMask);
            } else {
                InterlockedAnd(&g_onlineLobbyCompatibleSlotMask, ~slotMask);
            }
            InterlockedExchange(&g_onlineLobbyCompatibilityReported, 0);
        }

        std::ostringstream message;
        message << onlineLobbySlotName(slot)
                << " has wkWall2Wall "
                << describeWallLobbyVersionInfo(payload, payloadSize);
        if (!compatible) {
            message << " (incompatible)";
        }
        if (protocolVersion != kWallProtocolVersion) {
            message << " (lobby header protocol " << protocolVersion << ")";
        }
        wallLobbyPrint(message.str());
        if (g_runtimeProbeLogger != nullptr && g_onlineLobbyPacketLogCount < 48) {
            InterlockedIncrement(&g_onlineLobbyPacketLogCount);
            g_runtimeProbeLogger->info("online lobby sync: " + message.str());
        }
        if (compatible && hasQueuedOnlineMetadataFrames()) {
            std::vector<std::vector<std::uint8_t>> frames;
            {
                std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
                frames = g_onlineOutgoingFrames;
            }
            const int sentSlots = sendQueuedOnlineMetadataToCompatibleLobbySlots(frames);
            if (sentSlots > 0 && g_runtimeProbeLogger != nullptr && g_onlineLobbyMessageLogCount < 24) {
                InterlockedIncrement(&g_onlineLobbyMessageLogCount);
                std::ostringstream log;
                log << "online lobby sync: sent queued metadata to "
                    << sentSlots
                    << " compatible slot(s) after version response";
                g_runtimeProbeLogger->info(log.str());
            }
        }
        reportOnlineLobbyCompatibilityStatus(false);
        return;
    }

    if (g_runtimeProbeLogger != nullptr && g_onlineLobbyPacketLogCount < 48) {
        InterlockedIncrement(&g_onlineLobbyPacketLogCount);
        std::ostringstream message;
        message << "online lobby sync: host ignored message type "
                << static_cast<int>(messageType)
                << " from slot "
                << slot;
        g_runtimeProbeLogger->info(message.str());
    }
}

void handleWallLobbyPacketAsClient(
    std::uint8_t messageType,
    std::uint16_t protocolVersion,
    const std::uint8_t* payload,
    std::size_t payloadSize) {
    if (protocolVersion != kWallProtocolVersion) {
        std::ostringstream message;
        message << "host wkWall2Wall protocol mismatch: host "
                << protocolVersion
                << ", local "
                << kWallProtocolVersion;
        wallLobbyPrint(message.str());
        if (g_runtimeProbeLogger != nullptr && g_onlineLobbyPacketLogCount < 48) {
            InterlockedIncrement(&g_onlineLobbyPacketLogCount);
            g_runtimeProbeLogger->warn("online lobby sync: " + message.str());
        }
        return;
    }

    if (messageType == kWallLobbyMessageVersionQuery) {
        sendWallLobbyVersionInfoToHost();
        wallLobbyPrint("host requested wkWall2Wall compatibility check.");
        return;
    }

    if (messageType == kWallLobbyMessageMetadataFrame) {
        handleIncomingOnlineMetadataFrame(payload, payloadSize);
        return;
    }

    if (messageType == kWallLobbyMessageVersionInfo) {
        wallLobbyPrint("host has wkWall2Wall " + describeWallLobbyVersionInfo(payload, payloadSize));
    }
}

LONG readWaObjectLong(void* owner, std::uintptr_t offset) {
    if (owner == nullptr) {
        return 0;
    }

    const auto address = reinterpret_cast<std::uintptr_t>(owner) + offset;
    LONG value = 0;
    return tryReadLong(address, value) ? value : 0;
}

std::size_t touchedOverlayWallCount();
std::size_t resetTouchedOverlayWallsForNewTurn();
void clearActiveWormCandidateForTurnChange();
void resetCollisionDiagnosticLogWindows();

const char* waTaskMessageName(std::uint32_t messageType) {
    switch (messageType) {
    case kWallGameTaskMessageMetadataFrame:
        return "Wall2WallMetadataFrame";
    case 7:
        return "CrateCollected";
    case 49:
        return "StartTurn";
    case 50:
        return "PauseTurn";
    case 51:
        return "ResumeTurn";
    case 52:
        return "FinishTurn";
    case 53:
        return "TurnStarted";
    case 54:
        return "TurnFinished";
    case 57:
        return "RetreatStarted";
    case 58:
        return "RetreatFinished";
    case 60:
        return "SetWorm";
    case 73:
        return "WeaponFinished";
    default:
        return "other";
    }
}

bool waTaskMessageLooksTurnRelated(std::uint32_t messageType) {
    switch (messageType) {
    case kWallGameTaskMessageMetadataFrame:
    case 7:
    case 49:
    case 52:
    case 53:
    case 54:
    case 57:
    case 58:
    case 60:
    case 73:
        return true;
    default:
        return false;
    }
}

enum class OpenGLOverlayPass {
    BeforeSwap,
    AfterGlEnd,
};
void drawOpenGLOverlayTestRects(OpenGLOverlayPass pass);

enum class AttackBlockReason {
    None,
    WallsIncomplete,
    CrateMissing,
    RopeRequired,
};

bool ownerKindLooksLikeRopeContext(LONG ownerKind);
void noteRecentRopeContext(LONG ownerKind);
bool recentRopeContextActive();

LONG readTurnGameLong(void* turnGame, std::uintptr_t offset) {
    if (turnGame == nullptr) {
        return 0;
    }

    LONG value = 0;
    const auto address = reinterpret_cast<std::uintptr_t>(turnGame) + offset;
    return tryReadLong(address, value) ? value : 0;
}

void logTurnGameMessageProbe(
    const char* phase,
    void* turnGame,
    void* sender,
    std::uint32_t messageType,
    std::size_t dataSize,
    void* data,
    int result) {
    if (!kVerboseRuntimeDiagnostics
        || g_runtimeProbeLogger == nullptr
        || !waTaskMessageLooksTurnRelated(messageType)) {
        return;
    }

    const LONG logCount = InterlockedIncrement(&g_turnGameHandleMessageLogCount);
    if (logCount > 160) {
        return;
    }

    const LONG teamA = readTurnGameLong(turnGame, 0x12C);
    const LONG teamB = readTurnGameLong(turnGame, 0x134);
    const LONG beforeRoundStart = readTurnGameLong(turnGame, 0x140);
    const LONG turnPaused = readTurnGameLong(turnGame, 0x150);
    const LONG retreatTimer = readTurnGameLong(turnGame, 0x178);
    const LONG roundTimer = readTurnGameLong(turnGame, 0x184);
    const LONG turnTimerA = readTurnGameLong(turnGame, 0x188);
    const LONG turnTimerB = readTurnGameLong(turnGame, 0x18C);

    LONG data0 = 0;
    const bool hasData0 = data != nullptr && dataSize >= sizeof(LONG)
        && tryReadLong(reinterpret_cast<std::uintptr_t>(data), data0);

    std::ostringstream message;
    message << "runtime probe: CTaskTurnGame::HandleMessage " << phase
            << " type " << messageType
            << " (" << waTaskMessageName(messageType) << ")"
            << " result " << result
            << " this " << formatAddress(reinterpret_cast<std::uintptr_t>(turnGame))
            << " sender " << formatAddress(reinterpret_cast<std::uintptr_t>(sender))
            << " size " << dataSize
            << " data " << formatAddress(reinterpret_cast<std::uintptr_t>(data));
    if (hasData0) {
        message << " data0 " << data0;
    }
    message << " team12C " << teamA
            << " team134 " << teamB
            << " beforeRound " << beforeRoundStart
            << " paused " << turnPaused
            << " retreatTimer " << retreatTimer
            << " roundTimer " << roundTimer
            << " turnTimer188 " << turnTimerA
            << " turnTimer18C " << turnTimerB
            << " touchedWalls " << touchedOverlayWallCount()
            << " crateCollected " << (g_crateCollectedThisTurn != 0 ? "yes" : "no");
    g_runtimeProbeLogger->info(message.str());
}

void resetTouchedOverlayWallsForTurnGameFinishTurn(void* turnGame, void* data, std::size_t dataSize) {
    if (touchedOverlayWallCount() == 0) {
        return;
    }

    const DWORD now = GetTickCount();
    const DWORD lastResetTick = static_cast<DWORD>(g_turnGameFinishTurnLastResetTick);
    if (lastResetTick != 0 && now - lastResetTick < kTurnGameFinishTurnResetDebounceMilliseconds) {
        return;
    }

    LONG data0 = 0;
    const bool hasData0 = data != nullptr && dataSize >= sizeof(LONG)
        && tryReadLong(reinterpret_cast<std::uintptr_t>(data), data0);
    const LONG teamA = readTurnGameLong(turnGame, 0x12C);
    const LONG teamB = readTurnGameLong(turnGame, 0x134);

    clearActiveWormCandidateForTurnChange();
    const std::size_t resetCount = resetTouchedOverlayWallsForNewTurn();
    if (resetCount == 0) {
        return;
    }

    InterlockedExchange(&g_wallTouchLastResetTick, static_cast<LONG>(now));
    InterlockedExchange(&g_turnGameFinishTurnLastResetTick, static_cast<LONG>(now));

    if (g_runtimeProbeLogger != nullptr && g_wallTouchResetLogCount < 32) {
        InterlockedIncrement(&g_wallTouchResetLogCount);

        std::ostringstream message;
        message << "runtime probe: wall touch state reset for CTaskTurnGame FinishTurn";
        if (hasData0) {
            message << " data0 " << data0;
        }
        message << " team12C "
                << teamA
                << " team134 "
                << teamB
                << ", reset "
                << resetCount
                << " touched wall(s)";
        g_runtimeProbeLogger->info(message.str());
    }
}

void resetCrateCollectionForNewTurn(const char* reason) {
    const LONG previous = InterlockedExchange(&g_crateCollectedThisTurn, 0);
    InterlockedExchange(&g_wallWarningSoundLastTick, 0);
    if (previous == 0 || g_runtimeProbeLogger == nullptr || g_crateCollectionLogCount >= 32) {
        return;
    }

    InterlockedIncrement(&g_crateCollectionLogCount);
    std::ostringstream message;
    message << "runtime probe: crate collection state reset for "
            << (reason != nullptr && reason[0] != '\0' ? reason : "new turn");
    g_runtimeProbeLogger->info(message.str());
}

void markCrateCollectedThisTurn(void* sender, void* data, std::size_t dataSize) {
    const LONG previous = InterlockedExchange(&g_crateCollectedThisTurn, 1);
    if (previous != 0 || g_runtimeProbeLogger == nullptr || g_crateCollectionLogCount >= 32) {
        return;
    }

    InterlockedIncrement(&g_crateCollectionLogCount);
    std::ostringstream message;
    message << "runtime probe: crate collected for attack requirement"
            << " sender " << formatAddress(reinterpret_cast<std::uintptr_t>(sender))
            << " data " << formatAddress(reinterpret_cast<std::uintptr_t>(data))
            << " size " << dataSize
            << " touchedWalls " << touchedOverlayWallCount()
            << "/" << g_direct3D9OverlayTestRects.size();
    g_runtimeProbeLogger->info(message.str());
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

std::size_t touchedOverlayWallCount() {
    std::size_t count = 0;
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (rect.touched) {
            ++count;
        }
    }
    return count;
}

void noteWallGameplayTaskActivity() {
    InterlockedExchange(&g_wallGameplayTaskActive, 1);
    InterlockedExchange(&g_wallGameplayTaskLastTick, static_cast<LONG>(GetTickCount()));
}

void resetWallGameplayTaskActivity() {
    InterlockedExchange(&g_wallGameplayTaskActive, 0);
    InterlockedExchange(&g_wallGameplayTaskLastTick, 0);
}

bool wallOverlayMetadataActive() {
    return g_direct3D9ActiveOverlayMapIndex >= 0
        && !g_direct3D9OverlayTestRects.empty();
}

bool wallRuntimeHooksShouldProcessFast() {
    return g_wallGameplayTaskActive != 0
        && wallOverlayMetadataActive();
}

bool activeOverlayMapTrustedByOnlineMetadata(LONG activeIndex) {
    return activeIndex >= 0 && g_onlineMetadataTrustedOverlayMapIndex == activeIndex;
}

void trustActiveOverlayMapForOnlineMetadata(std::size_t mapIndex) {
    if (mapIndex > static_cast<std::size_t>(std::numeric_limits<LONG>::max())) {
        return;
    }

    InterlockedExchange(
        &g_onlineMetadataTrustedOverlayMapIndex,
        static_cast<LONG>(mapIndex));
}

void clearOnlineMetadataTrust() {
    InterlockedExchange(&g_onlineMetadataTrustedOverlayMapIndex, -1);
}

bool activeOverlayMapStillMatchesDetectedMap() {
    const LONG activeIndex = g_direct3D9ActiveOverlayMapIndex;
    if (activeIndex < 0 || static_cast<std::size_t>(activeIndex) >= g_direct3D9OverlayMaps.size()) {
        return false;
    }

    if (activeOverlayMapTrustedByOnlineMetadata(activeIndex)) {
        return true;
    }

    std::string detectedPath;
    std::string detectedFileName;
    {
        std::lock_guard<std::mutex> lock(g_detectedMapMutex);
        detectedPath = g_detectedMapPath;
        detectedFileName = g_detectedMapFileName;
    }

    if (detectedPath.empty() || detectedFileName.empty()) {
        return false;
    }

    const WaOverlayMap& activeMap = g_direct3D9OverlayMaps[static_cast<std::size_t>(activeIndex)];
    return sameFileName(activeMap.fileName, detectedFileName)
        || sameFileName(activeMap.fileName, detectedPath);
}

bool wallGameplayRulesActiveForCurrentMap() {
    const DWORD lastRendererGameplayTick =
        static_cast<DWORD>(g_direct3D9OverlayLastGameplayEvidenceTick);
    const bool recentRendererGameplayEvidence =
        g_direct3D9OverlayGameplayActive != 0
        && lastRendererGameplayTick != 0
        && GetTickCount() - lastRendererGameplayTick <= 1500;

    return g_wallGameplayTaskActive != 0
        && recentRendererGameplayEvidence
        && wallOverlayMetadataActive()
        && activeOverlayMapStillMatchesDetectedMap();
}

AttackBlockReason currentAttackBlockReason() {
    if (!onlineWallModuleAllowedForCurrentContext()
        || !wallGameplayRulesActiveForCurrentMap()) {
        return AttackBlockReason::None;
    }

    const std::size_t totalWalls = g_direct3D9OverlayTestRects.size();
    if (totalWalls == 0) {
        return AttackBlockReason::None;
    }

    if (touchedOverlayWallCount() < totalWalls) {
        return AttackBlockReason::WallsIncomplete;
    }

    if (g_crateCollectedThisTurn == 0) {
        return AttackBlockReason::CrateMissing;
    }

    return AttackBlockReason::None;
}

bool attackRulesApplyToCurrentMap() {
    return onlineWallModuleAllowedForCurrentContext()
        && wallGameplayRulesActiveForCurrentMap();
}

const char* attackBlockReasonName(AttackBlockReason reason) {
    switch (reason) {
    case AttackBlockReason::WallsIncomplete:
        return "walls incomplete";
    case AttackBlockReason::CrateMissing:
        return "crate missing";
    case AttackBlockReason::RopeRequired:
        return "rope required";
    default:
        return "";
    }
}

bool wallSoundFileExists(const std::string& path) {
    if (path.empty()) {
        return false;
    }

    const DWORD attributes = GetFileAttributesA(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::uint16_t readLe16(const std::vector<BYTE>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(bytes[offset])
        | (static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
}

std::uint32_t readLe32(const std::vector<BYTE>& bytes, std::size_t offset) {
    return static_cast<std::uint32_t>(bytes[offset])
        | (static_cast<std::uint32_t>(bytes[offset + 1]) << 8)
        | (static_cast<std::uint32_t>(bytes[offset + 2]) << 16)
        | (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

bool chunkIdEquals(const std::vector<BYTE>& bytes, std::size_t offset, const char* id) {
    return offset + 4 <= bytes.size()
        && bytes[offset] == static_cast<BYTE>(id[0])
        && bytes[offset + 1] == static_cast<BYTE>(id[1])
        && bytes[offset + 2] == static_cast<BYTE>(id[2])
        && bytes[offset + 3] == static_cast<BYTE>(id[3]);
}

bool loadPcmWaveFile(
    const std::string& path,
    int volumePercent,
    WAVEFORMATEX& format,
    std::vector<BYTE>& audioData) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }

    std::vector<BYTE> bytes(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    if (bytes.size() < 44
        || !chunkIdEquals(bytes, 0, "RIFF")
        || !chunkIdEquals(bytes, 8, "WAVE")) {
        return false;
    }

    std::size_t fmtOffset = 0;
    std::uint32_t fmtSize = 0;
    std::size_t dataOffset = 0;
    std::uint32_t dataSize = 0;
    std::size_t offset = 12;
    while (offset + 8 <= bytes.size()) {
        const std::uint32_t chunkSize = readLe32(bytes, offset + 4);
        const std::size_t chunkDataOffset = offset + 8;
        if (chunkDataOffset + chunkSize > bytes.size()) {
            break;
        }

        if (chunkIdEquals(bytes, offset, "fmt ")) {
            fmtOffset = chunkDataOffset;
            fmtSize = chunkSize;
        } else if (chunkIdEquals(bytes, offset, "data")) {
            dataOffset = chunkDataOffset;
            dataSize = chunkSize;
        }

        offset = chunkDataOffset + chunkSize + (chunkSize & 1U);
    }

    if (fmtOffset == 0 || fmtSize < 16 || dataOffset == 0 || dataSize == 0) {
        return false;
    }

    const std::uint16_t audioFormat = readLe16(bytes, fmtOffset);
    const std::uint16_t channels = readLe16(bytes, fmtOffset + 2);
    const std::uint32_t samplesPerSecond = readLe32(bytes, fmtOffset + 4);
    const std::uint32_t averageBytesPerSecond = readLe32(bytes, fmtOffset + 8);
    const std::uint16_t blockAlign = readLe16(bytes, fmtOffset + 12);
    const std::uint16_t bitsPerSample = readLe16(bytes, fmtOffset + 14);
    if (audioFormat != WAVE_FORMAT_PCM
        || channels == 0
        || samplesPerSecond == 0
        || blockAlign == 0
        || (bitsPerSample != 8 && bitsPerSample != 16)) {
        return false;
    }

    format = {};
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = channels;
    format.nSamplesPerSec = samplesPerSecond;
    format.nAvgBytesPerSec = averageBytesPerSecond;
    format.nBlockAlign = blockAlign;
    format.wBitsPerSample = bitsPerSample;

    audioData.assign(bytes.begin() + dataOffset, bytes.begin() + dataOffset + dataSize);
    const int clampedVolume = std::max(0, std::min(100, volumePercent));
    if (clampedVolume == 100) {
        return true;
    }

    if (bitsPerSample == 16) {
        for (std::size_t index = 0; index + 1 < audioData.size(); index += 2) {
            const int sample = static_cast<short>(
                static_cast<std::uint16_t>(audioData[index])
                | (static_cast<std::uint16_t>(audioData[index + 1]) << 8));
            const int scaled = (sample * clampedVolume) / 100;
            const auto output = static_cast<std::int16_t>(std::max(-32768, std::min(32767, scaled)));
            audioData[index] = static_cast<BYTE>(output & 0xFF);
            audioData[index + 1] = static_cast<BYTE>((output >> 8) & 0xFF);
        }
    } else {
        for (BYTE& sample : audioData) {
            const int centered = static_cast<int>(sample) - 128;
            const int scaled = (centered * clampedVolume) / 100;
            sample = static_cast<BYTE>(std::max(0, std::min(255, scaled + 128)));
        }
    }

    return true;
}

struct WallSoundPlaybackRequest {
    std::string path;
    int volumePercent = 100;
};

DWORD WINAPI wallSoundPlaybackThread(LPVOID parameter) {
    std::unique_ptr<WallSoundPlaybackRequest> request(static_cast<WallSoundPlaybackRequest*>(parameter));
    if (request == nullptr) {
        return 0;
    }

    WAVEFORMATEX format = {};
    std::vector<BYTE> audioData;
    if (!loadPcmWaveFile(request->path, request->volumePercent, format, audioData)) {
        if (g_runtimeProbeLogger != nullptr && g_wallSoundLogCount < 8) {
            InterlockedIncrement(&g_wallSoundLogCount);
            g_runtimeProbeLogger->warn("wall sound WAV load failed: " + request->path);
        }
        return 0;
    }

    HWAVEOUT waveOut = nullptr;
    MMRESULT result = waveOutOpen(&waveOut, WAVE_MAPPER, &format, 0, 0, CALLBACK_NULL);
    if (result != MMSYSERR_NOERROR || waveOut == nullptr) {
        if (g_runtimeProbeLogger != nullptr && g_wallSoundLogCount < 8) {
            InterlockedIncrement(&g_wallSoundLogCount);
            g_runtimeProbeLogger->warn("wall sound waveOutOpen failed: " + request->path);
        }
        return 0;
    }

    WAVEHDR header = {};
    header.lpData = reinterpret_cast<LPSTR>(audioData.data());
    header.dwBufferLength = static_cast<DWORD>(audioData.size());
    result = waveOutPrepareHeader(waveOut, &header, sizeof(header));
    if (result == MMSYSERR_NOERROR) {
        result = waveOutWrite(waveOut, &header, sizeof(header));
    }

    if (result != MMSYSERR_NOERROR) {
        if (header.dwFlags & WHDR_PREPARED) {
            waveOutUnprepareHeader(waveOut, &header, sizeof(header));
        }
        waveOutClose(waveOut);
        if (g_runtimeProbeLogger != nullptr && g_wallSoundLogCount < 8) {
            InterlockedIncrement(&g_wallSoundLogCount);
            g_runtimeProbeLogger->warn("wall sound waveOutWrite failed: " + request->path);
        }
        return 0;
    }

    while ((header.dwFlags & WHDR_DONE) == 0) {
        Sleep(5);
    }

    waveOutUnprepareHeader(waveOut, &header, sizeof(header));
    waveOutClose(waveOut);

    if (g_runtimeProbeLogger != nullptr && g_wallSoundLogCount < 8) {
        InterlockedIncrement(&g_wallSoundLogCount);
        g_runtimeProbeLogger->info("wall sound playback started: " + request->path);
    }
    return 0;
}

void playWallSoundPath(const std::string& path) {
    if (!g_soundConfig.enabled || path.empty() || g_soundConfig.volumePercent <= 0) {
        return;
    }

    if (!wallSoundFileExists(path)) {
        if (g_runtimeProbeLogger != nullptr && g_wallSoundMissingLogCount < 8) {
            InterlockedIncrement(&g_wallSoundMissingLogCount);
            g_runtimeProbeLogger->warn("wall sound file not found: " + path);
        }
        return;
    }

    auto request = std::make_unique<WallSoundPlaybackRequest>();
    request->path = path;
    request->volumePercent = g_soundConfig.volumePercent;
    HANDLE thread = CreateThread(nullptr, 0, wallSoundPlaybackThread, request.get(), 0, nullptr);
    if (thread == nullptr) {
        if (g_runtimeProbeLogger != nullptr && g_wallSoundLogCount < 8) {
            InterlockedIncrement(&g_wallSoundLogCount);
            g_runtimeProbeLogger->warn("wall sound playback thread creation failed: " + path);
        }
        return;
    }

    request.release();
    CloseHandle(thread);
}

void playWallTouchedSoundForCount(std::size_t touchedCount, std::size_t totalWallCount) {
    if (!g_soundConfig.enabled || touchedCount == 0) {
        return;
    }

    if (totalWallCount > 0 && touchedCount == totalWallCount) {
        playWallSoundPath(g_soundConfig.allWallsTouchedSoundPath);
        return;
    }

    if (touchedCount <= g_soundConfig.wallTouchedSoundPaths.size()) {
        playWallSoundPath(g_soundConfig.wallTouchedSoundPaths[touchedCount - 1]);
    } else {
        playWallSoundPath(g_soundConfig.wallTouchedExtraSoundPath);
    }
}

void playBlockedAttackWarningSound(AttackBlockReason reason) {
    if (!g_soundConfig.enabled || g_soundConfig.volumePercent <= 0) {
        return;
    }

    const std::string* path = nullptr;
    switch (reason) {
    case AttackBlockReason::WallsIncomplete:
        path = &g_soundConfig.warningWallsSoundPath;
        break;
    case AttackBlockReason::CrateMissing:
        path = &g_soundConfig.warningCrateSoundPath;
        break;
    case AttackBlockReason::RopeRequired:
        path = &g_soundConfig.warningRopeSoundPath;
        break;
    default:
        return;
    }
    if (path == nullptr || path->empty()) {
        return;
    }

    const DWORD now = GetTickCount();
    const DWORD previous = static_cast<DWORD>(g_wallWarningSoundLastTick);
    if (previous != 0 && now - previous < kBlockedAttackWarningSoundCooldownMilliseconds) {
        return;
    }

    InterlockedExchange(&g_wallWarningSoundLastTick, static_cast<LONG>(now));
    playWallSoundPath(*path);
}

void rememberWaStateUiAddress(std::uintptr_t stateUiAddress) {
    if (stateUiAddress == 0
        || !isReadableMemoryRange(stateUiAddress + kWaCurrentTeamByteOffset, sizeof(BYTE))) {
        return;
    }

    const LONG previousAddress = g_waStateUiAddress;
    if (previousAddress == static_cast<LONG>(stateUiAddress)) {
        return;
    }

    InterlockedExchange(&g_waStateUiAddress, static_cast<LONG>(stateUiAddress));

    if (g_runtimeProbeLogger != nullptr && g_waStateUiLogCount < 8) {
        InterlockedIncrement(&g_waStateUiLogCount);

        std::ostringstream message;
        message << "runtime probe: cached W:A state UI address "
                << formatAddress(stateUiAddress)
                << " for active team tracking";
        g_runtimeProbeLogger->info(message.str());
    }
}

bool tryReadStateUiAddressFromOwner(std::uintptr_t ownerAddress, std::uintptr_t& stateUiAddress) {
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

    stateUiAddress = static_cast<std::uintptr_t>(stateUiAddressLong);
    return stateUiAddress != 0;
}

bool tryReadCurrentActiveTeamByteFromStateUi(std::uintptr_t stateUiAddress, BYTE& activeTeamByte) {
    if (stateUiAddress == 0) {
        return false;
    }

    return tryReadByte(stateUiAddress + kWaCurrentTeamByteOffset, activeTeamByte);
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
    InterlockedExchange(&g_recentRopeContextTick, 0);
    InterlockedExchange(&g_wallTouchTurnOwnerAddress, 0);
    InterlockedExchange(&g_wallTouchLastTouchTick, 0);
    resetCollisionDiagnosticLogWindows();
}

void clearActiveWormCoordinateCandidateForReselection() {
    InterlockedExchange(&g_activeWormCandidateOwnerAddress, 0);
    InterlockedExchange(&g_activeWormCandidateBaseAddress, 0);
    InterlockedExchange(&g_activeWormCandidateXOffset, 0);
    InterlockedExchange(&g_activeWormCandidateYOffset, 0);
    InterlockedExchange(&g_activeWormCandidateOffsetValid, 0);
    InterlockedExchange(&g_activeWormCandidateSourceKind, 0);
    InterlockedExchange(&g_activeWormCandidateSourceOffset, 0);
    InterlockedExchange(&g_activeWormCandidateRefreshTick, 0);
    InterlockedExchange(&g_recentRopeContextTick, 0);
}

void resetCollisionQueryCommonLogWindow() {
    InterlockedExchange(&g_jumpTerrainCollisionResultProbeHits, 0);
    InterlockedExchange(&g_jumpTerrainCollisionResultLogCount, 0);
    InterlockedExchange(&g_jumpTerrainCollisionResultNearWallLogCount, 0);
    InterlockedExchange(&g_jumpTerrainCollisionResultLogCount, 0);
    InterlockedExchange(&g_jumpTerrainCollisionResultNearWallLogCount, 0);
}

void resetCollisionDiagnosticLogWindows() {
    resetCollisionQueryCommonLogWindow();
    InterlockedExchange(&g_movementResolutionResultLogCount, 0);
    InterlockedExchange(&g_movementResolutionResultNearWallLogCount, 0);
}

bool markTouchedOverlayWallFromPhysics(
    std::size_t wallIndex,
    std::uintptr_t ownerAddress,
    int ownerX,
    int ownerY,
    int distancePixels,
    const char* method) {
    if (!onlineWallModuleAllowedForCurrentContext()
        || !wallGameplayRulesActiveForCurrentMap()) {
        return false;
    }

    const DWORD now = GetTickCount();
    for (Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (rect.wallIndex != wallIndex) {
            continue;
        }

        if (rect.touched) {
            return false;
        }

        rect.touched = true;
        const std::size_t touchedCount = touchedOverlayWallCount();
        const std::size_t totalWallCount = g_direct3D9OverlayTestRects.size();
        playWallTouchedSoundForCount(touchedCount, totalWallCount);
        InterlockedExchange(&g_wallTouchLastTouchTick, static_cast<LONG>(now));
        if (ownerAddress != 0) {
            InterlockedCompareExchange(
                &g_wallTouchTurnOwnerAddress,
                static_cast<LONG>(ownerAddress),
                0);
        }

        if (g_runtimeProbeLogger != nullptr && g_direct3D9WallTouchLogCount < 64) {
            InterlockedIncrement(&g_direct3D9WallTouchLogCount);

            std::ostringstream message;
            message << "runtime probe: wall touched by active worm, wall "
                    << rect.wallIndex
                    << " method "
                    << (method != nullptr && method[0] != '\0' ? method : "physics")
                    << " rect "
                    << rect.left
                    << ","
                    << rect.top
                    << "-"
                    << rect.right
                    << ","
                    << rect.bottom
                    << " active "
                    << ownerX
                    << ","
                    << ownerY
                    << " distance "
                    << distancePixels
                    << " activeOwner "
                    << formatAddress(ownerAddress)
                    << " turnOwner "
                    << formatAddress(static_cast<std::uintptr_t>(
                        static_cast<std::uint32_t>(g_wallTouchTurnOwnerAddress)));
            g_runtimeProbeLogger->info(message.str());
        }
        return true;
    }

    return false;
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
    const LONG previousOwnerAddress = g_activeWormCandidateOwnerAddress;
    if (previousOwnerAddress != 0 && previousOwnerAddress != static_cast<LONG>(ownerAddress)) {
        resetCollisionQueryCommonLogWindow();
    }

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

void clearWormLiveSample(WormLiveSample& sample) {
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

void resetTransientGameplayTrackingState(const char* reason, bool clearWormSamples) {
    const std::size_t resetWallCount = resetTouchedOverlayWallsForNewTurn();
    resetCrateCollectionForNewTurn(reason);
    resetCollisionDiagnosticLogWindows();
    InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayPinnedBaselineBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayPinnedAutoProbeTick, 0);
    if (resetWallCount != 0) {
        InterlockedExchange(&g_wallTouchLastResetTick, static_cast<LONG>(GetTickCount()));
    }

    if (resetWallCount != 0 && g_runtimeProbeLogger != nullptr && g_wallTouchResetLogCount < 32) {
        InterlockedIncrement(&g_wallTouchResetLogCount);

        const char* resetReason = reason != nullptr && reason[0] != '\0'
            ? reason
            : "D3D context transition";
        std::ostringstream message;
        message << "runtime probe: wall touch state reset for "
                << resetReason
                << ", reset "
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
    InterlockedExchange(&g_trackingTargetReferencePreviousX, 0);
    InterlockedExchange(&g_trackingTargetReferencePreviousY, 0);
    InterlockedExchange(&g_trackingTargetReferenceOlderX, 0);
    InterlockedExchange(&g_trackingTargetReferenceOlderY, 0);
    InterlockedExchange(&g_trackingTargetReferenceHistoryCount, 0);
    InterlockedExchange(&g_trackingTargetFallbackLogCount, 0);

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
    InterlockedExchange(&g_recentRopeContextTick, 0);
    InterlockedExchange(&g_wallTouchTurnOwnerAddress, 0);
    InterlockedExchange(&g_wallTouchLastTouchTick, 0);
    InterlockedExchange(&g_wallTouchLastResetTick, 0);
    InterlockedExchange(&g_activeWormCandidateLogCount, 0);
    InterlockedExchange(&g_activeWormCandidatePollLogCount, 0);
    InterlockedExchange(&g_activeWormCandidateScanMissLogCount, 0);
    InterlockedExchange(&g_activeWormMovementLogCount, 0);
    InterlockedExchange(&g_wormMotionCandidateProbeLogCount, 0);
    InterlockedExchange(&g_wormMotionCandidateLastOwnerAddress, 0);
    InterlockedExchange(&g_direct3D9OverlayGameplayActive, 0);
    InterlockedExchange(&g_direct3D9OverlayLastGameplayEvidenceTick, 0);

    for (WormLiveSample& sample : g_wormLiveSamples) {
        if (clearWormSamples) {
            clearWormLiveSample(sample);
        } else {
            resetWormLiveSampleTransientHistory(sample);
        }
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

    if (kVerboseRuntimeDiagnostics
        && g_runtimeProbeLogger != nullptr
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

bool activeOwnerHasRecentMotion(LONG ownerAddressLong, DWORD maxAgeMilliseconds) {
    if (ownerAddressLong == 0) {
        return false;
    }

    const WormLiveSample* sample = findWormLiveSampleByOwner(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(ownerAddressLong)));
    if (sample == nullptr || sample->aliveFlag == 0) {
        return false;
    }

    const DWORD motionTick = static_cast<DWORD>(sample->lastMotionTick);
    if (motionTick == 0) {
        return false;
    }

    return GetTickCount() - motionTick <= maxAgeMilliseconds;
}

bool selectActiveWormCandidateFromRecentMotionHandoff(LONG excludedOwnerAddress, const char* selectionReason) {
    const DWORD now = GetTickCount();
    const WormLiveSample* bestSample = nullptr;
    LONG bestScore = INT32_MAX;

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        const LONG ownerAddressLong = sample.ownerAddress;
        const DWORD sampleTick = static_cast<DWORD>(
            sample.lastPollTick != 0 ? sample.lastPollTick : sample.tick);
        const DWORD motionTick = static_cast<DWORD>(sample.lastMotionTick);
        if (ownerAddressLong == 0
            || ownerAddressLong == excludedOwnerAddress
            || sampleTick == 0
            || motionTick == 0
            || now - sampleTick > 3000
            || now - motionTick > kRecentMotionHandoffMilliseconds
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

        const auto ownerAddress = static_cast<std::uintptr_t>(static_cast<std::uint32_t>(ownerAddressLong));
        const LONG motionScore = sample.motionScore;
        LONG score = static_cast<LONG>(std::min<DWORD>(now - motionTick, kRecentMotionHandoffMilliseconds));
        score -= std::min<LONG>(motionScore, 10000);
        if (waObjectCurrentTeamMatches(reinterpret_cast<void*>(ownerAddress))) {
            score -= 3000;
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

        if (kVerboseRuntimeDiagnostics
            && g_runtimeProbeLogger != nullptr
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
    LONG teamIndex = 0;
    if (!tryReadLong(ownerAddress + kWaObjectTeamOffset, teamIndex)
        || teamIndex < 0
        || teamIndex >= 8) {
        return false;
    }

    std::uintptr_t stateUiAddress = 0;
    if (!tryReadStateUiAddressFromOwner(ownerAddress, stateUiAddress)) {
        return false;
    }

    BYTE activeTeamByte = 0;
    BYTE objectTeamByte = 0;
    const auto objectTeamByteAddress = static_cast<std::uintptr_t>(
        static_cast<std::intptr_t>(stateUiAddress)
        + (static_cast<std::intptr_t>(teamIndex) * static_cast<std::intptr_t>(kWaTeamNameStride))
        + kWaTeamByteListOffset);
    if (!tryReadCurrentActiveTeamByteFromStateUi(stateUiAddress, activeTeamByte)
        || !tryReadByte(objectTeamByteAddress, objectTeamByte)) {
        return false;
    }

    rememberWaStateUiAddress(stateUiAddress);
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

    const LONG previousValid = g_trackingTargetReferenceValid;
    const LONG previousHistoryCount = g_trackingTargetReferenceHistoryCount;
    const LONG lastX = g_trackingTargetReferenceCenterX;
    const LONG lastY = g_trackingTargetReferenceCenterY;
    const bool changed = previousValid == 0
        || lastX != reference.centerX
        || lastY != reference.centerY;

    if (changed) {
        if (previousValid == 0 || previousHistoryCount <= 0) {
            InterlockedExchange(&g_trackingTargetReferencePreviousX, reference.centerX);
            InterlockedExchange(&g_trackingTargetReferencePreviousY, reference.centerY);
            InterlockedExchange(&g_trackingTargetReferenceOlderX, reference.centerX);
            InterlockedExchange(&g_trackingTargetReferenceOlderY, reference.centerY);
            InterlockedExchange(&g_trackingTargetReferenceHistoryCount, 1);
        } else {
            InterlockedExchange(
                &g_trackingTargetReferenceOlderX,
                previousHistoryCount >= 2 ? g_trackingTargetReferencePreviousX : lastX);
            InterlockedExchange(
                &g_trackingTargetReferenceOlderY,
                previousHistoryCount >= 2 ? g_trackingTargetReferencePreviousY : lastY);
            InterlockedExchange(&g_trackingTargetReferencePreviousX, lastX);
            InterlockedExchange(&g_trackingTargetReferencePreviousY, lastY);
            InterlockedExchange(&g_trackingTargetReferenceHistoryCount, std::min<LONG>(previousHistoryCount + 1, 3));
        }
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
            const LONG ownerAddressLong = g_activeWormCandidateOwnerAddress;
            const auto ownerAddress = static_cast<std::uintptr_t>(
                static_cast<std::uint32_t>(ownerAddressLong));
            if (ownerAddress != 0
                && waObjectCurrentTeamMatches(reinterpret_cast<void*>(ownerAddress))) {
                if (!activeOwnerHasRecentMotion(ownerAddressLong, kActiveOwnerRecentMotionKeepMilliseconds)
                    && selectActiveWormCandidateFromRecentMotionHandoff(
                        ownerAddressLong,
                        "recent motion handoff")) {
                    return;
                }

                return;
            }

            clearActiveWormCoordinateCandidateForReselection();
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
        if (kVerboseRuntimeDiagnostics
            && g_runtimeProbeLogger != nullptr
            && g_activeWormCandidateLogCount < 24) {
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
        if (kVerboseRuntimeDiagnostics
            && g_runtimeProbeLogger != nullptr
            && g_activeWormCandidateLogCount < 16) {
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
    if (point == nullptr || !wallOverlayMetadataActive()) {
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
    if (kVerboseRuntimeDiagnostics
        && (hits <= 4 || previousPointAddress != static_cast<LONG>(pointAddress))
        && g_runtimeProbeLogger != nullptr) {
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
    if (!wallOverlayMetadataActive()) {
        return;
    }

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

    noteRecentRopeContext(objectKind);

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

    if (kVerboseRuntimeDiagnostics
        && g_runtimeProbeLogger != nullptr
        && slotHits == 1
        && g_cameraTargetAggregateProbeLogCount < 32) {
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

    if (!wallOverlayMetadataActive()) {
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

    if (kVerboseRuntimeDiagnostics
        && g_runtimeProbeLogger != nullptr
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

extern "C" void __cdecl recordWaJumpTerrainCollisionResult(
    void* owner,
    LONG xFixed,
    LONG yFixed,
    LONG collisionResult) noexcept {
    if (owner == nullptr || !wallRuntimeHooksShouldProcessFast()) {
        return;
    }

    const LONG hits = InterlockedIncrement(&g_jumpTerrainCollisionResultProbeHits);
    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);

    LONG objectKind = 0;
    LONG teamIndex = 0;
    LONG wormIndex = 0;
    LONG velocityX = 0;
    LONG velocityY = 0;
    const bool readObjectKind = tryReadLong(ownerAddress + kWaObjectKindOffset, objectKind);
    const bool readTeamIndex = tryReadLong(ownerAddress + kWaObjectTeamOffset, teamIndex);
    const bool readWormIndex = tryReadLong(ownerAddress + kWaObjectWormOffset, wormIndex);
    const bool readVelocityX = tryReadLong(ownerAddress + 0x90, velocityX);
    const bool readVelocityY = tryReadLong(ownerAddress + 0x94, velocityY);
    if (!readObjectKind || !readTeamIndex || !readWormIndex || !readVelocityX || !readVelocityY) {
        return;
    }
    noteRecentRopeContext(objectKind);

    const int xPixels = fixedDeltaToPixels(xFixed);
    const int yPixels = fixedDeltaToPixels(yFixed);
    const bool mapCoordinate = candidateLooksLikeMapCoordinate(xFixed, yFixed);
    const bool currentTeamMatches = waObjectCurrentTeamMatches(owner);
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;
    const bool activeCandidateMatches =
        activeOwnerAddress != 0 && activeOwnerAddress == static_cast<LONG>(ownerAddress);
    const LONG turnOwnerAddress = g_wallTouchTurnOwnerAddress;
    const bool turnOwnerMatches =
        turnOwnerAddress != 0 && turnOwnerAddress == static_cast<LONG>(ownerAddress);

    constexpr int kJumpTerrainResultWallMarginPixels = 16;
    constexpr int kJumpTerrainHitMaxSquaredDistance = 36;
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (xPixels < rect.left - kJumpTerrainResultWallMarginPixels
            || xPixels > rect.right + kJumpTerrainResultWallMarginPixels
            || yPixels < rect.top - kJumpTerrainResultWallMarginPixels
            || yPixels > rect.bottom + kJumpTerrainResultWallMarginPixels) {
            continue;
        }

        const int closestX = std::clamp<int>(
            xPixels,
            static_cast<int>(rect.left),
            static_cast<int>(rect.right));
        const int closestY = std::clamp<int>(
            yPixels,
            static_cast<int>(rect.top),
            static_cast<int>(rect.bottom));
        const int dx = std::abs(xPixels - closestX);
        const int dy = std::abs(yPixels - closestY);
        const int wallDistance = std::max(dx, dy);
        const int squaredWallDistance = (dx * dx) + (dy * dy);
        const bool jumpTerrainHit =
            collisionResult != 0
            && mapCoordinate
            && (activeCandidateMatches || turnOwnerMatches)
            && squaredWallDistance <= kJumpTerrainHitMaxSquaredDistance;

        if (jumpTerrainHit) {
            markTouchedOverlayWallFromPhysics(
                rect.wallIndex,
                ownerAddress,
                xPixels,
                yPixels,
                wallDistance,
                "jump-terrain-collision");
        }

        if (kVerboseRuntimeDiagnostics
            && g_runtimeProbeLogger != nullptr
            && g_jumpTerrainCollisionResultLogCount < 96) {
            InterlockedIncrement(&g_jumpTerrainCollisionResultLogCount);

            std::ostringstream message;
            message << "runtime probe: jump terrain collision result near wall "
                    << rect.wallIndex
                    << " owner "
                    << formatAddress(ownerAddress)
                    << " objectKind "
                    << objectKind
                    << " team "
                    << teamIndex
                    << " worm "
                    << wormIndex
                    << " currentTeam "
                    << (currentTeamMatches ? "yes" : "no")
                    << " activeCandidate "
                    << (activeCandidateMatches ? "yes" : "no")
                    << " turnOwner "
                    << (turnOwnerMatches ? "yes" : "no")
                    << " queryFixed "
                    << xFixed
                    << ","
                    << yFixed
                    << " queryPixels "
                    << xPixels
                    << ","
                    << yPixels
                    << " velocity "
                    << fixedDeltaToPixels(velocityX)
                    << ","
                    << fixedDeltaToPixels(velocityY)
                    << " result "
                    << collisionResult
                    << " rect "
                    << rect.left
                    << ","
                    << rect.top
                    << "-"
                    << rect.right
                    << ","
                    << rect.bottom
                    << " distance "
                    << wallDistance
                    << " squaredDistance "
                    << squaredWallDistance
                    << " jumpTerrainHit "
                    << (jumpTerrainHit ? "yes" : "no")
                    << " total hits "
                    << hits;
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }
}

extern "C" void __cdecl recordWaMovementResolutionResult(
    void* owner,
    LONG result,
    LONG siteRva) noexcept {
    if (owner == nullptr || !wallRuntimeHooksShouldProcessFast()) {
        return;
    }

    const LONG hits = InterlockedIncrement(&g_movementResolutionResultProbeHits);

    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    LONG ownerKind = 0;
    LONG ownerTeam = 0;
    LONG ownerWorm = 0;
    LONG ownerXFixed = 0;
    LONG ownerYFixed = 0;
    LONG velocityXFixed = 0;
    LONG velocityYFixed = 0;
    LONG stateAc = 0;
    LONG stateB0 = 0;
    LONG stateB4 = 0;
    LONG stateB8 = 0;
    LONG stateBc = 0;
    const bool readOwnerKind = tryReadLong(ownerAddress + kWaObjectKindOffset, ownerKind);
    const bool readOwnerTeam = tryReadLong(ownerAddress + kWaObjectTeamOffset, ownerTeam);
    const bool readOwnerWorm = tryReadLong(ownerAddress + kWaObjectWormOffset, ownerWorm);
    const bool readOwnerX = tryReadLong(ownerAddress + kWaObjectPrimaryXOffset, ownerXFixed);
    const bool readOwnerY = tryReadLong(ownerAddress + kWaObjectPrimaryYOffset, ownerYFixed);
    const bool readVelocityX = tryReadLong(ownerAddress + 0x90, velocityXFixed);
    const bool readVelocityY = tryReadLong(ownerAddress + 0x94, velocityYFixed);
    tryReadLong(ownerAddress + 0xAC, stateAc);
    tryReadLong(ownerAddress + 0xB0, stateB0);
    tryReadLong(ownerAddress + 0xB4, stateB4);
    tryReadLong(ownerAddress + 0xB8, stateB8);
    tryReadLong(ownerAddress + 0xBC, stateBc);

    const bool looksLikeWorm = readOwnerKind
        && (waObjectKindLooksLikeWorm(ownerKind) || ownerKind == 102 || ownerKind == 121 || ownerKind == 123 || ownerKind == 127);
    const bool currentTeamMatches = waObjectCurrentTeamMatches(owner);
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;
    const bool activeCandidateMatches =
        activeOwnerAddress != 0 && activeOwnerAddress == static_cast<LONG>(ownerAddress);
    const LONG turnOwnerAddress = g_wallTouchTurnOwnerAddress;
    const bool turnOwnerMatches =
        turnOwnerAddress != 0 && turnOwnerAddress == static_cast<LONG>(ownerAddress);
    const int ownerXPixels = readOwnerX ? fixedDeltaToPixels(ownerXFixed) : -9999;
    const int ownerYPixels = readOwnerY ? fixedDeltaToPixels(ownerYFixed) : -9999;
    const int velocityXPixels = readVelocityX ? fixedDeltaToPixels(velocityXFixed) : -9999;
    const int velocityYPixels = readVelocityY ? fixedDeltaToPixels(velocityYFixed) : -9999;

    if (!looksLikeWorm || !readOwnerX || !readOwnerY) {
        return;
    }
    noteRecentRopeContext(ownerKind);

    int nearestWall = -1;
    int nearestDistance = 999999;
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        const int dx = ownerXPixels < rect.left ? rect.left - ownerXPixels
            : ownerXPixels > rect.right ? ownerXPixels - rect.right
                                       : 0;
        const int dy = ownerYPixels < rect.top ? rect.top - ownerYPixels
            : ownerYPixels > rect.bottom ? ownerYPixels - rect.bottom
                                        : 0;
        const int distance = std::max(dx, dy);
        if (distance < nearestDistance) {
            nearestDistance = distance;
            nearestWall = static_cast<int>(rect.wallIndex);
        }
    }

    constexpr int kMovementResolutionNearWallPixels = 96;
    if (nearestWall < 0 || nearestDistance > kMovementResolutionNearWallPixels) {
        return;
    }

    constexpr int kMovementResolutionTouchDistancePixels = 5;
    const bool movementResolutionHit =
        siteRva == static_cast<LONG>(kWa381MovementResolutionSecondaryResultRva)
        && result != 0
        && ownerKind == 121
        && (activeCandidateMatches || turnOwnerMatches)
        && nearestDistance <= kMovementResolutionTouchDistancePixels;

    if (movementResolutionHit) {
        markTouchedOverlayWallFromPhysics(
            static_cast<std::size_t>(nearestWall),
            ownerAddress,
            ownerXPixels,
            ownerYPixels,
            nearestDistance,
            "movement-resolution-collision");
    }

    InterlockedIncrement(&g_movementResolutionResultNearWallLogCount);
    if (!kVerboseRuntimeDiagnostics
        || g_runtimeProbeLogger == nullptr
        || g_movementResolutionResultLogCount >= 220) {
        return;
    }
    InterlockedIncrement(&g_movementResolutionResultLogCount);

    std::ostringstream message;
    message << "runtime probe: movement resolution result rva "
            << formatAddress(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(siteRva)))
            << " result "
            << formatAddress(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(result)))
            << " resultNonZero "
            << (result != 0 ? "yes" : "no")
            << " owner "
            << formatAddress(ownerAddress)
            << " ownerKind "
            << (readOwnerKind ? ownerKind : -9999)
            << " ownerTeam "
            << (readOwnerTeam ? ownerTeam : -9999)
            << " ownerWorm "
            << (readOwnerWorm ? ownerWorm : -9999)
            << " currentTeam "
            << (currentTeamMatches ? "yes" : "no")
            << " activeCandidate "
            << (activeCandidateMatches ? "yes" : "no")
            << " turnOwner "
            << (turnOwnerMatches ? "yes" : "no")
            << " ownerPixels "
            << ownerXPixels
            << ","
            << ownerYPixels
            << " velocity "
            << velocityXPixels
            << ","
            << velocityYPixels
            << " wall "
            << nearestWall
            << " distance "
            << nearestDistance
            << " states ac/b0/b4/b8/bc "
            << stateAc
            << "/"
            << stateB0
            << "/"
            << stateB4
            << "/"
            << stateB8
            << "/"
            << stateBc
            << " total hits "
            << hits;
    g_runtimeProbeLogger->info(message.str());
}

extern "C" void __cdecl recordWaMovementCollisionResult(
    void* owner,
    LONG xFixed,
    LONG yFixed,
    LONG collisionResult) noexcept {
    if (owner == nullptr || !wallRuntimeHooksShouldProcessFast()) {
        return;
    }

    InterlockedIncrement(&g_movementCollisionResultProbeHits);
    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    const int xPixels = fixedDeltaToPixels(xFixed);
    const int yPixels = fixedDeltaToPixels(yFixed);
    const bool mapCoordinate = candidateLooksLikeMapCoordinate(xFixed, yFixed);

    LONG objectKind = 0;
    const bool readObjectKind = owner != nullptr && tryReadLong(ownerAddress + kWaObjectKindOffset, objectKind);
    const bool looksLikeWorm = readObjectKind && waObjectKindLooksLikeWorm(objectKind);
    if (readObjectKind) {
        noteRecentRopeContext(objectKind);
    }
    const bool activeCandidateMatches =
        g_activeWormCandidateOwnerAddress == static_cast<LONG>(ownerAddress);

    const bool physicsOwnerLooksLikeWorm =
        looksLikeWorm || objectKind == 102 || objectKind == 123 || objectKind == 127;
    if (!physicsOwnerLooksLikeWorm
        || !mapCoordinate
        || g_direct3D9OverlayTestRects.empty()) {
        return;
    }

    constexpr int kMovementCollisionWallMarginPixels = 96;
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (xPixels < rect.left - kMovementCollisionWallMarginPixels
            || xPixels > rect.right + kMovementCollisionWallMarginPixels
            || yPixels < rect.top - kMovementCollisionWallMarginPixels
            || yPixels > rect.bottom + kMovementCollisionWallMarginPixels) {
            continue;
        }

        const int wallDistance = std::max(
            xPixels < rect.left ? rect.left - xPixels
                : xPixels > rect.right ? xPixels - rect.right
                                       : 0,
            yPixels < rect.top ? rect.top - yPixels
                : yPixels > rect.bottom ? yPixels - rect.bottom
                                        : 0);
        constexpr int kWormMovementCollisionTouchDistancePixels = 5;
        const bool ropeMovementCollisionHit =
            collisionResult != 0
            && activeCandidateMatches
            && (objectKind == 101 || objectKind == 123)
            && wallDistance <= kWormMovementCollisionTouchDistancePixels;

        if (ropeMovementCollisionHit) {
            markTouchedOverlayWallFromPhysics(
                rect.wallIndex,
                ownerAddress,
                xPixels,
                yPixels,
                wallDistance,
                "rope-movement-collision");
        }
        return;
    }
}

extern "C" void __cdecl recordWaMovementCollisionPath(void* owner, void* collided) noexcept {
    if (owner == nullptr || !wallRuntimeHooksShouldProcessFast()) {
        return;
    }

    InterlockedIncrement(&g_movementCollisionPathProbeHits);
    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    const auto collidedAddress = reinterpret_cast<std::uintptr_t>(collided);

    LONG ownerKind = 0;
    LONG ownerXFixed = 0;
    LONG ownerYFixed = 0;
    LONG collidedKind = 0;
    const bool readOwnerKind = owner != nullptr && tryReadLong(ownerAddress + kWaObjectKindOffset, ownerKind);
    const bool readOwnerX = owner != nullptr && tryReadLong(ownerAddress + kWaObjectPrimaryXOffset, ownerXFixed);
    const bool readOwnerY = owner != nullptr && tryReadLong(ownerAddress + kWaObjectPrimaryYOffset, ownerYFixed);
    const bool readCollidedKind = collided != nullptr
        && tryReadLong(collidedAddress + kWaObjectKindOffset, collidedKind);

    const int ownerXPixels = readOwnerX ? fixedDeltaToPixels(ownerXFixed) : -9999;
    const int ownerYPixels = readOwnerY ? fixedDeltaToPixels(ownerYFixed) : -9999;
    const bool looksLikeWorm = readOwnerKind
        && (waObjectKindLooksLikeWorm(ownerKind) || ownerKind == 102 || ownerKind == 123 || ownerKind == 127 || ownerKind == 128);
    if (readOwnerKind) {
        noteRecentRopeContext(ownerKind);
    }
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;
    const bool activeCandidateMatches =
        activeOwnerAddress != 0 && activeOwnerAddress == static_cast<LONG>(ownerAddress);
    const LONG turnOwnerAddress = g_wallTouchTurnOwnerAddress;
    const bool turnOwnerMatches =
        turnOwnerAddress != 0 && turnOwnerAddress == static_cast<LONG>(ownerAddress);
    const bool currentTeamMatches = waObjectCurrentTeamMatches(owner);

    if (!looksLikeWorm
        || !readOwnerX
        || !readOwnerY
        || g_direct3D9OverlayTestRects.empty()) {
        return;
    }

    constexpr int kMovementCollisionPathWallMarginPixels = 96;
    const Direct3D9OverlayRect* closestRect = nullptr;
    int closestDistancePixels = std::numeric_limits<int>::max();
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (ownerXPixels < rect.left - kMovementCollisionPathWallMarginPixels
            || ownerXPixels > rect.right + kMovementCollisionPathWallMarginPixels
            || ownerYPixels < rect.top - kMovementCollisionPathWallMarginPixels
            || ownerYPixels > rect.bottom + kMovementCollisionPathWallMarginPixels) {
            continue;
        }

        const int dx = ownerXPixels < rect.left ? rect.left - ownerXPixels
            : ownerXPixels > rect.right ? ownerXPixels - rect.right
                                       : 0;
        const int dy = ownerYPixels < rect.top ? rect.top - ownerYPixels
            : ownerYPixels > rect.bottom ? ownerYPixels - rect.bottom
                                        : 0;
        const int distance = std::max(dx, dy);
        if (distance < closestDistancePixels) {
            closestDistancePixels = distance;
            closestRect = &rect;
        }
    }

    if (closestRect != nullptr) {
        const Direct3D9OverlayRect& rect = *closestRect;
        constexpr int kRopeCollisionPathTouchDistancePixels = 5;
        constexpr int kTrackedRopeCollisionPathTouchDistancePixels = 8;
        const bool trackedActiveOwner = activeCandidateMatches || turnOwnerMatches;
        const bool ropeCollisionPathHit =
            readOwnerKind
            && ownerKind == 128
            && readCollidedKind
            && collidedKind == 0
            && ((trackedActiveOwner && closestDistancePixels <= kTrackedRopeCollisionPathTouchDistancePixels)
                || (currentTeamMatches && closestDistancePixels <= kRopeCollisionPathTouchDistancePixels));
        if (ropeCollisionPathHit) {
            markTouchedOverlayWallFromPhysics(
                rect.wallIndex,
                ownerAddress,
                ownerXPixels,
                ownerYPixels,
                closestDistancePixels,
                "rope-collision-path");
        }
    }
}

extern "C" void __cdecl recordWaMovementCollisionBranch(void* owner, void* collided) noexcept {
    if (owner == nullptr || !wallRuntimeHooksShouldProcessFast()) {
        return;
    }

    InterlockedIncrement(&g_movementCollisionBranchProbeHits);
    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    const auto collidedAddress = reinterpret_cast<std::uintptr_t>(collided);

    LONG ownerKind = 0;
    LONG ownerXFixed = 0;
    LONG ownerYFixed = 0;
    LONG collidedKind = 0;
    const bool readOwnerKind = owner != nullptr && tryReadLong(ownerAddress + kWaObjectKindOffset, ownerKind);
    const bool readOwnerX = owner != nullptr && tryReadLong(ownerAddress + kWaObjectPrimaryXOffset, ownerXFixed);
    const bool readOwnerY = owner != nullptr && tryReadLong(ownerAddress + kWaObjectPrimaryYOffset, ownerYFixed);
    const bool readCollidedKind = collided != nullptr
        && tryReadLong(collidedAddress + kWaObjectKindOffset, collidedKind);

    const int ownerXPixels = readOwnerX ? fixedDeltaToPixels(ownerXFixed) : -9999;
    const int ownerYPixels = readOwnerY ? fixedDeltaToPixels(ownerYFixed) : -9999;
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;
    if (readOwnerKind) {
        noteRecentRopeContext(ownerKind);
    }
    const bool activeCandidateMatches =
        activeOwnerAddress != 0 && activeOwnerAddress == static_cast<LONG>(ownerAddress);
    const LONG turnOwnerAddress = g_wallTouchTurnOwnerAddress;
    const bool turnOwnerMatches =
        turnOwnerAddress != 0 && turnOwnerAddress == static_cast<LONG>(ownerAddress);
    const bool currentTeamMatches = waObjectCurrentTeamMatches(owner);

    int nearWallIndex = -1;
    int nearWallDistance = 999999;
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        const int dx = ownerXPixels < rect.left ? rect.left - ownerXPixels
            : ownerXPixels > rect.right ? ownerXPixels - rect.right
                                       : 0;
        const int dy = ownerYPixels < rect.top ? rect.top - ownerYPixels
            : ownerYPixels > rect.bottom ? ownerYPixels - rect.bottom
                                        : 0;
        const int distance = std::max(dx, dy);
        if (distance < nearWallDistance) {
            nearWallDistance = distance;
            nearWallIndex = static_cast<int>(rect.wallIndex);
        }
    }

    constexpr int kMovementCollisionBranchDryRunTouchThresholdPixels = 10;
    const bool dryRunWouldTouch =
        nearWallIndex >= 0 && nearWallDistance <= kMovementCollisionBranchDryRunTouchThresholdPixels;
    const bool ropeCollisionOwner = readOwnerKind && (ownerKind == 123 || ownerKind == 128);
    const bool physicsOwnerEligible = activeCandidateMatches
        || turnOwnerMatches
        || (ropeCollisionOwner && currentTeamMatches);
    const bool terrainCollision = readCollidedKind && collidedKind == 0;
    if (dryRunWouldTouch
        && terrainCollision
        && ropeCollisionOwner
        && physicsOwnerEligible) {
        markTouchedOverlayWallFromPhysics(
            static_cast<std::size_t>(nearWallIndex),
            ownerAddress,
            ownerXPixels,
            ownerYPixels,
            nearWallDistance,
            "rope-physics");
    }
}

extern "C" void __cdecl recordWaCollisionQueryCommon(
    void* caller,
    void* context,
    void* owner,
    LONG xFixed,
    LONG yFixed,
    void* surface,
    LONG flags) noexcept {
    (void)context;
    (void)surface;

    if (owner == nullptr || !wallRuntimeHooksShouldProcessFast()) {
        return;
    }

    InterlockedIncrement(&g_collisionQueryCommonProbeHits);
    const auto callerAddress = reinterpret_cast<std::uintptr_t>(caller);
    const auto ownerAddress = reinterpret_cast<std::uintptr_t>(owner);
    const int xPixels = fixedDeltaToPixels(xFixed);
    const int yPixels = fixedDeltaToPixels(yFixed);
    const bool mapCoordinate = candidateLooksLikeMapCoordinate(xFixed, yFixed);

    LONG ownerKind = 0;
    LONG ownerXFixed = 0;
    LONG ownerYFixed = 0;
    const bool readOwnerKind = owner != nullptr && tryReadLong(ownerAddress + kWaObjectKindOffset, ownerKind);
    const bool readOwnerX = owner != nullptr && tryReadLong(ownerAddress + kWaObjectPrimaryXOffset, ownerXFixed);
    const bool readOwnerY = owner != nullptr && tryReadLong(ownerAddress + kWaObjectPrimaryYOffset, ownerYFixed);
    const bool looksLikeWorm = readOwnerKind && waObjectKindLooksLikeWorm(ownerKind);
    if (readOwnerKind) {
        noteRecentRopeContext(ownerKind);
    }
    const LONG activeOwnerAddress = g_activeWormCandidateOwnerAddress;
    const bool activeCandidateMatches =
        activeOwnerAddress != 0 && activeOwnerAddress == static_cast<LONG>(ownerAddress);
    const LONG turnOwnerAddress = g_wallTouchTurnOwnerAddress;
    const bool turnOwnerMatches =
        turnOwnerAddress != 0 && turnOwnerAddress == static_cast<LONG>(ownerAddress);
    const bool ownerIsTrackedActiveWorm = activeOwnerAddress != 0 && (activeCandidateMatches || turnOwnerMatches);
    const std::uintptr_t callerRva = g_waModuleBase != 0 && callerAddress >= g_waModuleBase
        ? callerAddress - g_waModuleBase
        : 0;

    if (!looksLikeWorm
        || !ownerIsTrackedActiveWorm
        || !mapCoordinate
        || g_direct3D9OverlayTestRects.empty()) {
        return;
    }

    constexpr int kCollisionQueryCommonWallMarginPixels = 64;
    const Direct3D9OverlayRect* closestRect = nullptr;
    int closestDistancePixels = std::numeric_limits<int>::max();
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (xPixels < rect.left - kCollisionQueryCommonWallMarginPixels
            || xPixels > rect.right + kCollisionQueryCommonWallMarginPixels
            || yPixels < rect.top - kCollisionQueryCommonWallMarginPixels
            || yPixels > rect.bottom + kCollisionQueryCommonWallMarginPixels) {
            continue;
        }

        const int dx = xPixels < rect.left ? rect.left - xPixels : (xPixels > rect.right ? xPixels - rect.right : 0);
        const int dy = yPixels < rect.top ? rect.top - yPixels : (yPixels > rect.bottom ? yPixels - rect.bottom : 0);
        const int distancePixels = std::max(dx, dy);
        if (distancePixels < closestDistancePixels) {
            closestRect = &rect;
            closestDistancePixels = distancePixels;
        }
    }

    if (closestRect != nullptr) {
        const Direct3D9OverlayRect& rect = *closestRect;
        const bool collisionQueryFootContact =
            flags == 2
            && closestDistancePixels <= 5
            && readOwnerX
            && readOwnerY
            && (callerRva == 0x00100284
                || callerRva == 0x0010016B
                || callerRva == 0x00100203
                || callerRva == 0x001001A3);
        const bool collisionQueryFootBounce =
            flags == 4328646
            && closestDistancePixels <= 6
            && readOwnerX
            && readOwnerY
            && (callerRva == 0x000FB9C0
                || callerRva == 0x000FD1BB);
        if (collisionQueryFootContact) {
            markTouchedOverlayWallFromPhysics(
                rect.wallIndex,
                ownerAddress,
                fixedDeltaToPixels(ownerXFixed),
                fixedDeltaToPixels(ownerYFixed),
                closestDistancePixels,
                "collision-query-foot");
        } else if (collisionQueryFootBounce) {
            markTouchedOverlayWallFromPhysics(
                rect.wallIndex,
                ownerAddress,
                fixedDeltaToPixels(ownerXFixed),
                fixedDeltaToPixels(ownerYFixed),
                closestDistancePixels,
                "collision-query-foot-bounce");
        }
        return;
    }
}

extern "C" void __cdecl recordWaCameraRenderOwner(void* owner) noexcept {
    if (owner == nullptr || !wallOverlayMetadataActive()) {
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
    if (kVerboseRuntimeDiagnostics
        && (hits <= 4 || previousPointAddress != static_cast<LONG>(pointAddress))
        && g_runtimeProbeLogger != nullptr) {
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
        if (kVerboseRuntimeDiagnostics && hits <= 4 && g_runtimeProbeLogger != nullptr) {
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

int __fastcall hookedWaTurnGameHandleMessage(
    void* turnGame,
    void* edx,
    void* sender,
    std::uint32_t messageType,
    std::size_t dataSize,
    void* data) {
    InterlockedIncrement(&g_turnGameHandleMessageProbeHits);

    const bool wallModeCandidate =
        wallOverlayMetadataActive()
        || messageType == kWallGameTaskMessageMetadataFrame;

    if (wallModeCandidate && waTaskMessageLooksTurnRelated(messageType)) {
        logTurnGameMessageProbe("before", turnGame, sender, messageType, dataSize, data, 0);
    }

    if (messageType == kWallGameTaskMessageMetadataFrame) {
        handleIncomingOnlineMetadataFrame(data, dataSize);
        return 0;
    }

    int result = 0;
    if (g_originalWaTurnGameHandleMessage != nullptr) {
        result = g_originalWaTurnGameHandleMessage(turnGame, edx, sender, messageType, dataSize, data);
    }

    if (wallModeCandidate && waTaskMessageLooksTurnRelated(messageType)) {
        noteWallGameplayTaskActivity();
        logTurnGameMessageProbe("after", turnGame, sender, messageType, dataSize, data, result);
    }

    if (wallModeCandidate && messageType == 7) {
        markCrateCollectedThisTurn(sender, data, dataSize);
    }

    if (wallModeCandidate && messageType == 52) {
        resetCrateCollectionForNewTurn("CTaskTurnGame FinishTurn");
        resetTouchedOverlayWallsForTurnGameFinishTurn(turnGame, data, dataSize);
    }

    return result;
}

int __fastcall hookedWaHostLobbyPacketHandler(
    void* host,
    void* edx,
    int slot,
    unsigned char* packet,
    std::size_t size) {
    std::uint8_t messageType = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t payloadSize = 0;
    std::uint16_t protocolVersion = 0;
    if (g_onlineSyncEnabled
        && parseWallLobbyPacket(packet, size, messageType, payload, payloadSize, protocolVersion)) {
        handleWallLobbyPacketAsHost(slot, messageType, protocolVersion, payload, payloadSize);
        return 0;
    }

    maybeBroadcastQueuedOnlineMetadataForLobbySlot(slot);

    if (g_originalWaHostLobbyPacketHandler == nullptr) {
        return 0;
    }
    return g_originalWaHostLobbyPacketHandler(host, edx, slot, packet, size);
}

int __fastcall hookedWaClientLobbyPacketHandler(
    void* client,
    void* edx,
    unsigned char* packet,
    std::size_t size) {
    std::uint8_t messageType = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t payloadSize = 0;
    std::uint16_t protocolVersion = 0;
    if (g_onlineSyncEnabled
        && parseWallLobbyPacket(packet, size, messageType, payload, payloadSize, protocolVersion)) {
        handleWallLobbyPacketAsClient(messageType, protocolVersion, payload, payloadSize);
        return 0;
    }

    if (g_originalWaClientLobbyPacketHandler == nullptr) {
        return 0;
    }
    return g_originalWaClientLobbyPacketHandler(client, edx, packet, size);
}

int __stdcall hookedWaConstructLobbyHostScreen(int screen, int arg) {
    int result = 0;
    if (g_originalWaConstructLobbyHostScreen != nullptr) {
        result = g_originalWaConstructLobbyHostScreen(screen, arg);
    }

    g_lobbyHostScreenAddress = static_cast<std::uintptr_t>(screen);
    g_lobbyClientScreenAddress = 0;
    resetWallGameplayTaskActivity();
    if (g_runtimeProbeLogger != nullptr && g_onlineLobbyHookLogCount < 16) {
        InterlockedIncrement(&g_onlineLobbyHookLogCount);
        std::ostringstream message;
        message << "online lobby sync: host lobby screen constructed at "
                << formatAddress(g_lobbyHostScreenAddress);
        g_runtimeProbeLogger->info(message.str());
    }
    return result;
}

int __stdcall hookedWaConstructLobbyClientScreen(int screen, int arg) {
    int result = 0;
    if (g_originalWaConstructLobbyClientScreen != nullptr) {
        result = g_originalWaConstructLobbyClientScreen(screen, arg);
    }

    g_lobbyClientScreenAddress = static_cast<std::uintptr_t>(screen);
    g_lobbyHostScreenAddress = 0;
    resetWallGameplayTaskActivity();
    if (g_runtimeProbeLogger != nullptr && g_onlineLobbyHookLogCount < 16) {
        InterlockedIncrement(&g_onlineLobbyHookLogCount);
        std::ostringstream message;
        message << "online lobby sync: client lobby screen constructed at "
                << formatAddress(g_lobbyClientScreenAddress);
        g_runtimeProbeLogger->info(message.str());
    }
    return result;
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

void* buildWaCameraTargetAggregateChainProbeStub(std::uintptr_t existingDetour, std::string& error) {
    error.clear();
    if (existingDetour == 0) {
        error = "invalid existing camera target aggregate detour";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 4 + 1 + 1 + 1 + 4 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t jumpBackBytes = kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + jumpBackBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate camera target aggregate chain probe stub";
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
        error = "camera target aggregate chain probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaCameraTargetAggregateCall));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x10; // add esp, 16
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::uint8_t* jumpExisting = stub + offset;
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpExisting), existingDetour)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "camera target aggregate existing detour is too far from chain stub";
        return nullptr;
    }
    writeRelativeJump(jumpExisting, existingDetour);

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

void* buildWaJumpTerrainCollisionResultProbeStub(std::uint8_t* target, std::string& error) {
    error.clear();
    if (target == nullptr) {
        error = "invalid jump terrain collision result probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes =
        1 + 1
        + 4 + 1
        + 4 + 3 + 5 + 1
        + 4 + 3 + 1
        + 4 + 1
        + kX86JumpBytes
        + 3 + 1 + 1;
    constexpr std::size_t replayBytes = 2 + 6 + kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + replayBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate jump terrain collision result probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x20; // mov eax, [esp+0x20] - original eax / collision result
    stub[offset++] = 0x50; // push eax

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x14; // mov eax, [esp+0x14] - original esp after result push
    stub[offset++] = 0x8B;
    stub[offset++] = 0x40;
    stub[offset++] = 0x1C; // mov eax, [eax+0x1c] - original y input
    stub[offset++] = 0x05;
    stub[offset++] = 0x00;
    stub[offset++] = 0x00;
    stub[offset++] = 0x01;
    stub[offset++] = 0x00; // add eax, 0x10000
    stub[offset++] = 0x50; // push eax (yFixed)

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x18; // mov eax, [esp+0x18] - original esp after result/y pushes
    stub[offset++] = 0x8B;
    stub[offset++] = 0x40;
    stub[offset++] = 0x18; // mov eax, [eax+0x18] - original x input
    stub[offset++] = 0x50; // push eax (xFixed)

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x14; // mov eax, [esp+0x14] - original esi after result/y/x pushes
    stub[offset++] = 0x50; // push eax (owner)

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaJumpTerrainCollisionResult))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "jump terrain collision result probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaJumpTerrainCollisionResult));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x10; // add esp, 16
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    stub[offset++] = 0x85;
    stub[offset++] = 0xC0; // test eax, eax

    stub[offset++] = 0x0F;
    stub[offset++] = 0x85; // jne original branch
    const std::uintptr_t originalBranchDestination = reinterpret_cast<std::uintptr_t>(target + 0x670);
    const auto conditionalDistance = static_cast<std::int32_t>(
        originalBranchDestination - reinterpret_cast<std::uintptr_t>(stub + offset + 4));
    std::memcpy(stub + offset, &conditionalDistance, sizeof(conditionalDistance));
    offset += sizeof(conditionalDistance);

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination =
        reinterpret_cast<std::uintptr_t>(target + kWaJumpTerrainCollisionResultPatchLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "jump terrain collision result probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);
    offset += kX86JumpBytes;

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaMovementResolutionResultProbeStub(
    std::uint8_t* target,
    std::uintptr_t siteRva,
    std::uint8_t zeroBranchOffset,
    const std::array<std::uint8_t, 4>& replayInstruction,
    std::string& error) {
    error.clear();
    if (target == nullptr) {
        error = "invalid movement resolution result probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes =
        1 + 1
        + 5
        + 4 + 1
        + 4 + 1
        + kX86JumpBytes
        + 3 + 1 + 1;
    constexpr std::size_t replayBytes = 2 + 6 + 4 + kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + replayBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate movement resolution result probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd

    stub[offset++] = 0x68; // push site RVA
    const auto siteRva32 = static_cast<std::uint32_t>(siteRva);
    std::memcpy(stub + offset, &siteRva32, sizeof(siteRva32));
    offset += sizeof(siteRva32);

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x24; // mov eax, [esp+0x24] - original eax after site push
    stub[offset++] = 0x50; // push eax (result)

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x1C; // mov eax, [esp+0x1c] - original ebx after site/result pushes
    stub[offset++] = 0x50; // push eax (owner)

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaMovementResolutionResult))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement resolution result probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaMovementResolutionResult));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x0C; // add esp, 12
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    stub[offset++] = 0x85;
    stub[offset++] = 0xC0; // test eax, eax

    std::uint8_t* jumpIfZero = stub + offset;
    const std::uintptr_t zeroDestination = reinterpret_cast<std::uintptr_t>(target + zeroBranchOffset);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpIfZero), zeroDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement resolution result conditional jump is too far from stub";
        return nullptr;
    }
    jumpIfZero[0] = 0x0F;
    jumpIfZero[1] = 0x84;
    const auto conditionalDistance = static_cast<std::int32_t>(
        zeroDestination - reinterpret_cast<std::uintptr_t>(jumpIfZero + 6));
    std::memcpy(jumpIfZero + 2, &conditionalDistance, sizeof(conditionalDistance));
    offset += 6;

    std::memcpy(stub + offset, replayInstruction.data(), replayInstruction.size());
    offset += replayInstruction.size();

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination =
        reinterpret_cast<std::uintptr_t>(target + kWaMovementResolutionResultPatchLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement resolution result probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);
    offset += kX86JumpBytes;

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaMovementCollisionResultProbeStub(std::uint8_t* target, std::string& error) {
    error.clear();
    if (target == nullptr) {
        error = "invalid movement collision result probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + (4 + 1) * 4 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t replayBytes = 2 + 6 + 2 + kX86JumpBytes + kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + replayBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate movement collision result probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x20; // mov eax, [esp+0x20] - original eax / collision result
    stub[offset++] = 0x50; // push eax

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x08; // mov eax, [esp+0x08] - original edi after collision push
    stub[offset++] = 0x50; // push eax (yFixed)

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x1C; // mov eax, [esp+0x1C] - original ebx after two pushes
    stub[offset++] = 0x50; // push eax (xFixed)

    stub[offset++] = 0x8B;
    stub[offset++] = 0x44;
    stub[offset++] = 0x24;
    stub[offset++] = 0x14; // mov eax, [esp+0x14] - original esi after three pushes
    stub[offset++] = 0x50; // push eax (owner)

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaMovementCollisionResult))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision result probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaMovementCollisionResult));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x10; // add esp, 16
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    stub[offset++] = 0x85;
    stub[offset++] = 0xC0; // test eax, eax

    std::uint8_t* jumpIfNoCollision = stub + offset;
    stub[offset++] = 0x0F;
    stub[offset++] = 0x84;
    offset += 4; // je success branch, patched below

    stub[offset++] = 0x33;
    stub[offset++] = 0xC0; // xor eax, eax

    std::uint8_t* blockedJump = stub + offset;
    const std::uintptr_t blockedDestination =
        reinterpret_cast<std::uintptr_t>(target + kWaMovementCollisionResultPatchLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(blockedJump), blockedDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision result blocked jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(blockedJump, blockedDestination);
    offset += kX86JumpBytes;

    std::uint8_t* successJumpTarget = stub + offset;
    std::uint8_t* successJump = stub + offset;
    const std::uintptr_t successDestination = reinterpret_cast<std::uintptr_t>(target + 0x0A);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(successJump), successDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision result success jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(successJump, successDestination);
    offset += kX86JumpBytes;

    const std::intptr_t conditionalDistance =
        reinterpret_cast<std::intptr_t>(successJumpTarget)
        - reinterpret_cast<std::intptr_t>(jumpIfNoCollision + 6);
    *reinterpret_cast<std::int32_t*>(jumpIfNoCollision + 2) = static_cast<std::int32_t>(conditionalDistance);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaMovementCollisionPathProbeStub(std::uint8_t* target, std::string& error) {
    error.clear();
    if (target == nullptr) {
        error = "invalid movement collision path probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 1 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t replayBytes = 3 + 6 + kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + replayBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate movement collision path probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd
    stub[offset++] = 0x57; // push edi - collided object
    stub[offset++] = 0x56; // push esi - moving owner

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaMovementCollisionPath))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision path probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaMovementCollisionPath));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x08; // add esp, 8
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    stub[offset++] = 0x3B;
    stub[offset++] = 0x7D;
    stub[offset++] = 0x08; // cmp edi, [ebp+0x8]

    std::uint8_t* jumpIfSameObject = stub + offset;
    const std::uintptr_t sameObjectDestination = reinterpret_cast<std::uintptr_t>(target + 0x4B);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpIfSameObject), sameObjectDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision path conditional jump is too far from stub";
        return nullptr;
    }
    jumpIfSameObject[0] = 0x0F;
    jumpIfSameObject[1] = 0x84;
    const std::intptr_t conditionalDistance = static_cast<std::intptr_t>(sameObjectDestination)
        - reinterpret_cast<std::intptr_t>(jumpIfSameObject + 6);
    *reinterpret_cast<std::int32_t*>(jumpIfSameObject + 2) = static_cast<std::int32_t>(conditionalDistance);
    offset += 6;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination =
        reinterpret_cast<std::uintptr_t>(target + kWaMovementCollisionPathPatchLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision path probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaMovementCollisionBranchProbeStub(std::uint8_t* target, std::string& error) {
    error.clear();
    if (target == nullptr) {
        error = "invalid movement collision branch probe target";
        return nullptr;
    }

    constexpr std::size_t prologueBytes = 1 + 1 + 1 + 1 + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t replayBytes = kWaMovementCollisionBranchPatchLength + kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + replayBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate movement collision branch probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd
    stub[offset++] = 0x51; // push ecx - collided object
    stub[offset++] = 0x56; // push esi - moving owner

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaMovementCollisionBranch))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision branch probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaMovementCollisionBranch));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x08; // add esp, 8
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::memcpy(stub + offset, target, kWaMovementCollisionBranchPatchLength);
    offset += kWaMovementCollisionBranchPatchLength;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination =
        reinterpret_cast<std::uintptr_t>(target + kWaMovementCollisionBranchPatchLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "movement collision branch probe jump-back is too far from stub";
        return nullptr;
    }
    writeRelativeJump(jumpBack, jumpBackDestination);

    FlushInstructionCache(GetCurrentProcess(), stub, stubSize);
    return stub;
}

void* buildWaCollisionQueryCommonProbeStub(std::uint8_t* target, std::string& error) {
    error.clear();
    if (target == nullptr) {
        error = "invalid collision query common probe target";
        return nullptr;
    }

    constexpr std::size_t pushedArgumentBytes = (4 + 1) * 7;
    constexpr std::size_t prologueBytes = 1 + 1 + pushedArgumentBytes + kX86JumpBytes + 3 + 1 + 1;
    constexpr std::size_t replayBytes = kWaCollisionQueryCommonPatchLength + kX86JumpBytes;
    const std::size_t stubSize = prologueBytes + replayBytes;

    auto* stub = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (stub == nullptr) {
        error = "failed to allocate collision query common probe stub";
        return nullptr;
    }

    std::size_t offset = 0;
    stub[offset++] = 0x60; // pushad
    stub[offset++] = 0x9C; // pushfd

    const std::uint8_t argumentOffsets[] = {
        0x3C, // flags, original [esp+0x18]
        0x3C, // surface, original [esp+0x14] after one push
        0x3C, // y, original [esp+0x10] after two pushes
        0x3C, // x, original [esp+0x0c] after three pushes
        0x3C, // owner, original [esp+0x08] after four pushes
        0x3C, // context, original [esp+0x04] after five pushes
        0x3C, // caller return, original [esp] after six pushes
    };

    for (std::uint8_t stackOffset : argumentOffsets) {
        stub[offset++] = 0x8B;
        stub[offset++] = 0x44;
        stub[offset++] = 0x24;
        stub[offset++] = stackOffset; // mov eax, [esp+offset]
        stub[offset++] = 0x50; // push eax
    }

    std::uint8_t* callRecord = stub + offset;
    if (!relativeJumpFits(
            reinterpret_cast<std::uintptr_t>(callRecord),
            reinterpret_cast<std::uintptr_t>(&recordWaCollisionQueryCommon))) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "collision query common probe callback is too far from stub";
        return nullptr;
    }
    writeRelativeCall(callRecord, reinterpret_cast<std::uintptr_t>(&recordWaCollisionQueryCommon));
    offset += kX86JumpBytes;

    stub[offset++] = 0x83;
    stub[offset++] = 0xC4;
    stub[offset++] = 0x1C; // add esp, 28
    stub[offset++] = 0x9D; // popfd
    stub[offset++] = 0x61; // popad

    std::memcpy(stub + offset, target, kWaCollisionQueryCommonPatchLength);
    offset += kWaCollisionQueryCommonPatchLength;

    std::uint8_t* jumpBack = stub + offset;
    const std::uintptr_t jumpBackDestination =
        reinterpret_cast<std::uintptr_t>(target + kWaCollisionQueryCommonPatchLength);
    if (!relativeJumpFits(reinterpret_cast<std::uintptr_t>(jumpBack), jumpBackDestination)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        error = "collision query common probe jump-back is too far from stub";
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

    g_cameraRenderCopyProbeStub = stub;

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
    bool chainedExistingDetour = false;
    std::uintptr_t existingDetour = 0;
    if (target[0] == 0xE9) {
        std::int32_t relativeDetour = 0;
        std::memcpy(&relativeDetour, target + 1, sizeof(relativeDetour));
        existingDetour = reinterpret_cast<std::uintptr_t>(target + kX86JumpBytes) + relativeDetour;
        chainedExistingDetour = true;
    } else if (target[0] != 0x8B || target[1] != 0x44 || target[2] != 0x24 || target[3] != 0x04 || target[4] != 0x56) {
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
    void* stub = chainedExistingDetour
        ? buildWaCameraTargetAggregateChainProbeStub(existingDetour, stubError)
        : buildWaCameraTargetAggregateProbeStub(target, kWaCameraTargetAggregatePatchLength, stubError);
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
    InterlockedExchange(&g_trackingTargetReferencePreviousX, 0);
    InterlockedExchange(&g_trackingTargetReferencePreviousY, 0);
    InterlockedExchange(&g_trackingTargetReferenceOlderX, 0);
    InterlockedExchange(&g_trackingTargetReferenceOlderY, 0);
    InterlockedExchange(&g_trackingTargetReferenceHistoryCount, 0);
    InterlockedExchange(&g_trackingTargetFallbackLogCount, 0);
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
    if (chainedExistingDetour) {
        message << ", chained existing detour "
                << formatAddress(existingDetour);
    }
    logger.info(message.str());
    return true;
}

bool installWaTurnGameHandleMessageProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    BytePattern pattern;
    std::string patternError;
    if (!parseBytePattern(
            "55 8B EC 83 E4 F8 81 EC ?? ?? ?? ?? 53 8B 5D 0C 56 8D 43 FE "
            "83 F8 7B 57 8B F1 0F 87 ?? ?? ?? ?? 0F B6 80 ?? ?? ?? ?? "
            "FF 24 85 ?? ?? ?? ?? 8B 86 ?? ?? ?? ??",
            pattern,
            patternError)) {
        error = "failed to parse CTaskTurnGame::HandleMessage pattern: " + patternError;
        return false;
    }

    const std::vector<std::uintptr_t> matches = findBytePattern(module, pattern, 2);
    std::uint8_t* target = nullptr;
    if (matches.empty()) {
        target = reinterpret_cast<std::uint8_t*>(module.base + kWa381TurnGameHandleMessageRva);
        std::ostringstream message;
        message << "runtime probe: CTaskTurnGame::HandleMessage pattern did not match; "
                << "falling back to W:A 3.8.1 RVA "
                << formatAddress(kWa381TurnGameHandleMessageRva)
                << ", bytes "
                << formatCodeBytes(target, 16);
        logger.warn(message.str());
    } else if (matches.size() > 1) {
        std::ostringstream message;
        message << "CTaskTurnGame::HandleMessage pattern matched "
                << matches.size()
                << " locations; using first match at "
                << formatAddress(matches.front());
        logger.warn(message.str());
        target = reinterpret_cast<std::uint8_t*>(matches.front());
    } else {
        target = reinterpret_cast<std::uint8_t*>(matches.front());
    }

    bool chainedExistingDetour = false;
    std::uintptr_t existingDetour = 0;
    if (target[0] == 0xE9) {
        std::int32_t relativeDetour = 0;
        std::memcpy(&relativeDetour, target + 1, sizeof(relativeDetour));
        existingDetour = reinterpret_cast<std::uintptr_t>(target + kX86JumpBytes) + relativeDetour;
        chainedExistingDetour = true;
    } else if (target[0] != 0x55
        || target[1] != 0x8B
        || target[2] != 0xEC
        || target[3] != 0x83
        || target[4] != 0xE4
        || target[5] != 0xF8) {
        std::ostringstream message;
        message << "CTaskTurnGame::HandleMessage prologue did not match expected bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatRva(reinterpret_cast<std::uintptr_t>(target), module.base)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    const std::size_t patchLength = chainedExistingDetour
        ? kX86JumpBytes
        : kWaTurnGameHandleMessagePatchLength;
    if (!hook.install(target, reinterpret_cast<void*>(&hookedWaTurnGameHandleMessage),
            patchLength, error)) {
        return false;
    }

    g_originalWaTurnGameHandleMessage = chainedExistingDetour
        ? reinterpret_cast<WaTurnGameHandleMessageFunction>(existingDetour)
        : reinterpret_cast<WaTurnGameHandleMessageFunction>(hook.trampoline());
    InterlockedExchange(&g_turnGameHandleMessageProbeHits, 0);
    InterlockedExchange(&g_turnGameHandleMessageLogCount, 0);

    std::ostringstream message;
    message << "runtime probe: CTaskTurnGame::HandleMessage hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " (RVA "
            << formatRva(reinterpret_cast<std::uintptr_t>(target), module.base)
            << "), trampoline "
            << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalWaTurnGameHandleMessage));
    if (chainedExistingDetour) {
        message << ", chained existing detour "
                << formatAddress(existingDetour);
    }
    logger.info(message.str());
    return true;
}

bool findWaHookPatternMask(
    Logger& logger,
    const ProcessModuleView& module,
    const char* name,
    const char* patternBytes,
    const char* mask,
    std::uintptr_t& address) {
    address = 0;
    if (patternBytes == nullptr || mask == nullptr || mask[0] == '\0') {
        logger.warn(std::string("online lobby sync: invalid ") + name + " masked pattern");
        return false;
    }

    BytePattern pattern;
    const std::size_t size = std::strlen(mask);
    pattern.bytes.reserve(size);
    pattern.mask.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        pattern.bytes.push_back(static_cast<std::uint8_t>(patternBytes[index]));
        pattern.mask.push_back(mask[index] != '?');
    }

    const std::vector<std::uintptr_t> matches = findBytePattern(module, pattern, 2);
    if (matches.empty()) {
        logger.warn(std::string("online lobby sync: missing W:A signature: ") + name);
        return false;
    }

    if (matches.size() > 1) {
        std::ostringstream message;
        message << "online lobby sync: "
                << name
                << " matched "
                << matches.size()
                << " locations; using first match";
        logger.warn(message.str());
    }

    address = matches.front();
    std::ostringstream message;
    message << "online lobby sync: "
            << name
            << " at "
            << formatAddress(address)
            << " (RVA "
            << formatRva(address, module.base)
            << ")";
    logger.info(message.str());
    return true;
}

bool tryReadPointer(std::uintptr_t address, std::uintptr_t& value) {
    value = 0;
    if (!isReadableMemoryRange(address, sizeof(std::uintptr_t))) {
        return false;
    }

    value = *reinterpret_cast<std::uintptr_t*>(address);
    return value != 0;
}

bool resolveExistingRelativeJump(std::uint8_t* target, std::uintptr_t& detourAddress) {
    detourAddress = 0;
    if (target == nullptr || target[0] != 0xE9) {
        return false;
    }

    std::int32_t relative = 0;
    std::memcpy(&relative, target + 1, sizeof(relative));
    detourAddress = reinterpret_cast<std::uintptr_t>(target + kX86JumpBytes) + relative;
    return detourAddress != 0;
}

bool installWaOnlineLobbyDetour(
    Logger& logger,
    const char* name,
    std::uintptr_t address,
    void* detour,
    std::size_t patchLength,
    X86DetourHook& hook,
    void*& original) {
    original = nullptr;
    if (address == 0 || detour == nullptr) {
        return false;
    }

    auto* target = reinterpret_cast<std::uint8_t*>(address);
    std::uintptr_t existingDetour = 0;
    const bool chainedExistingDetour = resolveExistingRelativeJump(target, existingDetour);
    const std::size_t effectivePatchLength = chainedExistingDetour ? kX86JumpBytes : patchLength;

    std::string hookError;
    if (!hook.install(target, detour, effectivePatchLength, hookError)) {
        logger.warn(std::string("online lobby sync: failed to install ") + name + " hook: " + hookError);
        return false;
    }

    original = chainedExistingDetour
        ? reinterpret_cast<void*>(existingDetour)
        : hook.trampoline();

    std::ostringstream message;
    message << "online lobby sync: "
            << name
            << " hook installed at "
            << formatAddress(address)
            << ", trampoline "
            << formatAddress(reinterpret_cast<std::uintptr_t>(original));
    if (chainedExistingDetour) {
        message << ", chained existing detour " << formatAddress(existingDetour);
    }
    logger.info(message.str());
    return true;
}

bool installWaOnlineLobbySyncHooks(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hostLobbyPacketHandlerHook,
    X86DetourHook& clientLobbyPacketHandlerHook,
    X86DetourHook& constructLobbyHostScreenHook,
    X86DetourHook& constructLobbyClientScreenHook) {
    bool installedAnyHook = false;
    std::uintptr_t hostUnicastAddress = 0;
    std::uintptr_t hostLobbyPacketHandlerAddress = 0;
    std::uintptr_t hostEndscreenPacketHandlerAddress = 0;
    std::uintptr_t hostSlotListConstructorAddress = 0;
    std::uintptr_t clientLobbyPacketHandlerAddress = 0;
    std::uintptr_t clientEndscreenPacketHandlerAddress = 0;
    std::uintptr_t constructLobbyHostScreenAddress = 0;
    std::uintptr_t constructLobbyClientScreenAddress = 0;
    std::uintptr_t lobbyDisplayMessageAddress = 0;

    findWaHookPatternMask(
        logger,
        module,
        "HostUnicast",
        "\x8B\x44\x24\x04\x83\x78\x0C\x00\x74\x28\x69\xC9\x00\x00\x00\x00"
        "\x03\xC1\x83\xB8\x00\x00\x00\x00\x00\x75\x2F\x8D\x88\x00\x00\x00"
        "\x00\x8B\x01\x52",
        "??????xxxx??????xxxx?????xxxx????xxx",
        hostUnicastAddress);
    findWaHookPatternMask(
        logger,
        module,
        "HostLobbyPacketHandler",
        "\x83\xEC\x10\x8B\x44\x24\x1C\x83\xF8\x02\x53\x8B\xD9\x89\x5C\x24"
        "\x04\x0F\x82\x00\x00\x00\x00\x55\x8B\x6C\x24\x20\x0F\xB7\x4D\x00"
        "\x85\xC9\x56\x57\x0F\x84\x00\x00\x00\x00\x83\xF9\x10\x0F\x84\x00"
        "\x00\x00\x00\x83\xF9\x1A\x74\x18",
        "???????xxxxxxxxxxxx????xxxxxxxxxxxxxxx????xxxxx????xxxxx",
        hostLobbyPacketHandlerAddress);
    findWaHookPatternMask(
        logger,
        module,
        "HostEndscreenPacketHandler",
        "\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89"
        "\x25\x00\x00\x00\x00\x83\xEC\x20\x53\x55\x56\x8B\x74\x24\x40\x0F"
        "\xB7\x06\x57\x33\xDB\x3B\xC3\x8B\xF9\x89\x7C\x24\x2C\x0F\x84\x00"
        "\x00\x00\x00\x83\xF8\x0F\x0F\x85\x00\x00\x00\x00",
        "???????xx????xxxx????xxxxxxxxxxxxxxxxxxxxxxxxxx????xxxxx????",
        hostEndscreenPacketHandlerAddress);
    findWaHookPatternMask(
        logger,
        module,
        "ClientLobbyPacketHandler",
        "\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x24\x53\x8B\x5D\x0C\x83\xFB\x02"
        "\x56\x8B\xF1\x57\x89\x74\x24\x10\x0F\x82\x00\x00\x00\x00\x8B\x7D"
        "\x08\x0F\xB7\x0F\x0F\xB7\xC1\x83\xF8\x32\x0F\x87\x00\x00\x00\x00"
        "\x0F\xB6\x90\x00\x00\x00\x00\xFF\x24\x95\x00\x00\x00\x00\x53",
        "??????xxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxxxx????xxx????xxx????x",
        clientLobbyPacketHandlerAddress);
    findWaHookPatternMask(
        logger,
        module,
        "ClientEndscreenPacketHandler",
        "\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x08\x56\x8B\x75\x08\x0F\xB7\x06"
        "\x83\xC0\xE7\x83\xF8\x10\x57\x8B\xF9\x0F\x87\x00\x00\x00\x00\x0F"
        "\xB6\x80\x00\x00\x00\x00\xFF\x24\x85\x00\x00\x00\x00\x83\x7D\x0C"
        "\x08\x0F\x82\x00\x00\x00\x00\x8B\x4E\x04\x83\xE9\x01\x83\xF9\x0C"
        "\x0F\x83\x00\x00\x00\x00",
        "??????xxxxxxxxxxxxxxxxxxxxx????xxx????xxx????xxxxxx????xxxxxxxxxxx????",
        clientEndscreenPacketHandlerAddress);
    findWaHookPatternMask(
        logger,
        module,
        "HostSlotListConstructor",
        "\x64\xA1\x00\x00\x00\x00\x6A\xFF\x68\x00\x00\x00\x00\x50\x64\x89"
        "\x25\x00\x00\x00\x00\x56\x8B\x74\x24\x14\x68\x00\x00\x00\x00\x68"
        "\x00\x00\x00\x00\xB8\x00\x00\x00\x00\x6A\x06\x89\x46\x04\x89\x46"
        "\x08\x68\x00\x00\x00\x00\x8D\x86\x00\x00\x00\x00",
        "??????xxx????xxxx????xxxxxx????x????x????xxxxxxxxx????xx????",
        hostSlotListConstructorAddress);
    findWaHookPatternMask(
        logger,
        module,
        "ConstructLobbyHostScreen",
        "\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89"
        "\x25\x00\x00\x00\x00\x83\xEC\x5C\x53\x8B\x5C\x24\x74\x55\x8B\x6C"
        "\x24\x74\x57\x8D\xBD\x00\x00\x00\x00\x57\x53\x68\x00\x00\x00\x00",
        "???????xx????xxxx????xxxxxxxxxxxxxxxx????xxx????",
        constructLobbyHostScreenAddress);
    findWaHookPatternMask(
        logger,
        module,
        "ConstructLobbyClientScreen",
        "\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89"
        "\x25\x00\x00\x00\x00\x83\xEC\x5C\x53\x8B\x5C\x24\x74\x55\x8B\x6C"
        "\x24\x74\x56\x57\x53\x55\xB9\x00\x00\x00\x00",
        "???????xx????xxxx????xxxxxxxxxxxxxxxxxx????",
        constructLobbyClientScreenAddress);
    findWaHookPatternMask(
        logger,
        module,
        "LobbyDisplayMessage",
        "\x55\x8B\xEC\x83\xE4\xF8\x64\xA1\x00\x00\x00\x00\x6A\xFF\x68\x00"
        "\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x83\xEC\x30\x53\x56"
        "\x57\xE8\x00\x00\x00\x00\x33\xC9\x85\xC0\x0F\x95\xC1\x85\xC9\x75"
        "\x0A\x68\x00\x00\x00\x00\xE8\x00\x00\x00\x00",
        "??????xx????xxx????xxxx????xxxxxxx????xxxxxxxxxxxx????x????",
        lobbyDisplayMessageAddress);

    g_lobbyHostUnicastAddress = hostUnicastAddress;
    if (hostEndscreenPacketHandlerAddress != 0
        && !tryReadPointer(hostEndscreenPacketHandlerAddress + 0xC6, g_lobbyHostSlotAddress)) {
        logger.warn("online lobby sync: failed to resolve host slot pointer");
    }
    if (hostSlotListConstructorAddress != 0) {
        std::uintptr_t hostVtable = 0;
        if (tryReadPointer(hostSlotListConstructorAddress + 0x5D, hostVtable)
            && !tryReadPointer(hostVtable + (9 * sizeof(std::uintptr_t)), g_lobbyHostIncomingConnectionAddress)) {
            logger.warn("online lobby sync: failed to resolve host incoming connection pointer");
        }
    }
    if (clientEndscreenPacketHandlerAddress != 0
        && !tryReadPointer(clientEndscreenPacketHandlerAddress + 0x103, g_lobbyClientSlotAddress)) {
        logger.warn("online lobby sync: failed to resolve client slot pointer");
    }
    if (lobbyDisplayMessageAddress != 0) {
        g_waLobbyDisplayMessage = reinterpret_cast<WaLobbyDisplayMessageFunction>(lobbyDisplayMessageAddress);
    }

    if (hostLobbyPacketHandlerAddress != 0) {
        void* original = nullptr;
        if (installWaOnlineLobbyDetour(
                logger,
                "host lobby packet",
                hostLobbyPacketHandlerAddress,
                reinterpret_cast<void*>(&hookedWaHostLobbyPacketHandler),
                kWaHostLobbyPacketHandlerPatchLength,
                hostLobbyPacketHandlerHook,
                original)) {
            g_originalWaHostLobbyPacketHandler = reinterpret_cast<WaHostLobbyPacketHandlerFunction>(original);
            installedAnyHook = true;
        }
    }

    if (clientLobbyPacketHandlerAddress != 0) {
        void* original = nullptr;
        if (installWaOnlineLobbyDetour(
                logger,
                "client lobby packet",
                clientLobbyPacketHandlerAddress,
                reinterpret_cast<void*>(&hookedWaClientLobbyPacketHandler),
                kWaClientLobbyPacketHandlerPatchLength,
                clientLobbyPacketHandlerHook,
                original)) {
            g_originalWaClientLobbyPacketHandler = reinterpret_cast<WaClientLobbyPacketHandlerFunction>(original);
            installedAnyHook = true;
        }
    }

    if (constructLobbyHostScreenAddress != 0) {
        void* original = nullptr;
        if (installWaOnlineLobbyDetour(
                logger,
                "host lobby screen",
                constructLobbyHostScreenAddress,
                reinterpret_cast<void*>(&hookedWaConstructLobbyHostScreen),
                kWaLobbyScreenConstructorPatchLength,
                constructLobbyHostScreenHook,
                original)) {
            g_originalWaConstructLobbyHostScreen = reinterpret_cast<WaConstructLobbyScreenFunction>(original);
            installedAnyHook = true;
        }
    }

    if (constructLobbyClientScreenAddress != 0) {
        void* original = nullptr;
        if (installWaOnlineLobbyDetour(
                logger,
                "client lobby screen",
                constructLobbyClientScreenAddress,
                reinterpret_cast<void*>(&hookedWaConstructLobbyClientScreen),
                kWaLobbyScreenConstructorPatchLength,
                constructLobbyClientScreenHook,
                original)) {
            g_originalWaConstructLobbyClientScreen = reinterpret_cast<WaConstructLobbyScreenFunction>(original);
            installedAnyHook = true;
        }
    }

    std::ostringstream summary;
    summary << "online lobby sync: resolved hostSlot="
            << formatAddress(g_lobbyHostSlotAddress)
            << ", hostIncomingConnection="
            << formatAddress(g_lobbyHostIncomingConnectionAddress)
            << ", clientSlot="
            << formatAddress(g_lobbyClientSlotAddress)
            << ", hostUnicast="
            << formatAddress(g_lobbyHostUnicastAddress)
            << ", lobbyDisplayMessage="
            << formatAddress(reinterpret_cast<std::uintptr_t>(g_waLobbyDisplayMessage));
    logger.info(summary.str());
    return installedAnyHook;
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

bool installWaJumpTerrainCollisionResultProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381JumpTerrainCollisionResultRva);
    if (target[0] != 0x85
        || target[1] != 0xC0
        || target[2] != 0x0F
        || target[3] != 0x85) {
        std::ostringstream message;
        message << "W:A jump terrain collision result prologue did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381JumpTerrainCollisionResultRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaJumpTerrainCollisionResultProbeStub(target, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaJumpTerrainCollisionResultPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_jumpTerrainCollisionResultProbeStub = stub;
    InterlockedExchange(&g_jumpTerrainCollisionResultProbeHits, 0);
    InterlockedExchange(&g_jumpTerrainCollisionResultLogCount, 0);
    InterlockedExchange(&g_jumpTerrainCollisionResultNearWallLogCount, 0);

    std::ostringstream message;
    message << "runtime probe: W:A jump terrain collision result hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381JumpTerrainCollisionResultRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaMovementResolutionResultProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::uintptr_t siteRva,
    std::uint8_t zeroBranchOffset,
    const std::array<std::uint8_t, 8>& expectedBytes,
    const std::array<std::uint8_t, 4>& replayInstruction,
    void*& stubStorage,
    const char* label,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + siteRva);
    if (!std::equal(expectedBytes.begin(), expectedBytes.end(), target)) {
        std::ostringstream message;
        message << "W:A "
                << label
                << " prologue did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(siteRva)
                << "), actual "
                << formatCodeBytes(target, 10);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaMovementResolutionResultProbeStub(
        target,
        siteRva,
        zeroBranchOffset,
        replayInstruction,
        stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaMovementResolutionResultPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    stubStorage = stub;
    InterlockedExchange(&g_movementResolutionResultProbeHits, 0);
    InterlockedExchange(&g_movementResolutionResultLogCount, 0);
    InterlockedExchange(&g_movementResolutionResultNearWallLogCount, 0);

    std::ostringstream message;
    message << "runtime probe: W:A "
            << label
            << " hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(siteRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaMovementCollisionResultProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381MovementCollisionResultRva);
    if (target[0] != 0x85
        || target[1] != 0xC0
        || target[2] != 0x74
        || target[3] != 0x06
        || target[4] != 0x33
        || target[5] != 0xC0) {
        std::ostringstream message;
        message << "W:A movement collision result prologue did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381MovementCollisionResultRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaMovementCollisionResultProbeStub(target, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaMovementCollisionResultPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_movementCollisionResultProbeStub = stub;
    InterlockedExchange(&g_movementCollisionResultProbeHits, 0);

    std::ostringstream message;
    message << "runtime probe: W:A movement collision result hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381MovementCollisionResultRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaMovementCollisionPathProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381MovementCollisionPathRva);
    if (target[0] != 0x3B
        || target[1] != 0x7D
        || target[2] != 0x08
        || target[3] != 0x74
        || target[4] != 0x46) {
        std::ostringstream message;
        message << "W:A movement collision path instruction did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381MovementCollisionPathRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaMovementCollisionPathProbeStub(target, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaMovementCollisionPathPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_movementCollisionPathProbeStub = stub;
    InterlockedExchange(&g_movementCollisionPathProbeHits, 0);

    std::ostringstream message;
    message << "runtime probe: W:A movement collision path hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381MovementCollisionPathRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaMovementCollisionBranchProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381MovementCollisionBranchRva);
    if (target[0] != 0x8B
        || target[1] != 0x7C
        || target[2] != 0x24
        || target[3] != 0x58
        || target[4] != 0x8B
        || target[5] != 0x37) {
        std::ostringstream message;
        message << "W:A movement collision branch instruction did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381MovementCollisionBranchRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaMovementCollisionBranchProbeStub(target, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaMovementCollisionBranchPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_movementCollisionBranchProbeStub = stub;
    InterlockedExchange(&g_movementCollisionBranchProbeHits, 0);

    std::ostringstream message;
    message << "runtime probe: W:A movement collision branch hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381MovementCollisionBranchRva)
            << ")";
    logger.info(message.str());
    return true;
}

bool installWaCollisionQueryCommonProbe(
    Logger& logger,
    const ProcessModuleView& module,
    X86DetourHook& hook,
    std::string& error) {
    error.clear();

    auto* target = reinterpret_cast<std::uint8_t*>(module.base + kWa381CollisionQueryCommonRva);
    if (target[0] != 0x83
        || target[1] != 0xEC
        || target[2] != 0x10
        || target[3] != 0x53
        || target[4] != 0x8B
        || target[5] != 0x5C
        || target[6] != 0x24
        || target[7] != 0x18) {
        std::ostringstream message;
        message << "W:A collision query common prologue did not match the expected 3.8.1 bytes at "
                << formatAddress(reinterpret_cast<std::uintptr_t>(target))
                << " (RVA "
                << formatAddress(kWa381CollisionQueryCommonRva)
                << "), actual "
                << formatCodeBytes(target, 8);
        error = message.str();
        return false;
    }

    std::string stubError;
    void* stub = buildWaCollisionQueryCommonProbeStub(target, stubError);
    if (stub == nullptr) {
        error = stubError;
        return false;
    }

    if (!hook.install(target, stub, kWaCollisionQueryCommonPatchLength, error)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return false;
    }

    g_collisionQueryCommonProbeStub = stub;
    InterlockedExchange(&g_collisionQueryCommonProbeHits, 0);

    std::ostringstream message;
    message << "runtime probe: W:A collision query common hook installed at "
            << formatAddress(reinterpret_cast<std::uintptr_t>(target))
            << " using probe stub "
            << formatAddress(reinterpret_cast<std::uintptr_t>(stub))
            << " (RVA "
            << formatAddress(kWa381CollisionQueryCommonRva)
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

HRESULT drawDirect3D9AlphaOverlayRects(IDirect3DDevice9* device, const std::vector<ScreenOverlayRect>& rects) {
    if (device == nullptr || rects.empty()) {
        return D3DERR_INVALIDCALL;
    }

    struct Vertex {
        float x;
        float y;
        float z;
        float rhw;
        D3DCOLOR color;
    };

    std::vector<Vertex> vertices;
    vertices.reserve(rects.size() * 6);
    for (const ScreenOverlayRect& rect : rects) {
        if (rect.right <= rect.left || rect.bottom <= rect.top) {
            continue;
        }

        const auto left = static_cast<float>(rect.left);
        const auto top = static_cast<float>(rect.top);
        const auto right = static_cast<float>(rect.right);
        const auto bottom = static_cast<float>(rect.bottom);
        const auto color = static_cast<D3DCOLOR>(rect.color);

        vertices.push_back(Vertex{left, top, 0.0f, 1.0f, color});
        vertices.push_back(Vertex{right, top, 0.0f, 1.0f, color});
        vertices.push_back(Vertex{left, bottom, 0.0f, 1.0f, color});
        vertices.push_back(Vertex{right, top, 0.0f, 1.0f, color});
        vertices.push_back(Vertex{right, bottom, 0.0f, 1.0f, color});
        vertices.push_back(Vertex{left, bottom, 0.0f, 1.0f, color});
    }

    if (vertices.empty()) {
        return D3DERR_INVALIDCALL;
    }

    IDirect3DStateBlock9* stateBlock = nullptr;
    if (SUCCEEDED(device->CreateStateBlock(D3DSBT_ALL, &stateBlock)) && stateBlock != nullptr) {
        stateBlock->Capture();
    }

    device->SetTexture(0, nullptr);
    device->SetPixelShader(nullptr);
    device->SetVertexShader(nullptr);
    device->SetFVF(D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
    device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
    device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
    device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    device->SetRenderState(D3DRS_ZENABLE, FALSE);
    device->SetRenderState(D3DRS_LIGHTING, FALSE);
    device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);

    const HRESULT result = device->DrawPrimitiveUP(
        D3DPT_TRIANGLELIST,
        static_cast<UINT>(vertices.size() / 3),
        vertices.data(),
        sizeof(Vertex));

    if (stateBlock != nullptr) {
        stateBlock->Apply();
        stateBlock->Release();
    }

    return result;
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

bool isBrightChatSeparatorPixel(const BYTE* pixel, D3DFORMAT format) {
    int red = 0;
    int green = 0;
    int blue = 0;

    if (format == D3DFMT_X8R8G8B8 || format == D3DFMT_A8R8G8B8) {
        blue = pixel[0];
        green = pixel[1];
        red = pixel[2];
    } else if (format == D3DFMT_R5G6B5) {
        const std::uint16_t value = static_cast<std::uint16_t>(pixel[0])
            | (static_cast<std::uint16_t>(pixel[1]) << 8);
        red = ((value >> 11) & 0x1F) * 255 / 31;
        green = ((value >> 5) & 0x3F) * 255 / 63;
        blue = (value & 0x1F) * 255 / 31;
    } else if (format == D3DFMT_X1R5G5B5) {
        const std::uint16_t value = static_cast<std::uint16_t>(pixel[0])
            | (static_cast<std::uint16_t>(pixel[1]) << 8);
        red = ((value >> 10) & 0x1F) * 255 / 31;
        green = ((value >> 5) & 0x1F) * 255 / 31;
        blue = (value & 0x1F) * 255 / 31;
    } else {
        return false;
    }

    return red >= 170 && green >= 170 && blue >= 170 && std::abs(red - green) <= 45 && std::abs(red - blue) <= 45;
}

int bytesPerPixelForDirect3D9Format(D3DFORMAT format) {
    if (format == D3DFMT_X8R8G8B8 || format == D3DFMT_A8R8G8B8) {
        return 4;
    }

    if (format == D3DFMT_R5G6B5 || format == D3DFMT_X1R5G5B5) {
        return 2;
    }

    return 0;
}

bool detectDirect3D9ChatOffsetFromRenderTarget(IDirect3DDevice9* device, bool pinnedOnly, int& offsetY) {
    offsetY = 0;
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
    if (FAILED(result) || description.Width < 64 || description.Height < 64) {
        renderTarget->Release();
        return false;
    }

    const int bytesPerPixel = bytesPerPixelForDirect3D9Format(description.Format);
    if (bytesPerPixel == 0) {
        renderTarget->Release();
        return false;
    }

    IDirect3DSurface9* systemSurface = nullptr;
    result = device->CreateOffscreenPlainSurface(
        description.Width,
        description.Height,
        description.Format,
        D3DPOOL_SYSTEMMEM,
        &systemSurface,
        nullptr);
    if (FAILED(result) || systemSurface == nullptr) {
        renderTarget->Release();
        return false;
    }

    result = device->GetRenderTargetData(renderTarget, systemSurface);
    renderTarget->Release();
    if (FAILED(result)) {
        systemSurface->Release();
        return false;
    }

    D3DLOCKED_RECT locked = {};
    result = systemSurface->LockRect(&locked, nullptr, D3DLOCK_READONLY);
    if (FAILED(result)) {
        systemSurface->Release();
        return false;
    }

    const int width = static_cast<int>(description.Width);
    const int height = static_cast<int>(description.Height);
    const int startX = width / 16;
    const int endX = width - startX;
    const int samples = std::max(1, (endX - startX + 3) / 4);
    int bestY = -1;
    int bestScore = 0;
    const int minimumScore = std::max(20, samples / 3);

    auto findChatSeparator = [&](int scanStartY, int scanEndY) {
        bestY = -1;
        bestScore = 0;

        const int clampedStartY = std::max(0, std::min(scanStartY, height - 1));
        const int clampedEndY = std::max(clampedStartY + 1, std::min(scanEndY, height));
        for (int y = clampedStartY; y < clampedEndY; ++y) {
            const BYTE* row = static_cast<const BYTE*>(locked.pBits) + (static_cast<std::ptrdiff_t>(locked.Pitch) * y);
            int score = 0;
            for (int x = startX; x < endX; x += 4) {
                const BYTE* pixel = row + (static_cast<std::ptrdiff_t>(x) * bytesPerPixel);
                if (isBrightChatSeparatorPixel(pixel, description.Format)) {
                    ++score;
                }
            }

            if (score >= minimumScore && (score > bestScore || (score == bestScore && y > bestY))) {
                bestScore = score;
                bestY = y;
            }
        }

        return bestY >= 0 && bestScore >= minimumScore;
    };

    bool pinnedChatBar = false;
    if (pinnedOnly) {
        const int endY = std::min(height - 1, std::max(96, (height * 62) / 100));
        pinnedChatBar = findChatSeparator(4, endY);
    } else if (findChatSeparator(4, std::min(height / 8, 96)) && bestY <= 72) {
        pinnedChatBar = true;
    } else {
        const int startY = std::max(8, height / 20);
        const int endY = std::min(height / 2, std::max(startY + 1, (height * 45) / 100));
        findChatSeparator(startY, endY);
    }

    systemSurface->UnlockRect();
    systemSurface->Release();

    if (bestY < 0 || bestScore < minimumScore) {
        return false;
    }

    offsetY = std::max(0, bestY / 2);
    if (offsetY > height / 3) {
        offsetY = height / 3;
    }

    if (g_runtimeProbeLogger != nullptr && g_chatOverlayScanLogCount < 16) {
        InterlockedIncrement(&g_chatOverlayScanLogCount);
        std::ostringstream message;
        message << "runtime: D3D9 chat separator detected at y "
                << bestY
                << (pinnedChatBar ? " (pinned)" : "")
                << ", score "
                << bestScore
                << "/"
                << samples
                << ", offset "
                << offsetY;
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

void resetChatOverlayScanSamples() {
    InterlockedExchange(&g_chatOverlayScanSampleCount, 0);
    for (LONG& sample : g_chatOverlayScanSamples) {
        sample = 0;
    }
}

void finalizeChatOverlayDetectedOffsetFromSamples() {
    const LONG sampleCount = g_chatOverlayScanSampleCount;
    const LONG count = std::min<LONG>(sampleCount, static_cast<LONG>(g_chatOverlayScanSamples.size()));
    if (count <= 0) {
        return;
    }

    std::array<LONG, 5> sorted = g_chatOverlayScanSamples;
    std::sort(sorted.begin(), sorted.begin() + count);
    const LONG median = sorted[static_cast<std::size_t>(count / 2)];
    InterlockedExchange(&g_chatOverlayDetectedOffsetY, median);
    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 1);

    if (g_runtimeProbeLogger != nullptr && g_chatOverlayScanLogCount < 16) {
        InterlockedIncrement(&g_chatOverlayScanLogCount);
        std::ostringstream message;
        message << "runtime: D3D9 chat separator stable offset "
                << median
                << " from "
                << count
                << " sample(s)";
        g_runtimeProbeLogger->info(message.str());
    }
}

Direct3D9OverlayRect makeDirect3D9OverlayRect(const WaOverlayRect& rect) {
    return Direct3D9OverlayRect{
        rect.left,
        rect.top,
        rect.right,
        rect.bottom,
        static_cast<D3DCOLOR>(rect.argb),
        static_cast<D3DCOLOR>(rect.touchedArgb),
        rect.wallIndex,
        false,
    };
}

WallMapMetadata wallMetadataFromOverlayMap(const WaOverlayMap& map) {
    WallMapMetadata metadata;
    metadata.name = map.name;
    metadata.fileName = map.fileName;
    metadata.sha256 = map.sha256;
    metadata.width = map.width;
    metadata.height = map.height;
    metadata.walls.reserve(map.rects.size());

    for (const WaOverlayRect& rect : map.rects) {
        if (rect.right <= rect.left || rect.bottom <= rect.top) {
            continue;
        }

        WallRect wall;
        wall.name = "Wall" + std::to_string(metadata.walls.size() + 1);
        wall.x = rect.left;
        wall.y = rect.top;
        wall.width = rect.right - rect.left;
        wall.height = rect.bottom - rect.top;
        wall.color = rect.touchedArgb & 0x00FFFFFF;
        metadata.walls.push_back(wall);
    }

    return metadata;
}

WaOverlayMap overlayMapFromWallMetadata(const WallMapMetadata& metadata) {
    WaOverlayMap map;
    map.name = metadata.name;
    map.fileName = metadata.fileName;
    map.sha256 = metadata.sha256;
    map.width = metadata.width;
    map.height = metadata.height;
    map.rects.reserve(metadata.walls.size());

    for (std::size_t index = 0; index < metadata.walls.size(); ++index) {
        const WallRect& wall = metadata.walls[index];
        if (wall.width <= 0 || wall.height <= 0) {
            continue;
        }

        map.rects.push_back(WaOverlayRect{
            wall.x,
            wall.y,
            wall.x + wall.width,
            wall.y + wall.height,
            0xFFFF00FF,
            0xFF000000 | (wall.color & 0x00FFFFFF),
            index,
        });
    }

    return map;
}

bool overlayMapsDescribeSameMap(const WaOverlayMap& left, const WaOverlayMap& right) {
    if (!left.sha256.empty() && !right.sha256.empty()) {
        return sameAsciiText(left.sha256, right.sha256);
    }

    return sameFileName(left.fileName, right.fileName)
        && left.width > 0
        && left.height > 0
        && left.width == right.width
        && left.height == right.height;
}

void resetOnlineMetadataTransportState() {
    std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
    g_onlineOutgoingFrames.clear();
    g_onlineIncomingMetadata.reset();
    InterlockedExchange(&g_onlineMetadataBroadcastMapIndex, -1);
    InterlockedExchange(&g_onlineLobbySeenSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyCompatibleSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyBroadcastSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyQuerySlotMask, 0);
    InterlockedExchange(&g_onlineLobbyLastConnectedSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyCompatibilityDeadlineTick, 0);
    InterlockedExchange(&g_onlineLobbyCompatibilityReported, 0);
}

void queueOnlineMetadataBroadcastForMap(std::size_t mapIndex) {
    if (!g_onlineSyncEnabled
        || !isOnlineLobbyHostContext()
        || mapIndex >= g_direct3D9OverlayMaps.size()) {
        return;
    }

    const LONG currentBroadcastIndex = g_onlineMetadataBroadcastMapIndex;
    if (currentBroadcastIndex == static_cast<LONG>(mapIndex)) {
        bool hasQueuedFrames = false;
        {
            std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
            hasQueuedFrames = !g_onlineOutgoingFrames.empty();
        }
        if (hasQueuedFrames) {
            return;
        }
    }

    const WallMapMetadata metadata = wallMetadataFromOverlayMap(g_direct3D9OverlayMaps[mapIndex]);
    if (metadata.walls.empty()) {
        return;
    }

    std::vector<std::vector<std::uint8_t>> frames;
    try {
        const std::vector<WallTransportFrame> transportFrames = makeWallMetadataFrames(
            metadata,
            static_cast<std::uint32_t>(GetTickCount()));
        frames.reserve(transportFrames.size());
        for (const WallTransportFrame& frame : transportFrames) {
            frames.push_back(serializeWallTransportFrame(frame));
        }
    } catch (...) {
        if (g_runtimeProbeLogger != nullptr && g_onlineMetadataErrorLogCount < 16) {
            InterlockedIncrement(&g_onlineMetadataErrorLogCount);
            g_runtimeProbeLogger->warn("online sync: failed to serialize host wall metadata");
        }
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
        g_onlineOutgoingFrames = std::move(frames);
        InterlockedExchange(&g_onlineMetadataBroadcastMapIndex, static_cast<LONG>(mapIndex));
        InterlockedExchange(&g_onlineLobbyLastBroadcastTick, 0);
        InterlockedExchange(&g_onlineLobbySeenSlotMask, 0);
        InterlockedExchange(&g_onlineLobbyCompatibleSlotMask, 0);
        InterlockedExchange(&g_onlineLobbyBroadcastSlotMask, 0);
        InterlockedExchange(&g_onlineLobbyQuerySlotMask, 0);
        InterlockedExchange(&g_onlineLobbyLastConnectedSlotMask, 0);
        InterlockedExchange(&g_onlineLobbyCompatibilityDeadlineTick, 0);
        InterlockedExchange(&g_onlineLobbyCompatibilityReported, 0);
    }
    trustActiveOverlayMapForOnlineMetadata(mapIndex);

    if (g_runtimeProbeLogger != nullptr && g_onlineMetadataSendLogCount < 24) {
        InterlockedIncrement(&g_onlineMetadataSendLogCount);
        std::ostringstream message;
        message << "online sync: queued host metadata for \""
                << metadata.name
                << "\" with "
                << metadata.walls.size()
                << " wall(s)";
        g_runtimeProbeLogger->info(message.str());
    }

    broadcastQueuedOnlineMetadataToLobby();
}

bool activeOverlayMapMatchesHostMetadata(const WallMapMetadata& metadata) {
    const LONG activeIndex = g_direct3D9ActiveOverlayMapIndex;
    if (activeIndex < 0 || static_cast<std::size_t>(activeIndex) >= g_direct3D9OverlayMaps.size()) {
        return true;
    }

    const WaOverlayMap& active = g_direct3D9OverlayMaps[static_cast<std::size_t>(activeIndex)];
    if (!active.sha256.empty() && !metadata.sha256.empty()) {
        return sameAsciiText(active.sha256, metadata.sha256);
    }

    if (active.width > 0 && active.height > 0 && metadata.width > 0 && metadata.height > 0) {
        return active.width == metadata.width && active.height == metadata.height;
    }

    return true;
}

bool addOrUpdateOnlineOverlayMap(const WallMapMetadata& metadata, std::size_t& mapIndex) {
    WaOverlayMap overlayMap = overlayMapFromWallMetadata(metadata);
    if (overlayMap.rects.empty()) {
        return false;
    }

    for (std::size_t index = 0; index < g_direct3D9OverlayMaps.size(); ++index) {
        if (!overlayMapsDescribeSameMap(g_direct3D9OverlayMaps[index], overlayMap)) {
            continue;
        }

        g_direct3D9OverlayMaps[index] = overlayMap;
        mapIndex = index;
        return true;
    }

    g_direct3D9OverlayMaps.push_back(overlayMap);
    mapIndex = g_direct3D9OverlayMaps.size() - 1;
    return true;
}

void clearDirect3D9OverlayMap(const char* reason) {
    const bool hadActiveMap = g_direct3D9ActiveOverlayMapIndex >= 0 || !g_direct3D9OverlayTestRects.empty();
    if (!hadActiveMap) {
        return;
    }

    g_direct3D9OverlayTestRects.clear();
    g_direct3D9OverlayTransform.mapWidth = 0;
    g_direct3D9OverlayTransform.mapHeight = 0;
    InterlockedExchange(&g_direct3D9ActiveOverlayMapIndex, -1);
    InterlockedExchange(&g_direct3D9OverlayGameplayActive, 0);
    InterlockedExchange(&g_direct3D9OverlayLastGameplayEvidenceTick, 0);
    InterlockedExchange(&g_detectedMapCacheAssociationPending, 0);
    InterlockedExchange(&g_detectedMapFromCacheSeed, 0);
    InterlockedExchange(&g_blockedWeaponInputKeyMask, 0);
    InterlockedExchange(&g_blockedWeaponInputSuppressUntilTick, 0);
    InterlockedExchange(&g_recentRopeContextTick, 0);
    clearOnlineMetadataTrust();
    resetWallGameplayTaskActivity();
    resetOnlineMetadataTransportState();
    resetTransientGameplayTrackingState("overlay map deactivation", true);
    if (g_activeHookManager != nullptr && g_runtimeProbeLogger != nullptr) {
        g_activeHookManager->disableGameplayHooks(*g_runtimeProbeLogger, reason);
    }

    if (g_runtimeProbeLogger != nullptr && g_direct3D9OverlayActivationLogCount < 32) {
        InterlockedIncrement(&g_direct3D9OverlayActivationLogCount);

        std::ostringstream message;
        message << "runtime probe: Direct3D9 wall overlay deactivated";
        if (reason != nullptr && reason[0] != '\0') {
            message << " (" << reason << ")";
        }
        g_runtimeProbeLogger->info(message.str());
    }
}

void activateDirect3D9OverlayMap(std::size_t mapIndex, const std::string& detectedFileName, bool broadcastOnlineMetadata = true) {
    if (mapIndex >= g_direct3D9OverlayMaps.size()) {
        clearDirect3D9OverlayMap("invalid map index");
        return;
    }

    const LONG activeIndex = g_direct3D9ActiveOverlayMapIndex;
    if (activeIndex == static_cast<LONG>(mapIndex)) {
        if (broadcastOnlineMetadata) {
            queueOnlineMetadataBroadcastForMap(mapIndex);
        }
        return;
    }

    const WaOverlayMap& map = g_direct3D9OverlayMaps[mapIndex];
    clearOnlineMetadataTrust();
    g_direct3D9OverlayTestRects.clear();
    g_direct3D9OverlayTestRects.reserve(map.rects.size());
    for (const WaOverlayRect& rect : map.rects) {
        g_direct3D9OverlayTestRects.push_back(makeDirect3D9OverlayRect(rect));
    }

    g_direct3D9OverlayTransform.mapWidth = map.width;
    g_direct3D9OverlayTransform.mapHeight = map.height;
    InterlockedExchange(&g_direct3D9ActiveOverlayMapIndex, static_cast<LONG>(mapIndex));
    InterlockedExchange(&g_direct3D9OverlayGameplayActive, 0);
    InterlockedExchange(&g_direct3D9OverlayLastGameplayEvidenceTick, 0);
    resetTransientGameplayTrackingState("overlay map activation", true);
    if (g_activeHookManager != nullptr && g_runtimeProbeLogger != nullptr) {
        g_activeHookManager->ensureGameplayHooks(*g_runtimeProbeLogger, "wall metadata map activation");
    }
    if (broadcastOnlineMetadata) {
        queueOnlineMetadataBroadcastForMap(mapIndex);
    }

    if (g_runtimeProbeLogger != nullptr && g_direct3D9OverlayActivationLogCount < 32) {
        InterlockedIncrement(&g_direct3D9OverlayActivationLogCount);

        std::ostringstream message;
        message << "runtime probe: Direct3D9 wall overlay activated metadata map \""
                << map.name
                << "\" for detected map file \""
                << detectedFileName
                << "\" with "
                << g_direct3D9OverlayTestRects.size()
                << " wall rect(s)";
        g_runtimeProbeLogger->info(message.str());
    }
}

void handleIncomingOnlineMetadataFrame(const void* data, std::size_t dataSize) {
    if (!g_onlineSyncEnabled || data == nullptr || dataSize == 0) {
        return;
    }

    WallTransportFrame frame;
    std::string error;
    if (!deserializeWallTransportFrame(
            static_cast<const std::uint8_t*>(data),
            dataSize,
            frame,
            error)) {
        if (g_runtimeProbeLogger != nullptr && g_onlineMetadataErrorLogCount < 16) {
            InterlockedIncrement(&g_onlineMetadataErrorLogCount);
            g_runtimeProbeLogger->warn("online sync: rejected incoming metadata frame: " + error);
        }
        return;
    }

    bool completed = false;
    std::vector<std::uint8_t> metadataPayload;
    {
        std::lock_guard<std::mutex> lock(g_onlineSyncMutex);
        if (!g_onlineIncomingMetadata.accept(frame, error)) {
            g_onlineIncomingMetadata.reset();
            if (g_runtimeProbeLogger != nullptr && g_onlineMetadataErrorLogCount < 16) {
                InterlockedIncrement(&g_onlineMetadataErrorLogCount);
                g_runtimeProbeLogger->warn("online sync: failed to accept incoming metadata frame: " + error);
            }
            return;
        }

        completed = g_onlineIncomingMetadata.complete();
        if (completed) {
            metadataPayload = g_onlineIncomingMetadata.payload();
            g_onlineIncomingMetadata.reset();
        }
    }

    if (!completed) {
        if (g_runtimeProbeLogger != nullptr && g_onlineMetadataReceiveLogCount < 24) {
            InterlockedIncrement(&g_onlineMetadataReceiveLogCount);
            std::ostringstream message;
            message << "online sync: accepted metadata frame "
                    << (frame.chunkIndex + 1)
                    << "/"
                    << frame.chunkCount
                    << " transfer "
                    << frame.transferId;
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }

    WallMapMetadata metadata;
    if (!deserializeWallMetadata(metadataPayload, metadata, error)) {
        if (g_runtimeProbeLogger != nullptr && g_onlineMetadataErrorLogCount < 16) {
            InterlockedIncrement(&g_onlineMetadataErrorLogCount);
            g_runtimeProbeLogger->warn("online sync: failed to deserialize host metadata: " + error);
        }
        return;
    }

    if (!activeOverlayMapMatchesHostMetadata(metadata)) {
        if (g_runtimeProbeLogger != nullptr && g_onlineMetadataErrorLogCount < 16) {
            InterlockedIncrement(&g_onlineMetadataErrorLogCount);
            g_runtimeProbeLogger->warn("online sync: ignored host metadata because it does not match the active map");
        }
        return;
    }

    std::size_t mapIndex = 0;
    if (!addOrUpdateOnlineOverlayMap(metadata, mapIndex)) {
        if (g_runtimeProbeLogger != nullptr && g_onlineMetadataErrorLogCount < 16) {
            InterlockedIncrement(&g_onlineMetadataErrorLogCount);
            g_runtimeProbeLogger->warn("online sync: host metadata had no valid walls");
        }
        return;
    }

    activateDirect3D9OverlayMap(mapIndex, metadata.fileName, false);
    trustActiveOverlayMapForOnlineMetadata(mapIndex);

    if (g_runtimeProbeLogger != nullptr && g_onlineMetadataReceiveLogCount < 24) {
        InterlockedIncrement(&g_onlineMetadataReceiveLogCount);
        std::ostringstream message;
        message << "online sync: applied host metadata \""
                << metadata.name
                << "\" with "
                << metadata.walls.size()
                << " wall(s)";
        g_runtimeProbeLogger->info(message.str());
    }
}

void refreshDetectedMapCacheForActiveOverlay() {
    if (g_detectedMapCachePath.empty()
        || g_customDatPath.empty()
        || g_direct3D9ActiveOverlayMapIndex < 0) {
        return;
    }

    const DWORD now = GetTickCount();
    const DWORD previousRefresh = static_cast<DWORD>(g_detectedMapCacheRefreshTick);
    if (previousRefresh != 0 && now - previousRefresh < kDetectedMapCacheRefreshPollMilliseconds) {
        return;
    }
    InterlockedExchange(&g_detectedMapCacheRefreshTick, static_cast<LONG>(now));

    std::string detectedPath;
    std::string detectedFileName;
    {
        std::lock_guard<std::mutex> lock(g_detectedMapMutex);
        detectedPath = g_detectedMapPath;
        detectedFileName = g_detectedMapFileName;
    }
    if (detectedPath.empty() || detectedFileName.empty()) {
        return;
    }

    const LONG activeIndex = g_direct3D9ActiveOverlayMapIndex;
    if (activeIndex < 0 || static_cast<std::size_t>(activeIndex) >= g_direct3D9OverlayMaps.size()) {
        return;
    }

    const WaOverlayMap& activeMap = g_direct3D9OverlayMaps[static_cast<std::size_t>(activeIndex)];
    if (!sameFileName(activeMap.fileName, detectedFileName)) {
        return;
    }

    const std::uint64_t customDatWriteTime = fileWriteTimeUtc(g_customDatPath);
    if (customDatWriteTime == 0 || customDatWriteTime == g_detectedMapCachedCustomDatWriteTime) {
        return;
    }

    const bool associationPending = g_detectedMapCacheAssociationPending != 0;
    const DWORD detectedMapTick = static_cast<DWORD>(g_detectedMapTick);
    const bool detectedFromCache = g_detectedMapFromCacheSeed != 0;
    const bool onlineTrustedMap = activeOverlayMapTrustedByOnlineMetadata(activeIndex)
        && !detectedFromCache;
    const bool recentRealMapDetection = associationPending
        && !detectedFromCache
        && detectedMapTick != 0
        && now - detectedMapTick <= kDetectedMapCacheRefreshWindowMilliseconds;
    if (!recentRealMapDetection && !onlineTrustedMap) {
        {
            std::lock_guard<std::mutex> lock(g_detectedMapMutex);
            g_detectedMapPath.clear();
            g_detectedMapFileName.clear();
        }
        InterlockedExchange(&g_detectedMapFromCacheSeed, 0);
        InterlockedExchange(&g_detectedMapCacheAssociationPending, 0);
        InterlockedIncrement(&g_detectedMapSequence);
        clearDirect3D9OverlayMap("custom.dat changed without a recent metadata map detection");
        writeDetectedMapCache("", "", false);

        if (g_runtimeProbeLogger != nullptr && g_detectedMapCacheRefreshLogCount < 8) {
            InterlockedIncrement(&g_detectedMapCacheRefreshLogCount);

            std::ostringstream message;
            message << "runtime probe: deactivated wall map cache because custom.dat changed without a recent metadata map detection";
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }

    writeDetectedMapCache(detectedPath, detectedFileName, true);
    InterlockedExchange(&g_detectedMapCacheAssociationPending, 0);
    InterlockedExchange(&g_detectedMapFromCacheSeed, 0);
    if (onlineTrustedMap && !recentRealMapDetection) {
        clearOnlineMetadataTrust();
    }

    if (g_runtimeProbeLogger != nullptr && g_detectedMapCacheRefreshLogCount < 8) {
        InterlockedIncrement(&g_detectedMapCacheRefreshLogCount);

        std::ostringstream message;
        message << "runtime probe: refreshed default wall map cache for \""
                << detectedFileName
                << "\" after custom.dat update";
        g_runtimeProbeLogger->info(message.str());
    }
}

void seedDetectedMapFromCacheIfCurrent() {
    if (g_runtimeProbeLogger != nullptr
        && InterlockedCompareExchange(&g_cachedDefaultMapSeedLogCount, 1, 0) == 0) {
        g_runtimeProbeLogger->info(
            "runtime probe: persistent cached map auto-activation disabled; waiting for real map detection");
    }
    return;

    if (g_cachedDefaultMapPath.empty()
        || g_cachedDefaultMapCustomDatSha256.empty()
        || g_direct3D9ActiveOverlayMapIndex >= 0
        || g_direct3D9OverlayMaps.empty()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_detectedMapMutex);
        if (!g_detectedMapPath.empty() || !g_detectedMapFileName.empty()) {
            return;
        }
    }

    const DWORD now = GetTickCount();
    const DWORD previousAttempt = static_cast<DWORD>(g_cachedDefaultMapSeedAttemptTick);
    if (previousAttempt != 0 && now - previousAttempt < 1000) {
        return;
    }
    InterlockedExchange(&g_cachedDefaultMapSeedAttemptTick, static_cast<LONG>(now));

    const std::string currentCustomDatSha256 = sha256FileHex(g_customDatPath);
    if (currentCustomDatSha256.empty()
        || !sameAsciiText(currentCustomDatSha256, g_cachedDefaultMapCustomDatSha256)) {
        return;
    }

    const LONG previousSequence = g_detectedMapSequence;
    recordDetectedWaMapFilePath(g_cachedDefaultMapPath);
    if (g_detectedMapSequence == previousSequence) {
        return;
    }
    InterlockedExchange(&g_detectedMapFromCacheSeed, 1);
    InterlockedExchange(&g_detectedMapCacheAssociationPending, 0);

    if (g_runtimeProbeLogger != nullptr && g_cachedDefaultMapSeedLogCount < 8) {
        InterlockedIncrement(&g_cachedDefaultMapSeedLogCount);

        std::ostringstream message;
        message << "runtime probe: seeded detected W:A map from wkWall2Wall cache \""
                << g_cachedDefaultMapPath
                << "\"";
        g_runtimeProbeLogger->info(message.str());
    }
}

void syncDirect3D9OverlayMapFromDetectedFile() {
    if (g_direct3D9OverlayMaps.empty()) {
        return;
    }

    seedDetectedMapFromCacheIfCurrent();

    const LONG detectedSequence = g_detectedMapSequence;
    if (detectedSequence == g_consumedMapSequence) {
        return;
    }

    std::string detectedPath;
    std::string detectedFileName;
    {
        std::lock_guard<std::mutex> lock(g_detectedMapMutex);
        detectedPath = g_detectedMapPath;
        detectedFileName = g_detectedMapFileName;
    }

    if (detectedPath.empty() || detectedFileName.empty()) {
        clearDirect3D9OverlayMap("no detected map file");
        InterlockedExchange(&g_consumedMapSequence, detectedSequence);
        return;
    }

    std::size_t mapIndex = 0;
    if (!direct3D9OverlayMapIndexForFileName(detectedPath, mapIndex)) {
        clearDirect3D9OverlayMap("detected map has no wall metadata");
        if (g_runtimeProbeLogger != nullptr && g_direct3D9OverlayActivationLogCount < 32) {
            InterlockedIncrement(&g_direct3D9OverlayActivationLogCount);

            std::ostringstream message;
            message << "runtime probe: no wall metadata matched detected map file \""
                    << detectedFileName
                    << "\"; overlay deactivated";
            g_runtimeProbeLogger->info(message.str());
        }
        InterlockedExchange(&g_consumedMapSequence, detectedSequence);
        return;
    }

    activateDirect3D9OverlayMap(mapIndex, detectedFileName);
    InterlockedExchange(&g_consumedMapSequence, detectedSequence);
}

bool metadataOverlayCameraWithinMapBounds(const CameraTrackingSnapshot& camera) {
    if (!camera.available) {
        return false;
    }

    if (camera.xPixels == 0 && camera.yPixels == 0) {
        return false;
    }

    const int mapWidth = g_direct3D9OverlayTransform.mapWidth;
    const int mapHeight = g_direct3D9OverlayTransform.mapHeight;
    if (mapWidth <= 0 || mapHeight <= 0) {
        return true;
    }

    return camera.xPixels >= -128
        && camera.xPixels <= mapWidth + 128
        && camera.yPixels >= -128
        && camera.yPixels <= mapHeight + 128;
}

bool direct3D9OverlayHasRecentGameplayEvidence() {
    const DWORD now = GetTickCount();

    if (g_direct3D9OverlayTransform.cameraFollow) {
        const CameraTrackingSnapshot camera = currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot);
        if (metadataOverlayCameraWithinMapBounds(camera)) {
            return true;
        }
    }

    for (const WormLiveSample& sample : g_wormLiveSamples) {
        if (sample.ownerAddress == 0 || sample.aliveFlag == 0) {
            continue;
        }

        const DWORD sampleTick = static_cast<DWORD>(
            sample.lastPollTick != 0 ? sample.lastPollTick : sample.tick);
        if (sampleTick != 0 && now - sampleTick <= kOverlayWormEvidenceKeepMilliseconds) {
            return true;
        }
    }

    return false;
}

bool direct3D9OverlayGameplayReady() {
    const DWORD now = GetTickCount();
    const bool ready = direct3D9OverlayHasRecentGameplayEvidence();
    if (ready) {
        InterlockedExchange(&g_direct3D9OverlayLastGameplayEvidenceTick, static_cast<LONG>(now));
        InterlockedExchange(&g_direct3D9OverlayGameplayActive, 1);
        return true;
    }

    const DWORD lastEvidenceTick = static_cast<DWORD>(g_direct3D9OverlayLastGameplayEvidenceTick);
    if (lastEvidenceTick != 0 && now - lastEvidenceTick <= kOverlayGameplayGraceMilliseconds) {
        InterlockedExchange(&g_direct3D9OverlayGameplayActive, 1);
        return true;
    }

    InterlockedExchange(&g_direct3D9OverlayGameplayActive, 0);
    return false;
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

int metadataOverlayBaseX(UINT renderTargetWidth) {
    int baseX = g_direct3D9OverlayTransform.offsetX;
    if (!g_direct3D9OverlayTransform.autoViewportX) {
        return baseX;
    }

    if (renderTargetWidth == 0) {
        return baseX;
    }

    const int mapWidth = scaledOverlayMapWidth();
    if (mapWidth <= 0) {
        return baseX;
    }

    return ((static_cast<int>(renderTargetWidth) - mapWidth) / 2) + baseX;
}

int metadataOverlayBaseY(UINT renderTargetHeight) {
    int baseY = g_direct3D9OverlayTransform.offsetY;
    if (!g_direct3D9OverlayTransform.autoViewportY) {
        return baseY;
    }

    if (renderTargetHeight == 0) {
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

void logMetadataOverlayTransform(
    const char* rendererName,
    UINT renderTargetWidth,
    UINT renderTargetHeight,
    int baseX,
    int baseY,
    const CameraTrackingSnapshot& camera) {
    if (!kVerboseRuntimeDiagnostics || g_runtimeProbeLogger == nullptr) {
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
    message << "runtime probe: "
            << rendererName
            << " metadata overlay transform: renderTarget "
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
    if (kVerboseRuntimeDiagnostics
        && distance >= 16
        && g_runtimeProbeLogger != nullptr
        && g_activeWormCandidatePollLogCount < 48) {
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

void updateTouchedOverlayWallsFromActiveWorm() {
    if (g_direct3D9OverlayTestRects.empty()) {
        return;
    }

    refreshActiveWormCandidateFromTrackingTarget();
}

bool prepareMetadataOverlayScreenRects(
    const char* rendererName,
    UINT renderTargetWidth,
    UINT renderTargetHeight,
    std::vector<ScreenOverlayRect>& screenRects,
    int viewportX = 0,
    int viewportY = 0,
    UINT viewportWidth = 0,
    UINT viewportHeight = 0) {
    screenRects.clear();

    syncDirect3D9OverlayMapFromDetectedFile();

    if (!onlineWallModuleAllowedForCurrentContext()) {
        return false;
    }

    if (!wallOverlayMetadataActive()) {
        return false;
    }

    if (!direct3D9OverlayGameplayReady()) {
        return false;
    }

    if (!wallGameplayRulesActiveForCurrentMap()) {
        return false;
    }

    refreshDetectedMapCacheForActiveOverlay();

    if (renderTargetWidth == 0 || renderTargetHeight == 0) {
        return false;
    }

    activatePendingChatOverlayPinnedModeIfReady();

    if (viewportWidth == 0) {
        viewportWidth = renderTargetWidth;
    }

    if (viewportHeight == 0) {
        viewportHeight = renderTargetHeight;
    }

    updateTouchedOverlayWallsFromActiveWorm();

    int baseX = metadataOverlayBaseX(renderTargetWidth);
    int baseY = metadataOverlayBaseY(renderTargetHeight);
    const CameraTrackingSnapshot camera = g_direct3D9OverlayTransform.cameraFollow
        ? currentCameraTrackingSnapshot(g_direct3D9OverlayTransform.cameraSlot)
        : CameraTrackingSnapshot{};
    if (g_direct3D9OverlayTransform.cameraFollow && camera.available && !metadataOverlayCameraWithinMapBounds(camera)) {
        return false;
    }

    if (g_direct3D9OverlayTransform.cameraFollow && camera.available) {
        baseX = viewportX
            + (static_cast<int>(viewportWidth) / 2)
            - camera.xPixels
            + g_direct3D9OverlayTransform.offsetX;
        baseY = viewportY
            + (static_cast<int>(viewportHeight) / 2)
            - camera.yPixels
            + g_direct3D9OverlayTransform.offsetY;

        if (g_chatOverlayPinnedMode != 0) {
            LONG pinnedBaseOffsetY = g_chatOverlayPinnedCameraOffsetY;
            if (pinnedBaseOffsetY == LONG_MIN) {
                LONG pinnedBaselineBaseY = g_chatOverlayPinnedBaselineBaseY;
                if (pinnedBaselineBaseY == LONG_MIN) {
                    InterlockedExchange(&g_chatOverlayPinnedBaselineBaseY, static_cast<LONG>(baseY));
                    pinnedBaselineBaseY = static_cast<LONG>(baseY);
                }

                const LONG lastUnpinnedBaseY = g_chatOverlayLastUnpinnedBaseY;
                const LONG candidateOffsetY = lastUnpinnedBaseY != LONG_MIN
                    ? lastUnpinnedBaseY - static_cast<LONG>(baseY)
                    : 0;
                pinnedBaseOffsetY = (std::abs(candidateOffsetY) <= 96) ? candidateOffsetY : 0;
                if (pinnedBaseOffsetY == 0) {
                    pinnedBaseOffsetY = std::max<LONG>(1, static_cast<LONG>((renderTargetHeight + 28) / 57));
                }
                const LONG baseDriftY = pinnedBaselineBaseY - static_cast<LONG>(baseY);
                pinnedBaseOffsetY += std::max<LONG>(-256, std::min<LONG>(256, baseDriftY));
                InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, pinnedBaseOffsetY);

                if (g_runtimeProbeLogger != nullptr && g_chatOverlayHiddenLogCount < 8) {
                    InterlockedIncrement(&g_chatOverlayHiddenLogCount);
                    std::ostringstream message;
                    message << "runtime: metadata overlay pinned base offset "
                            << pinnedBaseOffsetY
                            << " px from base y "
                            << baseY
                            << " baseline base y "
                            << pinnedBaselineBaseY;
                    g_runtimeProbeLogger->info(message.str());
                }
            }

            baseY += static_cast<int>(pinnedBaseOffsetY);
        } else {
            if (g_chatOverlayActive == 0 && g_chatOverlayPinnedPending == 0) {
                InterlockedExchange(&g_chatOverlayLastUnpinnedCameraYPixels, static_cast<LONG>(camera.yPixels));
                InterlockedExchange(&g_chatOverlayLastUnpinnedBaseY, static_cast<LONG>(baseY));
            }
            InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
        }
    }

    const bool viewportMovedForChat =
        viewportX != 0
        || viewportY != 0
        || viewportWidth != renderTargetWidth
        || viewportHeight != renderTargetHeight;
    if (g_chatOverlayActive != 0 && g_chatOverlayPinnedMode == 0 && !viewportMovedForChat) {
        const bool detectedChatOffset = g_chatOverlayDetectedOffsetValid != 0;
        if (detectedChatOffset) {
            const int chatOffsetY = static_cast<int>(g_chatOverlayDetectedOffsetY);
            baseY += chatOffsetY;
            const LONG hits = InterlockedIncrement(&g_chatOverlayHiddenLogCount);
            if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
                std::ostringstream message;
                message << "runtime: metadata overlay shifted by detected chat offset "
                        << chatOffsetY
                        << " px";
                g_runtimeProbeLogger->info(message.str());
            }
        }
    } else if (g_chatOverlayActive != 0 && viewportMovedForChat) {
        const LONG hits = InterlockedIncrement(&g_chatOverlayHiddenLogCount);
        if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime: metadata overlay using renderer viewport for chat: origin "
                    << viewportX
                    << ","
                    << viewportY
                    << " size "
                    << viewportWidth
                    << "x"
                    << viewportHeight;
            g_runtimeProbeLogger->info(message.str());
        }
    }

    logMetadataOverlayTransform(
        rendererName != nullptr ? rendererName : "renderer",
        renderTargetWidth,
        renderTargetHeight,
        baseX,
        baseY,
        camera);

    screenRects.reserve(g_direct3D9OverlayTestRects.size());
    for (const Direct3D9OverlayRect& rect : g_direct3D9OverlayTestRects) {
        if (!rect.touched) {
            continue;
        }

        appendTouchedWallVisualRects(
            screenRects,
            static_cast<LONG>(scaledOverlayCoordinate(rect.left) + baseX),
            static_cast<LONG>(scaledOverlayCoordinate(rect.top) + baseY),
            static_cast<LONG>(scaledOverlayCoordinate(rect.right) + baseX),
            static_cast<LONG>(scaledOverlayCoordinate(rect.bottom) + baseY),
            rect.wallIndex);
    }

    return !screenRects.empty();
}

bool metadataOverlayHiddenByChatForFallbackRenderer(const char* rendererName) {
    activatePendingChatOverlayPinnedModeIfReady();

    if (g_chatOverlayActive == 0
        && g_chatOverlayPinnedMode == 0
        && g_chatOverlayPinnedPending == 0) {
        return false;
    }

    const LONG hits = InterlockedIncrement(&g_chatOverlayHiddenLogCount);
    if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime: "
                << (rendererName != nullptr ? rendererName : "renderer")
                << " metadata overlay hidden while W:A chat is active";
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

void drawDirect3D9OverlayTestRects(IDirect3DDevice9* device) {
    if (!wallOverlayMetadataActive()) {
        return;
    }

    UINT renderTargetWidth = 0;
    UINT renderTargetHeight = 0;
    if (!getDirect3D9RenderTargetSize(device, renderTargetWidth, renderTargetHeight)) {
        return;
    }

    const LONG pendingScanTick = g_chatOverlayScanPendingTick;
    if (g_chatOverlayActive != 0 && g_chatOverlayPinnedMode == 0 && pendingScanTick != 0) {
        const DWORD now = GetTickCount();
        if (static_cast<LONG>(now - static_cast<DWORD>(pendingScanTick)) >= 0
            && InterlockedCompareExchange(&g_chatOverlayScanPendingTick, 0, pendingScanTick) == pendingScanTick) {
            int detectedOffsetY = 0;
            if (detectDirect3D9ChatOffsetFromRenderTarget(device, false, detectedOffsetY)) {
                const LONG sampleIndex = InterlockedIncrement(&g_chatOverlayScanSampleCount) - 1;
                if (sampleIndex >= 0 && sampleIndex < static_cast<LONG>(g_chatOverlayScanSamples.size())) {
                    g_chatOverlayScanSamples[static_cast<std::size_t>(sampleIndex)] = detectedOffsetY;
                }

                constexpr LONG kChatOverlayScanTargetSamples = 5;
                if (sampleIndex + 1 >= kChatOverlayScanTargetSamples) {
                    finalizeChatOverlayDetectedOffsetFromSamples();
                } else {
                    InterlockedExchange(&g_chatOverlayScanPendingTick, static_cast<LONG>(GetTickCount() + 80));
                }
            } else {
                const LONG currentSampleCount = g_chatOverlayScanSampleCount;
                if (currentSampleCount > 0) {
                    finalizeChatOverlayDetectedOffsetFromSamples();
                } else {
                    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 0);
                }

                if (currentSampleCount == 0 && g_runtimeProbeLogger != nullptr && g_chatOverlayScanLogCount < 16) {
                    InterlockedIncrement(&g_chatOverlayScanLogCount);
                    g_runtimeProbeLogger->info("runtime: D3D9 chat separator scan found no reliable separator; chat overlay offset disabled");
                }
            }
        }
    }

    D3DVIEWPORT9 viewport = {};
    int viewportX = 0;
    int viewportY = 0;
    UINT viewportWidth = renderTargetWidth;
    UINT viewportHeight = renderTargetHeight;
    if (SUCCEEDED(device->GetViewport(&viewport))
        && viewport.Width > 0
        && viewport.Height > 0) {
        viewportX = static_cast<int>(viewport.X);
        viewportY = static_cast<int>(viewport.Y);
        viewportWidth = viewport.Width;
        viewportHeight = viewport.Height;
    }

    std::vector<ScreenOverlayRect> screenRects;
    if (!prepareMetadataOverlayScreenRects(
            "Direct3D9",
            renderTargetWidth,
            renderTargetHeight,
            screenRects,
            viewportX,
            viewportY,
            viewportWidth,
            viewportHeight)) {
        return;
    }

    const HRESULT result = drawDirect3D9AlphaOverlayRects(device, screenRects);
    const std::size_t drawn = SUCCEEDED(result) ? screenRects.size() : 0;

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

    if (FAILED(result)) {
        const LONG failures = InterlockedIncrement(&g_direct3D9MetadataOverlayFailureHits);
        if (failures == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: Direct3D9 metadata overlay failed with HRESULT "
                    << formatHex32(static_cast<std::uint32_t>(result));
            g_runtimeProbeLogger->warn(message.str());
        }
    }
}

const char* openGLOverlayPassName(OpenGLOverlayPass pass) {
    switch (pass) {
    case OpenGLOverlayPass::AfterGlEnd:
        return "after-glEnd";
    case OpenGLOverlayPass::BeforeSwap:
    default:
        return "before-swap";
    }
}

bool getOpenGLViewportSize(UINT& width, UINT& height) {
    width = 0;
    height = 0;

    if (wglGetCurrentContext() == nullptr) {
        return false;
    }

    GLint viewport[4] = {};
    glGetIntegerv(GL_VIEWPORT, viewport);
    if (viewport[2] <= 0 || viewport[3] <= 0) {
        return false;
    }

    width = static_cast<UINT>(viewport[2]);
    height = static_cast<UINT>(viewport[3]);
    return true;
}

bool drawOpenGLOverlayRect(const ScreenOverlayRect& rect, UINT viewportWidth, UINT viewportHeight) {
    if (rect.right <= rect.left || rect.bottom <= rect.top) {
        return false;
    }

    const LONG left = std::clamp<LONG>(rect.left, 0, static_cast<LONG>(viewportWidth));
    const LONG top = std::clamp<LONG>(rect.top, 0, static_cast<LONG>(viewportHeight));
    const LONG right = std::clamp<LONG>(rect.right, 0, static_cast<LONG>(viewportWidth));
    const LONG bottom = std::clamp<LONG>(rect.bottom, 0, static_cast<LONG>(viewportHeight));
    if (right <= left || bottom <= top) {
        return false;
    }

    const GLfloat alpha = static_cast<GLfloat>((rect.color >> 24) & 0xFF) / 255.0f;
    const GLfloat red = static_cast<GLfloat>((rect.color >> 16) & 0xFF) / 255.0f;
    const GLfloat green = static_cast<GLfloat>((rect.color >> 8) & 0xFF) / 255.0f;
    const GLfloat blue = static_cast<GLfloat>(rect.color & 0xFF) / 255.0f;

    glScissor(
        left,
        static_cast<GLint>(viewportHeight) - bottom,
        right - left,
        bottom - top);
    glClearColor(red, green, blue, alpha);
    glClear(GL_COLOR_BUFFER_BIT);
    return true;
}

void drawOpenGLOverlayTestRects(OpenGLOverlayPass pass) {
    if (!wallOverlayMetadataActive()) {
        return;
    }

    UINT viewportWidth = 0;
    UINT viewportHeight = 0;
    if (!getOpenGLViewportSize(viewportWidth, viewportHeight)) {
        return;
    }

    if (metadataOverlayHiddenByChatForFallbackRenderer("OpenGL")) {
        return;
    }

    std::vector<ScreenOverlayRect> screenRects;
    if (!prepareMetadataOverlayScreenRects("OpenGL", viewportWidth, viewportHeight, screenRects)) {
        return;
    }

    GLint previousMatrixMode = GL_MODELVIEW;
    GLint previousDrawBuffer = GL_BACK;
    glGetIntegerv(GL_MATRIX_MODE, &previousMatrixMode);
    glGetIntegerv(GL_DRAW_BUFFER, &previousDrawBuffer);

    const LONG contextLogHits = InterlockedIncrement(&g_openGLMetadataOverlayContextLogHits);
    if (contextLogHits <= 4 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: OpenGL metadata overlay context: hglrc "
                << formatAddress(reinterpret_cast<std::uintptr_t>(wglGetCurrentContext()))
                << ", hdc "
                << formatAddress(reinterpret_cast<std::uintptr_t>(wglGetCurrentDC()))
                << ", viewport "
                << viewportWidth
                << "x"
                << viewportHeight
                << ", drawBuffer "
                << formatHex32(static_cast<std::uint32_t>(previousDrawBuffer))
                << ", pass "
                << openGLOverlayPassName(pass);
        g_runtimeProbeLogger->info(message.str());
    }

    glPushAttrib(GL_ALL_ATTRIB_BITS);

    glDrawBuffer(static_cast<GLenum>(previousDrawBuffer));
    GLenum drawBufferError = glGetError();
    if (drawBufferError != GL_NO_ERROR) {
        glDrawBuffer(previousDrawBuffer);
        drawBufferError = glGetError();
    }

    glDisable(GL_TEXTURE_2D);
    glDisable(GL_DEPTH_TEST);
    glDisable(GL_LIGHTING);
    glDisable(GL_CULL_FACE);
    glDisable(GL_SCISSOR_TEST);
    glDisable(GL_ALPHA_TEST);
    glDisable(GL_BLEND);
    glColorMask(GL_TRUE, GL_TRUE, GL_TRUE, GL_TRUE);
    glDepthMask(GL_FALSE);
    glEnable(GL_SCISSOR_TEST);

    std::size_t drawn = 0;
    for (const ScreenOverlayRect& rect : screenRects) {
        if (drawOpenGLOverlayRect(rect, viewportWidth, viewportHeight)) {
            ++drawn;
        }
    }

    glMatrixMode(previousMatrixMode);

    glFlush();

    glPopAttrib();

    const GLenum error = glGetError();
    if (drawn > 0 && error == GL_NO_ERROR && drawBufferError == GL_NO_ERROR) {
        const LONG hits = InterlockedIncrement(&g_openGLMetadataOverlayDrawHits);
        if (hits == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: OpenGL metadata overlay drew "
                    << drawn
                    << " rect(s) on "
                    << openGLOverlayPassName(pass);
            g_runtimeProbeLogger->info(message.str());
        }
        return;
    }

    if (error != GL_NO_ERROR || drawBufferError != GL_NO_ERROR) {
        const LONG failures = InterlockedIncrement(&g_openGLMetadataOverlayFailureHits);
        if (failures == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: OpenGL metadata overlay failed with GL error "
                    << formatHex32(static_cast<std::uint32_t>(error))
                    << ", drawBuffer error "
                    << formatHex32(static_cast<std::uint32_t>(drawBufferError));
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

DirectDrawObjectVtableHook* directDrawObjectHookForVtable(std::uintptr_t* vtable) {
    for (DirectDrawObjectVtableHook& hook : g_directDrawObjectVtableHooks) {
        if (hook.vtable == vtable) {
            return &hook;
        }
    }

    return nullptr;
}

DirectDrawSurfaceVtableHook* directDrawSurfaceHookForVtable(std::uintptr_t* vtable) {
    for (DirectDrawSurfaceVtableHook& hook : g_directDrawSurfaceVtableHooks) {
        if (hook.vtable == vtable) {
            return &hook;
        }
    }

    return nullptr;
}

DirectDrawObjectVtableHook directDrawObjectHookSnapshot(void* directDraw) {
    DirectDrawObjectVtableHook snapshot;
    if (directDraw == nullptr) {
        return snapshot;
    }

    auto** objectVtableSlot = reinterpret_cast<std::uintptr_t**>(directDraw);
    std::uintptr_t* vtable = *objectVtableSlot;
    std::lock_guard<std::mutex> lock(g_directDrawProbeMutex);
    if (DirectDrawObjectVtableHook* hook = directDrawObjectHookForVtable(vtable)) {
        snapshot = *hook;
    }
    return snapshot;
}

DirectDrawSurfaceVtableHook directDrawSurfaceHookSnapshot(void* surface) {
    DirectDrawSurfaceVtableHook snapshot;
    if (surface == nullptr) {
        return snapshot;
    }

    auto** objectVtableSlot = reinterpret_cast<std::uintptr_t**>(surface);
    std::uintptr_t* vtable = *objectVtableSlot;
    std::lock_guard<std::mutex> lock(g_directDrawProbeMutex);
    if (DirectDrawSurfaceVtableHook* hook = directDrawSurfaceHookForVtable(vtable)) {
        snapshot = *hook;
    }
    return snapshot;
}

DWORD directDrawMaskComponent(BYTE component, DWORD mask) {
    if (mask == 0) {
        return 0;
    }

    DWORD shiftedMask = mask;
    DWORD shift = 0;
    while ((shiftedMask & 1U) == 0U) {
        shiftedMask >>= 1;
        ++shift;
    }

    DWORD maxValue = 0;
    DWORD bit = 1;
    while ((shiftedMask & bit) != 0U) {
        maxValue = (maxValue << 1U) | 1U;
        bit <<= 1U;
    }

    if (maxValue == 0) {
        return 0;
    }

    const DWORD scaled = (static_cast<DWORD>(component) * maxValue + 127U) / 255U;
    return (scaled << shift) & mask;
}

DWORD directDrawFillColorFromArgb(DWORD argb, const DDPIXELFORMAT& pixelFormat) {
    const BYTE red = static_cast<BYTE>((argb >> 16) & 0xFF);
    const BYTE green = static_cast<BYTE>((argb >> 8) & 0xFF);
    const BYTE blue = static_cast<BYTE>(argb & 0xFF);

    if ((pixelFormat.dwFlags & DDPF_RGB) != 0
        && pixelFormat.dwRGBBitCount != 0
        && (pixelFormat.dwRBitMask != 0
            || pixelFormat.dwGBitMask != 0
            || pixelFormat.dwBBitMask != 0)) {
        return directDrawMaskComponent(red, pixelFormat.dwRBitMask)
            | directDrawMaskComponent(green, pixelFormat.dwGBitMask)
            | directDrawMaskComponent(blue, pixelFormat.dwBBitMask);
    }

    return argb & 0x00FFFFFFU;
}

bool directDrawSurfaceLooksLikeContextTransition(DWORD caps, DWORD flags) {
    if ((caps & DDSCAPS_PRIMARYSURFACE) != 0) {
        return true;
    }

    if ((caps & (DDSCAPS_BACKBUFFER | DDSCAPS_FLIP)) != 0) {
        return true;
    }

    return (caps & DDSCAPS_OFFSCREENPLAIN) != 0
        && (flags & (DDSD_WIDTH | DDSD_HEIGHT)) == (DDSD_WIDTH | DDSD_HEIGHT);
}

void noteDirectDrawSurfaceContextTransition(DWORD caps, DWORD flags, DWORD width, DWORD height, const char* sourceName) {
    if (!directDrawSurfaceLooksLikeContextTransition(caps, flags)) {
        return;
    }

    const DWORD now = GetTickCount();
    const DWORD previousTick = static_cast<DWORD>(g_directDrawSurfaceTransitionTick);
    if (previousTick != 0 && now - previousTick < kDirectDrawSurfaceTransitionDebounceMilliseconds) {
        return;
    }

    InterlockedExchange(&g_directDrawSurfaceTransitionTick, static_cast<LONG>(now));
    resetTransientGameplayTrackingState("DirectDraw surface transition", true);

    const LONG logHits = InterlockedIncrement(&g_directDrawSurfaceTransitionLogCount);
    if (logHits <= 16 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDraw surface transition detected from "
                << (sourceName != nullptr ? sourceName : "CreateSurface")
                << ", caps "
                << formatHex32(caps)
                << ", flags "
                << formatHex32(flags);
        if ((flags & (DDSD_WIDTH | DDSD_HEIGHT)) == (DDSD_WIDTH | DDSD_HEIGHT)) {
            message << ", size " << width << "x" << height;
        }
        g_runtimeProbeLogger->info(message.str());
    }
}

bool directDrawSurfaceTransitionCooldownActive() {
    const DWORD transitionTick = static_cast<DWORD>(g_directDrawSurfaceTransitionTick);
    if (transitionTick == 0) {
        return false;
    }

    return GetTickCount() - transitionTick < kDirectDrawSurfaceTransitionDrawCooldownMilliseconds;
}

HRESULT getDirectDrawSurfaceDescription(
    void* surface,
    const DirectDrawSurfaceVtableHook& hook,
    DWORD& width,
    DWORD& height,
    DWORD& caps,
    DDPIXELFORMAT& pixelFormat) {
    width = 0;
    height = 0;
    caps = 0;
    pixelFormat = {};

    if (surface == nullptr) {
        return E_POINTER;
    }

    if (hook.usesSurfaceDesc2) {
        auto* directDrawSurface = reinterpret_cast<IDirectDrawSurface7*>(surface);
        DDSURFACEDESC2 surfaceDescription = {};
        surfaceDescription.dwSize = sizeof(surfaceDescription);
        const HRESULT result = directDrawSurface->GetSurfaceDesc(&surfaceDescription);
        if (FAILED(result)) {
            return result;
        }

        width = surfaceDescription.dwWidth;
        height = surfaceDescription.dwHeight;
        caps = surfaceDescription.ddsCaps.dwCaps;
        pixelFormat = surfaceDescription.ddpfPixelFormat;
        return result;
    }

    auto* directDrawSurface = reinterpret_cast<IDirectDrawSurface*>(surface);
    DDSURFACEDESC surfaceDescription = {};
    surfaceDescription.dwSize = sizeof(surfaceDescription);
    const HRESULT result = directDrawSurface->GetSurfaceDesc(&surfaceDescription);
    if (FAILED(result)) {
        return result;
    }

    width = surfaceDescription.dwWidth;
    height = surfaceDescription.dwHeight;
    caps = surfaceDescription.ddsCaps.dwCaps;
    pixelFormat = surfaceDescription.ddpfPixelFormat;
    return result;
}

void drawDirectDrawOverlayTestRects(
    void* surface,
    const DirectDrawSurfaceVtableHook& hook,
    const char* triggerName) {
    if (!wallOverlayMetadataActive()) {
        return;
    }

    if (surface == nullptr || hook.originalBlt == nullptr) {
        return;
    }

    if (directDrawSurfaceTransitionCooldownActive()) {
        return;
    }

    if (metadataOverlayHiddenByChatForFallbackRenderer("DirectDraw")) {
        return;
    }

    if (InterlockedCompareExchange(&g_directDrawOverlayDrawing, 1, 0) != 0) {
        return;
    }

    DWORD surfaceWidth = 0;
    DWORD surfaceHeight = 0;
    DWORD surfaceCaps = 0;
    DDPIXELFORMAT pixelFormat = {};
    HRESULT result = getDirectDrawSurfaceDescription(
        surface,
        hook,
        surfaceWidth,
        surfaceHeight,
        surfaceCaps,
        pixelFormat);
    if (FAILED(result) || surfaceWidth == 0 || surfaceHeight == 0) {
        const LONG failures = InterlockedIncrement(&g_directDrawOverlayFailureHits);
        if (failures == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: DirectDraw metadata overlay GetSurfaceDesc failed after "
                    << (triggerName != nullptr ? triggerName : "surface update")
                    << " with HRESULT "
                    << formatHex32(static_cast<std::uint32_t>(result));
            g_runtimeProbeLogger->warn(message.str());
        }
        InterlockedExchange(&g_directDrawOverlayDrawing, 0);
        return;
    }

    const LONG width = static_cast<LONG>(surfaceWidth);
    const LONG height = static_cast<LONG>(surfaceHeight);

    std::vector<ScreenOverlayRect> screenRects;
    const bool prepared = prepareMetadataOverlayScreenRects(
        "DirectDraw",
        static_cast<UINT>(width),
        static_cast<UINT>(height),
        screenRects);

    std::size_t drawn = 0;
    std::size_t attempted = 0;
    HRESULT firstFailure = S_OK;
    if (prepared) {
        for (const ScreenOverlayRect& rect : screenRects) {
            RECT target{
                std::clamp<LONG>(rect.left, 0, width),
                std::clamp<LONG>(rect.top, 0, height),
                std::clamp<LONG>(rect.right, 0, width),
                std::clamp<LONG>(rect.bottom, 0, height),
            };
            if (target.right <= target.left || target.bottom <= target.top) {
                continue;
            }

            ++attempted;
            DDBLTFX effects = {};
            effects.dwSize = sizeof(effects);
            effects.dwFillColor = directDrawFillColorFromArgb(rect.color, pixelFormat);
            result = hook.originalBlt(
                surface,
                &target,
                nullptr,
                nullptr,
                DDBLT_COLORFILL | DDBLT_WAIT,
                &effects);
            if (SUCCEEDED(result)) {
                ++drawn;
            } else if (SUCCEEDED(firstFailure)) {
                firstFailure = result;
            }
        }
    }

    InterlockedExchange(&g_directDrawOverlayDrawing, 0);

    if (drawn > 0) {
        const LONG hits = InterlockedIncrement(&g_directDrawOverlayDrawHits);
        if (hits == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: DirectDraw metadata overlay drew "
                    << drawn
                    << " rect(s) after "
                    << (triggerName != nullptr ? triggerName : "surface update")
                    << " on surface "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(surface))
                    << ", caps "
                    << formatHex32(surfaceCaps)
                    << ", desc "
                    << (hook.usesSurfaceDesc2 ? "DDSURFACEDESC2" : "DDSURFACEDESC")
                    << ", size "
                    << width
                    << "x"
                    << height;
            g_runtimeProbeLogger->info(message.str());
        }
    } else if (prepared) {
        const LONG noDrawHits = InterlockedIncrement(&g_directDrawOverlayNoDrawHits);
        if (noDrawHits <= 4 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: DirectDraw metadata overlay prepared "
                    << screenRects.size()
                    << " rect(s) after "
                    << (triggerName != nullptr ? triggerName : "surface update")
                    << " but drew none; attempted "
                    << attempted
                    << " on surface "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(surface))
                    << " size "
                    << width
                    << "x"
                    << height;
            g_runtimeProbeLogger->info(message.str());
        }
    } else if (FAILED(firstFailure)) {
        const LONG failures = InterlockedIncrement(&g_directDrawOverlayFailureHits);
        if (failures == 1 && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: DirectDraw metadata overlay color fill failed after "
                    << (triggerName != nullptr ? triggerName : "surface update")
                    << " with HRESULT "
                    << formatHex32(static_cast<std::uint32_t>(firstFailure));
            g_runtimeProbeLogger->warn(message.str());
        }
    }
}

bool installDirectDrawSurfaceProbe(void* surface, bool usesSurfaceDesc2) {
    if (surface == nullptr) {
        return false;
    }

    auto** objectVtableSlot = reinterpret_cast<std::uintptr_t**>(surface);
    std::uintptr_t* vtable = *objectVtableSlot;
    if (vtable == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_directDrawProbeMutex);
    if (directDrawSurfaceHookForVtable(vtable) != nullptr) {
        return true;
    }

    DirectDrawSurfaceVtableHook hook;
    hook.vtable = vtable;
    hook.usesSurfaceDesc2 = usesSurfaceDesc2;
    hook.originalBlt = reinterpret_cast<DirectDrawSurfaceBltFunction>(vtable[kDirectDrawSurfaceBltIndex]);
    hook.originalBltFast = reinterpret_cast<DirectDrawSurfaceBltFastFunction>(vtable[kDirectDrawSurfaceBltFastIndex]);
    hook.originalFlip = reinterpret_cast<DirectDrawSurfaceFlipFunction>(vtable[kDirectDrawSurfaceFlipIndex]);
    hook.originalUnlock = reinterpret_cast<DirectDrawSurfaceUnlockFunction>(vtable[kDirectDrawSurfaceUnlockIndex]);

    const bool bltPatched = writeDirect3D9DeviceVtableSlot(
        vtable,
        kDirectDrawSurfaceBltIndex,
        reinterpret_cast<std::uintptr_t>(&hookedDirectDrawSurfaceBlt));
    const bool bltFastPatched = bltPatched && writeDirect3D9DeviceVtableSlot(
        vtable,
        kDirectDrawSurfaceBltFastIndex,
        reinterpret_cast<std::uintptr_t>(&hookedDirectDrawSurfaceBltFast));
    const bool flipPatched = bltFastPatched && writeDirect3D9DeviceVtableSlot(
        vtable,
        kDirectDrawSurfaceFlipIndex,
        reinterpret_cast<std::uintptr_t>(&hookedDirectDrawSurfaceFlip));
    const bool unlockPatched = flipPatched && writeDirect3D9DeviceVtableSlot(
        vtable,
        kDirectDrawSurfaceUnlockIndex,
        reinterpret_cast<std::uintptr_t>(&hookedDirectDrawSurfaceUnlock));
    if (!unlockPatched) {
        if (flipPatched) {
            writeDirect3D9DeviceVtableSlot(
                vtable,
                kDirectDrawSurfaceFlipIndex,
                reinterpret_cast<std::uintptr_t>(hook.originalFlip));
        }
        if (bltFastPatched) {
            writeDirect3D9DeviceVtableSlot(
                vtable,
                kDirectDrawSurfaceBltFastIndex,
                reinterpret_cast<std::uintptr_t>(hook.originalBltFast));
        }
        if (bltPatched) {
            writeDirect3D9DeviceVtableSlot(
                vtable,
                kDirectDrawSurfaceBltIndex,
                reinterpret_cast<std::uintptr_t>(hook.originalBlt));
        }
        return false;
    }

    g_directDrawSurfaceVtableHooks.push_back(hook);
    if (g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDraw surface vtable probe installed for surface "
                << formatAddress(reinterpret_cast<std::uintptr_t>(surface))
                << ", vtable "
                << formatAddress(reinterpret_cast<std::uintptr_t>(vtable))
                << ", desc "
                << (usesSurfaceDesc2 ? "DDSURFACEDESC2" : "DDSURFACEDESC");
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

bool installDirectDrawObjectProbe(void* directDraw, bool usesSurfaceDesc2) {
    if (directDraw == nullptr) {
        return false;
    }

    auto** objectVtableSlot = reinterpret_cast<std::uintptr_t**>(directDraw);
    std::uintptr_t* vtable = *objectVtableSlot;
    if (vtable == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_directDrawProbeMutex);
    if (directDrawObjectHookForVtable(vtable) != nullptr) {
        return true;
    }

    DirectDrawObjectVtableHook hook;
    hook.vtable = vtable;
    hook.usesSurfaceDesc2 = usesSurfaceDesc2;
    hook.originalQueryInterface =
        reinterpret_cast<DirectDrawQueryInterfaceFunction>(vtable[kDirectDrawQueryInterfaceIndex]);
    if (usesSurfaceDesc2) {
        hook.originalCreateSurface =
            reinterpret_cast<DirectDrawCreateSurfaceFunction>(vtable[kDirectDrawCreateSurfaceIndex]);
        hook.originalCreateSurface7 =
            reinterpret_cast<DirectDraw7CreateSurfaceFunction>(vtable[kDirectDrawCreateSurfaceIndex]);
    } else {
        hook.originalCreateSurface =
            reinterpret_cast<DirectDrawCreateSurfaceFunction>(vtable[kDirectDrawCreateSurfaceIndex]);
    }

    const bool queryPatched = writeDirect3D9DeviceVtableSlot(
        vtable,
        kDirectDrawQueryInterfaceIndex,
        reinterpret_cast<std::uintptr_t>(&hookedDirectDrawQueryInterface));
    const bool createSurfacePatched = queryPatched && writeDirect3D9DeviceVtableSlot(
        vtable,
        kDirectDrawCreateSurfaceIndex,
        usesSurfaceDesc2
            ? reinterpret_cast<std::uintptr_t>(&hookedDirectDraw7CreateSurface)
            : reinterpret_cast<std::uintptr_t>(&hookedDirectDrawCreateSurface));
    if (!createSurfacePatched) {
        if (queryPatched) {
            writeDirect3D9DeviceVtableSlot(
                vtable,
                kDirectDrawQueryInterfaceIndex,
                reinterpret_cast<std::uintptr_t>(hook.originalQueryInterface));
        }
        return false;
    }

    g_directDrawObjectVtableHooks.push_back(hook);
    if (g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDraw object vtable probe installed for object "
                << formatAddress(reinterpret_cast<std::uintptr_t>(directDraw))
                << ", vtable "
                << formatAddress(reinterpret_cast<std::uintptr_t>(vtable))
                << ", desc "
                << (usesSurfaceDesc2 ? "DDSURFACEDESC2" : "DDSURFACEDESC");
        g_runtimeProbeLogger->info(message.str());
    }

    return true;
}

HRESULT STDMETHODCALLTYPE hookedDirectDrawQueryInterface(void* directDraw, REFIID iid, void** object) {
    DirectDrawObjectVtableHook hook = directDrawObjectHookSnapshot(directDraw);
    if (hook.originalQueryInterface == nullptr) {
        return E_NOINTERFACE;
    }

    HRESULT result = hook.originalQueryInterface(directDraw, iid, object);
    if (SUCCEEDED(result) && object != nullptr && *object != nullptr && isDirectDrawInterfaceGuid(iid)) {
        installDirectDrawObjectProbe(*object, directDrawInterfaceUsesSurfaceDesc2(iid));
    }

    const LONG hits = InterlockedIncrement(&g_directDrawQueryInterfaceProbeHits);
    if (hits <= 16 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDraw::QueryInterface("
                << directDrawInterfaceName(iid)
                << ") returned HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", object "
                << (object != nullptr ? formatAddress(reinterpret_cast<std::uintptr_t>(*object)) : "null");
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedDirectDrawCreateSurface(
    IDirectDraw* directDraw,
    LPDDSURFACEDESC surfaceDescription,
    LPDIRECTDRAWSURFACE* surface,
    IUnknown* outer) {
    DirectDrawObjectVtableHook hook = directDrawObjectHookSnapshot(directDraw);
    if (hook.originalCreateSurface == nullptr) {
        return DDERR_GENERIC;
    }

    const LONG hits = InterlockedIncrement(&g_directDrawCreateSurfaceProbeHits);
    HRESULT result = hook.originalCreateSurface(directDraw, surfaceDescription, surface, outer);
    if (SUCCEEDED(result) && surface != nullptr && *surface != nullptr) {
        installDirectDrawSurfaceProbe(*surface, false);
        if (surfaceDescription != nullptr) {
            const DWORD flags = surfaceDescription->dwFlags;
            const DWORD width = (flags & DDSD_WIDTH) != 0 ? surfaceDescription->dwWidth : 0;
            const DWORD height = (flags & DDSD_HEIGHT) != 0 ? surfaceDescription->dwHeight : 0;
            noteDirectDrawSurfaceContextTransition(
                surfaceDescription->ddsCaps.dwCaps,
                flags,
                width,
                height,
                "IDirectDraw::CreateSurface");
        }
    }

    if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirectDraw::CreateSurface hook fired with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", surface "
                << (surface != nullptr ? formatAddress(reinterpret_cast<std::uintptr_t>(*surface)) : "null");
        if (surfaceDescription != nullptr) {
            message << ", flags " << formatHex32(surfaceDescription->dwFlags)
                    << ", caps " << formatHex32(surfaceDescription->ddsCaps.dwCaps);
            if ((surfaceDescription->dwFlags & DDSD_WIDTH) != 0
                && (surfaceDescription->dwFlags & DDSD_HEIGHT) != 0) {
                message << ", size "
                        << surfaceDescription->dwWidth
                        << "x"
                        << surfaceDescription->dwHeight;
            }
        }
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedDirectDraw7CreateSurface(
    IDirectDraw7* directDraw,
    LPDDSURFACEDESC2 surfaceDescription,
    LPDIRECTDRAWSURFACE7* surface,
    IUnknown* outer) {
    DirectDrawObjectVtableHook hook = directDrawObjectHookSnapshot(directDraw);
    if (hook.originalCreateSurface7 == nullptr) {
        return DDERR_GENERIC;
    }

    const LONG hits = InterlockedIncrement(&g_directDrawCreateSurfaceProbeHits);
    HRESULT result = hook.originalCreateSurface7(directDraw, surfaceDescription, surface, outer);
    if (SUCCEEDED(result) && surface != nullptr && *surface != nullptr) {
        installDirectDrawSurfaceProbe(*surface, true);
        if (surfaceDescription != nullptr) {
            const DWORD flags = surfaceDescription->dwFlags;
            const DWORD width = (flags & DDSD_WIDTH) != 0 ? surfaceDescription->dwWidth : 0;
            const DWORD height = (flags & DDSD_HEIGHT) != 0 ? surfaceDescription->dwHeight : 0;
            noteDirectDrawSurfaceContextTransition(
                surfaceDescription->ddsCaps.dwCaps,
                flags,
                width,
                height,
                "IDirectDraw7::CreateSurface");
        }
    }

    if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: IDirectDraw7::CreateSurface hook fired with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", surface "
                << (surface != nullptr ? formatAddress(reinterpret_cast<std::uintptr_t>(*surface)) : "null");
        if (surfaceDescription != nullptr) {
            message << ", flags " << formatHex32(surfaceDescription->dwFlags)
                    << ", caps " << formatHex32(surfaceDescription->ddsCaps.dwCaps);
            if ((surfaceDescription->dwFlags & DDSD_WIDTH) != 0
                && (surfaceDescription->dwFlags & DDSD_HEIGHT) != 0) {
                message << ", size "
                        << surfaceDescription->dwWidth
                        << "x"
                        << surfaceDescription->dwHeight;
            }
        }
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceBlt(
    void* surface,
    LPRECT destinationRect,
    void* sourceSurface,
    LPRECT sourceRect,
    DWORD flags,
    LPDDBLTFX effects) {
    DirectDrawSurfaceVtableHook hook = directDrawSurfaceHookSnapshot(surface);
    if (hook.originalBlt == nullptr) {
        return DDERR_GENERIC;
    }

    HRESULT result = hook.originalBlt(surface, destinationRect, sourceSurface, sourceRect, flags, effects);
    const LONG hits = InterlockedIncrement(&g_directDrawSurfaceBltProbeHits);
    if (SUCCEEDED(result)) {
        drawDirectDrawOverlayTestRects(surface, hook, "Blt");
    }

    if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDrawSurface::Blt hook fired with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", flags "
                << formatHex32(flags);
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceBltFast(
    void* surface,
    DWORD x,
    DWORD y,
    void* sourceSurface,
    LPRECT sourceRect,
    DWORD flags) {
    DirectDrawSurfaceVtableHook hook = directDrawSurfaceHookSnapshot(surface);
    if (hook.originalBltFast == nullptr) {
        return DDERR_GENERIC;
    }

    HRESULT result = hook.originalBltFast(surface, x, y, sourceSurface, sourceRect, flags);
    const LONG hits = InterlockedIncrement(&g_directDrawSurfaceBltFastProbeHits);
    if (SUCCEEDED(result)) {
        drawDirectDrawOverlayTestRects(surface, hook, "BltFast");
    }

    if (hits <= 8 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDrawSurface::BltFast hook fired with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", destination "
                << x
                << ","
                << y
                << ", source "
                << formatAddress(reinterpret_cast<std::uintptr_t>(sourceSurface))
                << ", flags "
                << formatHex32(flags);
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceFlip(void* surface, void* targetOverride, DWORD flags) {
    DirectDrawSurfaceVtableHook hook = directDrawSurfaceHookSnapshot(surface);
    if (hook.originalFlip == nullptr) {
        return DDERR_GENERIC;
    }

    HRESULT result = hook.originalFlip(surface, targetOverride, flags);
    const LONG hits = InterlockedIncrement(&g_directDrawSurfaceFlipProbeHits);
    if (SUCCEEDED(result)) {
        drawDirectDrawOverlayTestRects(surface, hook, "Flip");
    }

    if (hits <= 4 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDrawSurface::Flip hook fired with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", flags "
                << formatHex32(flags);
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT STDMETHODCALLTYPE hookedDirectDrawSurfaceUnlock(void* surface, void* surfaceData) {
    DirectDrawSurfaceVtableHook hook = directDrawSurfaceHookSnapshot(surface);
    if (hook.originalUnlock == nullptr) {
        return DDERR_GENERIC;
    }

    HRESULT result = hook.originalUnlock(surface, surfaceData);
    const LONG hits = InterlockedIncrement(&g_directDrawSurfaceUnlockProbeHits);
    if (SUCCEEDED(result)) {
        drawDirectDrawOverlayTestRects(surface, hook, "Unlock");
    }

    if (hits <= 16 && g_runtimeProbeLogger != nullptr) {
        DWORD surfaceWidth = 0;
        DWORD surfaceHeight = 0;
        DWORD surfaceCaps = 0;
        DDPIXELFORMAT pixelFormat = {};
        const HRESULT descriptionResult = getDirectDrawSurfaceDescription(
            surface,
            hook,
            surfaceWidth,
            surfaceHeight,
            surfaceCaps,
            pixelFormat);

        std::ostringstream message;
        message << "runtime probe: DirectDrawSurface::Unlock hook fired with HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", surface "
                << formatAddress(reinterpret_cast<std::uintptr_t>(surface))
                << ", data "
                << formatAddress(reinterpret_cast<std::uintptr_t>(surfaceData));
        if (SUCCEEDED(descriptionResult)) {
            message << ", caps "
                    << formatHex32(surfaceCaps)
                    << ", desc "
                    << (hook.usesSurfaceDesc2 ? "DDSURFACEDESC2" : "DDSURFACEDESC")
                    << ", size "
                    << surfaceWidth
                    << "x"
                    << surfaceHeight;
        }
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
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

    resetTransientGameplayTrackingState("D3D context transition", true);

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

bool controlKeyDown() {
    return g_chatOverlayControlKeyActive != 0
        || (GetKeyState(VK_CONTROL) & 0x8000) != 0
        || (GetKeyState(VK_LCONTROL) & 0x8000) != 0
        || (GetKeyState(VK_RCONTROL) & 0x8000) != 0;
}

const char* weaponInputKeyName(int key) {
    switch (key) {
    case VK_LBUTTON:
        return "LButton";
    case VK_RBUTTON:
        return "RButton";
    case VK_SPACE:
        return "Space";
    case VK_RETURN:
        return "Enter";
    case VK_BACK:
        return "Backspace";
    case VK_TAB:
        return "Tab";
    case VK_ESCAPE:
        return "Escape";
    case VK_F1:
        return "F1";
    case VK_F2:
        return "F2";
    case VK_F3:
        return "F3";
    case VK_F4:
        return "F4";
    case VK_F5:
        return "F5";
    case VK_F6:
        return "F6";
    case VK_F7:
        return "F7";
    case VK_F8:
        return "F8";
    case VK_F9:
        return "F9";
    case VK_F10:
        return "F10";
    case VK_F11:
        return "F11";
    case VK_F12:
        return "F12";
    default:
        if (key >= '0' && key <= '9') {
            static thread_local char digitName[2] = {};
            digitName[0] = static_cast<char>(key);
            digitName[1] = '\0';
            return digitName;
        }
        return nullptr;
    }
}

bool weaponInputKeyCanFire(int key) {
    return key == VK_SPACE || key == VK_RETURN;
}

LONG weaponInputKeyMask(int key) {
    switch (key) {
    case VK_SPACE:
        return 1;
    case VK_RETURN:
        return 2;
    default:
        return 0;
    }
}

bool messageIsKeyDown(UINT message) {
    return message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
}

void rememberUtilityActionSelectionInput(const MSG& message) {
    if (!messageIsKeyDown(message.message) || static_cast<int>(message.wParam) != VK_F12) {
        return;
    }

    const DWORD untilTick = GetTickCount() + kUtilityActionSelectionGraceMilliseconds;
    InterlockedExchange(&g_utilityActionSelectionGraceUntilTick, static_cast<LONG>(untilTick));
}

bool keyLooksLikeWeaponSelection(int key) {
    return (key >= VK_F1 && key <= VK_F11)
        || (key >= '0' && key <= '9');
}

void cancelUtilityActionSelectionOnWeaponSwitch(const MSG& message) {
    if (!messageIsKeyDown(message.message)) {
        return;
    }

    const int key = static_cast<int>(message.wParam);
    if (!keyLooksLikeWeaponSelection(key)) {
        return;
    }

    InterlockedExchange(&g_utilityActionSelectionGraceUntilTick, 0);
}

bool consumeUtilityActionSelectionGrace() {
    const LONG untilTick = g_utilityActionSelectionGraceUntilTick;
    if (untilTick == 0) {
        return false;
    }

    const DWORD now = GetTickCount();
    if (static_cast<DWORD>(untilTick) - now > kUtilityActionSelectionGraceMilliseconds) {
        InterlockedExchange(&g_utilityActionSelectionGraceUntilTick, 0);
        return false;
    }

    if (static_cast<DWORD>(untilTick) < now) {
        InterlockedExchange(&g_utilityActionSelectionGraceUntilTick, 0);
        return false;
    }

    InterlockedExchange(&g_utilityActionSelectionGraceUntilTick, 0);
    return true;
}

bool tryReadActiveSelectedWeaponId(LONG& weaponId) {
    weaponId = -1;

    const std::uintptr_t activeOwnerAddress =
        static_cast<std::uintptr_t>(static_cast<DWORD>(g_activeWormCandidateOwnerAddress));
    if (activeOwnerAddress == 0) {
        return false;
    }

    return tryReadLong(activeOwnerAddress + 0x170, weaponId);
}

bool tryReadActiveOwnerKind(LONG& ownerKind) {
    ownerKind = 0;

    const std::uintptr_t activeOwnerAddress =
        static_cast<std::uintptr_t>(static_cast<DWORD>(g_activeWormCandidateOwnerAddress));
    if (activeOwnerAddress == 0) {
        return false;
    }

    return tryReadLong(activeOwnerAddress + kWaObjectKindOffset, ownerKind);
}

bool selectedWeaponBypassesAttackRequirements(LONG weaponId) {
    switch (weaponId) {
    case 37:
    case 38:
    case 39:
    case 40:
    case 41:
    case 57: // Skip Go
    case 58: // Surrender
        return true;
    default:
        return false;
    }
}

bool selectedWeaponRequiresRopeToAttack(LONG weaponId) {
    // These are the active selected-weapon values read from the live W:A object
    // and validated in-game against the attack-from-rope weapon list.
    switch (weaponId) {
    case 0:  // Sheep
    case 1:  // Banana Bomb / Sally Army / Super Banana Bomb
    case 2:  // Holy Hand Grenade
    case 3:  // Mole Bomb
    case 4:  // Homing Missile
    case 6:  // Dynamite
    case 7:  // Bazooka
    case 21: // Cluster Bomb
    case 22: // Homing Pigeon
    case 24: // Super Sheep
    case 25: // Aqua Sheep
    case 26: // Magic Bullet
    case 33: // Petrol Bomb
    case 42: // Sheep Launcher
    case 43: // Grenade
    case 45: // Pneumatic Drill
    case 47: // Old Woman
    case 49: // Ming Vase
    case 52: // Land Mine
    case 53: // Mortar
    case 61: // Mad Cow
        return true;
    default:
        return false;
    }
}

bool ownerKindLooksLikeRopeContext(LONG ownerKind) {
    return ownerKind == 115
        || ownerKind == 123
        || ownerKind == 127
        || ownerKind == 128;
}

void noteRecentRopeContext(LONG ownerKind) {
    if (ownerKindLooksLikeRopeContext(ownerKind)) {
        InterlockedExchange(&g_recentRopeContextTick, static_cast<LONG>(GetTickCount()));
    }
}

bool recentRopeContextActive() {
    const DWORD tick = static_cast<DWORD>(g_recentRopeContextTick);
    return tick != 0 && GetTickCount() - tick <= 250;
}

bool chatInputCapturesKeyboard() {
    return g_chatOverlayActive != 0 && g_chatOverlayPinnedMode == 0;
}

void clearBlockedWeaponInputState() {
    InterlockedExchange(&g_blockedWeaponInputKeyMask, 0);
    InterlockedExchange(&g_blockedWeaponInputSuppressUntilTick, 0);
}

bool blockedWeaponInputKeyStateSuppressed(int key) {
    if (chatInputCapturesKeyboard()) {
        clearBlockedWeaponInputState();
        return false;
    }

    const LONG keyMask = weaponInputKeyMask(key);
    if (keyMask == 0) {
        return false;
    }

    if ((g_blockedWeaponInputKeyMask & keyMask) != 0) {
        return true;
    }

    const LONG untilTick = g_blockedWeaponInputSuppressUntilTick;
    if (untilTick == 0) {
        return false;
    }

    const DWORD now = GetTickCount();
    if (static_cast<LONG>(now - static_cast<DWORD>(untilTick)) < 0) {
        return true;
    }

    InterlockedCompareExchange(&g_blockedWeaponInputSuppressUntilTick, 0, untilTick);
    return false;
}

bool activeOwnerLooksLikeRopeContext() {
    LONG ownerKind = 0;
    if (!tryReadActiveOwnerKind(ownerKind)) {
        return false;
    }

    noteRecentRopeContext(ownerKind);
    return ownerKindLooksLikeRopeContext(ownerKind);
}

bool attackRuleShouldBlockWeaponInput(int key, LONG& weaponId, AttackBlockReason& reason) {
    weaponId = -1;
    reason = AttackBlockReason::None;
    if (!weaponInputKeyCanFire(key)) {
        return false;
    }

    if (chatInputCapturesKeyboard()) {
        clearBlockedWeaponInputState();
        return false;
    }

    if (!attackRulesApplyToCurrentMap()) {
        return false;
    }

    const bool ropeContext = activeOwnerLooksLikeRopeContext() || recentRopeContextActive();
    if (key == VK_RETURN && !ropeContext) {
        return false;
    }

    if (key == VK_SPACE && ropeContext) {
        return false;
    }

    const AttackBlockReason prerequisiteReason = currentAttackBlockReason();
    if (!tryReadActiveSelectedWeaponId(weaponId)) {
        return false;
    }

    if (selectedWeaponBypassesAttackRequirements(weaponId)) {
        return false;
    }

    const bool ropeRequiredCandidate =
        key == VK_SPACE
        && !ropeContext
        && selectedWeaponRequiresRopeToAttack(weaponId);

    if (prerequisiteReason != AttackBlockReason::None) {
        reason = prerequisiteReason;
        return true;
    }

    if (ropeRequiredCandidate) {
        reason = AttackBlockReason::RopeRequired;
        return true;
    }

    return false;
}

const char* weaponWindowMessageName(UINT message) {
    switch (message) {
    case WM_KEYDOWN:
        return "WM_KEYDOWN";
    case WM_KEYUP:
        return "WM_KEYUP";
    case WM_SYSKEYDOWN:
        return "WM_SYSKEYDOWN";
    case WM_SYSKEYUP:
        return "WM_SYSKEYUP";
    default:
        return "WM_OTHER";
    }
}

void logBlockedWeaponInput(const MSG& message, const char* source, LONG weaponId, const char* reason) {
    if (g_runtimeProbeLogger == nullptr) {
        return;
    }

    const LONG logCount = InterlockedIncrement(&g_weaponInputBlockLogCount);
    if (logCount > 48) {
        return;
    }

    const int key = static_cast<int>(message.wParam);
    std::ostringstream log;
    log << "runtime: attack rule blocked weapon input "
        << source
        << " " << weaponWindowMessageName(message.message)
        << " " << (weaponInputKeyName(key) != nullptr ? weaponInputKeyName(key) : "?")
        << " weaponId " << weaponId
        << " reason " << (reason != nullptr ? reason : "")
        << " touchedWalls " << touchedOverlayWallCount()
        << "/" << g_direct3D9OverlayTestRects.size()
        << " crateCollected " << (g_crateCollectedThisTurn != 0 ? "yes" : "no")
        << " activeMap " << g_direct3D9ActiveOverlayMapIndex;
    g_runtimeProbeLogger->info(log.str());
}

bool consumeBlockedWeaponWindowInput(MSG& message, const char* source, UINT peekRemoveMessage) {
    const UINT msg = message.message;
    if (msg != WM_KEYDOWN && msg != WM_SYSKEYDOWN && msg != WM_KEYUP && msg != WM_SYSKEYUP) {
        return false;
    }

    rememberUtilityActionSelectionInput(message);
    cancelUtilityActionSelectionOnWeaponSwitch(message);

    const int key = static_cast<int>(message.wParam);
    if (!weaponInputKeyCanFire(key)) {
        return false;
    }

    if (chatInputCapturesKeyboard()) {
        clearBlockedWeaponInputState();
        return false;
    }

    if (!attackRulesApplyToCurrentMap()) {
        clearBlockedWeaponInputState();
        return false;
    }

    if (source != nullptr
        && std::strcmp(source, "PeekMessageA") == 0
        && (peekRemoveMessage & PM_REMOVE) == 0) {
        return false;
    }

    const bool down = messageIsKeyDown(msg);
    const LONG keyMask = weaponInputKeyMask(key);
    if (down && consumeUtilityActionSelectionGrace()) {
        return false;
    }

    if (!down && keyMask != 0 && (g_blockedWeaponInputKeyMask & keyMask) != 0) {
        InterlockedAnd(&g_blockedWeaponInputKeyMask, ~keyMask);
        logBlockedWeaponInput(message, source, -1, "matching key up");
        message.message = WM_NULL;
        message.wParam = 0;
        message.lParam = 0;
        return true;
    }

    if (!down) {
        return false;
    }

    if (keyMask != 0 && (g_blockedWeaponInputKeyMask & keyMask) != 0) {
        logBlockedWeaponInput(message, source, -1, "held key down");
        message.message = WM_NULL;
        message.wParam = 0;
        message.lParam = 0;
        return true;
    }

    LONG weaponId = -1;
    AttackBlockReason blockReason = AttackBlockReason::None;
    if (!attackRuleShouldBlockWeaponInput(key, weaponId, blockReason)) {
        return false;
    }

    if (keyMask != 0) {
        InterlockedOr(&g_blockedWeaponInputKeyMask, keyMask);
        InterlockedExchange(
            &g_blockedWeaponInputSuppressUntilTick,
            static_cast<LONG>(GetTickCount() + 350));
    }

    logBlockedWeaponInput(message, source, weaponId, attackBlockReasonName(blockReason));
    playBlockedAttackWarningSound(blockReason);
    message.message = WM_NULL;
    message.wParam = 0;
    message.lParam = 0;
    return true;
}

void scheduleChatOverlayScan(DWORD delayMilliseconds) {
    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetY, 0);
    resetChatOverlayScanSamples();
    InterlockedExchange(&g_chatOverlayScanPendingTick, static_cast<LONG>(GetTickCount() + delayMilliseconds));
}

void activateChatOverlayPinnedMode() {
    InterlockedExchange(&g_chatOverlayActive, 1);
    InterlockedExchange(&g_chatOverlayPinnedMode, 1);
    InterlockedExchange(&g_chatOverlayPinnedPending, 0);
    InterlockedExchange(&g_chatOverlayPinnedActivationTick, 0);
    InterlockedExchange(&g_chatOverlayPinnedAutoProbeTick, 0);
    InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayPinnedBaselineBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayLastUnpinnedBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayScanPendingTick, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetY, 0);
    resetChatOverlayScanSamples();
}

void scheduleChatOverlayPinnedActivation(DWORD delayMilliseconds) {
    InterlockedExchange(&g_chatOverlayActive, 0);
    InterlockedExchange(&g_chatOverlayPinnedMode, 0);
    InterlockedExchange(&g_chatOverlayPinnedPending, 1);
    InterlockedExchange(&g_chatOverlayPinnedAutoProbeTick, 0);
    InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayPinnedBaselineBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayLastUnpinnedBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayScanPendingTick, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetY, 0);
    resetChatOverlayScanSamples();
    InterlockedExchange(&g_chatOverlayPinnedActivationTick, static_cast<LONG>(GetTickCount() + delayMilliseconds));
}

void activatePendingChatOverlayPinnedModeIfReady() {
    const LONG pendingTick = g_chatOverlayPinnedActivationTick;
    if (g_chatOverlayPinnedPending == 0 || pendingTick == 0) {
        return;
    }

    const DWORD now = GetTickCount();
    if (static_cast<LONG>(now - static_cast<DWORD>(pendingTick)) < 0) {
        return;
    }

    if (InterlockedCompareExchange(&g_chatOverlayPinnedActivationTick, 0, pendingTick) == pendingTick) {
        activateChatOverlayPinnedMode();
        if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            g_runtimeProbeLogger->info("runtime: W:A chat overlay pinned mode enabled after deferred close");
        }
    }
}

void resetChatOverlayState() {
    InterlockedExchange(&g_chatOverlayActive, 0);
    InterlockedExchange(&g_chatOverlayPinnedMode, 0);
    InterlockedExchange(&g_chatOverlayPinnedPending, 0);
    InterlockedExchange(&g_chatOverlayPinnedActivationTick, 0);
    InterlockedExchange(&g_chatOverlayPinnedAutoProbeTick, 0);
    InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayPinnedBaselineBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayScanPendingTick, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetY, 0);
    resetChatOverlayScanSamples();
}

void updateChatOverlayStateFromWindowMessage(const MSG& message) {
    const UINT msg = message.message;
    if (msg != WM_KEYDOWN && msg != WM_SYSKEYDOWN && msg != WM_KEYUP && msg != WM_SYSKEYUP) {
        return;
    }

    const WPARAM key = message.wParam;
    if (key == VK_CONTROL || key == VK_LCONTROL || key == VK_RCONTROL) {
        const bool down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
        InterlockedExchange(&g_chatOverlayControlKeyActive, down ? 1 : 0);
        return;
    }

    if (msg != WM_KEYDOWN && msg != WM_SYSKEYDOWN) {
        return;
    }

    const bool ctrl = controlKeyDown();
    if (ctrl && key == VK_NEXT) {
        if (g_chatOverlayActive != 0 && g_chatOverlayPinnedMode == 0) {
            InterlockedExchange(&g_chatOverlayPinnedPending, 1);
            if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
                InterlockedIncrement(&g_chatInputLogCount);
                g_runtimeProbeLogger->info("runtime: W:A chat overlay pinned mode pending until normal chat closes");
            }
            return;
        }

        activateChatOverlayPinnedMode();
        if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            g_runtimeProbeLogger->info("runtime: W:A chat overlay pinned mode enabled from Ctrl+PageDown");
        }
        return;
    }

    if (ctrl && key == VK_PRIOR) {
        if (g_chatOverlayPinnedMode == 0) {
            if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
                InterlockedIncrement(&g_chatInputLogCount);
                g_runtimeProbeLogger->info("runtime: W:A chat overlay ignored Ctrl+PageUp outside pinned mode");
            }
            return;
        }

        const LONG previous = g_chatOverlayActive;
        resetChatOverlayState();
        if (previous != 0 && g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            g_runtimeProbeLogger->info("runtime: W:A chat overlay suppression disabled from Ctrl+PageUp unpin");
        }
        return;
    }

    const bool plainArrow =
        !ctrl
        && (key == VK_UP || key == VK_DOWN || key == VK_LEFT || key == VK_RIGHT);
    if (g_chatOverlayActive != 0 && plainArrow) {
        if (g_chatOverlayPinnedMode != 0) {
            if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
                InterlockedIncrement(&g_chatInputLogCount);
                g_runtimeProbeLogger->info("runtime: W:A chat overlay ignored arrow key while pinned");
            }
            return;
        }

        if (g_chatOverlayPinnedPending != 0) {
            scheduleChatOverlayPinnedActivation(260);
            if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
                InterlockedIncrement(&g_chatInputLogCount);
                g_runtimeProbeLogger->info("runtime: W:A chat overlay pinned mode deferred after arrow key closed normal chat");
            }
            return;
        }

        const LONG previous = g_chatOverlayActive;
        resetChatOverlayState();
        if (previous != 0 && g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            g_runtimeProbeLogger->info("runtime: W:A chat overlay suppression disabled from arrow key");
        }
        return;
    }

    if (g_chatOverlayActive != 0
        && ctrl
        && (key == VK_UP || key == VK_DOWN)) {
        if (g_chatOverlayPinnedMode != 0) {
            InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
            if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
                InterlockedIncrement(&g_chatInputLogCount);
                std::ostringstream logMessage;
                logMessage << "runtime: W:A chat overlay pinned resize base recalculation from Ctrl+"
                           << (key == VK_UP ? "Up" : "Down");
                g_runtimeProbeLogger->info(logMessage.str());
            }
            return;
        }

        scheduleChatOverlayScan(220);
        if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            std::ostringstream logMessage;
            logMessage << "runtime: W:A chat overlay rescan scheduled from Ctrl+"
                       << (key == VK_UP ? "Up" : "Down");
            g_runtimeProbeLogger->info(logMessage.str());
        }
        return;
    }

    if (key != VK_NEXT && key != VK_PRIOR) {
        return;
    }

    if (key == VK_PRIOR && g_chatOverlayPinnedMode != 0) {
        if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            g_runtimeProbeLogger->info("runtime: W:A chat overlay ignored PageUp while pinned");
        }
        return;
    }

    if (key == VK_PRIOR && g_chatOverlayPinnedPending != 0) {
        scheduleChatOverlayPinnedActivation(260);
        if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
            InterlockedIncrement(&g_chatInputLogCount);
            g_runtimeProbeLogger->info("runtime: W:A chat overlay pinned mode deferred after PageUp closed normal chat");
        }
        return;
    }

    LONG previous = 0;
    LONG newValue = 0;
    if (key == VK_NEXT) {
        if (g_chatOverlayPinnedMode != 0) {
            InterlockedExchange(&g_chatOverlayPinnedMode, 0);
            InterlockedExchange(&g_chatOverlayPinnedPending, 1);
            InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
            InterlockedExchange(&g_chatOverlayActive, 1);
            scheduleChatOverlayScan(220);
            if (g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
                InterlockedIncrement(&g_chatInputLogCount);
                g_runtimeProbeLogger->info("runtime: W:A chat overlay pinned chat expanded from PageDown");
            }
            return;
        }

        previous = InterlockedCompareExchange(&g_chatOverlayActive, 1, 0);
        if (previous != 0) {
            if (g_chatOverlayPinnedMode == 0) {
                scheduleChatOverlayScan(220);
            }
            return;
        }

        InterlockedExchange(&g_chatOverlayPinnedMode, 0);
        InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
        newValue = 1;
        scheduleChatOverlayScan(220);
    } else {
        newValue = 0;
        previous = g_chatOverlayActive;
        resetChatOverlayState();
    }

    if (previous != newValue && g_runtimeProbeLogger != nullptr && g_chatInputLogCount < 12) {
        InterlockedIncrement(&g_chatInputLogCount);
        std::ostringstream logMessage;
        logMessage << "runtime: W:A chat overlay suppression "
                   << (newValue != 0 ? "enabled" : "disabled")
                   << " from "
                   << (key == VK_NEXT ? "PageDown" : "PageUp");
        g_runtimeProbeLogger->info(logMessage.str());
    }
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

    const BOOL result = g_originalGetMessageA(message, window, messageFilterMin, messageFilterMax);
    if (result > 0 && message != nullptr) {
        consumeBlockedWeaponWindowInput(*message, "GetMessageA", 0);
        updateChatOverlayStateFromWindowMessage(*message);
    }
    checkOnlineLobbyCompatibilityTimeout();

    return result;
}

BOOL WINAPI hookedPeekMessageA(LPMSG message, HWND window, UINT messageFilterMin, UINT messageFilterMax, UINT removeMessage) {
    const LONG hits = InterlockedIncrement(&g_peekMessageProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: USER32!PeekMessageA IAT hook fired");
    }

    if (g_originalPeekMessageA == nullptr) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    const BOOL result = g_originalPeekMessageA(message, window, messageFilterMin, messageFilterMax, removeMessage);
    if (result && message != nullptr) {
        consumeBlockedWeaponWindowInput(*message, "PeekMessageA", removeMessage);
        updateChatOverlayStateFromWindowMessage(*message);
    }
    checkOnlineLobbyCompatibilityTimeout();

    return result;
}

SHORT WINAPI hookedGetAsyncKeyState(int virtualKey) noexcept {
    if (g_originalGetAsyncKeyState == nullptr) {
        return 0;
    }

    const SHORT result = g_originalGetAsyncKeyState(virtualKey);
    if (blockedWeaponInputKeyStateSuppressed(virtualKey)) {
        return 0;
    }

    return result;
}

SHORT WINAPI hookedGetKeyState(int virtualKey) noexcept {
    if (g_originalGetKeyState == nullptr) {
        return 0;
    }

    const SHORT result = g_originalGetKeyState(virtualKey);
    if (blockedWeaponInputKeyStateSuppressed(virtualKey)) {
        return static_cast<SHORT>(result & 0x0001);
    }

    return result;
}

BOOL WINAPI hookedGetKeyboardState(PBYTE keyState) noexcept {
    if (g_originalGetKeyboardState == nullptr) {
        return FALSE;
    }

    const BOOL result = g_originalGetKeyboardState(keyState);
    if (result && keyState != nullptr) {
        if (blockedWeaponInputKeyStateSuppressed(VK_SPACE)) {
            keyState[VK_SPACE] = static_cast<BYTE>(keyState[VK_SPACE] & 0x01);
        }
        if (blockedWeaponInputKeyStateSuppressed(VK_RETURN)) {
            keyState[VK_RETURN] = static_cast<BYTE>(keyState[VK_RETURN] & 0x01);
        }
    }

    return result;
}

HANDLE WINAPI hookedCreateFileA(
    LPCSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile) noexcept {
    if (g_originalCreateFileA == nullptr) {
        return INVALID_HANDLE_VALUE;
    }

    const HANDLE result = g_originalCreateFileA(
        fileName,
        desiredAccess,
        shareMode,
        securityAttributes,
        creationDisposition,
        flagsAndAttributes,
        templateFile);
    if (result != INVALID_HANDLE_VALUE && fileName != nullptr) {
        recordDetectedWaMapFilePath(fileName);
    }

    return result;
}

HANDLE WINAPI hookedCreateFileW(
    LPCWSTR fileName,
    DWORD desiredAccess,
    DWORD shareMode,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition,
    DWORD flagsAndAttributes,
    HANDLE templateFile) noexcept {
    if (g_originalCreateFileW == nullptr) {
        return INVALID_HANDLE_VALUE;
    }

    const HANDLE result = g_originalCreateFileW(
        fileName,
        desiredAccess,
        shareMode,
        securityAttributes,
        creationDisposition,
        flagsAndAttributes,
        templateFile);
    if (result != INVALID_HANDLE_VALUE && fileName != nullptr) {
        recordDetectedWaMapFilePath(wideToActiveCodePage(fileName));
    }

    return result;
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

    if (g_openGLEndProbeHits == 0) {
        drawOpenGLOverlayTestRects(OpenGLOverlayPass::BeforeSwap);
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

HRESULT WINAPI hookedDirectDrawCreate(GUID* guid, LPDIRECTDRAW* directDraw, IUnknown* outer) {
    const LONG hits = InterlockedIncrement(&g_directDrawCreateProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: DirectDrawCreate hook fired");
    }

    if (g_originalDirectDrawCreate == nullptr) {
        return DDERR_GENERIC;
    }

    HRESULT result = g_originalDirectDrawCreate(guid, directDraw, outer);
    if (SUCCEEDED(result) && directDraw != nullptr && *directDraw != nullptr) {
        installDirectDrawObjectProbe(*directDraw, false);
    }

    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDrawCreate returned HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", object "
                << (directDraw != nullptr ? formatAddress(reinterpret_cast<std::uintptr_t>(*directDraw)) : "null");
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

HRESULT WINAPI hookedDirectDrawCreateEx(GUID* guid, LPVOID* directDraw, REFIID iid, IUnknown* outer) {
    const LONG hits = InterlockedIncrement(&g_directDrawCreateExProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: DirectDrawCreateEx hook fired");
    }

    if (g_originalDirectDrawCreateEx == nullptr) {
        return DDERR_GENERIC;
    }

    HRESULT result = g_originalDirectDrawCreateEx(guid, directDraw, iid, outer);
    if (SUCCEEDED(result) && directDraw != nullptr && *directDraw != nullptr) {
        installDirectDrawObjectProbe(*directDraw, directDrawInterfaceUsesSurfaceDesc2(iid));
    }

    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        std::ostringstream message;
        message << "runtime probe: DirectDrawCreateEx returned HRESULT "
                << formatHex32(static_cast<std::uint32_t>(result))
                << ", object "
                << (directDraw != nullptr ? formatAddress(reinterpret_cast<std::uintptr_t>(*directDraw)) : "null");
        g_runtimeProbeLogger->info(message.str());
    }

    return result;
}

FARPROC direct3DCreate9DetourAsFarproc() {
    Direct3DCreate9Function detour = &hookedDirect3DCreate9;
    FARPROC result = nullptr;
    static_assert(sizeof(result) == sizeof(detour));
    std::memcpy(&result, &detour, sizeof(result));
    return result;
}

FARPROC directDrawCreateDetourAsFarproc() {
    DirectDrawCreateFunction detour = &hookedDirectDrawCreate;
    FARPROC result = nullptr;
    static_assert(sizeof(result) == sizeof(detour));
    std::memcpy(&result, &detour, sizeof(result));
    return result;
}

FARPROC directDrawCreateExDetourAsFarproc() {
    DirectDrawCreateExFunction detour = &hookedDirectDrawCreateEx;
    FARPROC result = nullptr;
    static_assert(sizeof(result) == sizeof(detour));
    std::memcpy(&result, &detour, sizeof(result));
    return result;
}

void APIENTRY hookedOpenGLEnd() {
    OpenGLEndFunction originalEnd = g_originalOpenGLEnd;
    if (originalEnd == nullptr) {
        return;
    }

    originalEnd();

    const LONG hits = InterlockedIncrement(&g_openGLEndProbeHits);
    if (hits == 1 && g_runtimeProbeLogger != nullptr) {
        g_runtimeProbeLogger->info("runtime probe: OpenGL glEnd hook fired");
    }

    drawOpenGLOverlayTestRects(OpenGLOverlayPass::AfterGlEnd);
}

FARPROC openGLEndDetourAsFarproc() {
    OpenGLEndFunction detour = &hookedOpenGLEnd;
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
        if (g_direct3DCreate9ExportTarget == 0
            || reinterpret_cast<std::uintptr_t>(proc) != g_direct3DCreate9ExportTarget) {
            g_originalDirect3DCreate9 = reinterpret_cast<Direct3DCreate9Function>(proc);
        }
        InterlockedExchange(&g_direct3D9ProbeHits, 0);
        InterlockedExchange(&g_direct3D9CreateDeviceProbeHits, 0);
        if (kVerboseRuntimeDiagnostics && g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: replacing GetProcAddress Direct3DCreate9 result with detour "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedDirect3DCreate9));
            g_runtimeProbeLogger->info(message.str());
        }
        return direct3DCreate9DetourAsFarproc();
    }

    if (proc != nullptr && isNamedProc(procName, "DirectDrawCreate")) {
        g_originalDirectDrawCreate = reinterpret_cast<DirectDrawCreateFunction>(proc);
        InterlockedExchange(&g_directDrawCreateProbeHits, 0);
        if (g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: replacing GetProcAddress DirectDrawCreate result with detour "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedDirectDrawCreate));
            g_runtimeProbeLogger->info(message.str());
        }
        return directDrawCreateDetourAsFarproc();
    }

    if (proc != nullptr && isNamedProc(procName, "DirectDrawCreateEx")) {
        g_originalDirectDrawCreateEx = reinterpret_cast<DirectDrawCreateExFunction>(proc);
        InterlockedExchange(&g_directDrawCreateExProbeHits, 0);
        if (g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: replacing GetProcAddress DirectDrawCreateEx result with detour "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedDirectDrawCreateEx));
            g_runtimeProbeLogger->info(message.str());
        }
        return directDrawCreateExDetourAsFarproc();
    }

    if (proc != nullptr && isNamedProc(procName, "glEnd")) {
        g_originalOpenGLEnd = reinterpret_cast<OpenGLEndFunction>(proc);
        if (g_runtimeProbeLogger != nullptr) {
            std::ostringstream message;
            message << "runtime probe: replacing GetProcAddress glEnd result with detour "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedOpenGLEnd));
            g_runtimeProbeLogger->info(message.str());
        }
        return openGLEndDetourAsFarproc();
    }

    return proc;
}

bool installLoadedDirect3D9CreateHook(Logger& logger, X86DetourHook& hook) {
    if (!g_direct3D9ProbeEnabled || hook.installed()) {
        return true;
    }

    HMODULE direct3D9Module = GetModuleHandleA("d3d9.dll");
    if (direct3D9Module == nullptr) {
        return true;
    }

    FARPROC createProc = g_originalGetProcAddress != nullptr
        ? g_originalGetProcAddress(direct3D9Module, "Direct3DCreate9")
        : GetProcAddress(direct3D9Module, "Direct3DCreate9");
    if (createProc == nullptr) {
        return true;
    }

    std::string hookError;
    if (!hook.install(reinterpret_cast<void*>(createProc), reinterpret_cast<void*>(&hookedDirect3DCreate9), 5, hookError)) {
        logger.warn("runtime probe: failed to install d3d9!Direct3DCreate9 export hook: " + hookError);
        return false;
    }

    g_direct3DCreate9ExportTarget = reinterpret_cast<std::uintptr_t>(createProc);
    g_originalDirect3DCreate9 = reinterpret_cast<Direct3DCreate9Function>(hook.trampoline());
    InterlockedExchange(&g_direct3D9ProbeHits, 0);
    InterlockedExchange(&g_direct3D9CreateDeviceProbeHits, 0);

    std::ostringstream message;
    message << "runtime probe: d3d9!Direct3DCreate9 export hook installed at "
            << formatAddress(g_direct3DCreate9ExportTarget)
            << ", trampoline "
            << formatAddress(reinterpret_cast<std::uintptr_t>(hook.trampoline()));
    logger.info(message.str());
    return true;
}

bool installRendererApiProbeHooks(
    Logger& logger,
    IatHook& loadLibraryAHook,
    IatHook& getProcAddressHook,
    X86DetourHook& direct3DCreate9ExportHook,
    std::string& error) {
    InterlockedExchange(&g_rendererApiProbeLoadHits, 0);
    InterlockedExchange(&g_rendererApiProbeProcHits, 0);

    void* originalLoadLibraryA = nullptr;
    if (!loadLibraryAHook.install("KERNEL32.dll", "LoadLibraryA", reinterpret_cast<void*>(&hookedLoadLibraryA), originalLoadLibraryA, error)) {
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
    if (!getProcAddressHook.install("KERNEL32.dll", "GetProcAddress", reinterpret_cast<void*>(&hookedGetProcAddress), originalGetProcAddress, error)) {
        logger.warn("runtime probe: failed to install KERNEL32!GetProcAddress IAT hook: " + error);
    } else {
        g_originalGetProcAddress = reinterpret_cast<GetProcAddressFunction>(originalGetProcAddress);

        std::ostringstream hookMessage;
        hookMessage << "runtime probe: KERNEL32!GetProcAddress IAT hook installed; original "
                    << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetProcAddress))
                    << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetProcAddress));
        logger.info(hookMessage.str());
    }

    if (!loadLibraryAHook.installed() && !getProcAddressHook.installed()) {
        error = "failed to install every renderer API runtime probe hook";
        logger.warn("runtime probe: " + error);
        return false;
    }

    if (!installLoadedDirect3D9CreateHook(logger, direct3DCreate9ExportHook)) {
        logger.warn("runtime probe: d3d9 export hook was not installed; waiting for GetProcAddress fallback");
    }

    return true;
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

void releaseProbeStub(void*& stub) {
    if (stub == nullptr) {
        return;
    }

    VirtualFree(stub, 0, MEM_RELEASE);
    stub = nullptr;
}

bool WaHookManager::ensureGameplayHooks(Logger& logger, const char* reason) {
    if (!initialized_ || !gameplayHookSupportEnabled_) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_gameplayHookLifecycleMutex);
    if (cameraTrackingHook_.installed()
        && cameraRenderCopyHook_.installed()
        && cameraTargetAggregateHook_.installed()
        && wormMotionCandidateHook_.installed()
        && movementCollisionResultHook_.installed()
        && movementCollisionPathHook_.installed()
        && movementCollisionBranchHook_.installed()
        && collisionQueryCommonHook_.installed()
        && movementResolutionSecondaryResultHook_.installed()
        && jumpTerrainCollisionResultHook_.installed()) {
        return true;
    }

    ProcessModuleView module{};
    module.base = moduleBase_;
    module.size = moduleSize_;
    if (!module) {
        logger.warn("runtime probe: cannot enable gameplay hooks without a valid W:A module view");
        return false;
    }

    bool installedAny = false;
    std::string hookError;
    auto warn = [&](const char* hookName, const std::string& error) {
        logger.warn(std::string("runtime probe: failed to enable ") + hookName + " hook on demand: " + error);
    };

    if (!cameraTrackingHook_.installed()) {
        hookError.clear();
        if (installWaCameraTrackingProbe(logger, module, cameraTrackingHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A camera tracking", hookError);
        }
    }

    if (!cameraRenderCopyHook_.installed()) {
        hookError.clear();
        if (installWaCameraRenderCopyProbe(logger, module, cameraRenderCopyHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A camera render copy", hookError);
        }
    }

    if (!cameraTargetAggregateHook_.installed()) {
        hookError.clear();
        if (installWaCameraTargetAggregateProbe(logger, module, cameraTargetAggregateHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A camera target aggregate", hookError);
        }
    }

    if (!wormMotionCandidateHook_.installed()) {
        hookError.clear();
        if (installWaWormMotionCandidateProbe(logger, module, wormMotionCandidateHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A worm motion candidate", hookError);
        }
    }

    if (!movementCollisionResultHook_.installed()) {
        hookError.clear();
        if (installWaMovementCollisionResultProbe(logger, module, movementCollisionResultHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A movement collision result", hookError);
        }
    }

    if (!movementCollisionPathHook_.installed()) {
        hookError.clear();
        if (installWaMovementCollisionPathProbe(logger, module, movementCollisionPathHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A movement collision path", hookError);
        }
    }

    if (!movementCollisionBranchHook_.installed()) {
        hookError.clear();
        if (installWaMovementCollisionBranchProbe(logger, module, movementCollisionBranchHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A movement collision branch", hookError);
        }
    }

    if (!collisionQueryCommonHook_.installed()) {
        hookError.clear();
        if (installWaCollisionQueryCommonProbe(logger, module, collisionQueryCommonHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A collision query common", hookError);
        }
    }

    if (!movementResolutionSecondaryResultHook_.installed()) {
        hookError.clear();
        if (installWaMovementResolutionResultProbe(
                logger,
                module,
                movementResolutionSecondaryResultHook_,
                kWa381MovementResolutionSecondaryResultRva,
                0x17,
                {0x85, 0xC0, 0x74, 0x13, 0x8B, 0x4C, 0x24, 0x1C},
                {0x8B, 0x4C, 0x24, 0x1C},
                g_movementResolutionSecondaryResultProbeStub,
                "movement resolution secondary result",
                hookError)) {
            installedAny = true;
        } else {
            warn("W:A movement resolution secondary result", hookError);
        }
    }

    if (!jumpTerrainCollisionResultHook_.installed()) {
        hookError.clear();
        if (installWaJumpTerrainCollisionResultProbe(logger, module, jumpTerrainCollisionResultHook_, hookError)) {
            installedAny = true;
        } else {
            warn("W:A jump terrain collision result", hookError);
        }
    }

    if (installedAny) {
        std::ostringstream message;
        message << "runtime probe: gameplay hook group enabled";
        if (reason != nullptr && reason[0] != '\0') {
            message << " (" << reason << ")";
        }
        logger.info(message.str());
    }

    return cameraTrackingHook_.installed()
        || cameraRenderCopyHook_.installed()
        || cameraTargetAggregateHook_.installed()
        || wormMotionCandidateHook_.installed()
        || movementCollisionResultHook_.installed()
        || movementCollisionPathHook_.installed()
        || movementCollisionBranchHook_.installed()
        || collisionQueryCommonHook_.installed()
        || movementResolutionSecondaryResultHook_.installed()
        || jumpTerrainCollisionResultHook_.installed();
}

void WaHookManager::disableGameplayHooks(Logger& logger, const char* reason) {
    std::lock_guard<std::mutex> lock(g_gameplayHookLifecycleMutex);

    bool uninstalledAny = false;
    std::string hookError;
    auto uninstall = [&](const char* hookName, X86DetourHook& hook, void*& stub) {
        if (!hook.installed()) {
            releaseProbeStub(stub);
            return;
        }

        hookError.clear();
        if (!hook.uninstall(hookError)) {
            logger.warn(std::string("runtime probe: failed to disable ") + hookName + " hook: " + hookError);
            return;
        }

        releaseProbeStub(stub);
        uninstalledAny = true;
    };

    uninstall("W:A jump terrain collision result", jumpTerrainCollisionResultHook_, g_jumpTerrainCollisionResultProbeStub);
    uninstall("W:A movement resolution secondary result", movementResolutionSecondaryResultHook_, g_movementResolutionSecondaryResultProbeStub);
    uninstall("W:A collision query common", collisionQueryCommonHook_, g_collisionQueryCommonProbeStub);
    uninstall("W:A movement collision branch", movementCollisionBranchHook_, g_movementCollisionBranchProbeStub);
    uninstall("W:A movement collision path", movementCollisionPathHook_, g_movementCollisionPathProbeStub);
    uninstall("W:A movement collision result", movementCollisionResultHook_, g_movementCollisionResultProbeStub);
    uninstall("W:A worm motion candidate", wormMotionCandidateHook_, g_wormMotionCandidateProbeStub);
    uninstall("W:A camera target aggregate", cameraTargetAggregateHook_, g_cameraTargetAggregateProbeStub);
    uninstall("W:A camera render copy", cameraRenderCopyHook_, g_cameraRenderCopyProbeStub);
    uninstall("W:A camera tracking", cameraTrackingHook_, g_cameraTrackingProbeStub);

    if (!uninstalledAny) {
        return;
    }

    std::ostringstream message;
    message << "runtime probe: gameplay hook group disabled";
    if (reason != nullptr && reason[0] != '\0') {
        message << " (" << reason << ")";
    }
    logger.info(message.str());
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
    const std::vector<WaOverlayMap>& direct3D9OverlayMaps,
    const WaOverlayTransform& direct3D9OverlayTransform,
    const WaSoundConfig& soundConfig,
    bool enableOnlineSync,
    bool requireAllPlayersOnline,
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

    const bool enableMetadataOverlayHooks = !direct3D9OverlayMaps.empty() || !direct3D9OverlayTestRects.empty();
    if (!enableMessagePumpProbe
        && !enableRenderProbe
        && !enableRendererApiProbe
        && !enableCameraProbe
        && !enableDirect3D9Probe
        && !enableMetadataOverlayHooks
        && !enableOnlineSync) {
        logger.info("hook runtime mode enabled, but no runtime probe hook is enabled in configuration");
        initialized_ = true;
        return true;
    }

    g_runtimeProbeLogger = &logger;
    moduleBase_ = module.base;
    moduleSize_ = module.size;
    gameplayHookSupportEnabled_ = enableCameraProbe;
    g_activeHookManager = this;
    g_direct3D9ProbeEnabled = enableDirect3D9Probe;
    g_direct3D9DeviceSlotProbeEnabled = enableDirect3D9DeviceSlotProbe;
    g_direct3D9OverlaySmokeTestEnabled = enableDirect3D9OverlaySmokeTest;
    g_onlineSyncEnabled = enableOnlineSync;
    g_onlineRequireAllPlayers = requireAllPlayersOnline;
    g_direct3D9OverlayTransform = direct3D9OverlayTransform;
    g_soundConfig = soundConfig;
    g_direct3D9OverlayMaps = direct3D9OverlayMaps;
    g_detectedMapCachePath = direct3D9OverlayTransform.mapCachePath;
    g_customDatPath = direct3D9OverlayTransform.customDatPath;
    g_cachedDefaultMapPath = direct3D9OverlayTransform.cachedMapPath;
    g_cachedDefaultMapCustomDatWriteTime = direct3D9OverlayTransform.cachedMapCustomDatWriteTime;
    g_cachedDefaultMapCustomDatSha256 = direct3D9OverlayTransform.cachedMapCustomDatSha256;
    g_detectedMapCachedCustomDatWriteTime = direct3D9OverlayTransform.cachedMapCustomDatWriteTime;
    g_detectedMapCachedCustomDatSha256 = direct3D9OverlayTransform.cachedMapCustomDatSha256;
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
    InterlockedExchange(&g_peekMessageProbeHits, 0);
    InterlockedExchange(&g_weaponInputBlockLogCount, 0);
    InterlockedExchange(&g_blockedWeaponInputKeyMask, 0);
    InterlockedExchange(&g_blockedWeaponInputSuppressUntilTick, 0);
    InterlockedExchange(&g_utilityActionSelectionGraceUntilTick, 0);
    InterlockedExchange(&g_recentRopeContextTick, 0);
    InterlockedExchange(&g_wallSoundLogCount, 0);
    InterlockedExchange(&g_wallSoundMissingLogCount, 0);
    InterlockedExchange(&g_wallWarningSoundLastTick, 0);
    InterlockedExchange(&g_crateCollectedThisTurn, 0);
    InterlockedExchange(&g_crateCollectionLogCount, 0);
    InterlockedExchange(&g_chatOverlayActive, 0);
    InterlockedExchange(&g_chatOverlayHiddenLogCount, 0);
    InterlockedExchange(&g_chatInputLogCount, 0);
    InterlockedExchange(&g_chatOverlayScanPendingTick, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetY, 0);
    InterlockedExchange(&g_chatOverlayDetectedOffsetValid, 0);
    InterlockedExchange(&g_chatOverlayScanLogCount, 0);
    InterlockedExchange(&g_chatOverlayControlKeyActive, 0);
    InterlockedExchange(&g_chatOverlayPinnedMode, 0);
    InterlockedExchange(&g_chatOverlayPinnedPending, 0);
    InterlockedExchange(&g_chatOverlayPinnedActivationTick, 0);
    InterlockedExchange(&g_chatOverlayPinnedAutoProbeTick, 0);
    InterlockedExchange(&g_chatOverlayLastUnpinnedCameraYPixels, 0);
    InterlockedExchange(&g_chatOverlayPinnedCameraOffsetY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayPinnedBaselineBaseY, LONG_MIN);
    InterlockedExchange(&g_chatOverlayLastUnpinnedBaseY, LONG_MIN);
    resetChatOverlayScanSamples();
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
    InterlockedExchange(&g_directDrawCreateProbeHits, 0);
    InterlockedExchange(&g_directDrawCreateExProbeHits, 0);
    InterlockedExchange(&g_directDrawQueryInterfaceProbeHits, 0);
    InterlockedExchange(&g_directDrawCreateSurfaceProbeHits, 0);
    InterlockedExchange(&g_directDrawSurfaceBltProbeHits, 0);
    InterlockedExchange(&g_directDrawSurfaceBltFastProbeHits, 0);
    InterlockedExchange(&g_directDrawSurfaceFlipProbeHits, 0);
    InterlockedExchange(&g_directDrawSurfaceUnlockProbeHits, 0);
    InterlockedExchange(&g_directDrawOverlayDrawHits, 0);
    InterlockedExchange(&g_directDrawOverlayFailureHits, 0);
    InterlockedExchange(&g_directDrawOverlayNoDrawHits, 0);
    InterlockedExchange(&g_directDrawOverlayDrawing, 0);
    InterlockedExchange(&g_directDrawSurfaceTransitionTick, 0);
    InterlockedExchange(&g_directDrawSurfaceTransitionLogCount, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayDrawHits, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayFailureHits, 0);
    InterlockedExchange(&g_openGLMetadataOverlayDrawHits, 0);
    InterlockedExchange(&g_openGLMetadataOverlayFailureHits, 0);
    InterlockedExchange(&g_openGLMetadataOverlayContextLogHits, 0);
    InterlockedExchange(&g_openGLEndProbeHits, 0);
    g_originalOpenGLEnd = nullptr;
    InterlockedExchange(&g_direct3D9MetadataOverlayTransformLogHits, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastBackBufferWidth, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastBackBufferHeight, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaX, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaY, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayLastCameraDeltaValid, 0);
    InterlockedExchange(&g_direct3D9MetadataOverlayCameraDeltaLogCount, 0);
    g_direct3DCreate9ExportTarget = 0;
    g_originalLoadLibraryA = nullptr;
    g_originalGetProcAddress = nullptr;
    g_originalDirect3DCreate9 = nullptr;
    InterlockedExchange(&g_direct3D9WallTouchLogCount, 0);
    InterlockedExchange(&g_wallTouchTurnOwnerAddress, 0);
    InterlockedExchange(&g_wallTouchResetLogCount, 0);
    InterlockedExchange(&g_wallTouchLastTouchTick, 0);
    InterlockedExchange(&g_wallTouchLastResetTick, 0);
    InterlockedExchange(&g_waStateUiAddress, 0);
    InterlockedExchange(&g_waStateUiLogCount, 0);
    InterlockedExchange(&g_movementCollisionResultProbeHits, 0);
    InterlockedExchange(&g_movementResolutionResultProbeHits, 0);
    InterlockedExchange(&g_movementResolutionResultLogCount, 0);
    InterlockedExchange(&g_movementResolutionResultNearWallLogCount, 0);
    InterlockedExchange(&g_turnGameHandleMessageProbeHits, 0);
    InterlockedExchange(&g_turnGameHandleMessageLogCount, 0);
    InterlockedExchange(&g_turnGameFinishTurnLastResetTick, 0);
    resetWallGameplayTaskActivity();
    g_originalWaTurnGameHandleMessage = nullptr;
    resetOnlineMetadataTransportState();
    InterlockedExchange(&g_onlineMetadataSendLogCount, 0);
    InterlockedExchange(&g_onlineMetadataReceiveLogCount, 0);
    InterlockedExchange(&g_onlineMetadataErrorLogCount, 0);
    InterlockedExchange(&g_onlineLobbyHookLogCount, 0);
    InterlockedExchange(&g_onlineLobbyPacketLogCount, 0);
    InterlockedExchange(&g_onlineLobbyMessageLogCount, 0);
    InterlockedExchange(&g_onlineLobbyLastBroadcastTick, 0);
    InterlockedExchange(&g_onlineLobbySeenSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyCompatibleSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyBroadcastSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyQuerySlotMask, 0);
    InterlockedExchange(&g_onlineLobbyLastConnectedSlotMask, 0);
    InterlockedExchange(&g_onlineLobbyCompatibilityDeadlineTick, 0);
    InterlockedExchange(&g_onlineLobbyCompatibilityReported, 0);
    g_lobbyHostScreenAddress = 0;
    g_lobbyClientScreenAddress = 0;
    g_lobbyHostSlotAddress = 0;
    g_lobbyClientSlotAddress = 0;
    g_lobbyHostUnicastAddress = 0;
    g_lobbyHostIncomingConnectionAddress = 0;
    g_waLobbyDisplayMessage = nullptr;
    g_originalWaHostLobbyPacketHandler = nullptr;
    g_originalWaClientLobbyPacketHandler = nullptr;
    g_originalWaConstructLobbyHostScreen = nullptr;
    g_originalWaConstructLobbyClientScreen = nullptr;
    InterlockedExchange(&g_detectedMapSequence, 0);
    InterlockedExchange(&g_consumedMapSequence, 0);
    InterlockedExchange(&g_detectedMapTick, 0);
    InterlockedExchange(&g_detectedMapFromCacheSeed, 0);
    InterlockedExchange(&g_detectedMapCacheAssociationPending, 0);
    InterlockedExchange(&g_direct3D9ActiveOverlayMapIndex, -1);
    InterlockedExchange(&g_detectedMapLogCount, 0);
    InterlockedExchange(&g_detectedMapCacheRefreshTick, 0);
    InterlockedExchange(&g_detectedMapCacheRefreshLogCount, 0);
    InterlockedExchange(&g_cachedDefaultMapSeedAttemptTick, 0);
    InterlockedExchange(&g_cachedDefaultMapSeedLogCount, 0);
    InterlockedExchange(&g_direct3D9OverlayActivationLogCount, 0);
    InterlockedExchange(&g_direct3D9OverlayGameplayActive, 0);
    InterlockedExchange(&g_direct3D9OverlayLastGameplayEvidenceTick, 0);
    InterlockedExchange(&g_direct3D9OverlayGameplayLogCount, 0);
    resetWallGameplayTaskActivity();
    {
        std::lock_guard<std::mutex> lock(g_directDrawProbeMutex);
        g_directDrawObjectVtableHooks.clear();
        g_directDrawSurfaceVtableHooks.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_detectedMapMutex);
        g_detectedMapPath.clear();
        g_detectedMapFileName.clear();
    }

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

    if (enableRendererApiProbe) {
        if (!installRendererApiProbeHooks(
                logger,
                loadLibraryAHook_,
                getProcAddressHook_,
                direct3DCreate9ExportHook_,
                error)) {
            g_runtimeProbeLogger = nullptr;
            return false;
        }
    }

    if (!g_direct3D9OverlayMaps.empty()) {
        void* originalCreateFileA = nullptr;
        if (!createFileAHook_.install("KERNEL32.dll", "CreateFileA", reinterpret_cast<void*>(&hookedCreateFileA), originalCreateFileA, error)) {
            logger.warn("runtime probe: failed to install KERNEL32!CreateFileA IAT hook: " + error);
        } else {
            g_originalCreateFileA = reinterpret_cast<CreateFileAFunction>(originalCreateFileA);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: KERNEL32!CreateFileA IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalCreateFileA))
                        << ", detour "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedCreateFileA));
            logger.info(hookMessage.str());
        }

        void* originalCreateFileW = nullptr;
        if (!createFileWHook_.install("KERNEL32.dll", "CreateFileW", reinterpret_cast<void*>(&hookedCreateFileW), originalCreateFileW, error)) {
            logger.warn("runtime probe: failed to install KERNEL32!CreateFileW IAT hook: " + error);
        } else {
            g_originalCreateFileW = reinterpret_cast<CreateFileWFunction>(originalCreateFileW);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: KERNEL32!CreateFileW IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalCreateFileW))
                        << ", detour "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedCreateFileW));
            logger.info(hookMessage.str());
        }

        if (!createFileAHook_.installed() && !createFileWHook_.installed()) {
            logger.warn("runtime probe: map file discovery will be passive because both CreateFile hooks failed");
        }
    }

    {
        std::string turnGameError;
        if (!installWaTurnGameHandleMessageProbe(logger, module, turnGameHandleMessageHook_, turnGameError)) {
            logger.warn("runtime probe: failed to install CTaskTurnGame::HandleMessage hook: " + turnGameError);
        }
    }

    if (enableOnlineSync) {
        if (!installWaOnlineLobbySyncHooks(
                logger,
                module,
                hostLobbyPacketHandlerHook_,
                clientLobbyPacketHandlerHook_,
                constructLobbyHostScreenHook_,
                constructLobbyClientScreenHook_)) {
            logger.warn("online lobby sync: no lobby hook was installed; online metadata sync will stay inactive");
        }
    }

    if (enableCameraProbe) {
        logger.info("runtime probe: W:A gameplay hooks will be enabled on demand for active wall metadata maps");
    }

    if (enableMessagePumpProbe || enableMetadataOverlayHooks) {
        void* originalGetMessageA = nullptr;
        if (!getMessageHook_.install("USER32.dll", "GetMessageA", reinterpret_cast<void*>(&hookedGetMessageA), originalGetMessageA, error)) {
            logger.warn("runtime probe: failed to install USER32!GetMessageA IAT hook: " + error);
        } else {
            g_originalGetMessageA = reinterpret_cast<GetMessageAFunction>(originalGetMessageA);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: USER32!GetMessageA IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetMessageA))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetMessageA));
            logger.info(hookMessage.str());
        }

        void* originalPeekMessageA = nullptr;
        if (!peekMessageHook_.install("USER32.dll", "PeekMessageA", reinterpret_cast<void*>(&hookedPeekMessageA), originalPeekMessageA, error)) {
            logger.warn("runtime probe: failed to install USER32!PeekMessageA IAT hook: " + error);
        } else {
            g_originalPeekMessageA = reinterpret_cast<PeekMessageAFunction>(originalPeekMessageA);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: USER32!PeekMessageA IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalPeekMessageA))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedPeekMessageA));
            logger.info(hookMessage.str());
        }

        if (!getMessageHook_.installed() && !peekMessageHook_.installed()) {
            g_runtimeProbeLogger = nullptr;
            error = "failed to install every USER32 message runtime probe hook";
            logger.warn("runtime probe: " + error);
            return false;
        }

        void* originalGetAsyncKeyState = nullptr;
        if (!getAsyncKeyStateHook_.install("USER32.dll", "GetAsyncKeyState", reinterpret_cast<void*>(&hookedGetAsyncKeyState), originalGetAsyncKeyState, error)) {
            logger.warn("runtime probe: failed to install USER32!GetAsyncKeyState IAT hook: " + error);
        } else {
            g_originalGetAsyncKeyState = reinterpret_cast<GetAsyncKeyStateFunction>(originalGetAsyncKeyState);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: USER32!GetAsyncKeyState IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetAsyncKeyState))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetAsyncKeyState));
            logger.info(hookMessage.str());
        }

        void* originalGetKeyState = nullptr;
        if (!getKeyStateHook_.install("USER32.dll", "GetKeyState", reinterpret_cast<void*>(&hookedGetKeyState), originalGetKeyState, error)) {
            logger.warn("runtime probe: failed to install USER32!GetKeyState IAT hook: " + error);
        } else {
            g_originalGetKeyState = reinterpret_cast<GetKeyStateFunction>(originalGetKeyState);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: USER32!GetKeyState IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetKeyState))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetKeyState));
            logger.info(hookMessage.str());
        }

        void* originalGetKeyboardState = nullptr;
        if (!getKeyboardStateHook_.install("USER32.dll", "GetKeyboardState", reinterpret_cast<void*>(&hookedGetKeyboardState), originalGetKeyboardState, error)) {
            logger.warn("runtime probe: failed to install USER32!GetKeyboardState IAT hook: " + error);
        } else {
            g_originalGetKeyboardState = reinterpret_cast<GetKeyboardStateFunction>(originalGetKeyboardState);

            std::ostringstream hookMessage;
            hookMessage << "runtime probe: USER32!GetKeyboardState IAT hook installed; original "
                        << formatAddress(reinterpret_cast<std::uintptr_t>(g_originalGetKeyboardState))
                        << ", detour " << formatAddress(reinterpret_cast<std::uintptr_t>(&hookedGetKeyboardState));
            logger.info(hookMessage.str());
        }
    }

    if (enableRenderProbe || enableMetadataOverlayHooks) {
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
