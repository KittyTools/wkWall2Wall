#include "../src/WallProtocol.h"
#include "../src/WallSession.h"
#include "../src/WallSync.h"
#include "../src/WallTransport.h"
#include "../src/WaMemory.h"
#include "../src/WaTaskMessageCodec.h"

#include <iostream>
#include <string>

int main() {
    BytePattern hookPattern;
    std::string hookPatternError;
    if (!parseBytePattern("AA ?? 10", hookPattern, hookPatternError)) {
        std::cerr << "hook pattern parse failed: " << hookPatternError << "\n";
        return 1;
    }

    const std::uint8_t hookPatternBytes[] = {0x01, 0xAA, 0x44, 0x10, 0xAA, 0x55, 0x11};
    const std::vector<std::uintptr_t> hookPatternMatches = findBytePattern(
        hookPatternBytes,
        sizeof(hookPatternBytes),
        hookPattern,
        2);
    if (hookPatternMatches.size() != 1 || hookPatternMatches[0] != reinterpret_cast<std::uintptr_t>(hookPatternBytes + 1)) {
        std::cerr << "hook pattern scan failed\n";
        return 1;
    }

    if (parseBytePattern("AA nope", hookPattern, hookPatternError)) {
        std::cerr << "invalid hook pattern was accepted\n";
        return 1;
    }

    WallMapMetadata hostMap;
    hostMap.name = "Test WXW";
    hostMap.fileName = "test.png";
    hostMap.sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    hostMap.width = 1920;
    hostMap.height = 696;
    hostMap.walls.push_back(WallRect{"Left", 10, 20, 30, 40, 0x00FF00});
    hostMap.walls.push_back(WallRect{"Right", 100, 120, 30, 40, 0xFF0000});

    WallMapQuery activeMap;
    activeMap.sha256 = hostMap.sha256;
    activeMap.width = hostMap.width;
    activeMap.height = hostMap.height;

    std::string error;
    WallSessionState hostSession;
    WallSyncController hostSync(hostSession);
    if (!hostSync.queueHostMetadata(hostMap, error)) {
        std::cerr << "host queue failed: " << error << "\n";
        return 1;
    }

    WallSessionState clientSession;
    WallSyncController clientSync(clientSession);
    WallSyncReceiveResult lastResult;
    WallGameMessage outgoingMessage;
    std::uint8_t waWireBuffer[kWaWallTaskMessageMaxWireBytes] = {};
    while (hostSync.popOutgoingGameMessage(outgoingMessage, error)) {
        if (outgoingMessage.taskMessageType != kWallGameTaskMessageMetadataFrame) {
            std::cerr << "unexpected game task message type\n";
            return 1;
        }

        if (outgoingMessage.payload.size() > kWallGameMessageMaxPayloadBytes) {
            std::cerr << "game task message payload too large\n";
            return 1;
        }

        WaWallTaskMessageData outgoingTaskData;
        std::size_t outgoingTaskDataSize = 0;
        if (!packWallGameMessageForTaskMessageData(outgoingMessage, outgoingTaskData, outgoingTaskDataSize, error)) {
            std::cerr << "WA task message data pack failed: " << error << "\n";
            return 1;
        }

        std::size_t bytesWritten = 0;
        if (!serializeWallTaskMessageDataForWa(
                outgoingMessage.taskMessageType,
                &outgoingTaskData,
                outgoingTaskDataSize,
                waWireBuffer,
                sizeof(waWireBuffer),
                bytesWritten,
                error)) {
            std::cerr << "WA task message data serialize failed: " << error << "\n";
            return 1;
        }

        std::size_t tinyBytesWritten = 0;
        std::uint8_t tinyBuffer[1] = {};
        if (serializeWallTaskMessageDataForWa(
                outgoingMessage.taskMessageType,
                &outgoingTaskData,
                outgoingTaskDataSize,
                tinyBuffer,
                sizeof(tinyBuffer),
                tinyBytesWritten,
                error)) {
            std::cerr << "WA task message data serialized into undersized buffer\n";
            return 1;
        }

        WaWallTaskMessageData decodedTaskData;
        std::uint32_t decodedTaskMessageType = 0;
        std::size_t decodedTaskDataSize = 0;
        std::size_t bytesRead = 0;
        if (!deserializeWallTaskMessageDataFromWa(
                waWireBuffer,
                bytesWritten,
                &decodedTaskData,
                sizeof(decodedTaskData),
                decodedTaskMessageType,
                decodedTaskDataSize,
                bytesRead,
                error)) {
            std::cerr << "WA task message data deserialize failed: " << error << "\n";
            return 1;
        }

        if (bytesRead != bytesWritten) {
            std::cerr << "WA task message byte count mismatch\n";
            return 1;
        }

        if (decodedTaskMessageType != outgoingMessage.taskMessageType || decodedTaskDataSize != outgoingTaskDataSize) {
            std::cerr << "WA task message data metadata mismatch\n";
            return 1;
        }

        std::uint8_t tinyRuntimeBuffer[1] = {};
        std::uint32_t ignoredTaskMessageType = 0;
        std::size_t ignoredTaskDataSize = 0;
        std::size_t ignoredTaskBytesRead = 0;
        if (deserializeWallTaskMessageDataFromWa(
                waWireBuffer,
                bytesWritten,
                tinyRuntimeBuffer,
                sizeof(tinyRuntimeBuffer),
                ignoredTaskMessageType,
                ignoredTaskDataSize,
                ignoredTaskBytesRead,
                error)) {
            std::cerr << "WA task message data deserialized into undersized runtime buffer\n";
            return 1;
        }

        WallGameMessage decodedMessage;
        if (!unpackWallGameMessageFromTaskMessageData(&decodedTaskData, decodedTaskDataSize, decodedMessage, error)) {
            std::cerr << "WA task message data unpack failed: " << error << "\n";
            return 1;
        }

        if (decodedMessage.payload != outgoingMessage.payload) {
            std::cerr << "WA task message payload mismatch\n";
            return 1;
        }

        lastResult = clientSync.receiveIncomingGameMessage(decodedMessage, activeMap);
        if (lastResult.status == WallSyncReceiveStatus::Error) {
            std::cerr << "client receive failed: " << lastResult.message << "\n";
            return 1;
        }
    }

    if (lastResult.status != WallSyncReceiveStatus::CompletedMetadata) {
        std::cerr << "client did not complete metadata receive\n";
        return 1;
    }

    const WallMapMetadata* synced = clientSession.activeMetadata();
    if (synced == nullptr || synced->walls.size() != 2 || clientSession.source() != WallMetadataSource::HostBroadcast) {
        std::cerr << "client session state mismatch\n";
        return 1;
    }

    if (clientSession.wallState().wallCount() != 2 || clientSession.wallState().touchedWallCount() != 0) {
        std::cerr << "client wall runtime state was not initialized\n";
        return 1;
    }

    if (clientSession.wallState().allWallsTouched()) {
        std::cerr << "client wall runtime state started completed\n";
        return 1;
    }

    bool changed = false;
    WallSessionState emptyTouchSession;
    if (emptyTouchSession.markWallTouched(0, changed, error)) {
        std::cerr << "wall touch without active metadata was accepted\n";
        return 1;
    }

    if (!clientSession.markWallTouched(0, changed, error) || !changed) {
        std::cerr << "client local wall touch failed: " << error << "\n";
        return 1;
    }

    if (!clientSession.wallState().isWallTouched(0) || clientSession.wallState().isWallTouched(1)) {
        std::cerr << "client local wall touch state mismatch\n";
        return 1;
    }

    std::uint32_t displayColor = 0;
    if (!clientSession.wallState().wallDisplayColor(*synced, 0, 0xFFFFFF, displayColor, error) || displayColor != synced->walls[0].color) {
        std::cerr << "client touched wall display color mismatch\n";
        return 1;
    }

    if (!clientSession.wallState().wallDisplayColor(*synced, 1, 0xFFFFFF, displayColor, error) || displayColor != 0xFFFFFF) {
        std::cerr << "client untouched wall display color mismatch\n";
        return 1;
    }

    if (!clientSession.markWallTouched(0, changed, error) || changed) {
        std::cerr << "duplicate local wall touch changed state\n";
        return 1;
    }

    if (clientSession.wallState().touchedWallCount() != 1 || clientSession.wallState().allWallsTouched()) {
        std::cerr << "duplicate local wall touch count mismatch\n";
        return 1;
    }

    if (!clientSession.markWallTouched(1, changed, error) || !changed || !clientSession.wallState().allWallsTouched()) {
        std::cerr << "client all-walls-touched state failed: " << error << "\n";
        return 1;
    }

    clientSession.resetWallTouchesForNewTurn();
    if (clientSession.wallState().touchedWallCount() != 0 || clientSession.wallState().allWallsTouched()) {
        std::cerr << "new turn wall touch reset failed\n";
        return 1;
    }

    if (clientSession.markWallTouched(99, changed, error)) {
        std::cerr << "out-of-range local wall touch was accepted\n";
        return 1;
    }

    const WallSyncReceiveResult wrongMessageType = clientSync.receiveIncomingGameMessage(
        12,
        outgoingMessage.payload.data(),
        outgoingMessage.payload.size(),
        activeMap);
    if (wrongMessageType.status != WallSyncReceiveStatus::Error) {
        std::cerr << "non-wkWall2Wall task message was accepted\n";
        return 1;
    }

    std::size_t ignoredBytesRead = 0;
    WallGameMessage ignoredMessage;
    waWireBuffer[0] = 12;
    waWireBuffer[1] = 1;
    waWireBuffer[2] = 0;
    if (deserializeWallTaskMessageFromWa(waWireBuffer, 3, ignoredMessage, ignoredBytesRead, error)) {
        std::cerr << "WA codec accepted non-wkWall2Wall task message\n";
        return 1;
    }

    std::uint8_t directWireWithTrailingBytes[6] = {
        kWallGameTaskMessageMetadataFrame,
        2,
        0,
        0xAA,
        0xBB,
        0xCC,
    };
    WallGameMessage directDecodedMessage;
    std::size_t directBytesRead = 0;
    if (!deserializeWallTaskMessageFromWa(
            directWireWithTrailingBytes,
            sizeof(directWireWithTrailingBytes),
            directDecodedMessage,
            directBytesRead,
            error)) {
        std::cerr << "WA codec rejected message with trailing bytes: " << error << "\n";
        return 1;
    }

    if (directBytesRead != 5 || directDecodedMessage.payload.size() != 2) {
        std::cerr << "WA codec did not stop at the length-delimited payload\n";
        return 1;
    }

    if (!hostSync.queueHostMetadata(hostMap, error)) {
        std::cerr << "host requeue failed: " << error << "\n";
        return 1;
    }

    WallMapQuery wrongActiveMap = activeMap;
    wrongActiveMap.sha256 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    WallSessionState rejectingClientSession;
    WallSyncController rejectingClientSync(rejectingClientSession);
    bool rejected = false;
    while (hostSync.popOutgoingGameMessage(outgoingMessage, error)) {
        const WallSyncReceiveResult result = rejectingClientSync.receiveIncomingGameMessage(
            outgoingMessage.taskMessageType,
            outgoingMessage.payload.data(),
            outgoingMessage.payload.size(),
            wrongActiveMap);
        if (result.status == WallSyncReceiveStatus::Error) {
            rejected = true;
            break;
        }
    }

    if (!rejected || rejectingClientSession.hasActiveMetadata()) {
        std::cerr << "client accepted metadata for the wrong active map\n";
        return 1;
    }

    const std::vector<WallTransportFrame> frames = makeWallMetadataFrames(hostMap, 42, 32);
    if (frames.size() < 2) {
        std::cerr << "expected chunked transport frames\n";
        return 1;
    }

    WallTransportReassembler reassembler;
    for (auto iterator = frames.rbegin(); iterator != frames.rend(); ++iterator) {
        const WallTransportFrame& frame = *iterator;
        const std::vector<std::uint8_t> wireFrame = serializeWallTransportFrame(frame);
        WallTransportFrame decodedFrame;
        if (!deserializeWallTransportFrame(wireFrame, decodedFrame, error)) {
            std::cerr << "transport frame decode failed: " << error << "\n";
            return 1;
        }
        if (!reassembler.accept(decodedFrame, error)) {
            std::cerr << "transport reassembly failed: " << error << "\n";
            return 1;
        }
    }

    if (!reassembler.accept(frames.front(), error)) {
        std::cerr << "duplicate transport frame failed: " << error << "\n";
        return 1;
    }

    if (!reassembler.complete()) {
        std::cerr << "transport reassembly did not complete\n";
        return 1;
    }

    const std::vector<std::uint8_t> payload = reassembler.payload();

    WallMapMetadata received;
    if (!deserializeWallMetadata(payload, received, error)) {
        std::cerr << "deserialize failed: " << error << "\n";
        return 1;
    }

    WallSessionState session;
    if (!session.applyHostMetadata(received, activeMap, error)) {
        std::cerr << "session apply failed: " << error << "\n";
        return 1;
    }

    const WallMapMetadata* active = session.activeMetadata();
    if (active == nullptr || active->walls.size() != 2 || session.source() != WallMetadataSource::HostBroadcast) {
        std::cerr << "session state mismatch\n";
        return 1;
    }

    activeMap.sha256 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    if (session.applyHostMetadata(received, activeMap, error)) {
        std::cerr << "mismatched host metadata was accepted\n";
        return 1;
    }

    std::cout << "protocol smoke test ok\n";
    return 0;
}
