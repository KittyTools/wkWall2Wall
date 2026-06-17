#pragma once

#include "WallGameMessage.h"
#include "WallMetadata.h"
#include "WallSession.h"
#include "WallTransport.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum class WallSyncReceiveStatus {
    Ignored,
    AcceptedChunk,
    CompletedMetadata,
    Error,
};

struct WallSyncReceiveResult {
    WallSyncReceiveStatus status = WallSyncReceiveStatus::Ignored;
    std::string message;
};

class WallSyncController {
public:
    explicit WallSyncController(WallSessionState& session);

    bool queueHostMetadata(const WallMapMetadata& map, std::string& error);
    bool hasOutgoingFrame() const;
    bool popOutgoingFrame(std::vector<std::uint8_t>& framePayload);
    bool popOutgoingGameMessage(WallGameMessage& message, std::string& error);

    WallSyncReceiveResult receiveIncomingFrame(const std::vector<std::uint8_t>& framePayload, const WallMapQuery& activeMap);
    WallSyncReceiveResult receiveIncomingGameMessage(const WallGameMessage& message, const WallMapQuery& activeMap);
    WallSyncReceiveResult receiveIncomingGameMessage(
        std::uint32_t taskMessageType,
        const std::uint8_t* data,
        std::size_t size,
        const WallMapQuery& activeMap);

    void resetIncoming();
    std::uint32_t nextTransferId();

private:
    WallSessionState& session_;
    std::uint32_t nextTransferId_ = 1;
    std::vector<std::vector<std::uint8_t>> outgoingFrames_;
    std::size_t outgoingIndex_ = 0;
    WallTransportReassembler incoming_;
};
