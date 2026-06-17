#include "WallSync.h"

#include "WallProtocol.h"

#include <stdexcept>

namespace {
std::uint32_t advanceTransferId(std::uint32_t value) {
    ++value;
    if (value == 0) {
        value = 1;
    }
    return value;
}
}

WallSyncController::WallSyncController(WallSessionState& session)
    : session_(session) {}

bool WallSyncController::queueHostMetadata(const WallMapMetadata& map, std::string& error) {
    error.clear();

    try {
        std::string validationError;
        if (!session_.activateLocalMetadata(map, validationError)) {
            error = validationError;
            return false;
        }

        const std::uint32_t transferId = nextTransferId();
        const std::vector<WallTransportFrame> frames = makeWallMetadataFrames(map, transferId);

        outgoingFrames_.clear();
        outgoingFrames_.reserve(frames.size());
        outgoingIndex_ = 0;

        for (const WallTransportFrame& frame : frames) {
            outgoingFrames_.push_back(serializeWallTransportFrame(frame));
        }

        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        outgoingFrames_.clear();
        outgoingIndex_ = 0;
        return false;
    }
}

bool WallSyncController::hasOutgoingFrame() const {
    return outgoingIndex_ < outgoingFrames_.size();
}

bool WallSyncController::popOutgoingFrame(std::vector<std::uint8_t>& framePayload) {
    if (!hasOutgoingFrame()) {
        framePayload.clear();
        return false;
    }

    framePayload = outgoingFrames_[outgoingIndex_++];
    if (outgoingIndex_ >= outgoingFrames_.size()) {
        outgoingFrames_.clear();
        outgoingIndex_ = 0;
    }

    return true;
}

bool WallSyncController::popOutgoingGameMessage(WallGameMessage& message, std::string& error) {
    std::vector<std::uint8_t> framePayload;
    if (!popOutgoingFrame(framePayload)) {
        message = WallGameMessage{};
        error.clear();
        return false;
    }

    return makeWallGameMessage(framePayload, message, error);
}

WallSyncReceiveResult WallSyncController::receiveIncomingFrame(const std::vector<std::uint8_t>& framePayload, const WallMapQuery& activeMap) {
    WallTransportFrame frame;
    std::string error;
    if (!deserializeWallTransportFrame(framePayload, frame, error)) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, error};
    }

    if (frame.type != WallTransportMessageType::MetadataChunk) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, "unsupported wall transport message type"};
    }

    if (!incoming_.accept(frame, error)) {
        incoming_.reset();
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, error};
    }

    if (!incoming_.complete()) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::AcceptedChunk, "metadata chunk accepted"};
    }

    WallMapMetadata map;
    const std::vector<std::uint8_t> payload = incoming_.payload();
    incoming_.reset();

    if (!deserializeWallMetadata(payload, map, error)) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, error};
    }

    if (!session_.applyHostMetadata(map, activeMap, error)) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, error};
    }

    return WallSyncReceiveResult{WallSyncReceiveStatus::CompletedMetadata, "host metadata applied"};
}

WallSyncReceiveResult WallSyncController::receiveIncomingGameMessage(const WallGameMessage& message, const WallMapQuery& activeMap) {
    std::vector<std::uint8_t> framePayload;
    std::string error;
    if (!extractWallFramePayload(message, framePayload, error)) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, error};
    }

    return receiveIncomingFrame(framePayload, activeMap);
}

WallSyncReceiveResult WallSyncController::receiveIncomingGameMessage(
    std::uint32_t taskMessageType,
    const std::uint8_t* data,
    std::size_t size,
    const WallMapQuery& activeMap) {
    std::vector<std::uint8_t> framePayload;
    std::string error;
    if (!extractWallFramePayload(taskMessageType, data, size, framePayload, error)) {
        return WallSyncReceiveResult{WallSyncReceiveStatus::Error, error};
    }

    return receiveIncomingFrame(framePayload, activeMap);
}

void WallSyncController::resetIncoming() {
    incoming_.reset();
}

std::uint32_t WallSyncController::nextTransferId() {
    const std::uint32_t transferId = nextTransferId_;
    nextTransferId_ = advanceTransferId(nextTransferId_);
    return transferId;
}
