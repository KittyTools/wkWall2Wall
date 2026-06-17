#include "WallGameMessage.h"

bool isWallGameTaskMessage(std::uint32_t taskMessageType) {
    return taskMessageType == kWallGameTaskMessageMetadataFrame;
}

bool makeWallGameMessage(const std::vector<std::uint8_t>& framePayload, WallGameMessage& message, std::string& error) {
    error.clear();
    message = WallGameMessage{};

    if (framePayload.empty()) {
        error = "wall game message payload is empty";
        return false;
    }

    if (framePayload.size() > kWallGameMessageMaxPayloadBytes) {
        error = "wall game message payload is too large";
        return false;
    }

    message.taskMessageType = kWallGameTaskMessageMetadataFrame;
    message.payload = framePayload;
    return true;
}

bool extractWallFramePayload(
    std::uint32_t taskMessageType,
    const std::uint8_t* data,
    std::size_t size,
    std::vector<std::uint8_t>& framePayload,
    std::string& error) {
    error.clear();
    framePayload.clear();

    if (!isWallGameTaskMessage(taskMessageType)) {
        error = "not a wkWall2Wall game message";
        return false;
    }

    if (data == nullptr || size == 0) {
        error = "wall game message payload is empty";
        return false;
    }

    if (size > kWallGameMessageMaxPayloadBytes) {
        error = "wall game message payload is too large";
        return false;
    }

    framePayload.assign(data, data + size);
    return true;
}

bool extractWallFramePayload(
    const WallGameMessage& message,
    std::vector<std::uint8_t>& framePayload,
    std::string& error) {
    return extractWallFramePayload(
        message.taskMessageType,
        message.payload.data(),
        message.payload.size(),
        framePayload,
        error);
}
