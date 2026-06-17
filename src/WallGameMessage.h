#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// wkRealTime uses 240 and 241 for its custom messages. 242 is reserved here for
// wkWall2Wall metadata frames, pending final hook compatibility testing.
constexpr std::uint8_t kWallGameTaskMessageMetadataFrame = 242;
constexpr std::size_t kWallGameMessageMaxPayloadBytes = 1536;

struct WallGameMessage {
    std::uint8_t taskMessageType = kWallGameTaskMessageMetadataFrame;
    std::vector<std::uint8_t> payload;
};

bool isWallGameTaskMessage(std::uint32_t taskMessageType);
bool makeWallGameMessage(const std::vector<std::uint8_t>& framePayload, WallGameMessage& message, std::string& error);
bool extractWallFramePayload(
    std::uint32_t taskMessageType,
    const std::uint8_t* data,
    std::size_t size,
    std::vector<std::uint8_t>& framePayload,
    std::string& error);
bool extractWallFramePayload(
    const WallGameMessage& message,
    std::vector<std::uint8_t>& framePayload,
    std::string& error);
