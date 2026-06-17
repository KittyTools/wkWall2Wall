#pragma once

#include "WallGameMessage.h"

#include <cstddef>
#include <cstdint>
#include <string>

constexpr std::size_t kWaTaskMessageTypeBytes = 1;
constexpr std::size_t kWaTaskMessagePayloadSizeBytes = 2;
constexpr std::size_t kWaWallTaskMessageRuntimeHeaderBytes = 2;
constexpr std::size_t kWaWallTaskMessageMaxRuntimeBytes = kWaWallTaskMessageRuntimeHeaderBytes + kWallGameMessageMaxPayloadBytes;
constexpr std::size_t kWaWallTaskMessageMaxWireBytes = kWaTaskMessageTypeBytes + kWaTaskMessagePayloadSizeBytes + kWallGameMessageMaxPayloadBytes;

struct WaWallTaskMessageData {
    std::uint16_t payloadSize = 0;
    std::uint8_t payload[kWallGameMessageMaxPayloadBytes] = {};
};

static_assert(sizeof(WaWallTaskMessageData) == kWaWallTaskMessageMaxRuntimeBytes);

bool packWallGameMessageForTaskMessageData(
    const WallGameMessage& message,
    WaWallTaskMessageData& data,
    std::size_t& dataSize,
    std::string& error);

bool unpackWallGameMessageFromTaskMessageData(
    const void* data,
    std::size_t dataSize,
    WallGameMessage& message,
    std::string& error);

bool serializeWallTaskMessageForWa(
    const WallGameMessage& message,
    std::uint8_t* output,
    std::size_t outputCapacity,
    std::size_t& bytesWritten,
    std::string& error);

bool deserializeWallTaskMessageFromWa(
    const std::uint8_t* input,
    std::size_t inputSize,
    WallGameMessage& message,
    std::size_t& bytesRead,
    std::string& error);

bool serializeWallTaskMessageDataForWa(
    std::uint32_t taskMessageType,
    const void* taskMessageData,
    std::size_t taskMessageDataSize,
    std::uint8_t* output,
    std::size_t outputCapacity,
    std::size_t& bytesWritten,
    std::string& error);

bool deserializeWallTaskMessageDataFromWa(
    const std::uint8_t* input,
    std::size_t inputSize,
    void* outputTaskMessageData,
    std::size_t outputCapacity,
    std::uint32_t& taskMessageType,
    std::size_t& taskMessageDataSize,
    std::size_t& bytesRead,
    std::string& error);
