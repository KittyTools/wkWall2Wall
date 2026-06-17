#pragma once

#include "WallMetadata.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

constexpr std::uint16_t kWallTransportVersion = 1;
constexpr std::uint32_t kWallTransportDefaultChunkBytes = 900;
constexpr std::uint32_t kWallTransportMaxChunkBytes = 1400;
constexpr std::uint16_t kWallTransportMaxChunks = 128;

enum class WallTransportMessageType : std::uint8_t {
    MetadataChunk = 1,
};

struct WallTransportFrame {
    WallTransportMessageType type = WallTransportMessageType::MetadataChunk;
    std::uint32_t transferId = 0;
    std::uint16_t chunkIndex = 0;
    std::uint16_t chunkCount = 0;
    std::uint32_t totalSize = 0;
    std::uint32_t payloadChecksum = 0;
    std::vector<std::uint8_t> chunk;
};

std::uint32_t wallTransportChecksum(const std::uint8_t* data, std::size_t size);
std::uint32_t wallTransportChecksum(const std::vector<std::uint8_t>& data);

std::vector<WallTransportFrame> makeWallMetadataFrames(
    const WallMapMetadata& map,
    std::uint32_t transferId,
    std::uint32_t maxChunkBytes = kWallTransportDefaultChunkBytes);

std::vector<std::uint8_t> serializeWallTransportFrame(const WallTransportFrame& frame);
bool deserializeWallTransportFrame(const std::uint8_t* data, std::size_t size, WallTransportFrame& frame, std::string& error);
bool deserializeWallTransportFrame(const std::vector<std::uint8_t>& payload, WallTransportFrame& frame, std::string& error);

class WallTransportReassembler {
public:
    bool accept(const WallTransportFrame& frame, std::string& error);
    bool complete() const;
    std::vector<std::uint8_t> payload() const;
    void reset();

    std::uint32_t transferId() const;
    std::uint16_t receivedCount() const;
    std::uint16_t chunkCount() const;

private:
    bool initialized_ = false;
    std::uint32_t transferId_ = 0;
    std::uint16_t chunkCount_ = 0;
    std::uint16_t receivedCount_ = 0;
    std::uint32_t totalSize_ = 0;
    std::uint32_t payloadChecksum_ = 0;
    std::vector<std::vector<std::uint8_t>> chunks_;
    std::vector<bool> received_;
};
