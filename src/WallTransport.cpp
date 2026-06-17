#include "WallTransport.h"

#include "WallProtocol.h"

#include <algorithm>
#include <stdexcept>

namespace {
constexpr std::uint8_t kMagic[4] = {'W', '2', 'W', 'T'};
constexpr std::size_t kFrameHeaderBytes = 4 + 2 + 1 + 1 + 4 + 2 + 2 + 4 + 4 + 2;

void writeU8(std::vector<std::uint8_t>& output, std::uint8_t value) {
    output.push_back(value);
}

void writeU16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xFF));
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

void writeU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xFF));
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    output.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

class FrameReader {
public:
    FrameReader(const std::uint8_t* data, std::size_t size)
        : data_(data), size_(size) {}

    std::uint8_t readU8() {
        require(1);
        return data_[offset_++];
    }

    std::uint16_t readU16() {
        require(2);
        const std::uint16_t value = static_cast<std::uint16_t>(data_[offset_])
            | static_cast<std::uint16_t>(data_[offset_ + 1] << 8);
        offset_ += 2;
        return value;
    }

    std::uint32_t readU32() {
        require(4);
        const std::uint32_t value = static_cast<std::uint32_t>(data_[offset_])
            | (static_cast<std::uint32_t>(data_[offset_ + 1]) << 8)
            | (static_cast<std::uint32_t>(data_[offset_ + 2]) << 16)
            | (static_cast<std::uint32_t>(data_[offset_ + 3]) << 24);
        offset_ += 4;
        return value;
    }

    std::vector<std::uint8_t> readBytes(std::size_t count) {
        require(count);
        std::vector<std::uint8_t> bytes(data_ + offset_, data_ + offset_ + count);
        offset_ += count;
        return bytes;
    }

    bool done() const {
        return offset_ == size_;
    }

private:
    void require(std::size_t count) const {
        if (count > size_ - offset_) {
            throw std::runtime_error("truncated wall transport frame");
        }
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t offset_ = 0;
};

bool validateFrameShape(const WallTransportFrame& frame, std::string& error) {
    if (frame.type != WallTransportMessageType::MetadataChunk) {
        error = "unsupported wall transport message type";
        return false;
    }

    if (frame.transferId == 0) {
        error = "wall transport transfer id must be non-zero";
        return false;
    }

    if (frame.chunkCount == 0 || frame.chunkCount > kWallTransportMaxChunks) {
        error = "wall transport chunk count is invalid";
        return false;
    }

    if (frame.chunkIndex >= frame.chunkCount) {
        error = "wall transport chunk index is out of range";
        return false;
    }

    if (frame.totalSize == 0 || frame.totalSize > kWallProtocolMaxPayloadBytes) {
        error = "wall transport total payload size is invalid";
        return false;
    }

    if (frame.chunk.empty() || frame.chunk.size() > kWallTransportMaxChunkBytes) {
        error = "wall transport chunk size is invalid";
        return false;
    }

    return true;
}
}

std::uint32_t wallTransportChecksum(const std::uint8_t* data, std::size_t size) {
    std::uint32_t hash = 2166136261u;
    for (std::size_t index = 0; index < size; ++index) {
        hash ^= data[index];
        hash *= 16777619u;
    }
    return hash;
}

std::uint32_t wallTransportChecksum(const std::vector<std::uint8_t>& data) {
    return wallTransportChecksum(data.data(), data.size());
}

std::vector<WallTransportFrame> makeWallMetadataFrames(
    const WallMapMetadata& map,
    std::uint32_t transferId,
    std::uint32_t maxChunkBytes) {
    if (transferId == 0) {
        throw std::runtime_error("wall metadata transfer id must be non-zero");
    }

    if (maxChunkBytes == 0 || maxChunkBytes > kWallTransportMaxChunkBytes) {
        throw std::runtime_error("invalid wall metadata chunk size");
    }

    const std::vector<std::uint8_t> payload = serializeWallMetadata(map);
    const std::uint32_t checksum = wallTransportChecksum(payload);
    const std::size_t chunkCountSize = (payload.size() + maxChunkBytes - 1) / maxChunkBytes;
    if (chunkCountSize == 0 || chunkCountSize > kWallTransportMaxChunks) {
        throw std::runtime_error("wall metadata payload requires too many chunks");
    }

    std::vector<WallTransportFrame> frames;
    frames.reserve(chunkCountSize);

    for (std::size_t index = 0; index < chunkCountSize; ++index) {
        const std::size_t offset = index * maxChunkBytes;
        const std::size_t length = std::min<std::size_t>(maxChunkBytes, payload.size() - offset);

        WallTransportFrame frame;
        frame.type = WallTransportMessageType::MetadataChunk;
        frame.transferId = transferId;
        frame.chunkIndex = static_cast<std::uint16_t>(index);
        frame.chunkCount = static_cast<std::uint16_t>(chunkCountSize);
        frame.totalSize = static_cast<std::uint32_t>(payload.size());
        frame.payloadChecksum = checksum;
        frame.chunk.assign(payload.begin() + offset, payload.begin() + offset + length);
        frames.push_back(std::move(frame));
    }

    return frames;
}

std::vector<std::uint8_t> serializeWallTransportFrame(const WallTransportFrame& frame) {
    std::string error;
    if (!validateFrameShape(frame, error)) {
        throw std::runtime_error(error);
    }

    std::vector<std::uint8_t> output;
    output.reserve(kFrameHeaderBytes + frame.chunk.size());
    output.insert(output.end(), std::begin(kMagic), std::end(kMagic));
    writeU16(output, kWallTransportVersion);
    writeU8(output, static_cast<std::uint8_t>(frame.type));
    writeU8(output, 0);
    writeU32(output, frame.transferId);
    writeU16(output, frame.chunkIndex);
    writeU16(output, frame.chunkCount);
    writeU32(output, frame.totalSize);
    writeU32(output, frame.payloadChecksum);
    writeU16(output, static_cast<std::uint16_t>(frame.chunk.size()));
    output.insert(output.end(), frame.chunk.begin(), frame.chunk.end());
    return output;
}

bool deserializeWallTransportFrame(const std::uint8_t* data, std::size_t size, WallTransportFrame& frame, std::string& error) {
    frame = WallTransportFrame{};
    error.clear();

    if (data == nullptr || size < kFrameHeaderBytes) {
        error = "wall transport frame is too small";
        return false;
    }

    try {
        FrameReader reader(data, size);
        for (std::uint8_t expected : kMagic) {
            if (reader.readU8() != expected) {
                error = "invalid wall transport frame magic";
                return false;
            }
        }

        const std::uint16_t version = reader.readU16();
        if (version != kWallTransportVersion) {
            error = "unsupported wall transport version";
            return false;
        }

        frame.type = static_cast<WallTransportMessageType>(reader.readU8());
        reader.readU8();
        frame.transferId = reader.readU32();
        frame.chunkIndex = reader.readU16();
        frame.chunkCount = reader.readU16();
        frame.totalSize = reader.readU32();
        frame.payloadChecksum = reader.readU32();
        const std::uint16_t chunkSize = reader.readU16();
        frame.chunk = reader.readBytes(chunkSize);

        if (!reader.done()) {
            error = "wall transport frame has trailing bytes";
            return false;
        }

        return validateFrameShape(frame, error);
    } catch (const std::exception& exception) {
        error = exception.what();
        frame = WallTransportFrame{};
        return false;
    }
}

bool deserializeWallTransportFrame(const std::vector<std::uint8_t>& payload, WallTransportFrame& frame, std::string& error) {
    return deserializeWallTransportFrame(payload.data(), payload.size(), frame, error);
}

bool WallTransportReassembler::accept(const WallTransportFrame& frame, std::string& error) {
    if (!validateFrameShape(frame, error)) {
        return false;
    }

    if (!initialized_) {
        initialized_ = true;
        transferId_ = frame.transferId;
        chunkCount_ = frame.chunkCount;
        totalSize_ = frame.totalSize;
        payloadChecksum_ = frame.payloadChecksum;
        chunks_.assign(chunkCount_, {});
        received_.assign(chunkCount_, false);
        receivedCount_ = 0;
    }

    if (frame.transferId != transferId_
        || frame.chunkCount != chunkCount_
        || frame.totalSize != totalSize_
        || frame.payloadChecksum != payloadChecksum_) {
        error = "wall transport frame does not match current transfer";
        return false;
    }

    if (received_[frame.chunkIndex]) {
        return true;
    }

    chunks_[frame.chunkIndex] = frame.chunk;
    received_[frame.chunkIndex] = true;
    ++receivedCount_;

    if (complete()) {
        const std::vector<std::uint8_t> assembled = payload();
        if (assembled.size() != totalSize_) {
            error = "assembled wall metadata payload size mismatch";
            return false;
        }

        if (wallTransportChecksum(assembled) != payloadChecksum_) {
            error = "assembled wall metadata payload checksum mismatch";
            return false;
        }
    }

    return true;
}

bool WallTransportReassembler::complete() const {
    return initialized_ && receivedCount_ == chunkCount_;
}

std::vector<std::uint8_t> WallTransportReassembler::payload() const {
    std::vector<std::uint8_t> assembled;
    if (!initialized_) {
        return assembled;
    }

    assembled.reserve(totalSize_);
    for (const std::vector<std::uint8_t>& chunk : chunks_) {
        assembled.insert(assembled.end(), chunk.begin(), chunk.end());
    }
    return assembled;
}

void WallTransportReassembler::reset() {
    initialized_ = false;
    transferId_ = 0;
    chunkCount_ = 0;
    receivedCount_ = 0;
    totalSize_ = 0;
    payloadChecksum_ = 0;
    chunks_.clear();
    received_.clear();
}

std::uint32_t WallTransportReassembler::transferId() const {
    return transferId_;
}

std::uint16_t WallTransportReassembler::receivedCount() const {
    return receivedCount_;
}

std::uint16_t WallTransportReassembler::chunkCount() const {
    return chunkCount_;
}
