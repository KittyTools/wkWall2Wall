#include "WallProtocol.h"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace {
constexpr std::uint8_t kMagic[4] = {'W', '2', 'W', 'M'};
constexpr std::uint16_t kMaxStringBytes = 1024;

bool isHexSha256(const std::string& value) {
    if (value.empty()) {
        return true;
    }

    if (value.size() != 64) {
        return false;
    }

    return std::all_of(value.begin(), value.end(), [](char character) {
        return std::isxdigit(static_cast<unsigned char>(character)) != 0;
    });
}

void writeU16(std::vector<std::uint8_t>& payload, std::uint16_t value) {
    payload.push_back(static_cast<std::uint8_t>(value & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

void writeU32(std::vector<std::uint8_t>& payload, std::uint32_t value) {
    payload.push_back(static_cast<std::uint8_t>(value & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

void writeI32(std::vector<std::uint8_t>& payload, int value) {
    writeU32(payload, static_cast<std::uint32_t>(value));
}

void writeString(std::vector<std::uint8_t>& payload, const std::string& value) {
    if (value.size() > kMaxStringBytes) {
        throw std::runtime_error("string is too long for wall metadata payload");
    }

    writeU16(payload, static_cast<std::uint16_t>(value.size()));
    payload.insert(payload.end(), value.begin(), value.end());
}

class PayloadReader {
public:
    PayloadReader(const std::uint8_t* data, std::size_t size)
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

    int readI32() {
        return static_cast<int>(readU32());
    }

    std::string readString() {
        const std::uint16_t length = readU16();
        if (length > kMaxStringBytes) {
            throw std::runtime_error("string length exceeds protocol limit");
        }

        require(length);
        std::string value(reinterpret_cast<const char*>(data_ + offset_), length);
        offset_ += length;
        return value;
    }

    bool done() const {
        return offset_ == size_;
    }

private:
    void require(std::size_t count) const {
        if (count > size_ - offset_) {
            throw std::runtime_error("truncated wall metadata payload");
        }
    }

    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t offset_ = 0;
};

}

bool validateSharedWallMetadata(const WallMapMetadata& map, std::string& error) {
    if (map.width <= 0 || map.height <= 0) {
        error = "map dimensions must be positive";
        return false;
    }

    if (!isHexSha256(map.sha256)) {
        error = "map sha256 must be empty or 64 hex characters";
        return false;
    }

    if (map.walls.empty()) {
        error = "metadata must contain at least one wall";
        return false;
    }

    if (map.walls.size() > kWallProtocolMaxWalls) {
        error = "metadata contains too many walls";
        return false;
    }

    for (const WallRect& wall : map.walls) {
        if (wall.x < 0 || wall.y < 0 || wall.width <= 0 || wall.height <= 0) {
            error = "wall rectangle has invalid coordinates";
            return false;
        }

        if (wall.x > map.width - wall.width || wall.y > map.height - wall.height) {
            error = "wall rectangle is outside map bounds";
            return false;
        }

        if (wall.name.size() > kMaxStringBytes) {
            error = "wall name is too long";
            return false;
        }
    }

    if (map.name.size() > kMaxStringBytes || map.fileName.size() > kMaxStringBytes || map.sha256.size() > kMaxStringBytes) {
        error = "map metadata string is too long";
        return false;
    }

    return true;
}

std::vector<std::uint8_t> serializeWallMetadata(const WallMapMetadata& map) {
    std::string error;
    if (!validateSharedWallMetadata(map, error)) {
        throw std::runtime_error(error);
    }

    std::vector<std::uint8_t> payload;
    payload.reserve(32 + map.walls.size() * 32);
    payload.insert(payload.end(), std::begin(kMagic), std::end(kMagic));
    writeU16(payload, kWallProtocolVersion);
    writeU16(payload, 0);
    writeString(payload, map.name);
    writeString(payload, map.fileName);
    writeString(payload, map.sha256);
    writeI32(payload, map.width);
    writeI32(payload, map.height);
    writeU16(payload, static_cast<std::uint16_t>(map.walls.size()));

    for (const WallRect& wall : map.walls) {
        writeString(payload, wall.name);
        writeI32(payload, wall.x);
        writeI32(payload, wall.y);
        writeI32(payload, wall.width);
        writeI32(payload, wall.height);
        writeU32(payload, wall.color);
    }

    if (payload.size() > kWallProtocolMaxPayloadBytes) {
        throw std::runtime_error("wall metadata payload exceeds protocol limit");
    }

    return payload;
}

bool deserializeWallMetadata(const std::uint8_t* data, std::size_t size, WallMapMetadata& map, std::string& error) {
    map = WallMapMetadata{};
    error.clear();

    if (data == nullptr || size < 8 || size > kWallProtocolMaxPayloadBytes) {
        error = "invalid wall metadata payload size";
        return false;
    }

    try {
        PayloadReader reader(data, size);
        for (std::uint8_t expected : kMagic) {
            if (reader.readU8() != expected) {
                error = "invalid wall metadata magic";
                return false;
            }
        }

        const std::uint16_t version = reader.readU16();
        if (version != kWallProtocolVersion) {
            error = "unsupported wall metadata protocol version";
            return false;
        }

        reader.readU16();
        map.name = reader.readString();
        map.fileName = reader.readString();
        map.sha256 = reader.readString();
        map.width = reader.readI32();
        map.height = reader.readI32();

        const std::uint16_t wallCount = reader.readU16();
        if (wallCount == 0 || wallCount > kWallProtocolMaxWalls) {
            error = "invalid wall count in payload";
            return false;
        }

        map.walls.reserve(wallCount);
        for (std::uint16_t index = 0; index < wallCount; ++index) {
            WallRect wall;
            wall.name = reader.readString();
            wall.x = reader.readI32();
            wall.y = reader.readI32();
            wall.width = reader.readI32();
            wall.height = reader.readI32();
            wall.color = reader.readU32();
            map.walls.push_back(wall);
        }

        if (!reader.done()) {
            error = "wall metadata payload has trailing bytes";
            return false;
        }

        if (!validateSharedWallMetadata(map, error)) {
            return false;
        }

        return true;
    } catch (const std::exception& exception) {
        error = exception.what();
        map = WallMapMetadata{};
        return false;
    }
}

bool deserializeWallMetadata(const std::vector<std::uint8_t>& payload, WallMapMetadata& map, std::string& error) {
    return deserializeWallMetadata(payload.data(), payload.size(), map, error);
}
