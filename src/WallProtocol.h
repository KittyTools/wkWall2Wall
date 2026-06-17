#pragma once

#include "WallMetadata.h"

#include <cstdint>
#include <string>
#include <vector>

constexpr std::uint16_t kWallProtocolVersion = 1;
constexpr std::uint16_t kWallProtocolMaxWalls = 512;
constexpr std::uint32_t kWallProtocolMaxPayloadBytes = 64 * 1024;

bool validateSharedWallMetadata(const WallMapMetadata& map, std::string& error);
std::vector<std::uint8_t> serializeWallMetadata(const WallMapMetadata& map);
bool deserializeWallMetadata(const std::uint8_t* data, std::size_t size, WallMapMetadata& map, std::string& error);
bool deserializeWallMetadata(const std::vector<std::uint8_t>& payload, WallMapMetadata& map, std::string& error);
