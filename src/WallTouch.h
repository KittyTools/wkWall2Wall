#pragma once

#include "WallMetadata.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct WallRuntimeWallState {
    bool touched = false;
};

class WallRuntimeState {
public:
    void clear();
    void resetForMetadata(const WallMapMetadata& map);
    void resetTouches();

    bool hasWalls() const;
    std::size_t wallCount() const;
    std::size_t touchedWallCount() const;
    bool allWallsTouched() const;

    bool markTouched(std::size_t wallIndex, bool& changed, std::string& error);

    bool isWallTouched(std::size_t wallIndex) const;
    bool wallDisplayColor(
        const WallMapMetadata& map,
        std::size_t wallIndex,
        std::uint32_t untouchedColor,
        std::uint32_t& color,
        std::string& error) const;

private:
    std::vector<WallRuntimeWallState> walls_;
};
