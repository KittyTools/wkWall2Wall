#include "WallTouch.h"

void WallRuntimeState::clear() {
    walls_.clear();
}

void WallRuntimeState::resetForMetadata(const WallMapMetadata& map) {
    walls_.assign(map.walls.size(), {});
}

void WallRuntimeState::resetTouches() {
    for (WallRuntimeWallState& wall : walls_) {
        wall.touched = false;
    }
}

bool WallRuntimeState::hasWalls() const {
    return !walls_.empty();
}

std::size_t WallRuntimeState::wallCount() const {
    return walls_.size();
}

std::size_t WallRuntimeState::touchedWallCount() const {
    std::size_t count = 0;
    for (const WallRuntimeWallState& wall : walls_) {
        if (wall.touched) {
            ++count;
        }
    }
    return count;
}

bool WallRuntimeState::allWallsTouched() const {
    return hasWalls() && touchedWallCount() == walls_.size();
}

bool WallRuntimeState::markTouched(std::size_t wallIndex, bool& changed, std::string& error) {
    changed = false;
    error.clear();

    if (wallIndex >= walls_.size()) {
        error = "wall touch index is out of range";
        return false;
    }

    WallRuntimeWallState& wall = walls_[wallIndex];
    if (wall.touched) {
        return true;
    }

    wall.touched = true;
    changed = true;
    return true;
}

bool WallRuntimeState::isWallTouched(std::size_t wallIndex) const {
    return wallIndex < walls_.size() && walls_[wallIndex].touched;
}

bool WallRuntimeState::wallDisplayColor(
    const WallMapMetadata& map,
    std::size_t wallIndex,
    std::uint32_t untouchedColor,
    std::uint32_t& color,
    std::string& error) const {
    color = untouchedColor;
    error.clear();

    if (wallIndex >= walls_.size() || wallIndex >= map.walls.size()) {
        error = "wall display color index is out of range";
        return false;
    }

    color = walls_[wallIndex].touched ? map.walls[wallIndex].color : untouchedColor;
    return true;
}
