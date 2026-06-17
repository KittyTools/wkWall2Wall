#pragma once

#include "WallMetadata.h"
#include "WallTouch.h"

#include <cstddef>
#include <string>
#include <vector>

enum class WallMetadataSource {
    None,
    LocalFile,
    HostBroadcast,
};

class WallSessionState {
public:
    void clear();

    bool activateLocalMetadata(const WallMapMetadata& map, std::string& error);
    bool applyHostMetadata(const WallMapMetadata& map, const WallMapQuery& activeMap, std::string& error);
    bool applyHostPayload(const std::vector<std::uint8_t>& payload, const WallMapQuery& activeMap, std::string& error);
    bool markWallTouched(std::size_t wallIndex, bool& changed, std::string& error);
    void resetWallTouchesForNewTurn();

    bool hasActiveMetadata() const;
    WallMetadataSource source() const;
    const WallMapMetadata* activeMetadata() const;
    const WallRuntimeState& wallState() const;

private:
    WallMetadataSource source_ = WallMetadataSource::None;
    WallMapMetadata active_;
    WallRuntimeState wallState_;
};

const char* wallMetadataSourceName(WallMetadataSource source);
