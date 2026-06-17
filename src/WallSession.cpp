#include "WallSession.h"

#include "WallProtocol.h"

#include <algorithm>
#include <cctype>

namespace {
std::string lowerAscii(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }
    return result;
}

bool sameHash(const std::string& left, const std::string& right) {
    return !left.empty() && !right.empty() && lowerAscii(left) == lowerAscii(right);
}

bool metadataMatchesActiveMap(const WallMapMetadata& map, const WallMapQuery& activeMap, std::string& error) {
    if (!activeMap.sha256.empty() && !map.sha256.empty() && !sameHash(activeMap.sha256, map.sha256)) {
        error = "host wall metadata does not match the active map sha256";
        return false;
    }

    if (activeMap.width > 0 && activeMap.height > 0 && (map.width != activeMap.width || map.height != activeMap.height)) {
        error = "host wall metadata dimensions do not match the active map";
        return false;
    }

    return true;
}
}

void WallSessionState::clear() {
    source_ = WallMetadataSource::None;
    active_ = WallMapMetadata{};
    wallState_.clear();
}

bool WallSessionState::activateLocalMetadata(const WallMapMetadata& map, std::string& error) {
    if (!validateSharedWallMetadata(map, error)) {
        return false;
    }

    active_ = map;
    source_ = WallMetadataSource::LocalFile;
    wallState_.resetForMetadata(active_);
    return true;
}

bool WallSessionState::applyHostMetadata(const WallMapMetadata& map, const WallMapQuery& activeMap, std::string& error) {
    if (!validateSharedWallMetadata(map, error)) {
        return false;
    }

    if (!metadataMatchesActiveMap(map, activeMap, error)) {
        return false;
    }

    active_ = map;
    source_ = WallMetadataSource::HostBroadcast;
    wallState_.resetForMetadata(active_);
    return true;
}

bool WallSessionState::applyHostPayload(const std::vector<std::uint8_t>& payload, const WallMapQuery& activeMap, std::string& error) {
    WallMapMetadata map;
    if (!deserializeWallMetadata(payload, map, error)) {
        return false;
    }

    return applyHostMetadata(map, activeMap, error);
}

bool WallSessionState::markWallTouched(std::size_t wallIndex, bool& changed, std::string& error) {
    changed = false;
    error.clear();

    if (!hasActiveMetadata()) {
        error = "cannot mark wall touch without active wall metadata";
        return false;
    }

    return wallState_.markTouched(wallIndex, changed, error);
}

void WallSessionState::resetWallTouchesForNewTurn() {
    wallState_.resetTouches();
}

bool WallSessionState::hasActiveMetadata() const {
    return source_ != WallMetadataSource::None;
}

WallMetadataSource WallSessionState::source() const {
    return source_;
}

const WallMapMetadata* WallSessionState::activeMetadata() const {
    return hasActiveMetadata() ? &active_ : nullptr;
}

const WallRuntimeState& WallSessionState::wallState() const {
    return wallState_;
}

const char* wallMetadataSourceName(WallMetadataSource source) {
    switch (source) {
    case WallMetadataSource::None:
        return "none";
    case WallMetadataSource::LocalFile:
        return "local file";
    case WallMetadataSource::HostBroadcast:
        return "host broadcast";
    }

    return "unknown";
}
