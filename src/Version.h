#pragma once

#include <cstdint>
#include <string>

struct WaVersion {
    std::uint16_t major = 0;
    std::uint16_t minor = 0;
    std::uint16_t patch = 0;
    std::uint16_t build = 0;

    bool valid() const;
    std::string toString() const;
    std::uint64_t packed() const;
};

WaVersion getCurrentWaVersion();
bool isSupportedWaVersion(const WaVersion& version);
