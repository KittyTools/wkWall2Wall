#include "Version.h"

#include <Windows.h>

#include <sstream>
#include <vector>

bool WaVersion::valid() const {
    return packed() != 0;
}

std::string WaVersion::toString() const {
    std::ostringstream stream;
    stream << major << '.' << minor << '.' << patch << '.' << build;
    return stream.str();
}

std::uint64_t WaVersion::packed() const {
    return (static_cast<std::uint64_t>(major) << 48)
        | (static_cast<std::uint64_t>(minor) << 32)
        | (static_cast<std::uint64_t>(patch) << 16)
        | static_cast<std::uint64_t>(build);
}

WaVersion getCurrentWaVersion() {
    char modulePath[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, modulePath, MAX_PATH)) {
        return {};
    }

    DWORD handle = 0;
    const DWORD size = GetFileVersionInfoSizeA(modulePath, &handle);
    if (size == 0) {
        return {};
    }

    std::vector<char> data(size);
    if (!GetFileVersionInfoA(modulePath, handle, size, data.data())) {
        return {};
    }

    VS_FIXEDFILEINFO* info = nullptr;
    UINT infoSize = 0;
    if (!VerQueryValueA(data.data(), "\\", reinterpret_cast<LPVOID*>(&info), &infoSize) || info == nullptr) {
        return {};
    }

    if (info->dwSignature != 0xFEEF04BD) {
        return {};
    }

    WaVersion version;
    version.major = HIWORD(info->dwFileVersionMS);
    version.minor = LOWORD(info->dwFileVersionMS);
    version.patch = HIWORD(info->dwFileVersionLS);
    version.build = LOWORD(info->dwFileVersionLS);
    return version;
}

bool isSupportedWaVersion(const WaVersion& version) {
    const WaVersion minimum{3, 8, 0, 0};
    const WaVersion maximumExclusive{3, 9, 0, 0};
    return version.valid() && version.packed() >= minimum.packed() && version.packed() < maximumExclusive.packed();
}
