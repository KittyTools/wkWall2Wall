#include "WallMetadata.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>

namespace {
std::string joinPath(const std::string& directory, const std::string& fileName) {
    if (directory.empty()) {
        return fileName;
    }

    const char last = directory.back();
    if (last == '\\' || last == '/') {
        return directory + fileName;
    }

    return directory + "\\" + fileName;
}

std::string readStringValue(const std::string& path, const char* section, const char* key, const char* fallback = "") {
    char buffer[1024] = {};
    GetPrivateProfileStringA(section, key, fallback, buffer, static_cast<DWORD>(sizeof(buffer)), path.c_str());
    return buffer;
}

std::uint32_t parseHexColor(const std::string& value) {
    std::string text;
    text.reserve(value.size());

    for (const char character : value) {
        if (character != '#') {
            text.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(character))));
        }
    }

    if (text.size() != 6) {
        return 0x00FF00;
    }

    std::uint32_t color = 0;
    for (const char character : text) {
        color <<= 4;
        if (character >= '0' && character <= '9') {
            color |= static_cast<std::uint32_t>(character - '0');
        } else if (character >= 'A' && character <= 'F') {
            color |= static_cast<std::uint32_t>(character - 'A' + 10);
        } else {
            return 0x00FF00;
        }
    }

    return color;
}

bool hasW2wIniExtension(const std::string& fileName) {
    const std::string suffix = ".w2w.ini";
    if (fileName.size() < suffix.size()) {
        return false;
    }

    return std::equal(suffix.rbegin(), suffix.rend(), fileName.rbegin(), [](char left, char right) {
        return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
    });
}

std::string toLowerAscii(const std::string& value) {
    std::string result;
    result.reserve(value.size());
    for (const char character : value) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }
    return result;
}

std::string fileNameOnly(const std::string& path) {
    const std::string::size_type slash = path.find_last_of("\\/");
    if (slash == std::string::npos) {
        return path;
    }
    return path.substr(slash + 1);
}

bool sameText(const std::string& left, const std::string& right) {
    return !left.empty() && !right.empty() && toLowerAscii(left) == toLowerAscii(right);
}

bool sameFileName(const std::string& left, const std::string& right) {
    return sameText(fileNameOnly(left), fileNameOnly(right));
}

bool sameDimensions(const WallMapMetadata& map, const WallMapQuery& query) {
    return map.width > 0 && map.height > 0 && map.width == query.width && map.height == query.height;
}

WallMapMetadata loadWallMetadataFile(const std::string& path) {
    WallMapMetadata map;
    map.name = readStringValue(path, "Map", "Name");
    map.fileName = readStringValue(path, "Map", "File");
    map.sha256 = readStringValue(path, "Map", "Sha256");
    map.width = GetPrivateProfileIntA("Map", "Width", 0, path.c_str());
    map.height = GetPrivateProfileIntA("Map", "Height", 0, path.c_str());

    const int wallCount = GetPrivateProfileIntA("Map", "WallCount", 0, path.c_str());
    if (wallCount < 0 || wallCount > 512) {
        throw std::runtime_error("invalid wall count in " + path);
    }

    for (int index = 1; index <= wallCount; ++index) {
        char section[32] = {};
        sprintf_s(section, "Wall.%d", index);

        const std::string type = readStringValue(path, section, "Type", "Rect");
        if (type != "Rect") {
            continue;
        }

        WallRect wall;
        wall.name = readStringValue(path, section, "Name");
        if (wall.name.empty()) {
            wall.name = "Wall" + std::to_string(index);
        }
        wall.x = GetPrivateProfileIntA(section, "X", 0, path.c_str());
        wall.y = GetPrivateProfileIntA(section, "Y", 0, path.c_str());
        wall.width = GetPrivateProfileIntA(section, "W", 0, path.c_str());
        wall.height = GetPrivateProfileIntA(section, "H", 0, path.c_str());
        wall.color = parseHexColor(readStringValue(path, section, "Color", "00FF00"));

        if (wall.width <= 0 || wall.height <= 0) {
            continue;
        }

        map.walls.push_back(wall);
    }

    return map;
}
}

WallMapMatch::operator bool() const {
    return map != nullptr;
}

std::size_t WallMetadataCatalog::wallCount() const {
    std::size_t total = 0;
    for (const WallMapMetadata& map : maps) {
        total += map.walls.size();
    }
    return total;
}

WallMapMatch WallMetadataCatalog::findBestMatch(const WallMapQuery& query) const {
    if (!query.sha256.empty()) {
        for (const WallMapMetadata& map : maps) {
            if (sameText(map.sha256, query.sha256)) {
                return WallMapMatch{&map, "sha256", true};
            }
        }
    }

    if (!query.fileName.empty() && query.width > 0 && query.height > 0) {
        for (const WallMapMetadata& map : maps) {
            if (sameFileName(map.fileName, query.fileName) && sameDimensions(map, query)) {
                return WallMapMatch{&map, "file name and dimensions", true};
            }
        }
    }

    if (!query.name.empty() && query.width > 0 && query.height > 0) {
        for (const WallMapMetadata& map : maps) {
            if (sameText(map.name, query.name) && sameDimensions(map, query)) {
                return WallMapMatch{&map, "map name and dimensions", false};
            }
        }
    }

    if (!query.fileName.empty()) {
        for (const WallMapMetadata& map : maps) {
            if (sameFileName(map.fileName, query.fileName)) {
                return WallMapMatch{&map, "file name only", false};
            }
        }
    }

    return WallMapMatch{};
}

WallMetadataCatalog loadWallMetadataCatalog(const std::string& directory) {
    WallMetadataCatalog catalog;

    WIN32_FIND_DATAA findData = {};
    const std::string searchPattern = joinPath(directory, "*.w2w.ini");
    HANDLE findHandle = FindFirstFileA(searchPattern.c_str(), &findData);
    if (findHandle == INVALID_HANDLE_VALUE) {
        return catalog;
    }

    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            continue;
        }

        const std::string fileName = findData.cFileName;
        if (!hasW2wIniExtension(fileName)) {
            continue;
        }

        ++catalog.fileCount;

        try {
            WallMapMetadata map = loadWallMetadataFile(joinPath(directory, fileName));
            if (!map.walls.empty()) {
                catalog.maps.push_back(map);
            } else {
                catalog.warnings.push_back(fileName + " has no valid wall rectangles");
            }
        } catch (const std::exception& exception) {
            catalog.warnings.push_back(fileName + ": " + exception.what());
        }
    } while (FindNextFileA(findHandle, &findData));

    FindClose(findHandle);
    return catalog;
}
