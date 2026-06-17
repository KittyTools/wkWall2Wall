#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct WallRect {
    std::string name;
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
    std::uint32_t color = 0x00FF00;
};

struct WallMapMetadata {
    std::string name;
    std::string fileName;
    std::string sha256;
    int width = 0;
    int height = 0;
    std::vector<WallRect> walls;
};

struct WallMapQuery {
    std::string name;
    std::string fileName;
    std::string sha256;
    int width = 0;
    int height = 0;
};

struct WallMapMatch {
    const WallMapMetadata* map = nullptr;
    std::string reason;
    bool exact = false;

    explicit operator bool() const;
};

struct WallMetadataCatalog {
    std::size_t fileCount = 0;
    std::vector<WallMapMetadata> maps;
    std::vector<std::string> warnings;

    std::size_t wallCount() const;
    WallMapMatch findBestMatch(const WallMapQuery& query) const;
};

WallMetadataCatalog loadWallMetadataCatalog(const std::string& directory);
