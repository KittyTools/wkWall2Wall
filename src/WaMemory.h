#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct ProcessModuleView {
    std::uintptr_t base = 0;
    std::size_t size = 0;

    explicit operator bool() const;
};

struct BytePattern {
    std::vector<std::uint8_t> bytes;
    std::vector<bool> mask;

    std::size_t size() const;
    bool empty() const;
};

ProcessModuleView currentProcessMainModule();
std::string formatAddress(std::uintptr_t address);

bool parseBytePattern(const std::string& patternText, BytePattern& pattern, std::string& error);
std::vector<std::uintptr_t> findBytePattern(
    const std::uint8_t* data,
    std::size_t size,
    const BytePattern& pattern,
    std::size_t maxMatches = 1);
std::vector<std::uintptr_t> findBytePattern(
    const ProcessModuleView& module,
    const BytePattern& pattern,
    std::size_t maxMatches = 1);
