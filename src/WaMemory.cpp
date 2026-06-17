#include "WaMemory.h"

#include <Windows.h>

#include <cctype>
#include <iomanip>
#include <sstream>

namespace {
bool isHexByte(const std::string& token) {
    if (token.size() != 2) {
        return false;
    }

    return std::isxdigit(static_cast<unsigned char>(token[0])) != 0
        && std::isxdigit(static_cast<unsigned char>(token[1])) != 0;
}

std::uint8_t parseHexByte(const std::string& token) {
    return static_cast<std::uint8_t>(std::stoul(token, nullptr, 16));
}
}

ProcessModuleView::operator bool() const {
    return base != 0 && size != 0;
}

std::size_t BytePattern::size() const {
    return bytes.size();
}

bool BytePattern::empty() const {
    return bytes.empty();
}

ProcessModuleView currentProcessMainModule() {
    const HMODULE module = GetModuleHandleA(nullptr);
    if (module == nullptr) {
        return ProcessModuleView{};
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return ProcessModuleView{};
    }

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        reinterpret_cast<const std::uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return ProcessModuleView{};
    }

    ProcessModuleView view;
    view.base = reinterpret_cast<std::uintptr_t>(module);
    view.size = nt->OptionalHeader.SizeOfImage;
    return view;
}

std::string formatAddress(std::uintptr_t address) {
    std::ostringstream stream;
    stream << "0x" << std::uppercase << std::hex << address;
    return stream.str();
}

bool parseBytePattern(const std::string& patternText, BytePattern& pattern, std::string& error) {
    pattern = BytePattern{};
    error.clear();

    std::istringstream stream(patternText);
    std::string token;
    while (stream >> token) {
        if (token == "?" || token == "??") {
            pattern.bytes.push_back(0);
            pattern.mask.push_back(false);
            continue;
        }

        if (!isHexByte(token)) {
            error = "invalid byte pattern token: " + token;
            pattern = BytePattern{};
            return false;
        }

        pattern.bytes.push_back(parseHexByte(token));
        pattern.mask.push_back(true);
    }

    if (pattern.empty()) {
        error = "byte pattern is empty";
        return false;
    }

    return true;
}

std::vector<std::uintptr_t> findBytePattern(
    const std::uint8_t* data,
    std::size_t size,
    const BytePattern& pattern,
    std::size_t maxMatches) {
    std::vector<std::uintptr_t> matches;
    if (data == nullptr || pattern.empty() || pattern.size() > size || maxMatches == 0) {
        return matches;
    }

    for (std::size_t offset = 0; offset <= size - pattern.size(); ++offset) {
        bool matched = true;
        for (std::size_t index = 0; index < pattern.size(); ++index) {
            if (pattern.mask[index] && data[offset + index] != pattern.bytes[index]) {
                matched = false;
                break;
            }
        }

        if (matched) {
            matches.push_back(reinterpret_cast<std::uintptr_t>(data + offset));
            if (matches.size() >= maxMatches) {
                break;
            }
        }
    }

    return matches;
}

std::vector<std::uintptr_t> findBytePattern(
    const ProcessModuleView& module,
    const BytePattern& pattern,
    std::size_t maxMatches) {
    if (!module) {
        return {};
    }

    return findBytePattern(
        reinterpret_cast<const std::uint8_t*>(module.base),
        module.size,
        pattern,
        maxMatches);
}
