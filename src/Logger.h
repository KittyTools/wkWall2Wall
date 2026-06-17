#pragma once

#include <Windows.h>

#include <fstream>
#include <string>

class Logger {
public:
    explicit Logger(const std::string& gameDirectory);
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void info(const std::string& message);
    void warn(const std::string& message);
    void error(const std::string& message);

private:
    std::ofstream stream_;
    CRITICAL_SECTION criticalSection_;
    bool criticalSectionInitialized_ = false;

    void write(const char* level, const std::string& message);
};
