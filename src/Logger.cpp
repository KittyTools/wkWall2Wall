#include "Logger.h"

#include <Windows.h>

#include <iomanip>
#include <sstream>

Logger::Logger(const std::string& gameDirectory) {
    InitializeCriticalSection(&criticalSection_);
    criticalSectionInitialized_ = true;
    stream_.open(gameDirectory + "\\wkWall2Wall.log", std::ios::app);
}

Logger::~Logger() {
    if (criticalSectionInitialized_) {
        DeleteCriticalSection(&criticalSection_);
    }
}

void Logger::info(const std::string& message) {
    write("INFO", message);
}

void Logger::warn(const std::string& message) {
    write("WARN", message);
}

void Logger::error(const std::string& message) {
    write("ERROR", message);
}

void Logger::write(const char* level, const std::string& message) {
    if (criticalSectionInitialized_) {
        EnterCriticalSection(&criticalSection_);
    }

    if (!stream_.is_open()) {
        if (criticalSectionInitialized_) {
            LeaveCriticalSection(&criticalSection_);
        }
        return;
    }

    SYSTEMTIME time;
    GetLocalTime(&time);

    stream_ << '['
            << std::setfill('0') << std::setw(4) << time.wYear << '-'
            << std::setw(2) << time.wMonth << '-'
            << std::setw(2) << time.wDay << ' '
            << std::setw(2) << time.wHour << ':'
            << std::setw(2) << time.wMinute << ':'
            << std::setw(2) << time.wSecond
            << "] [" << level << "] " << message << std::endl;

    if (criticalSectionInitialized_) {
        LeaveCriticalSection(&criticalSection_);
    }
}
