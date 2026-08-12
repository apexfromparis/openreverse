#pragma once
// OpenReverse - Utils: Logger
// Thread-safe logging system with severity levels and ring buffer

#include <string>
#include <vector>
#include <mutex>
#include <cstdarg>
#include <cstdio>
#include <windows.h>

namespace openreverse {

enum class LogLevel { Debug, Info, Warning, Error };

struct LogEntry {
    LogLevel    level;
    std::string message;
    std::string timestamp;
};

class Logger {
public:
    static Logger& Get()
    {
        static Logger instance;
        return instance;
    }

    void Log(LogLevel level, const char* fmt, ...)
    {
        char buf[2048];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        // Timestamp
        SYSTEMTIME st;
        GetLocalTime(&st);
        char ts[64];
        snprintf(ts, sizeof(ts), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        std::lock_guard<std::mutex> lock(mutex_);
        entries_.push_back({ level, std::string(buf), std::string(ts) });

        // Keep max 2000 entries
        if (entries_.size() > 2000)
            entries_.erase(entries_.begin());
    }

    std::vector<LogEntry> Snapshot() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_;
    }
    void Clear() { std::lock_guard<std::mutex> lock(mutex_); entries_.clear(); }

private:
    Logger() = default;
    std::vector<LogEntry> entries_;
    mutable std::mutex mutex_;
};

} // namespace openreverse
