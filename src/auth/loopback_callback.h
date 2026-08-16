#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace openreverse::auth {

class LoopbackCallbackServer {
public:
    LoopbackCallbackServer() = default;
    ~LoopbackCallbackServer();

    LoopbackCallbackServer(const LoopbackCallbackServer&) = delete;
    LoopbackCallbackServer& operator=(const LoopbackCallbackServer&) = delete;

    bool Start(std::string& error);
    bool WaitForRequest(std::chrono::milliseconds timeout,
                        const std::atomic_bool& cancelled,
                        std::string& requestTarget, std::string& error);
    void Stop();
    std::string CallbackUri() const;
    uint16_t Port() const;

private:
    mutable std::mutex mutex_;
    uintptr_t listenSocket_ = static_cast<uintptr_t>(~0ULL);
    uint16_t port_ = 0;
    bool winsockStarted_ = false;
};

} // namespace openreverse::auth
