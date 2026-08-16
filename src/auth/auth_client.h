#pragma once

#include "auth_session.h"
#include "loopback_callback.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace openreverse::auth {

class DesktopAuthClient {
public:
    DesktopAuthClient();
    DesktopAuthClient(std::shared_ptr<IAccountApi> api,
                      std::shared_ptr<IAccountCredentialStore> credentials);
    ~DesktopAuthClient();

    DesktopAuthClient(const DesktopAuthClient&) = delete;
    DesktopAuthClient& operator=(const DesktopAuthClient&) = delete;

    bool StartLogin(std::string& authorizationUrl, std::string& error);
    bool StartRefresh(std::string& error);
    void CancelLogin();
    bool Logout(std::string& providerLogoutUrl, std::string& error);
    AuthStatus Status() const;

private:
    void JoinFinishedWorker();
    void JoinWorker();

    std::shared_ptr<IAccountApi> api_;
    std::shared_ptr<IAccountCredentialStore> credentials_;
    AuthSession session_;
    LoopbackCallbackServer callbackServer_;
    std::atomic_bool cancelled_{false};
    std::atomic_bool workerActive_{false};
    mutable std::mutex workerMutex_;
    std::thread worker_;
};

} // namespace openreverse::auth
