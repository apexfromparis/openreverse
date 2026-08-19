#pragma once

#include "auth_session.h"

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

    bool StartBrowserLogin(std::string& error);
    bool CancelBrowserLogin(std::string& error);
    bool StartPasswordLogin(std::string email, std::string password, std::string& error);
    bool StartRefresh(std::string& error);
    bool StartProfileRefresh(std::string& error);
    bool SignOut(std::string& error);

    AuthStatus Status() const;
    AccountSnapshot Snapshot() const;
    bool IsProActive() const;
    const AccountServiceConfig& Config() const;

private:
    void JoinFinishedWorker();
    void JoinWorker();

    std::shared_ptr<IAccountApi> api_;
    std::shared_ptr<IAccountCredentialStore> credentials_;
    AuthSession session_;
    std::atomic_bool workerActive_{false};
    std::atomic_bool browserCancelled_{false};
    mutable std::mutex workerMutex_;
    std::thread worker_;
};

} // namespace openreverse::auth
