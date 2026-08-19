#include "auth_client.h"
#include "pkce.h"

#include <utility>

namespace openreverse::auth {

namespace {

std::shared_ptr<IAccountApi> CreateDefaultApi()
{
    return std::make_shared<SupabaseAccountApi>(SupabaseAccountApi::FromEnvironment());
}

std::shared_ptr<IAccountCredentialStore> CreateDefaultCredentialStore()
{
    return std::make_shared<WindowsAccountCredentialStore>();
}

} // namespace

DesktopAuthClient::DesktopAuthClient()
    : DesktopAuthClient(CreateDefaultApi(), CreateDefaultCredentialStore())
{
}

DesktopAuthClient::DesktopAuthClient(
    std::shared_ptr<IAccountApi> api,
    std::shared_ptr<IAccountCredentialStore> credentials)
    : api_(std::move(api)), credentials_(std::move(credentials)),
      session_(api_, credentials_)
{
    // Attempt non-blocking startup restore in background
    std::string ignored;
    StartRefresh(ignored);
}

DesktopAuthClient::~DesktopAuthClient()
{
    JoinWorker();
}

bool DesktopAuthClient::StartPasswordLogin(std::string email, std::string password, std::string& error)
{
    error.clear();
    JoinFinishedWorker();
    if (workerActive_.load())
    {
        error = "Another account operation is already active.";
        SecureClear(password);
        return false;
    }

    workerActive_.store(true);
    try
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        worker_ = std::thread([this, userEmail = std::move(email), userPass = std::move(password)]() mutable {
            try
            {
                std::string loginError;
                session_.SignInWithPassword(userEmail, userPass, loginError);
            }
            catch (...)
            {
                session_.FailOperation("Authentication operation failed unexpectedly.");
            }
            SecureClear(userPass);
            workerActive_.store(false);
        });
    }
    catch (...)
    {
        workerActive_.store(false);
        SecureClear(password);
        error = "Could not start sign-in worker thread.";
        session_.FailOperation(error);
        return false;
    }
    return true;
}

bool DesktopAuthClient::StartRefresh(std::string& error)
{
    error.clear();
    JoinFinishedWorker();
    if (workerActive_.load())
    {
        error = "Another account operation is already active.";
        return false;
    }

    workerActive_.store(true);
    try
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        worker_ = std::thread([this]() {
            try
            {
                std::string refreshError;
                session_.RestoreStoredSession(refreshError);
            }
            catch (...)
            {
                session_.FailOperation("Session restoration failed unexpectedly.");
            }
            workerActive_.store(false);
        });
    }
    catch (...)
    {
        workerActive_.store(false);
        error = "Could not start session restoration worker thread.";
        return false;
    }
    return true;
}

bool DesktopAuthClient::StartProfileRefresh(std::string& error)
{
    error.clear();
    JoinFinishedWorker();
    if (workerActive_.load())
    {
        error = "Another account operation is already active.";
        return false;
    }

    workerActive_.store(true);
    try
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        worker_ = std::thread([this]() {
            try
            {
                std::string profileError;
                session_.RefreshAccountSnapshot(profileError);
            }
            catch (...)
            {
                session_.FailOperation("Profile refresh failed unexpectedly.");
            }
            workerActive_.store(false);
        });
    }
    catch (...)
    {
        workerActive_.store(false);
        error = "Could not start profile refresh worker thread.";
        return false;
    }
    return true;
}

bool DesktopAuthClient::SignOut(std::string& error)
{
    JoinWorker();
    return session_.SignOut(error);
}

AuthStatus DesktopAuthClient::Status() const
{
    return session_.Status();
}

AccountSnapshot DesktopAuthClient::Snapshot() const
{
    return session_.Snapshot();
}

bool DesktopAuthClient::IsProActive() const
{
    return session_.IsProActive();
}

const AccountServiceConfig& DesktopAuthClient::Config() const
{
    static const AccountServiceConfig kEmptyConfig{};
    return api_ ? api_->Config() : kEmptyConfig;
}

void DesktopAuthClient::JoinFinishedWorker()
{
    if (!workerActive_.load()) JoinWorker();
}

void DesktopAuthClient::JoinWorker()
{
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        if (worker_.joinable() && worker_.get_id() != std::this_thread::get_id())
            worker = std::move(worker_);
    }
    if (worker.joinable()) worker.join();
}

} // namespace openreverse::auth
