#include "auth_client.h"

#include <chrono>
#include <utility>

namespace openreverse::auth {

namespace {

std::shared_ptr<IAccountApi> CreateDefaultApi()
{
    return std::make_shared<WorkOSAccountApi>(WorkOSAccountApi::FromEnvironment());
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
    std::string ignored;
    session_.RestoreStoredSession(ignored);
}

DesktopAuthClient::~DesktopAuthClient()
{
    CancelLogin();
    JoinWorker();
}

bool DesktopAuthClient::StartLogin(std::string& authorizationUrl, std::string& error)
{
    authorizationUrl.clear();
    error.clear();
    CancelLogin();
    JoinFinishedWorker();
    if (!callbackServer_.Start(error)) return false;

    AuthLaunch launch;
    if (!session_.BeginLogin(callbackServer_.CallbackUri(),
                             AuthSession::TimePoint::clock::now(), launch, error))
    {
        callbackServer_.Stop();
        return false;
    }

    authorizationUrl = std::move(launch.authorizationUrl);
    cancelled_.store(false);
    workerActive_.store(true);
    try
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        worker_ = std::thread([this]() {
            try
            {
                std::string requestTarget;
                std::string listenerError;
                const bool received = callbackServer_.WaitForRequest(
                    AuthSession::LoginTimeout(), cancelled_, requestTarget, listenerError);
                callbackServer_.Stop();
                if (!cancelled_.load())
                {
                    if (received)
                    {
                        std::string callbackError;
                        session_.ProcessCallback(requestTarget,
                            AuthSession::TimePoint::clock::now(), callbackError);
                    }
                    else if (!session_.CheckTimeout(AuthSession::TimePoint::clock::now()))
                    {
                        session_.FailOperation(listenerError.empty()
                            ? "Authentication callback failed." : listenerError);
                    }
                }
            }
            catch (...)
            {
                callbackServer_.Stop();
                if (!cancelled_.load())
                    session_.FailOperation("Authentication operation failed safely.");
            }
            workerActive_.store(false);
        });
    }
    catch (...)
    {
        cancelled_.store(true);
        workerActive_.store(false);
        callbackServer_.Stop();
        session_.CancelLogin();
        authorizationUrl.clear();
        error = "Authentication worker could not be started";
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
        error = "Another account operation is already active";
        return false;
    }
    cancelled_.store(false);
    workerActive_.store(true);
    try
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        worker_ = std::thread([this]() {
            try
            {
                std::string ignored;
                session_.RefreshStoredSession(ignored);
            }
            catch (...)
            {
                session_.FailOperation("Account refresh failed safely.");
            }
            workerActive_.store(false);
        });
    }
    catch (...)
    {
        workerActive_.store(false);
        session_.FailOperation("Account refresh worker could not be started.");
        error = "Account refresh worker could not be started";
        return false;
    }
    return true;
}

void DesktopAuthClient::CancelLogin()
{
    cancelled_.store(true);
    callbackServer_.Stop();
    session_.CancelLogin();
    JoinWorker();
    workerActive_.store(false);
}

bool DesktopAuthClient::Logout(std::string& providerLogoutUrl, std::string& error)
{
    CancelLogin();
    return session_.Logout(providerLogoutUrl, error);
}

AuthStatus DesktopAuthClient::Status() const
{
    return session_.Status();
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
