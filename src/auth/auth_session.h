#pragma once

#include "account_api.h"
#include "secure_credentials.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace openreverse::auth {

enum class AuthState {
    SignedOut,
    StartingLogin,
    WaitingForBrowser,
    ProcessingCallback,
    ExchangingCode,
    SignedIn,
    Refreshing,
    ReauthenticationRequired,
    Error,
    LoggingOut
};

struct AuthStatus {
    AuthState state = AuthState::SignedOut;
    std::string email;
    std::string message;
    int64_t accessTokenExpiresAtUnix = 0;
    bool providerConfigured = false;
};

struct AuthLaunch {
    std::string authorizationUrl;
};

class AuthSession {
public:
    using TimePoint = std::chrono::steady_clock::time_point;

    AuthSession(std::shared_ptr<IAccountApi> api,
                std::shared_ptr<IAccountCredentialStore> credentials);
    ~AuthSession();

    AuthSession(const AuthSession&) = delete;
    AuthSession& operator=(const AuthSession&) = delete;

    bool RestoreStoredSession(std::string& error);
    bool BeginLogin(const std::string& callbackUri, TimePoint now,
                    AuthLaunch& launch, std::string& error);
    bool ProcessCallback(const std::string& requestTarget, TimePoint now,
                         std::string& error);
    bool CheckTimeout(TimePoint now);
    void CancelLogin();
    void FailOperation(const std::string& message);
    bool RefreshStoredSession(std::string& error);
    bool Logout(std::string& providerLogoutUrl, std::string& error);

    AuthStatus Status() const;
    static const char* StateName(AuthState state);
    static constexpr std::chrono::minutes LoginTimeout() { return std::chrono::minutes(5); }

private:
    struct PendingAuth {
        std::string state;
        std::string codeVerifier;
        std::string callbackUri;
        TimePoint createdAt;
        AuthState cancelState = AuthState::SignedOut;
    };

    void InvalidatePendingLocked();
    void ClearActiveSessionLocked();
    bool ApplyTokenResponse(uint64_t generation, AuthTokenResponse& response,
                            std::string& error);

    std::shared_ptr<IAccountApi> api_;
    std::shared_ptr<IAccountCredentialStore> credentials_;
    mutable std::mutex mutex_;
    AuthState state_ = AuthState::SignedOut;
    std::string message_ = "Not signed in.";
    std::string email_;
    std::string userId_;
    std::string sessionId_;
    std::string accessToken_;
    int64_t accessTokenExpiresAtUnix_ = 0;
    std::optional<PendingAuth> pending_;
    uint64_t generation_ = 0;
};

} // namespace openreverse::auth
