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
    SigningIn,
    SignedIn,
    Refreshing,
    ReauthenticationRequired,
    Error,
    SigningOut
};

struct AuthStatus {
    AuthState state = AuthState::SignedOut;
    std::string email;
    std::string displayName;
    std::string userId;
    std::string plan = "community";
    std::string subscriptionStatus;
    bool isProActive = false;
    std::string currentPeriodEnd;
    bool cancelAtPeriodEnd = false;
    std::string message;
    int64_t accessTokenExpiresAtUnix = 0;
    bool providerConfigured = false;
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
    bool SignInWithPassword(const std::string& email,
                            const std::string& password,
                            std::string& error);
    bool RefreshStoredSession(std::string& error);
    bool RefreshAccountSnapshot(std::string& error);
    bool SignOut(std::string& error);
    void FailOperation(const std::string& message);

    AuthStatus Status() const;
    AccountSnapshot Snapshot() const;
    bool IsProActive() const;
    static const char* StateName(AuthState state);

private:
    void ClearActiveSessionLocked();
    bool ApplyTokenResponseLocked(AuthTokenResponse& response, std::string& error);

    std::shared_ptr<IAccountApi> api_;
    std::shared_ptr<IAccountCredentialStore> credentials_;
    mutable std::mutex mutex_;
    AuthState state_ = AuthState::SignedOut;
    std::string message_ = "Not signed in.";
    std::string accessToken_;
    int64_t accessTokenExpiresAtUnix_ = 0;
    AccountSnapshot snapshot_;
};

} // namespace openreverse::auth
