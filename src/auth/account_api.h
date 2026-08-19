#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace openreverse::auth {

struct AccountUser {
    std::string id;          // Supabase Auth auth.users.id (UUID)
    std::string email;
    std::string displayName;
    std::string avatarUrl;
};

struct SubscriptionState {
    std::string plan = "community";  // "community", "pro"
    std::string status;              // "active", "canceled", "past_due", etc.
    bool isProActive = false;
    std::string currentPeriodEnd;    // ISO timestamp or date string
    bool cancelAtPeriodEnd = false;
};

struct AccountSnapshot {
    AccountUser user;
    SubscriptionState subscription;
};

struct AuthTokenResponse {
    std::string accessToken;
    std::string refreshToken;
    AccountUser user;
    int64_t expiresAtUnix = 0;
};

struct AccountServiceConfig {
    std::string supabaseUrl;
    std::string supabasePublishableKey;
    std::string accountApiBaseUrl;
    std::string desktopAuthUrl;
    std::string signupUrl;
    std::string accountManageUrl;
    std::string billingManageUrl;
};

class IAccountApi {
public:
    virtual ~IAccountApi() = default;
    virtual bool IsConfigured() const = 0;
    virtual const AccountServiceConfig& Config() const = 0;
    virtual std::string BuildBrowserAuthorizationUrl(const std::string& codeChallenge,
                                                     const std::string& state,
                                                     const std::string& redirectUri) const = 0;
    virtual bool ExchangeAuthCode(const std::string& authCode,
                                  const std::string& codeVerifier,
                                  AuthTokenResponse& response,
                                  std::string& error) = 0;
    virtual bool SignInWithPassword(const std::string& email,
                                    const std::string& password,
                                    AuthTokenResponse& response,
                                    std::string& error) = 0;
    virtual bool RefreshSession(const std::string& refreshToken,
                                AuthTokenResponse& response,
                                std::string& error) = 0;
    virtual bool SignOut(const std::string& accessToken,
                         std::string& error) = 0;
    virtual bool GetAccountProfile(const std::string& accessToken,
                                   const std::string& expectedUserId,
                                   AccountSnapshot& snapshot,
                                   std::string& error) = 0;
};

class SupabaseAccountApi final : public IAccountApi {
public:
    explicit SupabaseAccountApi(AccountServiceConfig config);
    static SupabaseAccountApi FromEnvironment();

    bool IsConfigured() const override;
    const AccountServiceConfig& Config() const override { return config_; }

    std::string BuildBrowserAuthorizationUrl(const std::string& codeChallenge,
                                             const std::string& state,
                                             const std::string& redirectUri) const override;
    bool ExchangeAuthCode(const std::string& authCode,
                          const std::string& codeVerifier,
                          AuthTokenResponse& response,
                          std::string& error) override;
    bool SignInWithPassword(const std::string& email,
                            const std::string& password,
                            AuthTokenResponse& response,
                            std::string& error) override;
    bool RefreshSession(const std::string& refreshToken,
                        AuthTokenResponse& response,
                        std::string& error) override;
    bool SignOut(const std::string& accessToken,
                 std::string& error) override;
    bool GetAccountProfile(const std::string& accessToken,
                           const std::string& expectedUserId,
                           AccountSnapshot& snapshot,
                           std::string& error) override;

private:
    AccountServiceConfig config_;
};

bool IsValidUuid(const std::string& value);
void ClearAuthTokenResponse(AuthTokenResponse& response);
void ClearAccountSnapshot(AccountSnapshot& snapshot);

} // namespace openreverse::auth
