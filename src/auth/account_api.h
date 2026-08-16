#pragma once

#include <cstdint>
#include <string>

namespace openreverse::auth {

struct AccountUser {
    std::string email;
    std::string userId;
};

struct AuthTokenResponse {
    std::string accessToken;
    std::string refreshToken;
    AccountUser user;
    std::string sessionId;
    int64_t expiresAtUnix = 0;
};

class IAccountApi {
public:
    virtual ~IAccountApi() = default;
    virtual bool IsConfigured() const = 0;
    virtual bool BuildAuthorizationUrl(const std::string& redirectUri,
                                       const std::string& state,
                                       const std::string& codeChallenge,
                                       std::string& url, std::string& error) const = 0;
    virtual bool ExchangeAuthorizationCode(const std::string& code,
                                           const std::string& codeVerifier,
                                           const std::string& redirectUri,
                                           AuthTokenResponse& response,
                                           std::string& error) = 0;
    virtual bool Refresh(const std::string& refreshToken,
                         AuthTokenResponse& response, std::string& error) = 0;
    virtual bool BuildLogoutUrl(const std::string& sessionId,
                                std::string& url, std::string& error) const = 0;
};

class WorkOSAccountApi final : public IAccountApi {
public:
    explicit WorkOSAccountApi(std::string clientId);
    static WorkOSAccountApi FromEnvironment();

    bool IsConfigured() const override;
    bool BuildAuthorizationUrl(const std::string& redirectUri,
                               const std::string& state,
                               const std::string& codeChallenge,
                               std::string& url, std::string& error) const override;
    bool ExchangeAuthorizationCode(const std::string& code,
                                   const std::string& codeVerifier,
                                   const std::string& redirectUri,
                                   AuthTokenResponse& response,
                                   std::string& error) override;
    bool Refresh(const std::string& refreshToken,
                 AuthTokenResponse& response, std::string& error) override;
    bool BuildLogoutUrl(const std::string& sessionId,
                        std::string& url, std::string& error) const override;

private:
    bool Authenticate(const std::string& body, AuthTokenResponse& response,
                      std::string& error);
    std::string clientId_;
};

void ClearAuthTokenResponse(AuthTokenResponse& response);

} // namespace openreverse::auth
