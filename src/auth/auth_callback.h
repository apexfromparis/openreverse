#pragma once

#include <string>

namespace openreverse::auth {

enum class AuthCallbackKind {
    AuthorizationCode,
    ProviderError
};

struct AuthCallback {
    AuthCallbackKind kind = AuthCallbackKind::AuthorizationCode;
    std::string code;
    std::string state;
    std::string providerError;
};

bool ParseAuthCallbackTarget(const std::string& requestTarget, AuthCallback& callback,
                             std::string& error);

} // namespace openreverse::auth
