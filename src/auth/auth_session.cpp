#include "auth_session.h"

#include "auth_callback.h"
#include "pkce.h"

#include <windows.h>

#include <algorithm>
#include <utility>

namespace openreverse::auth {

namespace {

bool ConstantTimeEqual(const std::string& left, const std::string& right)
{
    size_t difference = left.size() ^ right.size();
    const size_t length = (std::max)(left.size(), right.size());
    for (size_t index = 0; index < length; ++index)
    {
        const unsigned char a = index < left.size() ? left[index] : 0;
        const unsigned char b = index < right.size() ? right[index] : 0;
        difference |= a ^ b;
    }
    return difference == 0;
}

} // namespace

AuthSession::AuthSession(std::shared_ptr<IAccountApi> api,
                         std::shared_ptr<IAccountCredentialStore> credentials)
    : api_(std::move(api)), credentials_(std::move(credentials))
{
}

AuthSession::~AuthSession()
{
    std::lock_guard<std::mutex> lock(mutex_);
    InvalidatePendingLocked();
    ClearActiveSessionLocked();
}

bool AuthSession::RestoreStoredSession(std::string& error)
{
    StoredAccountCredential stored;
    const CredentialReadResult result = credentials_->Read(stored, error);
    std::lock_guard<std::mutex> lock(mutex_);
    if (result == CredentialReadResult::Missing)
    {
        state_ = AuthState::SignedOut;
        message_ = "Not signed in.";
        return true;
    }
    if (result == CredentialReadResult::Error)
    {
        state_ = AuthState::Error;
        message_ = error;
        return false;
    }
    email_ = stored.email;
    userId_ = stored.userId;
    sessionId_ = stored.sessionId;
    ClearStoredCredential(stored);
    state_ = AuthState::ReauthenticationRequired;
    message_ = "A stored account session requires refresh or sign-in.";
    return true;
}

bool AuthSession::BeginLogin(const std::string& callbackUri, TimePoint now,
                             AuthLaunch& launch, std::string& error)
{
    launch = {};
    error.clear();
    if (!api_ || !credentials_ || !api_->IsConfigured())
    {
        error = "A public WorkOS desktop client ID is not configured";
        return false;
    }
    PkcePair pkce;
    std::string state;
    if (!GeneratePkcePair(pkce, error) || !GenerateAuthState(state, error))
    {
        SecureClear(pkce.verifier);
        SecureClear(state);
        return false;
    }
    if (!api_->BuildAuthorizationUrl(callbackUri, state, pkce.challenge,
                                      launch.authorizationUrl, error))
    {
        SecureClear(pkce.verifier);
        SecureClear(state);
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == AuthState::WaitingForBrowser || state_ == AuthState::ProcessingCallback ||
        state_ == AuthState::ExchangingCode || state_ == AuthState::Refreshing ||
        state_ == AuthState::LoggingOut)
    {
        SecureClear(pkce.verifier);
        SecureClear(state);
        launch = {};
        error = "Another account operation is already active";
        return false;
    }
    const AuthState cancelState = state_ == AuthState::ReauthenticationRequired
        ? AuthState::ReauthenticationRequired : AuthState::SignedOut;
    InvalidatePendingLocked();
    ++generation_;
    pending_ = PendingAuth{std::move(state), std::move(pkce.verifier), callbackUri,
                           now, cancelState};
    state_ = AuthState::WaitingForBrowser;
    message_ = "Waiting for browser authentication. No account credential has been received.";
    return true;
}

bool AuthSession::ProcessCallback(const std::string& requestTarget, TimePoint now,
                                  std::string& error)
{
    error.clear();
    AuthCallback callback;
    if (!ParseAuthCallbackTarget(requestTarget, callback, error))
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_)
        {
            InvalidatePendingLocked();
            ++generation_;
            state_ = AuthState::Error;
            message_ = error;
        }
        SecureClear(callback.code);
        return false;
    }

    std::string verifier;
    std::string callbackUri;
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!pending_ || state_ != AuthState::WaitingForBrowser)
        {
            error = "Authentication callback has no active login transaction";
            SecureClear(callback.code);
            return false;
        }
        if (now - pending_->createdAt >= LoginTimeout())
        {
            InvalidatePendingLocked();
            ++generation_;
            state_ = AuthState::SignedOut;
            message_ = "Sign-in timed out. Start a new login attempt.";
            error = "Authentication callback arrived after the login timeout";
            SecureClear(callback.code);
            return false;
        }
        state_ = AuthState::ProcessingCallback;
        if (!ConstantTimeEqual(callback.state, pending_->state))
        {
            InvalidatePendingLocked();
            ++generation_;
            state_ = AuthState::Error;
            message_ = "Authentication callback rejected: state mismatch.";
            error = message_;
            SecureClear(callback.code);
            return false;
        }
        if (callback.kind == AuthCallbackKind::ProviderError)
        {
            InvalidatePendingLocked();
            ++generation_;
            state_ = AuthState::Error;
            message_ = "Authentication was not completed by the provider.";
            error = message_;
            return false;
        }
        verifier = std::move(pending_->codeVerifier);
        callbackUri = pending_->callbackUri;
        pending_->state.clear();
        pending_->callbackUri.clear();
        pending_.reset();
        generation = generation_;
        state_ = AuthState::ExchangingCode;
        message_ = "Completing secure authorization code exchange.";
    }

    AuthTokenResponse response;
    const bool exchanged = api_->ExchangeAuthorizationCode(
        callback.code, verifier, callbackUri, response, error);
    SecureClear(callback.code);
    SecureClear(verifier);
    callbackUri.clear();
    if (!exchanged)
    {
        ClearAuthTokenResponse(response);
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation == generation_)
        {
            state_ = AuthState::Error;
            message_ = error.empty() ? "Authorization code exchange failed." : error;
        }
        return false;
    }
    return ApplyTokenResponse(generation, response, error);
}

bool AuthSession::CheckTimeout(TimePoint now)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!pending_ || now - pending_->createdAt < LoginTimeout()) return false;
    InvalidatePendingLocked();
    ++generation_;
    state_ = AuthState::SignedOut;
    message_ = "Sign-in timed out. Start a new login attempt.";
    return true;
}

void AuthSession::CancelLogin()
{
    std::lock_guard<std::mutex> lock(mutex_);
    const AuthState destination = pending_ ? pending_->cancelState :
        (state_ == AuthState::ReauthenticationRequired
            ? AuthState::ReauthenticationRequired : AuthState::SignedOut);
    InvalidatePendingLocked();
    ++generation_;
    if (state_ == AuthState::SignedIn)
    {
        message_ = "Signed in securely.";
    }
    else if (state_ == AuthState::ReauthenticationRequired)
    {
        message_ = "A stored account session requires refresh or sign-in.";
    }
    else
    {
        state_ = destination;
        message_ = destination == AuthState::ReauthenticationRequired
            ? "A stored account session requires refresh or sign-in." : "Not signed in.";
    }
}

void AuthSession::FailOperation(const std::string& message)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != AuthState::WaitingForBrowser &&
        state_ != AuthState::ProcessingCallback && state_ != AuthState::ExchangingCode &&
        state_ != AuthState::Refreshing)
        return;
    InvalidatePendingLocked();
    ++generation_;
    state_ = AuthState::Error;
    message_ = message.empty() ? "Authentication operation failed." : message;
}

bool AuthSession::RefreshStoredSession(std::string& error)
{
    error.clear();
    StoredAccountCredential stored;
    const CredentialReadResult read = credentials_->Read(stored, error);
    if (read != CredentialReadResult::Found)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = read == CredentialReadResult::Missing
            ? AuthState::SignedOut : AuthState::Error;
        message_ = read == CredentialReadResult::Missing
            ? "Not signed in." : error;
        return false;
    }
    uint64_t generation = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++generation_;
        generation = generation_;
        state_ = AuthState::Refreshing;
        message_ = "Refreshing the account session.";
    }
    AuthTokenResponse response;
    const bool refreshed = api_->Refresh(stored.refreshToken, response, error);
    ClearStoredCredential(stored);
    if (!refreshed)
    {
        ClearAuthTokenResponse(response);
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation == generation_)
        {
            state_ = AuthState::ReauthenticationRequired;
            message_ = error.empty() ? "Account session requires sign-in." : error;
        }
        return false;
    }
    return ApplyTokenResponse(generation, response, error);
}

bool AuthSession::Logout(std::string& providerLogoutUrl, std::string& error)
{
    providerLogoutUrl.clear();
    error.clear();
    std::string sessionId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++generation_;
        InvalidatePendingLocked();
        state_ = AuthState::LoggingOut;
        message_ = "Signing out.";
        sessionId = sessionId_;
    }
    std::string remoteError;
    if (!sessionId.empty()) api_->BuildLogoutUrl(sessionId, providerLogoutUrl, remoteError);
    const bool deleted = credentials_->Delete(error);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearActiveSessionLocked();
        state_ = AuthState::SignedOut;
        message_ = deleted ? "Not signed in." : error;
    }
    return deleted;
}

AuthStatus AuthSession::Status() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return {state_, email_, message_, accessTokenExpiresAtUnix_,
            api_ && api_->IsConfigured()};
}

const char* AuthSession::StateName(AuthState state)
{
    switch (state)
    {
    case AuthState::SignedOut: return "Signed out";
    case AuthState::StartingLogin: return "Starting sign-in";
    case AuthState::WaitingForBrowser: return "Waiting for browser";
    case AuthState::ProcessingCallback: return "Processing callback";
    case AuthState::ExchangingCode: return "Exchanging code";
    case AuthState::SignedIn: return "Signed in";
    case AuthState::Refreshing: return "Refreshing";
    case AuthState::ReauthenticationRequired: return "Sign-in required";
    case AuthState::Error: return "Error";
    case AuthState::LoggingOut: return "Signing out";
    }
    return "Unknown";
}

void AuthSession::InvalidatePendingLocked()
{
    if (!pending_) return;
    SecureClear(pending_->state);
    SecureClear(pending_->codeVerifier);
    pending_->callbackUri.clear();
    pending_.reset();
}

void AuthSession::ClearActiveSessionLocked()
{
    SecureClear(accessToken_);
    SecureClear(email_);
    SecureClear(userId_);
    SecureClear(sessionId_);
    accessTokenExpiresAtUnix_ = 0;
}

bool AuthSession::ApplyTokenResponse(uint64_t generation, AuthTokenResponse& response,
                                     std::string& error)
{
    StoredAccountCredential stored{response.refreshToken, response.user.email,
                                   response.user.userId, response.sessionId};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation != generation_ || state_ == AuthState::SignedOut)
        {
            ClearStoredCredential(stored);
            ClearAuthTokenResponse(response);
            error = "Authentication result was cancelled";
            return false;
        }
    }
    if (!credentials_->Store(stored, error))
    {
        ClearStoredCredential(stored);
        ClearAuthTokenResponse(response);
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation == generation_)
        {
            state_ = AuthState::Error;
            message_ = error;
        }
        return false;
    }
    ClearStoredCredential(stored);

    std::lock_guard<std::mutex> lock(mutex_);
    if (generation != generation_)
    {
        std::string ignored;
        credentials_->Delete(ignored);
        ClearAuthTokenResponse(response);
        error = "Authentication result was cancelled";
        return false;
    }
    ClearActiveSessionLocked();
    accessToken_ = std::move(response.accessToken);
    SecureClear(response.refreshToken);
    email_ = std::move(response.user.email);
    userId_ = std::move(response.user.userId);
    sessionId_ = std::move(response.sessionId);
    accessTokenExpiresAtUnix_ = response.expiresAtUnix;
    state_ = AuthState::SignedIn;
    message_ = "Signed in securely.";
    return true;
}

} // namespace openreverse::auth
