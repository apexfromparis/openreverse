#include "auth_session.h"
#include "pkce.h"

#include <algorithm>
#include <utility>

namespace openreverse::auth {

AuthSession::AuthSession(std::shared_ptr<IAccountApi> api,
                         std::shared_ptr<IAccountCredentialStore> credentials)
    : api_(std::move(api)), credentials_(std::move(credentials))
{
}

AuthSession::~AuthSession()
{
    std::lock_guard<std::mutex> lock(mutex_);
    ClearActiveSessionLocked();
}

bool AuthSession::RestoreStoredSession(std::string& error)
{
    error.clear();
    StoredAccountCredential credential;
    std::string readError;
    const CredentialReadResult readResult = credentials_
        ? credentials_->Read(credential, readError) : CredentialReadResult::Missing;

    if (readResult == CredentialReadResult::Missing)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::SignedOut;
        message_ = "Not signed in.";
        return true;
    }

    if (readResult == CredentialReadResult::Error)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::ReauthenticationRequired;
        message_ = "Stored account session could not be read.";
        error = readError;
        return false;
    }

    if (!api_ || !api_->IsConfigured())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::ReauthenticationRequired;
        message_ = "Account provider is not configured.";
        ClearStoredCredential(credential);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::Refreshing;
        message_ = "Restoring account session...";
    }

    AuthTokenResponse response;
    std::string refreshError;
    const bool refreshed = api_->RefreshSession(credential.refreshToken, response, refreshError);
    ClearStoredCredential(credential);

    if (!refreshed)
    {
        std::string deleteError;
        if (credentials_) credentials_->Delete(deleteError);

        std::lock_guard<std::mutex> lock(mutex_);
        ClearActiveSessionLocked();
        state_ = AuthState::ReauthenticationRequired;
        message_ = "Session expired or revoked. Please sign in.";
        error = refreshError;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return ApplyTokenResponseLocked(response, error);
}

bool AuthSession::SignInWithPassword(const std::string& email,
                                     const std::string& password,
                                     std::string& error)
{
    error.clear();
    if (!api_ || !api_->IsConfigured())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::Error;
        message_ = "Account provider is not configured.";
        error = message_;
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::SigningIn;
        message_ = "Signing in to OpenReverse account...";
    }

    AuthTokenResponse response;
    const bool success = api_->SignInWithPassword(email, password, response, error);

    if (!success)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::Error;
        message_ = error.empty() ? "Sign in failed." : error;
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return ApplyTokenResponseLocked(response, error);
}

bool AuthSession::RefreshStoredSession(std::string& error)
{
    error.clear();
    StoredAccountCredential credential;
    std::string readError;
    const CredentialReadResult readResult = credentials_
        ? credentials_->Read(credential, readError) : CredentialReadResult::Missing;

    if (readResult != CredentialReadResult::Found || credential.refreshToken.empty())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearActiveSessionLocked();
        state_ = AuthState::SignedOut;
        message_ = "No stored session to refresh.";
        error = message_;
        ClearStoredCredential(credential);
        return false;
    }

    if (!api_ || !api_->IsConfigured())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::Error;
        message_ = "Account provider is not configured.";
        error = message_;
        ClearStoredCredential(credential);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::Refreshing;
        message_ = "Refreshing account session...";
    }

    AuthTokenResponse response;
    const bool refreshed = api_->RefreshSession(credential.refreshToken, response, error);
    ClearStoredCredential(credential);

    if (!refreshed)
    {
        std::string deleteError;
        if (credentials_) credentials_->Delete(deleteError);

        std::lock_guard<std::mutex> lock(mutex_);
        ClearActiveSessionLocked();
        state_ = AuthState::ReauthenticationRequired;
        message_ = "Account session expired. Please sign in again.";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    return ApplyTokenResponseLocked(response, error);
}

bool AuthSession::RefreshAccountSnapshot(std::string& error)
{
    error.clear();
    std::string token;
    std::string userId;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != AuthState::SignedIn || accessToken_.empty())
        {
            error = "Not signed in";
            return false;
        }
        token = accessToken_;
        userId = snapshot_.user.id;
    }

    AccountSnapshot updated;
    const bool fetched = api_ ? api_->GetAccountProfile(token, userId, updated, error) : false;
    SecureClear(token);

    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != AuthState::SignedIn) return false;

    if (fetched)
    {
        snapshot_ = updated;
        accountSyncFailed_ = false;
        message_ = "Account profile up to date.";
        return true;
    }
    else
    {
        accountSyncFailed_ = true;
        message_ = "Signed in — account status unavailable.";
        return false;
    }
}

bool AuthSession::SignOut(std::string& error)
{
    error.clear();
    std::string token;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = AuthState::SigningOut;
        message_ = "Signing out...";
        token = accessToken_;
    }

    bool remoteRevoked = true;
    if (api_ && !token.empty() && api_->IsConfigured())
    {
        std::string remoteError;
        if (!api_->SignOut(token, remoteError))
        {
            remoteRevoked = false;
        }
    }
    SecureClear(token);

    if (credentials_)
    {
        std::string deleteError;
        credentials_->Delete(deleteError);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    ClearActiveSessionLocked();
    state_ = AuthState::SignedOut;
    if (!remoteRevoked)
    {
        message_ = "Signed out locally. Remote session revocation could not be confirmed.";
        error = message_;
    }
    else
    {
        message_ = "Signed out.";
    }
    return true;
}

void AuthSession::FailOperation(const std::string& message)
{
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = AuthState::Error;
    message_ = message.empty() ? "Authentication operation failed." : message;
}

AuthStatus AuthSession::Status() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    AuthStatus status;
    status.state = state_;
    status.email = snapshot_.user.email;
    status.displayName = snapshot_.user.displayName;
    status.userId = snapshot_.user.id;
    status.plan = snapshot_.subscription.plan;
    status.subscriptionStatus = snapshot_.subscription.status;
    status.isProActive = snapshot_.subscription.isProActive;
    status.currentPeriodEnd = snapshot_.subscription.currentPeriodEnd;
    status.cancelAtPeriodEnd = snapshot_.subscription.cancelAtPeriodEnd;
    status.message = message_;
    status.accessTokenExpiresAtUnix = accessTokenExpiresAtUnix_;
    status.providerConfigured = api_ ? api_->IsConfigured() : false;
    status.accountSyncFailed = accountSyncFailed_;
    return status;
}

AccountSnapshot AuthSession::Snapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_;
}

bool AuthSession::IsProActive() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == AuthState::SignedIn && snapshot_.subscription.isProActive;
}

const char* AuthSession::StateName(AuthState state)
{
    switch (state)
    {
    case AuthState::SignedOut: return "Signed Out";
    case AuthState::SigningIn: return "Signing In";
    case AuthState::SignedIn: return "Signed In";
    case AuthState::Refreshing: return "Refreshing Session";
    case AuthState::ReauthenticationRequired: return "Reauthentication Required";
    case AuthState::Error: return "Authentication Error";
    case AuthState::SigningOut: return "Signing Out";
    default: return "Unknown";
    }
}

void AuthSession::ClearActiveSessionLocked()
{
    SecureClear(accessToken_);
    accessTokenExpiresAtUnix_ = 0;
    ClearAccountSnapshot(snapshot_);
    accountSyncFailed_ = false;
}

bool AuthSession::ApplyTokenResponseLocked(AuthTokenResponse& response, std::string& error)
{
    if (response.accessToken.empty() || response.refreshToken.empty() || response.user.id.empty())
    {
        ClearActiveSessionLocked();
        state_ = AuthState::Error;
        message_ = "Received invalid authentication tokens.";
        error = message_;
        ClearAuthTokenResponse(response);
        return false;
    }

    // Persist refresh token securely in Windows Credential Manager
    if (credentials_)
    {
        StoredAccountCredential cred;
        cred.refreshToken = response.refreshToken;
        cred.email = response.user.email;
        cred.userId = response.user.id;
        std::string storeError;
        if (!credentials_->Store(cred, storeError))
        {
            ClearActiveSessionLocked();
            state_ = AuthState::Error;
            message_ = "Could not store account session credentials securely.";
            error = message_;
            ClearAuthTokenResponse(response);
            return false;
        }
    }

    accessToken_ = response.accessToken;
    accessTokenExpiresAtUnix_ = response.expiresAtUnix;
    snapshot_.user = response.user;
    snapshot_.subscription.plan = "community";
    snapshot_.subscription.isProActive = false;

    // Query /api/me for authoritative profile and subscription
    bool profileSynced = false;
    if (api_)
    {
        AccountSnapshot profileSnapshot;
        std::string profileError;
        if (api_->GetAccountProfile(accessToken_, response.user.id, profileSnapshot, profileError))
        {
            snapshot_ = profileSnapshot;
            profileSynced = true;
        }
    }

    state_ = AuthState::SignedIn;
    accountSyncFailed_ = !profileSynced;
    if (profileSynced)
    {
        message_ = "Signed in.";
    }
    else
    {
        message_ = "Signed in — account status unavailable.";
    }
    ClearAuthTokenResponse(response);
    return true;
}

} // namespace openreverse::auth
