#include "auth/account_api.h"
#include "auth/auth_callback.h"
#include "auth/auth_session.h"
#include "auth/loopback_callback.h"
#include "auth/pkce.h"
#include "auth/secure_credentials.h"

#include <windows.h>

#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace openreverse::auth;

int failures = 0;

void Expect(bool condition, const char* message)
{
    if (!condition)
    {
        std::cerr << "FAILED: " << message << '\n';
        ++failures;
    }
}

class MemoryCredentialStore final : public IAccountCredentialStore {
public:
    bool Store(const StoredAccountCredential& credential, std::string& error) override
    {
        error.clear();
        stored = credential;
        ++stores;
        return allowStore;
    }

    CredentialReadResult Read(StoredAccountCredential& credential,
                              std::string& error) const override
    {
        error.clear();
        if (!stored) return CredentialReadResult::Missing;
        credential = *stored;
        return CredentialReadResult::Found;
    }

    bool Delete(std::string& error) override
    {
        error.clear();
        stored.reset();
        ++deletes;
        return true;
    }

    std::optional<StoredAccountCredential> stored;
    int stores = 0;
    int deletes = 0;
    bool allowStore = true;
};

class FakeAccountApi final : public IAccountApi {
public:
    bool IsConfigured() const override { return configured; }

    bool BuildAuthorizationUrl(const std::string& redirectUri,
                               const std::string& state,
                               const std::string& challenge,
                               std::string& url, std::string& error) const override
    {
        error.clear();
        if (!configured || redirectUri.empty() || state.empty() || challenge.empty())
            return false;
        url = "https://auth.example.test/authorize?state=" + state +
            "&code_challenge=" + challenge + "&code_challenge_method=S256";
        return true;
    }

    bool ExchangeAuthorizationCode(const std::string& code,
                                   const std::string& verifier,
                                   const std::string& redirectUri,
                                   AuthTokenResponse& response,
                                   std::string& error) override
    {
        ++exchanges;
        if (code != "valid-code" || !IsValidPkceVerifier(verifier) ||
            redirectUri.rfind("http://127.0.0.1:", 0) != 0)
        {
            error = code == "expired-code" ? "Authorization code expired" :
                "Authorization code rejected";
            return false;
        }
        response = MakeResponse("rotating-refresh-one");
        return true;
    }

    bool Refresh(const std::string& refreshToken,
                 AuthTokenResponse& response, std::string& error) override
    {
        ++refreshes;
        if (refreshToken != "stored-refresh")
        {
            error = "Stored session requires sign-in";
            return false;
        }
        response = MakeResponse("rotating-refresh-two");
        return true;
    }

    bool BuildLogoutUrl(const std::string& sessionId,
                        std::string& url, std::string& error) const override
    {
        error.clear();
        if (sessionId.empty()) return false;
        url = "https://auth.example.test/logout";
        return true;
    }

    static AuthTokenResponse MakeResponse(const std::string& refresh)
    {
        AuthTokenResponse response;
        response.accessToken = "memory-only-access-value";
        response.refreshToken = refresh;
        response.user = {"tester@example.test", "user-test"};
        response.sessionId = "session-test";
        response.expiresAtUnix = 2000000000;
        return response;
    }

    bool configured = true;
    int exchanges = 0;
    int refreshes = 0;
};

std::string QueryValue(const std::string& url, const std::string& name)
{
    const std::string marker = name + "=";
    const size_t start = url.find(marker);
    if (start == std::string::npos) return {};
    const size_t valueStart = start + marker.size();
    const size_t end = url.find('&', valueStart);
    return url.substr(valueStart, end == std::string::npos ? std::string::npos : end - valueStart);
}

AuthLaunch Begin(AuthSession& session, AuthSession::TimePoint now)
{
    AuthLaunch launch;
    std::string error;
    Expect(session.BeginLogin("http://127.0.0.1:49152/callback", now, launch, error),
           "signed-out session can begin PKCE login");
    return launch;
}

void TestPkce()
{
    const std::string verifier =
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    std::string challenge;
    std::string error;
    Expect(CreateS256Challenge(verifier, challenge, error),
           "RFC 7636 verifier produces a challenge");
    Expect(challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
           "RFC 7636 S256 test vector matches");
    std::string repeated;
    Expect(CreateS256Challenge(verifier, repeated, error) && repeated == challenge,
           "the same verifier produces the same challenge");
    std::string different;
    Expect(CreateS256Challenge(verifier + "A", different, error) && different != challenge,
           "different verifiers produce different challenges");

    PkcePair pair;
    Expect(GeneratePkcePair(pair, error), "cryptographic PKCE generation succeeds");
    Expect(pair.verifier.size() >= 43 && pair.verifier.size() <= 128,
           "generated verifier length follows RFC 7636");
    Expect(IsValidPkceVerifier(pair.verifier), "generated verifier characters are valid");
    Expect(pair.challenge.size() == 43 && pair.challenge.find('=') == std::string::npos,
           "generated challenge is unpadded base64url");
    std::string state;
    Expect(GenerateAuthState(state, error) && state.size() == 43,
           "authentication state uses 256 bits of random data");
    SecureClear(pair.verifier);
    SecureClear(state);
}

void TestCallbackParser()
{
    AuthCallback callback;
    std::string error;
    Expect(ParseAuthCallbackTarget("/callback?code=short-code&state=random-state",
                                   callback, error),
           "bounded authorization code and state callback is accepted");
    Expect(callback.code == "short-code" && callback.state == "random-state",
           "callback fields are parsed exactly");
    Expect(!ParseAuthCallbackTarget("/other?code=a&state=b", callback, error),
           "unexpected callback paths are rejected");
    Expect(!ParseAuthCallbackTarget("/callback?state=b", callback, error),
           "missing code is rejected");
    Expect(!ParseAuthCallbackTarget("/callback?code=a", callback, error),
           "missing state is rejected");
    Expect(!ParseAuthCallbackTarget("/callback?code=a&code=b&state=c", callback, error),
           "duplicate code is rejected");
    Expect(!ParseAuthCallbackTarget("/callback?code=a&state=b&state=c", callback, error),
           "duplicate state is rejected");
    Expect(!ParseAuthCallbackTarget("/callback?code=%ZZ&state=b", callback, error),
           "malformed percent encoding is rejected");
    Expect(!ParseAuthCallbackTarget("/callback?code=a&state=b&extra=c", callback, error),
           "unknown callback fields are rejected");
    Expect(!ParseAuthCallbackTarget("/callback?code=" + std::string(2049, 'a') +
                                    "&state=b", callback, error),
           "oversized authorization codes are rejected");
    const std::vector<std::string> forbidden = {
        "token", "access_token", "refresh_token", "api_key", "client_secret", "secret"
    };
    for (const auto& field : forbidden)
    {
        const std::string target = "/callback?code=a&state=b&" + field + "=value";
        Expect(!ParseAuthCallbackTarget(target, callback, error),
               "credential-bearing callback field is rejected");
    }
    Expect(ParseAuthCallbackTarget("/callback?error=access_denied&state=random-state",
                                   callback, error) &&
           callback.kind == AuthCallbackKind::ProviderError,
           "bounded provider cancellation is parsed without exposing details");
    Expect(ParseAuthCallbackTarget(
               "/callback?error=access_denied&error_description=User+cancelled&state=random-state",
               callback, error) && callback.kind == AuthCallbackKind::ProviderError,
           "bounded provider error descriptions are ignored safely");
}

void TestSessionLifecycle()
{
    auto api = std::make_shared<FakeAccountApi>();
    auto storage = std::make_shared<MemoryCredentialStore>();
    AuthSession session(api, storage);
    const auto now = AuthSession::TimePoint::clock::now();

    std::string error;
    Expect(session.Status().state == AuthState::SignedOut,
           "new authentication session is signed out");
    Expect(!session.ProcessCallback("/callback?code=valid-code&state=no-transaction", now,
                                    error),
           "signed-out to signed-in transition without a transaction is rejected");

    const AuthLaunch launch = Begin(session, now);
    const std::string state = QueryValue(launch.authorizationUrl, "state");
    Expect(session.Status().state == AuthState::WaitingForBrowser,
           "login enters waiting-for-browser state");
    Expect(session.ProcessCallback("/callback?code=valid-code&state=" + state,
                                   now + std::chrono::seconds(1), error),
           "valid state completes one code exchange");
    Expect(session.Status().state == AuthState::SignedIn && storage->stores == 1,
           "successful exchange stores one refresh credential and signs in");
    Expect(!session.ProcessCallback("/callback?code=valid-code&state=" + state,
                                    now + std::chrono::seconds(2), error) &&
           storage->stores == 1,
           "authorization callback replay is rejected");
    std::string logoutUrl;
    Expect(session.Logout(logoutUrl, error) && session.Status().state == AuthState::SignedOut &&
           !storage->stored && storage->deletes == 1,
           "logout deletes only the account credential and returns to signed out");
    Expect(logoutUrl.rfind("https://", 0) == 0,
           "logout uses an HTTPS provider endpoint");

    const AuthLaunch wrongLaunch = Begin(session, now);
    (void)wrongLaunch;
    Expect(!session.ProcessCallback("/callback?code=valid-code&state=wrong-state", now, error) &&
           session.Status().state == AuthState::Error,
           "wrong state rejects and invalidates the transaction");

    const AuthLaunch cancelLaunch = Begin(session, now);
    const std::string cancelState = QueryValue(cancelLaunch.authorizationUrl, "state");
    const int storesBeforeCancel = storage->stores;
    session.CancelLogin();
    Expect(session.Status().state == AuthState::SignedOut,
           "browser login cancellation returns to signed out");
    Expect(!session.ProcessCallback("/callback?code=valid-code&state=" + cancelState,
                                    now + std::chrono::seconds(1), error) &&
           storage->stores == storesBeforeCancel,
           "callback after cancellation cannot store a credential");

    const AuthLaunch timeoutLaunch = Begin(session, now);
    const std::string timeoutState = QueryValue(timeoutLaunch.authorizationUrl, "state");
    Expect(session.CheckTimeout(now + AuthSession::LoginTimeout()),
           "pending browser login expires at the configured timeout");
    Expect(session.Status().state == AuthState::SignedOut,
           "timeout returns to signed out");
    Expect(!session.ProcessCallback("/callback?code=valid-code&state=" + timeoutState,
                                    now + AuthSession::LoginTimeout() +
                                        std::chrono::seconds(1), error),
           "late callback after timeout is rejected");

    const AuthLaunch invalidLaunch = Begin(session, now);
    const std::string invalidState = QueryValue(invalidLaunch.authorizationUrl, "state");
    Expect(!session.ProcessCallback("/callback?code=expired-code&state=" + invalidState,
                                    now, error) && session.Status().state == AuthState::Error,
           "expired or invalid code exchange enters error state");

    const AuthLaunch rejectedLaunch = Begin(session, now);
    const std::string rejectedState = QueryValue(rejectedLaunch.authorizationUrl, "state");
    Expect(!session.ProcessCallback("/callback?code=invalid-code&state=" + rejectedState,
                                    now, error) && session.Status().state == AuthState::Error,
           "deterministic invalid code exchange is rejected");
}

void TestRefresh()
{
    auto api = std::make_shared<FakeAccountApi>();
    auto storage = std::make_shared<MemoryCredentialStore>();
    storage->stored = StoredAccountCredential{
        "stored-refresh", "tester@example.test", "user-test", "session-test"};
    AuthSession session(api, storage);
    std::string error;
    Expect(session.RestoreStoredSession(error) &&
           session.Status().state == AuthState::ReauthenticationRequired,
           "stored refresh credential is not treated as an active access session");
    Expect(session.RefreshStoredSession(error) && session.Status().state == AuthState::SignedIn,
           "valid stored refresh session can be refreshed");
    Expect(storage->stored && storage->stored->refreshToken == "rotating-refresh-two",
           "rotated refresh credential replaces the previous secure credential");

    auto failingStorage = std::make_shared<MemoryCredentialStore>();
    failingStorage->stored = StoredAccountCredential{
        "invalid-refresh", "tester@example.test", "user-test", "session-test"};
    AuthSession failing(api, failingStorage);
    Expect(failing.RestoreStoredSession(error), "invalid stored session metadata can be loaded");
    Expect(!failing.RefreshStoredSession(error) &&
           failing.Status().state == AuthState::ReauthenticationRequired,
           "refresh failure requires explicit reauthentication");
}

void TestWindowsCredentialStore()
{
    const std::string target = "OpenReverse.Account.Tests." +
        std::to_string(GetCurrentProcessId()) + "." + std::to_string(GetTickCount64());
    WindowsAccountCredentialStore storage(target);
    std::string error;
    storage.Delete(error);
    StoredAccountCredential read;
    Expect(storage.Read(read, error) == CredentialReadResult::Missing,
           "isolated Windows credential target starts missing");
    StoredAccountCredential first{
        "test-refresh-one", "tester@example.test", "user-one", "session-one"};
    Expect(storage.Store(first, error), "Windows Credential Manager stores account session");
    Expect(storage.Read(read, error) == CredentialReadResult::Found &&
           read.refreshToken == first.refreshToken && read.email == first.email,
           "Windows Credential Manager reads the isolated account session");
    ClearStoredCredential(read);
    StoredAccountCredential replacement{
        "test-refresh-two", "second@example.test", "user-two", "session-two"};
    Expect(storage.Store(replacement, error), "Windows Credential Manager replaces account session");
    Expect(storage.Read(read, error) == CredentialReadResult::Found &&
           read.refreshToken == replacement.refreshToken && read.email == replacement.email,
           "replacement is read from the isolated credential target");
    ClearStoredCredential(read);
    Expect(storage.Delete(error), "Windows Credential Manager deletes account session");
    Expect(storage.Read(read, error) == CredentialReadResult::Missing,
           "deleted Windows credential target is missing");
}

void TestProviderAndLoopbackConfiguration()
{
    WorkOSAccountApi provider("client_public_test");
    std::string url;
    std::string error;
    const std::string value(43, 'a');
    Expect(provider.BuildAuthorizationUrl("http://127.0.0.1:49152/callback", value,
                                          value, url, error),
           "public provider builds loopback PKCE authorization URL");
    Expect(url.rfind("https://api.workos.com/", 0) == 0 &&
           url.find("code_challenge_method=S256") != std::string::npos &&
           url.find("client_secret") == std::string::npos,
           "authorization request is HTTPS, S256, and contains no client secret");
    Expect(!provider.BuildAuthorizationUrl(
               "http://127.0.0.1:49152/callback/extra", value, value, url, error) &&
           !provider.BuildAuthorizationUrl(
               "http://127.0.0.1:49152@attacker.test/callback", value, value, url, error),
           "provider rejects non-exact or ambiguous loopback redirect URIs");

    LoopbackCallbackServer server;
    Expect(server.Start(error), "loopback callback listener starts");
    Expect(server.Port() != 0 &&
           server.CallbackUri().rfind("http://127.0.0.1:", 0) == 0 &&
           server.CallbackUri().find("/callback") != std::string::npos,
           "callback listener binds loopback with an ephemeral port and strict path");
    server.Stop();
    Expect(server.Port() == 0, "loopback callback listener closes immediately on stop");
}

} // namespace

int main()
{
    TestPkce();
    TestCallbackParser();
    TestSessionLifecycle();
    TestRefresh();
    TestWindowsCredentialStore();
    TestProviderAndLoopbackConfiguration();
    if (failures == 0)
    {
        std::cout << "All OpenReverse authentication tests passed.\n";
        return 0;
    }
    std::cerr << failures << " authentication test(s) failed.\n";
    return 1;
}
