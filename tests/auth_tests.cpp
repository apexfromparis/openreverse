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
    FakeAccountApi()
    {
        config.supabaseUrl = "https://auth.example.test";
        config.supabasePublishableKey = "real_anon_key_for_testing";
        config.accountApiBaseUrl = "https://example.test";
        config.signupUrl = "https://example.test/signup";
        config.accountManageUrl = "https://example.test/account";
        config.billingManageUrl = "https://example.test/account";
    }

    bool IsConfigured() const override { return configured; }
    const AccountServiceConfig& Config() const override { return config; }

    bool SignInWithPassword(const std::string& email,
                            const std::string& password,
                            AuthTokenResponse& response,
                            std::string& error) override
    {
        ++signIns;
        if (!configured)
        {
            error = "Provider not configured";
            return false;
        }
        if (email == "valid@example.test" && password == "correct_password")
        {
            response.accessToken = "access-token-1";
            response.refreshToken = "refresh-token-1";
            response.user.id = "11111111-1111-1111-1111-111111111111";
            response.user.email = email;
            response.user.displayName = "Valid User";
            response.expiresAtUnix = 2000000000;
            return true;
        }
        error = "Invalid login credentials";
        return false;
    }

    bool RefreshSession(const std::string& refreshToken,
                        AuthTokenResponse& response,
                        std::string& error) override
    {
        ++refreshes;
        if (!configured)
        {
            error = "Provider not configured";
            return false;
        }
        if (refreshToken == "stored-refresh" || refreshToken == "refresh-token-1")
        {
            response.accessToken = "access-token-rotated";
            response.refreshToken = "refresh-token-rotated";
            response.user.id = "11111111-1111-1111-1111-111111111111";
            response.user.email = "valid@example.test";
            response.user.displayName = "Valid User";
            response.expiresAtUnix = 2000000000;
            return true;
        }
        error = "Session expired or revoked";
        return false;
    }

    bool SignOut(const std::string&, std::string& error) override
    {
        ++signOuts;
        if (!signOutSuccess)
        {
            error = "Remote logout connection failed";
            return false;
        }
        return true;
    }

    bool GetAccountProfile(const std::string& accessToken,
                           const std::string& expectedUserId,
                           AccountSnapshot& snapshot,
                           std::string& error) override
    {
        ++profileRequests;
        if (!configured || accessToken.empty())
        {
            error = "Invalid access token";
            return false;
        }

        if (profileErrorMode)
        {
            error = "Account endpoint temporarily unavailable";
            return false;
        }

        snapshot = mockSnapshot;
        if (!expectedUserId.empty() && snapshot.user.id != expectedUserId)
        {
            error = "Account identity mismatch between auth session and profile";
            return false;
        }
        return true;
    }

    AccountServiceConfig config;
    AccountSnapshot mockSnapshot{
        {"11111111-1111-1111-1111-111111111111", "valid@example.test", "Valid User", ""},
        {"community", "", false, "", false}
    };
    bool configured = true;
    bool profileErrorMode = false;
    bool signOutSuccess = true;
    int signIns = 0;
    int refreshes = 0;
    int signOuts = 0;
    int profileRequests = 0;
};

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

void TestUuidValidation()
{
    Expect(IsValidUuid("123e4567-e89b-12d3-a456-426614174000"), "valid standard UUID is accepted");
    Expect(IsValidUuid("00000000-0000-0000-0000-000000000000"), "all-zero UUID is accepted");
    Expect(IsValidUuid("ffffffff-ffff-ffff-ffff-ffffffffffff"), "all-f UUID is accepted");
    Expect(!IsValidUuid("123e4567-e89b-12d3-a456-42661417400"), "too short UUID is rejected");
    Expect(!IsValidUuid("123e4567-e89b-12d3-a456-4266141740000"), "too long UUID is rejected");
    Expect(!IsValidUuid("123e4567_e89b-12d3-a456-426614174000"), "wrong delimiter UUID is rejected");
    Expect(!IsValidUuid("123e4567-e89b-12d3-a456-42661417400g"), "non-hex character UUID is rejected");
    Expect(!IsValidUuid(""), "empty string is rejected");
}

void TestConfigurationValidation()
{
    AccountServiceConfig emptyConfig;
    SupabaseAccountApi emptyApi(emptyConfig);
    Expect(!emptyApi.IsConfigured(), "empty configuration is not configured");

    AccountServiceConfig placeholderConfig;
    placeholderConfig.supabaseUrl = "https://your-project.supabase.co";
    placeholderConfig.supabasePublishableKey = "client_publishable_placeholder";
    placeholderConfig.accountApiBaseUrl = "https://example.com";
    SupabaseAccountApi placeholderApi(placeholderConfig);
    Expect(!placeholderApi.IsConfigured(), "placeholder configuration is rejected");

    AccountServiceConfig validConfig;
    validConfig.supabaseUrl = "https://xyz123.supabase.co";
    validConfig.supabasePublishableKey = "sb_publishable_key_xyz123";
    validConfig.accountApiBaseUrl = "https://openreverse.dev";
    SupabaseAccountApi validApi(validConfig);
    Expect(validApi.IsConfigured(), "legitimate HTTPS configuration is accepted");
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
        "test-refresh-one", "tester@example.test", "11111111-1111-1111-1111-111111111111", "session-one"};
    Expect(storage.Store(first, error), "Windows Credential Manager stores account session");
    Expect(storage.Read(read, error) == CredentialReadResult::Found &&
           read.refreshToken == first.refreshToken && read.email == first.email &&
           read.userId == first.userId,
           "Windows Credential Manager reads the isolated account session");
    ClearStoredCredential(read);
    StoredAccountCredential replacement{
        "test-refresh-two", "second@example.test", "22222222-2222-2222-2222-222222222222", "session-two"};
    Expect(storage.Store(replacement, error), "Windows Credential Manager replaces account session");
    Expect(storage.Read(read, error) == CredentialReadResult::Found &&
           read.refreshToken == replacement.refreshToken && read.email == replacement.email &&
           read.userId == replacement.userId,
           "replacement is read from the isolated credential target");
    ClearStoredCredential(read);
    Expect(storage.Delete(error), "Windows Credential Manager deletes account session");
    Expect(storage.Read(read, error) == CredentialReadResult::Missing,
           "deleted Windows credential target is missing");
}

void TestPasswordAuthAndSessionLifecycle()
{
    auto api = std::make_shared<FakeAccountApi>();
    auto storage = std::make_shared<MemoryCredentialStore>();
    AuthSession session(api, storage);

    std::string error;
    Expect(session.Status().state == AuthState::SignedOut, "new session is signed out");

    // Invalid password
    Expect(!session.SignInWithPassword("valid@example.test", "wrong_password", error),
           "bad password login is rejected");
    Expect(session.Status().state == AuthState::Error, "bad password transitions to Error state");
    Expect(storage->stores == 0, "failed login stores no credentials");

    // Successful password sign-in
    Expect(session.SignInWithPassword("valid@example.test", "correct_password", error),
           "correct credentials succeed");
    Expect(session.Status().state == AuthState::SignedIn, "session transitions to SignedIn");
    Expect(session.Status().email == "valid@example.test", "user email is available in status");
    Expect(session.Status().userId == "11111111-1111-1111-1111-111111111111", "canonical user UUID is set");
    Expect(storage->stores == 1 && storage->stored.has_value(), "refresh token is saved to credential store");
    Expect(storage->stored->refreshToken == "refresh-token-1", "correct refresh token stored");

    // Sign out
    Expect(session.SignOut(error), "sign out succeeds");
    Expect(session.Status().state == AuthState::SignedOut, "state returns to SignedOut");
    Expect(!storage->stored.has_value(), "credential store is wiped on sign out");
    Expect(session.Status().email.empty(), "in-memory email cleared on sign out");
}

void TestSessionRestoreAndRefreshRotation()
{
    auto api = std::make_shared<FakeAccountApi>();
    auto storage = std::make_shared<MemoryCredentialStore>();
    storage->stored = StoredAccountCredential{
        "stored-refresh", "valid@example.test", "11111111-1111-1111-1111-111111111111", ""
    };

    AuthSession session(api, storage);
    std::string error;

    // Restore on startup
    Expect(session.RestoreStoredSession(error), "session restore succeeds with valid refresh token");
    Expect(session.Status().state == AuthState::SignedIn, "restored session is SignedIn");
    Expect(session.Status().userId == "11111111-1111-1111-1111-111111111111", "identity restored");
    Expect(storage->stored.has_value() && storage->stored->refreshToken == "refresh-token-rotated",
           "rotated refresh token replaces old token in credential store");

    // Refresh with invalid stored token (simulating revocation)
    storage->stored = StoredAccountCredential{
        "revoked-refresh-token", "valid@example.test", "11111111-1111-1111-1111-111111111111", ""
    };
    AuthSession revokedSession(api, storage);
    Expect(!revokedSession.RestoreStoredSession(error), "revoked token refresh fails");
    Expect(revokedSession.Status().state == AuthState::ReauthenticationRequired,
           "revoked session enters ReauthenticationRequired state");
    Expect(!storage->stored.has_value(), "revoked credential is deleted from store");
}

void TestAccountSyncFailureAndLogoutWarning()
{
    auto api = std::make_shared<FakeAccountApi>();
    auto storage = std::make_shared<MemoryCredentialStore>();
    AuthSession session(api, storage);
    std::string error;

    // Simulate /api/me outage during sign in
    api->profileErrorMode = true;
    Expect(session.SignInWithPassword("valid@example.test", "correct_password", error),
           "sign in succeeds even when /api/me is down");
    Expect(session.Status().state == AuthState::SignedIn, "state is SignedIn");
    Expect(session.Status().accountSyncFailed, "accountSyncFailed is true");
    Expect(!session.IsProActive(), "Pro fails closed when /api/me is unavailable");
    Expect(session.Status().message == "Signed in — account status unavailable.",
           "clear message indicating account status unavailable");

    // Recover /api/me
    api->profileErrorMode = false;
    Expect(session.RefreshAccountSnapshot(error), "profile refresh succeeds");
    Expect(!session.Status().accountSyncFailed, "accountSyncFailed cleared");
    Expect(session.Status().message == "Account profile up to date.", "updated status message");

    // Remote logout failure
    api->signOutSuccess = false;
    Expect(session.SignOut(error), "local logout succeeds even if remote logout fails");
    Expect(session.Status().state == AuthState::SignedOut, "session is SignedOut");
    Expect(!storage->stored.has_value(), "local credentials deleted on logout");
    Expect(session.Status().message.find("Remote session revocation could not be confirmed") != std::string::npos,
           "safe warning message recorded on remote logout failure");
}

void TestCommercialAuthorityAndFailClosed()
{
    auto api = std::make_shared<FakeAccountApi>();
    auto storage = std::make_shared<MemoryCredentialStore>();
    AuthSession session(api, storage);
    std::string error;

    // 1. Community Account (Default)
    api->mockSnapshot = AccountSnapshot{
        {"11111111-1111-1111-1111-111111111111", "valid@example.test", "Community User", ""},
        {"community", "", false, "", false}
    };
    Expect(session.SignInWithPassword("valid@example.test", "correct_password", error), "sign in community");
    Expect(!session.IsProActive(), "community user is NOT pro");
    Expect(session.Status().plan == "community", "community plan displayed");

    // 2. Active Pro Account
    api->mockSnapshot = AccountSnapshot{
        {"11111111-1111-1111-1111-111111111111", "valid@example.test", "Pro User", ""},
        {"pro", "active", true, "2026-12-31T23:59:59Z", false}
    };
    Expect(session.RefreshAccountSnapshot(error), "refresh profile to pro");
    Expect(session.IsProActive(), "active pro user is ProActive");
    Expect(session.Status().plan == "pro", "pro plan displayed");
    Expect(session.Status().subscriptionStatus == "active", "active status displayed");

    // 3. Pro Canceled / Expired
    api->mockSnapshot = AccountSnapshot{
        {"11111111-1111-1111-1111-111111111111", "valid@example.test", "Canceled Pro", ""},
        {"pro", "canceled", false, "2026-01-01T00:00:00Z", false}
    };
    Expect(session.RefreshAccountSnapshot(error), "refresh profile to canceled pro");
    Expect(!session.IsProActive(), "canceled pro is NOT ProActive");

    // 4. Commercial Fail-Closed: plan is "community" but server claims is_pro_active = true
    AccountSnapshot inconsistentCommunity;
    inconsistentCommunity.user.id = "11111111-1111-1111-1111-111111111111";
    inconsistentCommunity.subscription.plan = "community";
    inconsistentCommunity.subscription.isProActive = false;
    api->mockSnapshot = inconsistentCommunity;
    Expect(session.RefreshAccountSnapshot(error), "refresh profile with inconsistent community");
    Expect(!session.IsProActive(), "inconsistent community response fails closed to NOT pro");

    // 5. Commercial Fail-Closed: plan is "unknown_tier", is_pro_active = true
    AccountSnapshot unknownTier;
    unknownTier.user.id = "11111111-1111-1111-1111-111111111111";
    unknownTier.subscription.plan = "unknown_tier";
    unknownTier.subscription.isProActive = false;
    api->mockSnapshot = unknownTier;
    Expect(session.RefreshAccountSnapshot(error), "refresh profile with unknown plan");
    Expect(!session.IsProActive(), "unknown tier fails closed to NOT pro");

    // 6. Identity Mismatch Test
    api->mockSnapshot = AccountSnapshot{
        {"22222222-2222-2222-2222-222222222222", "different@example.test", "Imposter", ""},
        {"pro", "active", true, "", false}
    };
    Expect(!session.RefreshAccountSnapshot(error), "identity mismatch is rejected");
}

} // namespace

int main()
{
    TestPkce();
    TestUuidValidation();
    TestConfigurationValidation();
    TestWindowsCredentialStore();
    TestPasswordAuthAndSessionLifecycle();
    TestSessionRestoreAndRefreshRotation();
    TestAccountSyncFailureAndLogoutWarning();
    TestCommercialAuthorityAndFailClosed();

    if (failures == 0)
    {
        std::cout << "All OpenReverse Supabase authentication and account tests passed.\n";
        return 0;
    }
    std::cerr << failures << " authentication test(s) failed.\n";
    return 1;
}
