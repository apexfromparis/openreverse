#include "secure_credentials.h"

#include "pkce.h"

#include <windows.h>
#include <wincred.h>
#include <nlohmann/json.hpp>

#include <limits>
#include <stdexcept>
#include <utility>

namespace openreverse::auth {

namespace {

constexpr size_t kMaximumCredentialBytes = 2048;
constexpr size_t kMaximumIdentityBytes = 512;

bool BoundedIdentity(const std::string& value)
{
    return value.size() <= kMaximumIdentityBytes && value.find('\0') == std::string::npos;
}

bool ValidCredential(const StoredAccountCredential& credential)
{
    return !credential.refreshToken.empty() &&
        credential.refreshToken.size() <= kMaximumCredentialBytes &&
        credential.refreshToken.find('\0') == std::string::npos &&
        BoundedIdentity(credential.email) && BoundedIdentity(credential.userId) &&
        BoundedIdentity(credential.sessionId);
}

} // namespace

WindowsAccountCredentialStore::WindowsAccountCredentialStore(std::string target)
    : target_(std::move(target))
{
}

bool WindowsAccountCredentialStore::Store(const StoredAccountCredential& credential,
                                           std::string& error)
{
    error.clear();
    if (target_.empty() || target_.size() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH ||
        !ValidCredential(credential))
    {
        error = "Account credential is invalid or exceeds secure-storage limits";
        return false;
    }
    nlohmann::json document = {
        {"version", 1},
        {"refresh_token", credential.refreshToken},
        {"email", credential.email},
        {"user_id", credential.userId},
        {"session_id", credential.sessionId}
    };
    std::string serialized = document.dump();
    if (serialized.size() > CRED_MAX_CREDENTIAL_BLOB_SIZE ||
        serialized.size() > (std::numeric_limits<DWORD>::max)())
    {
        SecureClear(serialized);
        error = "Account credential exceeds Windows Credential Manager limits";
        return false;
    }

    CREDENTIALA native{};
    native.Type = CRED_TYPE_GENERIC;
    native.TargetName = const_cast<LPSTR>(target_.c_str());
    native.CredentialBlobSize = static_cast<DWORD>(serialized.size());
    native.CredentialBlob = reinterpret_cast<LPBYTE>(serialized.data());
    native.Persist = CRED_PERSIST_LOCAL_MACHINE;
    native.UserName = const_cast<LPSTR>("OpenReverse Account");
    const bool stored = CredWriteA(&native, 0) == TRUE;
    SecureClear(serialized);
    if (!stored) error = "Windows Credential Manager could not store the account session";
    return stored;
}

CredentialReadResult WindowsAccountCredentialStore::Read(
    StoredAccountCredential& credential, std::string& error) const
{
    ClearStoredCredential(credential);
    error.clear();
    PCREDENTIALA native = nullptr;
    if (!CredReadA(target_.c_str(), CRED_TYPE_GENERIC, 0, &native) || !native)
    {
        if (GetLastError() == ERROR_NOT_FOUND) return CredentialReadResult::Missing;
        error = "Windows Credential Manager could not read the account session";
        return CredentialReadResult::Error;
    }
    if (!native->CredentialBlob || native->CredentialBlobSize == 0 ||
        native->CredentialBlobSize > CRED_MAX_CREDENTIAL_BLOB_SIZE)
    {
        CredFree(native);
        error = "Stored account session is malformed";
        return CredentialReadResult::Error;
    }
    std::string serialized(reinterpret_cast<const char*>(native->CredentialBlob),
                           native->CredentialBlobSize);
    CredFree(native);
    try
    {
        const auto document = nlohmann::json::parse(serialized);
        if (!document.is_object() || document.value("version", 0) != 1 ||
            !document.contains("refresh_token") || !document["refresh_token"].is_string() ||
            !document.contains("email") || !document["email"].is_string() ||
            !document.contains("user_id") || !document["user_id"].is_string() ||
            !document.contains("session_id") || !document["session_id"].is_string())
            throw std::runtime_error("invalid account credential schema");
        credential.refreshToken = document["refresh_token"].get<std::string>();
        credential.email = document["email"].get<std::string>();
        credential.userId = document["user_id"].get<std::string>();
        credential.sessionId = document["session_id"].get<std::string>();
        if (!ValidCredential(credential))
            throw std::runtime_error("account credential exceeds limits");
    }
    catch (...)
    {
        SecureClear(serialized);
        ClearStoredCredential(credential);
        error = "Stored account session is malformed";
        return CredentialReadResult::Error;
    }
    SecureClear(serialized);
    return CredentialReadResult::Found;
}

bool WindowsAccountCredentialStore::Delete(std::string& error)
{
    error.clear();
    if (CredDeleteA(target_.c_str(), CRED_TYPE_GENERIC, 0) == TRUE ||
        GetLastError() == ERROR_NOT_FOUND)
        return true;
    error = "Windows Credential Manager could not delete the account session";
    return false;
}

void ClearStoredCredential(StoredAccountCredential& credential)
{
    SecureClear(credential.refreshToken);
    SecureClear(credential.email);
    SecureClear(credential.userId);
    SecureClear(credential.sessionId);
}

} // namespace openreverse::auth
