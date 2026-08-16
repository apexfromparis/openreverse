#pragma once

#include <string>

namespace openreverse::auth {

struct StoredAccountCredential {
    std::string refreshToken;
    std::string email;
    std::string userId;
    std::string sessionId;
};

enum class CredentialReadResult {
    Found,
    Missing,
    Error
};

class IAccountCredentialStore {
public:
    virtual ~IAccountCredentialStore() = default;
    virtual bool Store(const StoredAccountCredential& credential, std::string& error) = 0;
    virtual CredentialReadResult Read(StoredAccountCredential& credential,
                                      std::string& error) const = 0;
    virtual bool Delete(std::string& error) = 0;
};

class WindowsAccountCredentialStore final : public IAccountCredentialStore {
public:
    explicit WindowsAccountCredentialStore(
        std::string target = "OpenReverse.Account.Session");

    bool Store(const StoredAccountCredential& credential, std::string& error) override;
    CredentialReadResult Read(StoredAccountCredential& credential,
                              std::string& error) const override;
    bool Delete(std::string& error) override;
    const std::string& Target() const { return target_; }

private:
    std::string target_;
};

void ClearStoredCredential(StoredAccountCredential& credential);

} // namespace openreverse::auth
