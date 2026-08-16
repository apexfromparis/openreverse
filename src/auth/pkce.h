#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace openreverse::auth {

struct PkcePair {
    std::string verifier;
    std::string challenge;
};

bool GenerateSecureRandom(size_t byteCount, std::vector<uint8_t>& output,
                          std::string& error);
std::string Base64UrlEncode(const uint8_t* data, size_t size);
bool Base64UrlDecode(const std::string& text, std::vector<uint8_t>& output);
bool CreateS256Challenge(const std::string& verifier, std::string& challenge,
                         std::string& error);
bool GeneratePkcePair(PkcePair& pair, std::string& error);
bool GenerateAuthState(std::string& state, std::string& error);
bool IsValidPkceVerifier(const std::string& verifier);
void SecureClear(std::string& value);

} // namespace openreverse::auth
