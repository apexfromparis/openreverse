#include "pkce.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>

namespace openreverse::auth {

namespace {

constexpr char kBase64UrlAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

} // namespace

bool GenerateSecureRandom(size_t byteCount, std::vector<uint8_t>& output,
                          std::string& error)
{
    output.clear();
    error.clear();
    if (byteCount == 0 || byteCount > (std::numeric_limits<ULONG>::max)())
    {
        error = "Requested random value length is invalid";
        return false;
    }
    output.resize(byteCount);
    if (BCryptGenRandom(nullptr, output.data(), static_cast<ULONG>(output.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
    {
        std::fill(output.begin(), output.end(), 0);
        output.clear();
        error = "Windows cryptographic random generation failed";
        return false;
    }
    return true;
}

std::string Base64UrlEncode(const uint8_t* data, size_t size)
{
    if (!data || size == 0) return {};
    std::string output;
    output.reserve((size * 4 + 2) / 3);
    uint32_t accumulator = 0;
    int bits = 0;
    for (size_t index = 0; index < size; ++index)
    {
        accumulator = (accumulator << 8) | data[index];
        bits += 8;
        while (bits >= 6)
        {
            bits -= 6;
            output.push_back(kBase64UrlAlphabet[(accumulator >> bits) & 0x3Fu]);
        }
    }
    if (bits != 0)
        output.push_back(kBase64UrlAlphabet[(accumulator << (6 - bits)) & 0x3Fu]);
    return output;
}

bool Base64UrlDecode(const std::string& text, std::vector<uint8_t>& output)
{
    output.clear();
    if (text.empty() || text.size() % 4 == 1) return false;
    uint32_t accumulator = 0;
    int bits = 0;
    for (unsigned char character : text)
    {
        const char* found = std::find(std::begin(kBase64UrlAlphabet),
                                      std::end(kBase64UrlAlphabet) - 1,
                                      static_cast<char>(character));
        if (found == std::end(kBase64UrlAlphabet) - 1)
        {
            output.clear();
            return false;
        }
        accumulator = (accumulator << 6) |
            static_cast<uint32_t>(found - std::begin(kBase64UrlAlphabet));
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            output.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xFFu));
        }
    }
    if (bits != 0 && (accumulator & ((1u << bits) - 1u)) != 0)
    {
        output.clear();
        return false;
    }
    return true;
}

bool IsValidPkceVerifier(const std::string& verifier)
{
    if (verifier.size() < 43 || verifier.size() > 128) return false;
    for (unsigned char character : verifier)
    {
        if (!(std::isalnum(character) || character == '-' || character == '.' ||
              character == '_' || character == '~'))
            return false;
    }
    return true;
}

bool CreateS256Challenge(const std::string& verifier, std::string& challenge,
                         std::string& error)
{
    challenge.clear();
    error.clear();
    if (!IsValidPkceVerifier(verifier))
    {
        error = "PKCE verifier does not satisfy RFC 7636 length or character rules";
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::array<uint8_t, 32> digest{};
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) < 0 ||
        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(verifier.data())),
                       static_cast<ULONG>(verifier.size()), 0) < 0 ||
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    {
        if (hash) BCryptDestroyHash(hash);
        if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
        error = "PKCE SHA-256 calculation failed";
        return false;
    }
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    challenge = Base64UrlEncode(digest.data(), digest.size());
    SecureZeroMemory(digest.data(), digest.size());
    return challenge.size() == 43 && challenge.find('=') == std::string::npos;
}

bool GeneratePkcePair(PkcePair& pair, std::string& error)
{
    SecureClear(pair.verifier);
    pair.challenge.clear();
    std::vector<uint8_t> random;
    if (!GenerateSecureRandom(48, random, error)) return false;
    pair.verifier = Base64UrlEncode(random.data(), random.size());
    SecureZeroMemory(random.data(), random.size());
    if (!CreateS256Challenge(pair.verifier, pair.challenge, error))
    {
        SecureClear(pair.verifier);
        return false;
    }
    return true;
}

bool GenerateAuthState(std::string& state, std::string& error)
{
    SecureClear(state);
    std::vector<uint8_t> random;
    if (!GenerateSecureRandom(32, random, error)) return false;
    state = Base64UrlEncode(random.data(), random.size());
    SecureZeroMemory(random.data(), random.size());
    return state.size() == 43;
}

void SecureClear(std::string& value)
{
    if (!value.empty()) SecureZeroMemory(value.data(), value.size());
    value.clear();
    value.shrink_to_fit();
}

} // namespace openreverse::auth
