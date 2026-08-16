#include "account_api.h"

#include "pkce.h"

#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace openreverse::auth {

namespace {

constexpr char kAuthorizationEndpoint[] =
    "https://api.workos.com/user_management/authorize";
constexpr wchar_t kApiHost[] = L"api.workos.com";
constexpr wchar_t kAuthenticationPath[] = L"/user_management/authenticate";
constexpr char kLogoutEndpoint[] =
    "https://api.workos.com/user_management/sessions/logout";
constexpr size_t kMaximumResponseBytes = 1024 * 1024;

bool IsSafeIdentifier(const std::string& value, size_t maximum)
{
    if (value.empty() || value.size() > maximum) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isalnum(character) || character == '_' || character == '-' ||
            character == '.' || character == ':' || character == '@';
    });
}

bool IsBase64UrlValue(const std::string& value, size_t requiredLength)
{
    return value.size() == requiredLength &&
        std::all_of(value.begin(), value.end(), [](unsigned char character) {
            return std::isalnum(character) || character == '-' || character == '_';
        });
}

bool IsValidLoopbackRedirect(const std::string& value)
{
    constexpr char prefix[] = "http://127.0.0.1:";
    constexpr char suffix[] = "/callback";
    if (value.rfind(prefix, 0) != 0 || value.size() > 256 ||
        value.size() <= sizeof(prefix) - 1 + sizeof(suffix) - 1 ||
        value.compare(value.size() - (sizeof(suffix) - 1), sizeof(suffix) - 1, suffix) != 0)
        return false;
    const size_t start = sizeof(prefix) - 1;
    const size_t length = value.size() - start - (sizeof(suffix) - 1);
    if (length == 0 || length > 5) return false;
    unsigned int port = 0;
    for (size_t index = 0; index < length; ++index)
    {
        const unsigned char character = static_cast<unsigned char>(value[start + index]);
        if (!std::isdigit(character)) return false;
        port = port * 10 + static_cast<unsigned int>(character - '0');
    }
    return port > 0 && port <= 65535;
}

std::string UrlEncode(const std::string& value)
{
    std::ostringstream encoded;
    encoded << std::uppercase << std::hex;
    for (unsigned char character : value)
    {
        if (std::isalnum(character) || character == '-' || character == '_' ||
            character == '.' || character == '~')
            encoded << static_cast<char>(character);
        else
            encoded << '%' << std::setw(2) << std::setfill('0')
                    << static_cast<unsigned int>(character);
    }
    return encoded.str();
}

bool ReadHttpResponse(HINTERNET request, std::string& body, std::string& error)
{
    body.clear();
    for (;;)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available))
        {
            error = "Authentication service response could not be read";
            return false;
        }
        if (available == 0) return true;
        if (body.size() + available > kMaximumResponseBytes)
        {
            error = "Authentication service response exceeds the 1 MiB limit";
            return false;
        }
        const size_t offset = body.size();
        body.resize(offset + available);
        DWORD received = 0;
        if (!WinHttpReadData(request, body.data() + offset, available, &received))
        {
            error = "Authentication service response could not be read";
            return false;
        }
        body.resize(offset + received);
    }
}

bool ExtractJwtMetadata(const std::string& token, int64_t& expiration,
                        std::string& sessionId)
{
    expiration = 0;
    sessionId.clear();
    const size_t first = token.find('.');
    const size_t second = first == std::string::npos ? std::string::npos : token.find('.', first + 1);
    if (first == std::string::npos || second == std::string::npos || second <= first + 1)
        return false;
    std::vector<uint8_t> decoded;
    if (!Base64UrlDecode(token.substr(first + 1, second - first - 1), decoded) ||
        decoded.size() > 64 * 1024)
        return false;
    try
    {
        const auto payload = nlohmann::json::parse(decoded.begin(), decoded.end());
        if (payload.contains("exp") && payload["exp"].is_number_integer())
            expiration = payload["exp"].get<int64_t>();
        if (payload.contains("sid") && payload["sid"].is_string())
            sessionId = payload["sid"].get<std::string>();
    }
    catch (...)
    {
        SecureZeroMemory(decoded.data(), decoded.size());
        return false;
    }
    SecureZeroMemory(decoded.data(), decoded.size());
    return IsSafeIdentifier(sessionId, 256) && expiration > 0;
}

bool ParseTokenResponse(const std::string& body, AuthTokenResponse& response,
                        std::string& error)
{
    ClearAuthTokenResponse(response);
    try
    {
        const auto document = nlohmann::json::parse(body);
        if (!document.is_object() || !document.contains("access_token") ||
            !document["access_token"].is_string() || !document.contains("refresh_token") ||
            !document["refresh_token"].is_string() || !document.contains("user") ||
            !document["user"].is_object())
            throw std::runtime_error("missing authentication response fields");
        const auto& user = document["user"];
        if (!user.contains("email") || !user["email"].is_string() ||
            !user.contains("id") || !user["id"].is_string())
            throw std::runtime_error("missing user identity fields");
        response.accessToken = document["access_token"].get<std::string>();
        response.refreshToken = document["refresh_token"].get<std::string>();
        response.user.email = user["email"].get<std::string>();
        response.user.userId = user["id"].get<std::string>();
        if (response.accessToken.empty() || response.accessToken.size() > 64 * 1024 ||
            response.refreshToken.empty() || response.refreshToken.size() > 2048 ||
            response.user.email.size() > 512 || response.user.userId.size() > 512 ||
            !ExtractJwtMetadata(response.accessToken, response.expiresAtUnix,
                                response.sessionId))
            throw std::runtime_error("authentication response exceeds limits");
    }
    catch (...)
    {
        ClearAuthTokenResponse(response);
        error = "Authentication service returned an invalid bounded response";
        return false;
    }
    return true;
}

} // namespace

WorkOSAccountApi::WorkOSAccountApi(std::string clientId) : clientId_(std::move(clientId)) {}

WorkOSAccountApi WorkOSAccountApi::FromEnvironment()
{
    std::array<char, 512> value{};
    const DWORD length = GetEnvironmentVariableA("OPENREVERSE_WORKOS_CLIENT_ID", value.data(),
                                                  static_cast<DWORD>(value.size()));
    if (length == 0 || length >= value.size()) return WorkOSAccountApi({});
    return WorkOSAccountApi(std::string(value.data(), length));
}

bool WorkOSAccountApi::IsConfigured() const
{
    return clientId_.rfind("client_", 0) == 0 && IsSafeIdentifier(clientId_, 256);
}

bool WorkOSAccountApi::BuildAuthorizationUrl(const std::string& redirectUri,
                                              const std::string& state,
                                              const std::string& codeChallenge,
                                              std::string& url,
                                              std::string& error) const
{
    url.clear();
    error.clear();
    if (!IsConfigured())
    {
        error = "A public WorkOS desktop client ID is not configured";
        return false;
    }
    if (!IsValidLoopbackRedirect(redirectUri) || !IsBase64UrlValue(state, 43) ||
        !IsBase64UrlValue(codeChallenge, 43))
    {
        error = "Authentication redirect, state, or PKCE challenge is invalid";
        return false;
    }
    url = std::string(kAuthorizationEndpoint) +
        "?response_type=code&provider=authkit&client_id=" + UrlEncode(clientId_) +
        "&redirect_uri=" + UrlEncode(redirectUri) +
        "&state=" + UrlEncode(state) +
        "&code_challenge_method=S256&code_challenge=" + UrlEncode(codeChallenge);
    return true;
}

bool WorkOSAccountApi::ExchangeAuthorizationCode(const std::string& code,
                                                  const std::string& codeVerifier,
                                                  const std::string&,
                                                  AuthTokenResponse& response,
                                                  std::string& error)
{
    if (!IsConfigured() || code.empty() || code.size() > 2048 ||
        !IsValidPkceVerifier(codeVerifier))
    {
        error = "Authorization code exchange input is invalid";
        return false;
    }
    nlohmann::json body = {
        {"client_id", clientId_},
        {"grant_type", "authorization_code"},
        {"code", code},
        {"code_verifier", codeVerifier}
    };
    std::string serialized = body.dump();
    const bool result = Authenticate(serialized, response, error);
    SecureClear(serialized);
    return result;
}

bool WorkOSAccountApi::Refresh(const std::string& refreshToken,
                               AuthTokenResponse& response, std::string& error)
{
    if (!IsConfigured() || refreshToken.empty() || refreshToken.size() > 2048)
    {
        error = "Stored account refresh input is invalid";
        return false;
    }
    nlohmann::json body = {
        {"client_id", clientId_},
        {"grant_type", "refresh_token"},
        {"refresh_token", refreshToken}
    };
    std::string serialized = body.dump();
    const bool result = Authenticate(serialized, response, error);
    SecureClear(serialized);
    return result;
}

bool WorkOSAccountApi::BuildLogoutUrl(const std::string& sessionId,
                                       std::string& url, std::string& error) const
{
    url.clear();
    error.clear();
    if (!IsSafeIdentifier(sessionId, 256))
    {
        error = "Account session identifier is unavailable for remote logout";
        return false;
    }
    url = std::string(kLogoutEndpoint) + "?session_id=" + UrlEncode(sessionId);
    return true;
}

bool WorkOSAccountApi::Authenticate(const std::string& body,
                                     AuthTokenResponse& response, std::string& error)
{
    ClearAuthTokenResponse(response);
    error.clear();
    if (body.empty() || body.size() > 16 * 1024)
    {
        error = "Authentication request exceeds limits";
        return false;
    }
    HINTERNET session = WinHttpOpen(L"OpenReverse/2.0 Auth", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
    {
        error = "Authentication HTTPS session could not be created";
        return false;
    }
    WinHttpSetTimeouts(session, 10000, 10000, 10000, 15000);
    HINTERNET connection = WinHttpConnect(session, kApiHost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST", kAuthenticationPath,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE) : nullptr;
    bool success = false;
    std::string responseBody;
    if (request)
    {
        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                              &redirectPolicy, sizeof(redirectPolicy)))
        {
            error = "Authentication HTTPS redirect policy could not be applied";
        }
        const wchar_t headers[] = L"Content-Type: application/json\r\nAccept: application/json\r\n";
        success = error.empty() && WinHttpSendRequest(request, headers, static_cast<DWORD>(-1L),
            const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()), 0) && WinHttpReceiveResponse(request, nullptr);
        if (success)
        {
            DWORD status = 0;
            DWORD size = sizeof(status);
            success = WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE |
                WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                WINHTTP_NO_HEADER_INDEX) && ReadHttpResponse(request, responseBody, error);
            if (success && status != 200)
            {
                std::string code;
                try
                {
                    const auto responseDocument = nlohmann::json::parse(responseBody);
                    if (responseDocument.contains("error") &&
                        responseDocument["error"].is_string())
                        code = responseDocument["error"].get<std::string>();
                }
                catch (...) {}
                error = "Authentication service rejected the request";
                if (IsSafeIdentifier(code, 64)) error += " (" + code + ")";
                success = false;
            }
        }
    }
    if (!success && error.empty()) error = "Authentication HTTPS request failed";
    if (success) success = ParseTokenResponse(responseBody, response, error);
    SecureClear(responseBody);
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return success;
}

void ClearAuthTokenResponse(AuthTokenResponse& response)
{
    SecureClear(response.accessToken);
    SecureClear(response.refreshToken);
    SecureClear(response.user.email);
    SecureClear(response.user.userId);
    SecureClear(response.sessionId);
    response.expiresAtUnix = 0;
}

} // namespace openreverse::auth
