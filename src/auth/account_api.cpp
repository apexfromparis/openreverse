#include "account_api.h"

#include "pkce.h"

#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace openreverse::auth {

namespace {

constexpr size_t kMaximumResponseBytes = 1024 * 1024;

bool IsSafeIdentifier(const std::string& value, size_t maximum)
{
    if (value.empty() || value.size() > maximum) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char character) {
        return std::isalnum(character) || character == '_' || character == '-' ||
            character == '.' || character == ':' || character == '@';
    });
}

std::string GetEnvVar(const char* name)
{
    std::array<char, 1024> buffer{};
    const DWORD length = GetEnvironmentVariableA(name, buffer.data(),
                                                 static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return {};
    return std::string(buffer.data(), length);
}

int64_t CurrentTimeUnix()
{
    const auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
}

bool ReadHttpResponse(HINTERNET request, std::string& body, std::string& error)
{
    body.clear();
    for (;;)
    {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available))
        {
            error = "Account service response could not be read";
            return false;
        }
        if (available == 0) return true;
        if (body.size() + available > kMaximumResponseBytes)
        {
            error = "Account service response exceeds the 1 MiB limit";
            return false;
        }
        const size_t offset = body.size();
        body.resize(offset + available);
        DWORD received = 0;
        if (!WinHttpReadData(request, body.data() + offset, available, &received))
        {
            error = "Account service response could not be read";
            return false;
        }
        body.resize(offset + received);
    }
}

struct ParsedUrl {
    std::wstring host;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    std::wstring path;
    bool isHttps = true;
};

bool ParseHttpsUrl(const std::string& urlString, ParsedUrl& parsed, std::string& error)
{
    parsed = {};
    if (urlString.empty() || urlString.size() > 2048)
    {
        error = "Invalid endpoint URL";
        return false;
    }
    const std::wstring wideUrl(urlString.begin(), urlString.end());
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.size()), 0, &components))
    {
        error = "Invalid endpoint URL format";
        return false;
    }

    if (components.nScheme != INTERNET_SCHEME_HTTPS && components.nScheme != INTERNET_SCHEME_HTTP)
    {
        error = "Endpoint must use HTTPS";
        return false;
    }

    // In production account flows, reject non-HTTPS except for local loopback tests
    if (components.nScheme != INTERNET_SCHEME_HTTPS)
    {
        const std::wstring host(components.lpszHostName, components.dwHostNameLength);
        if (host != L"127.0.0.1" && host != L"localhost")
        {
            error = "Account service endpoint must use HTTPS";
            return false;
        }
        parsed.isHttps = false;
    }
    else
    {
        parsed.isHttps = true;
    }

    parsed.host.assign(components.lpszHostName, components.dwHostNameLength);
    parsed.port = components.nPort;
    parsed.path.assign(components.lpszUrlPath, components.dwUrlPathLength + components.dwExtraInfoLength);
    if (parsed.path.empty()) parsed.path = L"/";
    return true;
}

bool ExecuteHttpRequest(const std::string& url,
                        const wchar_t* method,
                        const std::wstring& customHeaders,
                        const std::string& requestBody,
                        std::string& responseBody,
                        DWORD& statusCode,
                        std::string& error)
{
    responseBody.clear();
    statusCode = 0;
    error.clear();

    ParsedUrl parsedUrl;
    if (!ParseHttpsUrl(url, parsedUrl, error))
        return false;

    HINTERNET session = WinHttpOpen(L"OpenReverse/2.0 Account",
                                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
    {
        error = "HTTPS session could not be created";
        return false;
    }
    WinHttpSetTimeouts(session, 10000, 10000, 10000, 15000);

    HINTERNET connection = WinHttpConnect(session, parsedUrl.host.c_str(), parsedUrl.port, 0);
    DWORD openFlags = parsedUrl.isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = connection ? WinHttpOpenRequest(connection, method, parsedUrl.path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags) : nullptr;

    bool success = false;
    if (request)
    {
        DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                         &redirectPolicy, sizeof(redirectPolicy));

        const wchar_t* headersPtr = customHeaders.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : customHeaders.c_str();
        DWORD headersLength = customHeaders.empty() ? 0 : static_cast<DWORD>(customHeaders.size());

        void* bodyPtr = requestBody.empty() ? nullptr : const_cast<char*>(requestBody.data());
        DWORD bodyLength = static_cast<DWORD>(requestBody.size());

        success = WinHttpSendRequest(request, headersPtr, headersLength,
                                     bodyPtr, bodyLength, bodyLength, 0) &&
                  WinHttpReceiveResponse(request, nullptr);

        if (success)
        {
            DWORD status = 0;
            DWORD size = sizeof(status);
            success = WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                          WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) &&
                      ReadHttpResponse(request, responseBody, error);
            if (success) statusCode = status;
        }
    }

    if (!success && error.empty()) error = "HTTPS request to account service failed";
    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return success;
}

bool ParseSupabaseTokenResponse(const std::string& body, AuthTokenResponse& response, std::string& error)
{
    ClearAuthTokenResponse(response);
    try
    {
        const auto document = nlohmann::json::parse(body);
        if (!document.is_object() ||
            !document.contains("access_token") || !document["access_token"].is_string() ||
            !document.contains("refresh_token") || !document["refresh_token"].is_string() ||
            !document.contains("user") || !document["user"].is_object())
        {
            error = "Authentication response is missing required token fields";
            return false;
        }

        const auto& userObj = document["user"];
        if (!userObj.contains("id") || !userObj["id"].is_string())
        {
            error = "Authentication response is missing user identity";
            return false;
        }

        const std::string userId = userObj["id"].get<std::string>();
        if (!IsValidUuid(userId))
        {
            error = "Authentication response contains an invalid user UUID";
            return false;
        }

        response.accessToken = document["access_token"].get<std::string>();
        response.refreshToken = document["refresh_token"].get<std::string>();
        response.user.id = userId;

        if (userObj.contains("email") && userObj["email"].is_string())
            response.user.email = userObj["email"].get<std::string>();

        if (userObj.contains("user_metadata") && userObj["user_metadata"].is_object())
        {
            const auto& meta = userObj["user_metadata"];
            if (meta.contains("display_name") && meta["display_name"].is_string())
                response.user.displayName = meta["display_name"].get<std::string>();
            else if (meta.contains("name") && meta["name"].is_string())
                response.user.displayName = meta["name"].get<std::string>();

            if (meta.contains("avatar_url") && meta["avatar_url"].is_string())
                response.user.avatarUrl = meta["avatar_url"].get<std::string>();
        }

        int64_t expiresIn = 3600;
        if (document.contains("expires_in") && document["expires_in"].is_number_integer())
            expiresIn = document["expires_in"].get<int64_t>();
        response.expiresAtUnix = CurrentTimeUnix() + expiresIn;

        if (response.accessToken.empty() || response.accessToken.size() > 64 * 1024 ||
            response.refreshToken.empty() || response.refreshToken.size() > 4096 ||
            response.user.email.size() > 512 || response.user.displayName.size() > 256)
        {
            ClearAuthTokenResponse(response);
            error = "Authentication tokens exceed safe size limits";
            return false;
        }
    }
    catch (...)
    {
        ClearAuthTokenResponse(response);
        error = "Failed to parse authentication response";
        return false;
    }
    return true;
}

bool ParseAccountSnapshotResponse(const std::string& body,
                                  const std::string& expectedUserId,
                                  AccountSnapshot& snapshot,
                                  std::string& error)
{
    ClearAccountSnapshot(snapshot);
    try
    {
        const auto document = nlohmann::json::parse(body);
        if (!document.is_object() ||
            !document.contains("user") || !document["user"].is_object() ||
            !document.contains("subscription") || !document["subscription"].is_object())
        {
            error = "Account endpoint returned a malformed response";
            return false;
        }

        const auto& userObj = document["user"];
        if (!userObj.contains("id") || !userObj["id"].is_string())
        {
            error = "Account profile missing canonical user ID";
            return false;
        }

        const std::string userId = userObj["id"].get<std::string>();
        if (!IsValidUuid(userId))
        {
            error = "Account profile contains invalid user UUID";
            return false;
        }

        if (!expectedUserId.empty() && userId != expectedUserId)
        {
            error = "Account identity mismatch between auth session and profile";
            return false;
        }

        snapshot.user.id = userId;
        if (userObj.contains("email") && userObj["email"].is_string())
            snapshot.user.email = userObj["email"].get<std::string>();
        if (userObj.contains("display_name") && userObj["display_name"].is_string())
            snapshot.user.displayName = userObj["display_name"].get<std::string>();
        if (userObj.contains("avatar_url") && userObj["avatar_url"].is_string())
            snapshot.user.avatarUrl = userObj["avatar_url"].get<std::string>();

        const auto& subObj = document["subscription"];
        std::string plan = "community";
        if (subObj.contains("plan") && subObj["plan"].is_string())
            plan = subObj["plan"].get<std::string>();

        std::string status;
        if (subObj.contains("status") && subObj["status"].is_string())
            status = subObj["status"].get<std::string>();

        bool isProActive = false;
        if (subObj.contains("is_pro_active") && subObj["is_pro_active"].is_boolean())
            isProActive = subObj["is_pro_active"].get<bool>();

        std::string currentPeriodEnd;
        if (subObj.contains("current_period_end") && subObj["current_period_end"].is_string())
            currentPeriodEnd = subObj["current_period_end"].get<std::string>();

        bool cancelAtPeriodEnd = false;
        if (subObj.contains("cancel_at_period_end") && subObj["cancel_at_period_end"].is_boolean())
            cancelAtPeriodEnd = subObj["cancel_at_period_end"].get<bool>();

        snapshot.subscription.plan = plan;
        snapshot.subscription.status = status;
        snapshot.subscription.currentPeriodEnd = currentPeriodEnd;
        snapshot.subscription.cancelAtPeriodEnd = cancelAtPeriodEnd;

        // Commercial fail-closed rule:
        // is_pro_active must be true ONLY if plan is "pro" and status is active/trialing.
        // Inconsistent state (e.g. plan == "community" but is_pro_active == true) fails closed.
        if (isProActive && plan == "pro" && (status == "active" || status == "trialing"))
        {
            snapshot.subscription.isProActive = true;
        }
        else
        {
            snapshot.subscription.isProActive = false;
        }

        if (snapshot.user.email.size() > 512 || snapshot.user.displayName.size() > 256 ||
            snapshot.subscription.plan.size() > 64 || snapshot.subscription.status.size() > 64)
        {
            ClearAccountSnapshot(snapshot);
            error = "Account data exceeds safe bounds";
            return false;
        }
    }
    catch (...)
    {
        ClearAccountSnapshot(snapshot);
        error = "Failed to parse account snapshot";
        return false;
    }
    return true;
}

} // namespace

bool IsValidUuid(const std::string& value)
{
    if (value.size() != 36) return false;
    for (size_t i = 0; i < 36; ++i)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
        {
            if (value[i] != '-') return false;
        }
        else
        {
            if (!std::isxdigit(static_cast<unsigned char>(value[i]))) return false;
        }
    }
    return true;
}

SupabaseAccountApi::SupabaseAccountApi(AccountServiceConfig config)
    : config_(std::move(config))
{
}

SupabaseAccountApi SupabaseAccountApi::FromEnvironment()
{
    AccountServiceConfig config;
    config.supabaseUrl = GetEnvVar("OPENREVERSE_SUPABASE_URL");

    config.supabasePublishableKey = GetEnvVar("OPENREVERSE_SUPABASE_ANON_KEY");
    if (config.supabasePublishableKey.empty())
        config.supabasePublishableKey = GetEnvVar("OPENREVERSE_SUPABASE_PUBLISHABLE_KEY");

    config.accountApiBaseUrl = GetEnvVar("OPENREVERSE_ACCOUNT_API_URL");
    if (config.accountApiBaseUrl.empty())
        config.accountApiBaseUrl = GetEnvVar("OPENREVERSE_WEBSITE_URL");

    if (!config.accountApiBaseUrl.empty())
    {
        config.signupUrl = config.accountApiBaseUrl + "/signup";
        config.accountManageUrl = config.accountApiBaseUrl + "/account";
        config.billingManageUrl = config.accountApiBaseUrl + "/account";
    }
    return SupabaseAccountApi(std::move(config));
}

bool SupabaseAccountApi::IsConfigured() const
{
    if (config_.supabaseUrl.empty() || config_.supabasePublishableKey.empty() ||
        config_.accountApiBaseUrl.empty())
    {
        return false;
    }

    const auto hasPlaceholder = [](const std::string& str) {
        std::string lower = str;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lower.find("placeholder") != std::string::npos ||
               lower.find("your-project") != std::string::npos ||
               lower.find("example.com") != std::string::npos ||
               lower.find("example.test") != std::string::npos ||
               lower.find("change_me") != std::string::npos ||
               lower.find("auth.openreverse.dev") != std::string::npos;
    };

    if (hasPlaceholder(config_.supabaseUrl) ||
        hasPlaceholder(config_.supabasePublishableKey) ||
        hasPlaceholder(config_.accountApiBaseUrl))
    {
        return false;
    }

    ParsedUrl parsedSupabase;
    std::string error;
    if (!ParseHttpsUrl(config_.supabaseUrl, parsedSupabase, error)) return false;

    ParsedUrl parsedApi;
    if (!ParseHttpsUrl(config_.accountApiBaseUrl, parsedApi, error)) return false;

    return true;
}

bool SupabaseAccountApi::SignInWithPassword(const std::string& email,
                                            const std::string& password,
                                            AuthTokenResponse& response,
                                            std::string& error)
{
    ClearAuthTokenResponse(response);
    error.clear();

    if (!IsConfigured())
    {
        error = "Account service is not configured";
        return false;
    }

    if (email.empty() || email.size() > 512 || password.empty() || password.size() > 512)
    {
        error = "Invalid email or password input";
        return false;
    }

    nlohmann::json requestJson = {
        {"email", email},
        {"password", password}
    };
    std::string requestBody = requestJson.dump();

    std::string endpoint = config_.supabaseUrl;
    if (endpoint.back() == '/') endpoint.pop_back();
    endpoint += "/auth/v1/token?grant_type=password";

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    headers += L"apikey: " + std::wstring(config_.supabasePublishableKey.begin(), config_.supabasePublishableKey.end()) + L"\r\n";

    std::string responseBody;
    DWORD statusCode = 0;
    const bool executed = ExecuteHttpRequest(endpoint, L"POST", headers, requestBody, responseBody, statusCode, error);
    SecureClear(requestBody);

    if (!executed) return false;

    if (statusCode != 200)
    {
        std::string errDetail;
        try
        {
            const auto doc = nlohmann::json::parse(responseBody);
            if (doc.contains("error_description") && doc["error_description"].is_string())
                errDetail = doc["error_description"].get<std::string>();
            else if (doc.contains("msg") && doc["msg"].is_string())
                errDetail = doc["msg"].get<std::string>();
        }
        catch (...) {}
        SecureClear(responseBody);

        if (statusCode == 400 || statusCode == 401)
            error = errDetail.empty() ? "Invalid email or password." : errDetail;
        else
            error = "Authentication failed (server error " + std::to_string(statusCode) + ")";
        return false;
    }

    const bool parsed = ParseSupabaseTokenResponse(responseBody, response, error);
    SecureClear(responseBody);
    return parsed;
}

bool SupabaseAccountApi::RefreshSession(const std::string& refreshToken,
                                        AuthTokenResponse& response,
                                        std::string& error)
{
    ClearAuthTokenResponse(response);
    error.clear();

    if (!IsConfigured())
    {
        error = "Account service is not configured";
        return false;
    }

    if (refreshToken.empty() || refreshToken.size() > 4096)
    {
        error = "Stored session token is invalid";
        return false;
    }

    nlohmann::json requestJson = {
        {"refresh_token", refreshToken}
    };
    std::string requestBody = requestJson.dump();

    std::string endpoint = config_.supabaseUrl;
    if (endpoint.back() == '/') endpoint.pop_back();
    endpoint += "/auth/v1/token?grant_type=refresh_token";

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    headers += L"apikey: " + std::wstring(config_.supabasePublishableKey.begin(), config_.supabasePublishableKey.end()) + L"\r\n";

    std::string responseBody;
    DWORD statusCode = 0;
    const bool executed = ExecuteHttpRequest(endpoint, L"POST", headers, requestBody, responseBody, statusCode, error);
    SecureClear(requestBody);

    if (!executed) return false;

    if (statusCode != 200)
    {
        SecureClear(responseBody);
        error = "Session expired or revoked (status " + std::to_string(statusCode) + ")";
        return false;
    }

    const bool parsed = ParseSupabaseTokenResponse(responseBody, response, error);
    SecureClear(responseBody);
    return parsed;
}

bool SupabaseAccountApi::SignOut(const std::string& accessToken,
                                 std::string& error)
{
    error.clear();
    if (!IsConfigured() || accessToken.empty()) return true;

    std::string endpoint = config_.supabaseUrl;
    if (endpoint.back() == '/') endpoint.pop_back();
    endpoint += "/auth/v1/logout";

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    headers += L"apikey: " + std::wstring(config_.supabasePublishableKey.begin(), config_.supabasePublishableKey.end()) + L"\r\n";
    headers += L"Authorization: Bearer " + std::wstring(accessToken.begin(), accessToken.end()) + L"\r\n";

    std::string responseBody;
    DWORD statusCode = 0;
    const bool executed = ExecuteHttpRequest(endpoint, L"POST", headers, "{}", responseBody, statusCode, error);
    SecureClear(responseBody);
    if (!executed || (statusCode != 200 && statusCode != 204))
    {
        error = "Remote logout request failed (status " + std::to_string(statusCode) + ")";
        return false;
    }
    return true;
}

bool SupabaseAccountApi::GetAccountProfile(const std::string& accessToken,
                                           const std::string& expectedUserId,
                                           AccountSnapshot& snapshot,
                                           std::string& error)
{
    ClearAccountSnapshot(snapshot);
    error.clear();

    if (!IsConfigured())
    {
        error = "Account service is not configured";
        return false;
    }

    if (accessToken.empty() || accessToken.size() > 64 * 1024)
    {
        error = "Invalid access token for account request";
        return false;
    }

    std::string endpoint = config_.accountApiBaseUrl;
    if (endpoint.back() == '/') endpoint.pop_back();
    endpoint += "/api/me";

    std::wstring headers = L"Accept: application/json\r\n";
    headers += L"Authorization: Bearer " + std::wstring(accessToken.begin(), accessToken.end()) + L"\r\n";

    std::string responseBody;
    DWORD statusCode = 0;
    const bool executed = ExecuteHttpRequest(endpoint, L"GET", headers, "", responseBody, statusCode, error);

    if (!executed) return false;

    if (statusCode != 200)
    {
        SecureClear(responseBody);
        error = "Account profile verification failed (status " + std::to_string(statusCode) + ")";
        return false;
    }

    const bool parsed = ParseAccountSnapshotResponse(responseBody, expectedUserId, snapshot, error);
    SecureClear(responseBody);
    return parsed;
}

void ClearAuthTokenResponse(AuthTokenResponse& response)
{
    SecureClear(response.accessToken);
    SecureClear(response.refreshToken);
    SecureClear(response.user.id);
    SecureClear(response.user.email);
    SecureClear(response.user.displayName);
    SecureClear(response.user.avatarUrl);
    response.expiresAtUnix = 0;
}

void ClearAccountSnapshot(AccountSnapshot& snapshot)
{
    SecureClear(snapshot.user.id);
    SecureClear(snapshot.user.email);
    SecureClear(snapshot.user.displayName);
    SecureClear(snapshot.user.avatarUrl);
    snapshot.subscription.plan = "community";
    snapshot.subscription.status.clear();
    snapshot.subscription.isProActive = false;
    snapshot.subscription.currentPeriodEnd.clear();
    snapshot.subscription.cancelAtPeriodEnd = false;
}

} // namespace openreverse::auth
