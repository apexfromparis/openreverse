#include "auth_callback.h"

#include <algorithm>
#include <cctype>
#include <map>

namespace openreverse::auth {

namespace {

constexpr size_t kMaximumRequestTargetBytes = 8192;
constexpr size_t kMaximumCodeBytes = 2048;
constexpr size_t kMaximumStateBytes = 256;
constexpr size_t kMaximumProviderErrorBytes = 128;

int HexValue(unsigned char character)
{
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

bool DecodeQueryComponent(const std::string& encoded, size_t maximum,
                          bool allowSpace, std::string& decoded)
{
    decoded.clear();
    if (encoded.empty() || encoded.size() > maximum * 3) return false;
    decoded.reserve(encoded.size());
    for (size_t index = 0; index < encoded.size(); ++index)
    {
        unsigned char character = static_cast<unsigned char>(encoded[index]);
        if (character == '%')
        {
            if (index + 2 >= encoded.size()) return false;
            const int high = HexValue(static_cast<unsigned char>(encoded[index + 1]));
            const int low = HexValue(static_cast<unsigned char>(encoded[index + 2]));
            if (high < 0 || low < 0) return false;
            character = static_cast<unsigned char>((high << 4) | low);
            index += 2;
        }
        else if (character == '+')
        {
            character = ' ';
        }
        if ((!allowSpace && character < 0x21) || character < 0x20 ||
            character > 0x7e || character == '#')
            return false;
        decoded.push_back(static_cast<char>(character));
        if (decoded.size() > maximum) return false;
    }
    return !decoded.empty();
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    return value;
}

bool IsForbiddenCredentialField(const std::string& name)
{
    const std::string lower = Lower(name);
    return lower == "token" || lower == "access_token" || lower == "refresh_token" ||
        lower == "api_key" || lower == "apikey" || lower == "secret" ||
        lower == "client_secret" || lower == "authorization";
}

} // namespace

bool ParseAuthCallbackTarget(const std::string& requestTarget, AuthCallback& callback,
                             std::string& error)
{
    callback = {};
    error.clear();
    if (requestTarget.empty() || requestTarget.size() > kMaximumRequestTargetBytes ||
        requestTarget.find('#') != std::string::npos)
    {
        error = "Authentication callback target is malformed or exceeds limits";
        return false;
    }
    const size_t queryOffset = requestTarget.find('?');
    if (queryOffset == std::string::npos || requestTarget.substr(0, queryOffset) != "/callback")
    {
        error = "Authentication callback path is not allowed";
        return false;
    }
    const std::string query = requestTarget.substr(queryOffset + 1);
    if (query.empty())
    {
        error = "Authentication callback query is empty";
        return false;
    }

    std::map<std::string, std::string> parameters;
    size_t start = 0;
    while (start <= query.size())
    {
        const size_t end = query.find('&', start);
        const std::string pair = query.substr(start,
            end == std::string::npos ? std::string::npos : end - start);
        const size_t equals = pair.find('=');
        if (pair.empty() || equals == std::string::npos || equals == 0 ||
            pair.find('=', equals + 1) != std::string::npos)
        {
            error = "Authentication callback contains a malformed parameter";
            return false;
        }
        std::string name;
        std::string value;
        if (!DecodeQueryComponent(pair.substr(0, equals), 64, false, name))
        {
            error = "Authentication callback contains invalid encoding";
            return false;
        }
        if (IsForbiddenCredentialField(name))
        {
            error = "Authentication callback attempted to carry a final credential";
            return false;
        }
        if (name != "code" && name != "state" && name != "error" &&
            name != "error_description")
        {
            error = "Authentication callback contains an unexpected field";
            return false;
        }
        const size_t maximum = name == "state" ? kMaximumStateBytes :
            (name == "error" ? kMaximumProviderErrorBytes :
             (name == "error_description" ? 512 : kMaximumCodeBytes));
        if (!DecodeQueryComponent(pair.substr(equals + 1), maximum,
                                  name == "error_description", value))
        {
            error = "Authentication callback contains invalid encoding";
            return false;
        }
        if (!parameters.emplace(name, std::move(value)).second)
        {
            error = "Authentication callback contains a duplicate field";
            return false;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }

    const auto state = parameters.find("state");
    if (state == parameters.end() || state->second.size() > kMaximumStateBytes)
    {
        error = "Authentication callback is missing a bounded state value";
        return false;
    }
    callback.state = state->second;

    const auto providerError = parameters.find("error");
    if (providerError != parameters.end())
    {
        if (parameters.find("code") != parameters.end() ||
            providerError->second.size() > kMaximumProviderErrorBytes)
        {
            error = "Authentication provider error response is malformed";
            return false;
        }
        callback.kind = AuthCallbackKind::ProviderError;
        callback.providerError = providerError->second;
        return true;
    }
    if (parameters.find("error_description") != parameters.end())
    {
        error = "Authentication callback contains an orphaned provider description";
        return false;
    }
    const auto code = parameters.find("code");
    if (code == parameters.end() || code->second.size() > kMaximumCodeBytes)
    {
        error = "Authentication callback is missing a bounded authorization code";
        return false;
    }
    callback.kind = AuthCallbackKind::AuthorizationCode;
    callback.code = code->second;
    return true;
}

} // namespace openreverse::auth
