#include "ai_service.h"

#include <nlohmann/json.hpp>
#include <windows.h>
#include <wincred.h>
#include <winhttp.h>

#include <algorithm>
#include <sstream>

using json = nlohmann::json;

namespace kyv::ai {

namespace {

std::wstring Widen(const std::string& value)
{
    if (value.empty()) return {};
    int count = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (count <= 1) return {};
    std::wstring result((size_t)count, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, result.data(), count);
    result.resize((size_t)count - 1);
    return result;
}

std::string Narrow(const std::wstring& value)
{
    if (value.empty()) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return {};
    std::string result((size_t)count, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), count, nullptr, nullptr);
    result.resize((size_t)count - 1);
    return result;
}

std::string TrimSlash(std::string value)
{
    while (!value.empty() && value.back() == '/') value.pop_back();
    return value;
}

} // namespace

AIService::AIService() = default;

AIService::~AIService()
{
    stopping_ = true;
    if (worker_.joinable()) worker_.join();
}

void AIService::Configure(const std::string& provider, const std::string& baseUrl, const std::string& model)
{
    std::lock_guard<std::mutex> lock(mutex_);
    provider_ = provider.empty() ? "Ollama (Free Local)" : provider;
    baseUrl_ = TrimSlash(baseUrl.empty() ? "http://localhost:11434/v1" : baseUrl);
    model_ = model.empty() ? "qwen2.5-coder:7b" : model;
}

std::string AIService::CredentialTarget() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return "KYV/AI/" + provider_;
}

bool AIService::SaveApiKey(const std::string& apiKey)
{
    if (apiKey.empty() || apiKey.size() > 4096) return false;
    std::string target = CredentialTarget();
    CREDENTIALA credential = {};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<char*>(target.c_str());
    credential.CredentialBlobSize = (DWORD)apiKey.size();
    credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(apiKey.data()));
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    return CredWriteA(&credential, 0) == TRUE;
}

std::string AIService::LoadApiKey() const
{
    std::string target = CredentialTarget();
    PCREDENTIALA credential = nullptr;
    if (!CredReadA(target.c_str(), CRED_TYPE_GENERIC, 0, &credential) || !credential)
        return {};
    std::string value(reinterpret_cast<char*>(credential->CredentialBlob), credential->CredentialBlobSize);
    CredFree(credential);
    return value;
}

bool AIService::HasSavedApiKey() const
{
    return !LoadApiKey().empty();
}

void AIService::ClearApiKey()
{
    std::string target = CredentialTarget();
    CredDeleteA(target.c_str(), CRED_TYPE_GENERIC, 0);
}

bool AIService::Send(const std::string& prompt, const ReverseSkill* skill)
{
    if (prompt.empty() || prompt.size() > 32000) return false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ == ChatState::Working) return false;
    }
    if (worker_.joinable()) worker_.join();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        conversation_.push_back({"user", prompt});
        if (conversation_.size() > 20)
            conversation_.erase(conversation_.begin(), conversation_.begin() + 2);
        state_ = ChatState::Working;
        status_ = "Sending request securely...";
    }
    worker_ = std::thread(&AIService::Worker, this, prompt, skill ? skill->systemPrompt : std::string());
    return true;
}

void AIService::Worker(std::string prompt, std::string skillPrompt)
{
    (void)prompt;
    std::string key = LoadApiKey();
    std::string error;
    std::vector<ChatMessage> history;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        history = conversation_;
    }

    if (key.empty())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        conversation_.push_back({"assistant", "No API key is configured. Open AI Settings and save a provider key."});
        state_ = ChatState::Error;
        status_ = "Missing API key (stored in Windows Credential Manager)";
        return;
    }

    std::string answer = Request(key, skillPrompt, history, error);
    std::lock_guard<std::mutex> lock(mutex_);
    if (!error.empty())
    {
        conversation_.push_back({"assistant", "Request failed: " + error});
        state_ = ChatState::Error;
        status_ = "Request failed. Secret values were not logged.";
    }
    else
    {
        conversation_.push_back({"assistant", answer});
        state_ = ChatState::Ready;
        status_ = "Response received";
    }
}

std::string AIService::Request(const std::string& apiKey, const std::string& systemPrompt,
    const std::vector<ChatMessage>& history, std::string& error) const
{
    std::string baseUrl;
    std::string model;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        baseUrl = baseUrl_;
        model = model_;
    }
    bool isHttps = (baseUrl.rfind("https://", 0) == 0);
    if (!isHttps && baseUrl.rfind("http://", 0) != 0)
    {
        error = "URL must start with http:// or https://";
        return {};
    }

    URL_COMPONENTS url = {};
    wchar_t host[256] = {};
    wchar_t path[2048] = {};
    url.dwStructSize = sizeof(url);
    url.lpszHostName = host;
    url.dwHostNameLength = sizeof(host);
    url.lpszUrlPath = path;
    url.dwUrlPathLength = sizeof(path);
    if (!WinHttpCrackUrl(Widen(baseUrl).c_str(), 0, 0, &url))
    {
        error = "Invalid API base URL";
        return {};
    }

    std::string endpoint = path[0] ? Narrow(path) : "/v1";
    if (endpoint.size() < 17 || endpoint.substr(endpoint.size() - 17) != "/chat/completions")
        endpoint = TrimSlash(endpoint) + "/chat/completions";

    json body;
    body["model"] = model;
    body["messages"] = json::array();
    if (!systemPrompt.empty()) body["messages"].push_back({ {"role", "system"}, {"content", systemPrompt} });
    for (const auto& msg : history) body["messages"].push_back({ {"role", msg.role}, {"content", msg.content} });
    if (model.find("o1") != std::string::npos || model.find("o3") != std::string::npos)
    {
        if (!systemPrompt.empty()) { body["messages"][0]["role"] = "user"; }
    }
    else
    {
        body["temperature"] = 0.2;
    }

    HINTERNET session = WinHttpOpen(L"KYV-Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { error = "Could not initialize HTTP session"; return {}; }
    HINTERNET connection = WinHttpConnect(session, host, url.nPort, 0);
    if (!connection) { WinHttpCloseHandle(session); error = "Could not connect to provider"; return {}; }
    DWORD reqFlags = isHttps ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connection, L"POST", Widen(endpoint).c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
    if (!request)
    {
        WinHttpCloseHandle(connection); WinHttpCloseHandle(session);
        error = "Could not create HTTP request"; return {};
    }
    WinHttpSetTimeouts(request, 5000, 5000, 10000, 30000);

    std::wstring headers = L"Content-Type: application/json\r\nAuthorization: Bearer " + Widen(apiKey);
    std::string payload = body.dump();
    BOOL sent = WinHttpSendRequest(request, headers.c_str(), (DWORD)-1L,
        payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0);
    if (sent) sent = WinHttpReceiveResponse(request, nullptr);
    if (!sent)
    {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connection); WinHttpCloseHandle(session);
        error = "Provider request failed"; return {};
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusSize, WINHTTP_NO_HEADER_INDEX);
    std::string response;
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0)
    {
        if (response.size() + available > 1024 * 1024)
        {
            error = "Provider response exceeded the 1 MB safety limit";
            break;
        }
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read) || read == 0) break;
        response.append(chunk.data(), read);
    }
    WinHttpCloseHandle(request); WinHttpCloseHandle(connection); WinHttpCloseHandle(session);
    if (!error.empty()) return {};
    if (statusCode < 200 || statusCode >= 300)
    {
        error = "Provider returned HTTP " + std::to_string(statusCode);
        return {};
    }
    try
    {
        json result = json::parse(response);
        if (!result.contains("choices") || result["choices"].empty())
        {
            error = "Provider returned no answer";
            return {};
        }
        return result["choices"][0]["message"]["content"].get<std::string>();
    }
    catch (...)
    {
        error = "Provider response was not valid JSON";
        return {};
    }
}

void AIService::ClearConversation()
{
    std::lock_guard<std::mutex> lock(mutex_);
    conversation_.clear();
    state_ = ChatState::Idle;
    status_ = "Conversation cleared";
}

ChatState AIService::State() const { std::lock_guard<std::mutex> lock(mutex_); return state_; }
std::string AIService::Status() const { std::lock_guard<std::mutex> lock(mutex_); return status_; }
std::string AIService::Provider() const { std::lock_guard<std::mutex> lock(mutex_); return provider_; }
std::string AIService::BaseUrl() const { std::lock_guard<std::mutex> lock(mutex_); return baseUrl_; }
std::string AIService::Model() const { std::lock_guard<std::mutex> lock(mutex_); return model_; }
std::vector<ChatMessage> AIService::Conversation() const { std::lock_guard<std::mutex> lock(mutex_); return conversation_; }

} // namespace kyv::ai
