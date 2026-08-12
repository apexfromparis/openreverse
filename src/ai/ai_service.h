#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace openreverse::ai {

enum class ChatState { Idle, Working, Ready, Error };

struct ChatMessage
{
    std::string role;
    std::string content;
};

class AIService
{
public:
    AIService();
    ~AIService();

    AIService(const AIService&) = delete;
    AIService& operator=(const AIService&) = delete;

    void Configure(const std::string& provider, const std::string& baseUrl, const std::string& model);
    bool SaveApiKey(const std::string& apiKey);
    bool HasSavedApiKey() const;
    bool RequiresApiKey() const;
    void ClearApiKey();

    bool Send(const std::string& prompt, const std::string& hiddenContext = "");
    void ClearConversation();

    ChatState State() const;
    std::string Status() const;
    std::string Provider() const;
    std::string BaseUrl() const;
    std::string Model() const;
    std::vector<ChatMessage> Conversation() const;

private:
    void Worker(std::string prompt, std::string hiddenContext,
                uint64_t conversationGeneration);
    std::string LoadApiKey() const;
    std::string Request(const std::string& apiKey, const std::string& systemPrompt,
        const std::vector<ChatMessage>& history, std::string& error) const;
    std::string CredentialTarget() const;

    mutable std::mutex mutex_;
    std::string provider_ = "Ollama";
    std::string baseUrl_ = "http://localhost:11434/v1";
    std::string model_ = "qwen2.5-coder:7b";
    std::vector<ChatMessage> conversation_;
    ChatState state_ = ChatState::Idle;
    std::string status_ = "AI service idle";
    uint64_t conversationGeneration_ = 0;
    std::thread worker_;
    std::atomic<bool> stopping_{false};
};

} // namespace openreverse::ai
