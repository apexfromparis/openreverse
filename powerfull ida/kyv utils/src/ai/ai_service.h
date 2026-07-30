#pragma once

#include "reverse_skills.h"

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace kyv::ai {

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
    void ClearApiKey();

    bool Send(const std::string& prompt, const ReverseSkill* skill);
    void ClearConversation();

    ChatState State() const;
    std::string Status() const;
    std::string Provider() const;
    std::string BaseUrl() const;
    std::string Model() const;
    std::vector<ChatMessage> Conversation() const;

private:
    void Worker(std::string prompt, std::string skillPrompt);
    std::string LoadApiKey() const;
    std::string Request(const std::string& apiKey, const std::string& systemPrompt,
        const std::vector<ChatMessage>& history, std::string& error) const;
    std::string CredentialTarget() const;

    mutable std::mutex mutex_;
    std::string provider_ = "OpenAI-compatible";
    std::string baseUrl_ = "https://api.openai.com/v1";
    std::string model_ = "gpt-4o-mini";
    std::vector<ChatMessage> conversation_;
    ChatState state_ = ChatState::Idle;
    std::string status_ = "AI service idle";
    std::thread worker_;
    std::atomic<bool> stopping_{false};
};

} // namespace kyv::ai
