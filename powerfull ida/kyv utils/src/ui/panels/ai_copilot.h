#pragma once

#include "ai/ai_service.h"

namespace kyv { class Application; namespace panels {

class AICopilotPanel
{
public:
    void Render(Application& app);

private:
    ai::ReverseSkillRegistry skills_;
    int selectedSkill_ = 0;
    char provider_[64] = "OpenAI-compatible";
    char baseUrl_[256] = "https://api.openai.com/v1";
    char model_[128] = "gpt-4o-mini";
    char apiKey_[512] = {};
    char prompt_[4096] = {};
};

}} // namespace kyv::panels
