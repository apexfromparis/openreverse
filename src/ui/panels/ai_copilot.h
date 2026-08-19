#pragma once

#include "ai/ai_service.h"

namespace openreverse { class Application; namespace panels {

class AICopilotPanel
{
public:
    void Render(Application& app);
    void OpenSettings();

private:
    void RenderSettings(Application& app);
    bool settingsOpen_ = false;
    char provider_[64] = "Ollama";
    char baseUrl_[256] = "http://localhost:11434/v1";
    char model_[128] = "qwen2.5-coder:7b";
    char apiKey_[512] = {};
    char prompt_[4096] = {};
};

}} // namespace openreverse::panels
