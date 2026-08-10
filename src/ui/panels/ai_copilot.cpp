#include "ai_copilot.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"

#include <imgui.h>

namespace openreverse::panels {

void AICopilotPanel::Render(Application& app)
{
    ImGui::Begin("AI Copilot", nullptr, ImGuiWindowFlags_None);
    ImGui::TextColored(ImVec4(0.00f, 0.90f, 1.00f, 1.0f), "OPENREVERSE STUDIO - AI COPILOT");
    ImGui::SameLine();
    ImGui::TextDisabled("secure provider bridge");
    ImGui::Separator();

    if (ImGui::CollapsingHeader("Provider settings", ImGuiTreeNodeFlags_DefaultOpen))
    {
        ImGui::TextDisabled("Ollama at localhost needs no key. Cloud keys are stored in Windows Credential Manager.");
        ImGui::TextColored(ImVec4(0.00f, 0.90f, 0.46f, 1.0f), "Provider presets:");
        if (ImGui::SmallButton("Ollama (Qwen-Coder 7B)"))
        {
            strncpy(provider_, "Ollama", sizeof(provider_) - 1);
            strncpy(baseUrl_, "http://localhost:11434/v1", sizeof(baseUrl_) - 1);
            strncpy(model_, "qwen2.5-coder:7b", sizeof(model_) - 1);
            app.aiService.Configure(provider_, baseUrl_, model_);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Ollama (DeepSeek-Coder)"))
        {
            strncpy(provider_, "Ollama", sizeof(provider_) - 1);
            strncpy(baseUrl_, "http://localhost:11434/v1", sizeof(baseUrl_) - 1);
            strncpy(model_, "deepseek-coder-v2", sizeof(model_) - 1);
            app.aiService.Configure(provider_, baseUrl_, model_);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("LM Studio (Local)"))
        {
            strncpy(provider_, "LM Studio", sizeof(provider_) - 1);
            strncpy(baseUrl_, "http://localhost:1234/v1", sizeof(baseUrl_) - 1);
            strncpy(model_, "qwen2.5-coder-7b-instruct", sizeof(model_) - 1);
            app.aiService.Configure(provider_, baseUrl_, model_);
        }
        if (ImGui::SmallButton("Groq Cloud (Llama-3.3 70B)"))
        {
            strncpy(provider_, "Groq Cloud", sizeof(provider_) - 1);
            strncpy(baseUrl_, "https://api.groq.com/openai/v1", sizeof(baseUrl_) - 1);
            strncpy(model_, "llama-3.3-70b-versatile", sizeof(model_) - 1);
            app.aiService.Configure(provider_, baseUrl_, model_);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("OpenRouter (Qwen-Coder 32B)"))
        {
            strncpy(provider_, "OpenRouter", sizeof(provider_) - 1);
            strncpy(baseUrl_, "https://openrouter.ai/api/v1", sizeof(baseUrl_) - 1);
            strncpy(model_, "qwen/qwen-2.5-coder-32b-instruct", sizeof(model_) - 1);
            app.aiService.Configure(provider_, baseUrl_, model_);
        }
        ImGui::Separator();
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("Provider", provider_, sizeof(provider_));
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("HTTPS base URL", baseUrl_, sizeof(baseUrl_));
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("Model", model_, sizeof(model_));
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("API key", apiKey_, sizeof(apiKey_), ImGuiInputTextFlags_Password);
        if (ImGui::Button("Save key securely"))
        {
            app.aiService.Configure(provider_, baseUrl_, model_);
            if (app.aiService.SaveApiKey(apiKey_))
                apiKey_[0] = '\0';
        }
        ImGui::SameLine();
        if (ImGui::Button("Forget saved key"))
            app.aiService.ClearApiKey();
        ImGui::SameLine();
        const bool requiresKey = app.aiService.RequiresApiKey();
        ImGui::TextColored(!requiresKey || app.aiService.HasSavedApiKey() ? ImVec4(0.00f, 0.90f, 0.46f, 1.0f) : ImVec4(1.00f, 0.67f, 0.25f, 1.0f),
            !requiresKey ? "no key required" : (app.aiService.HasSavedApiKey() ? "saved" : "not configured"));
    }

    ImGui::Separator();
    ImGui::Text("Reverse skill");
    const auto& skills = skills_.All();
    if (!skills.empty())
    {
        if (ImGui::BeginCombo("##skill", skills[(size_t)selectedSkill_].title.c_str()))
        {
            for (int i = 0; i < (int)skills.size(); ++i)
            {
                bool selected = selectedSkill_ == i;
                if (ImGui::Selectable(skills[(size_t)i].title.c_str(), selected)) selectedSkill_ = i;
                if (selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }
        ImGui::TextWrapped("%s", skills[(size_t)selectedSkill_].description.c_str());
    }

    ImGui::Separator();
    ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.92f, 1.0f), "Quick Context Injectors (1-Click attach to prompt):");
    if (ImGui::SmallButton("+ Disassembly"))
    {
        char buf[512];
        snprintf(buf, sizeof(buf), "Analyze this x86/x64 disassembly at 0x%llX:\n", (unsigned long long)app.currentAddress);
        size_t len = strlen(prompt_);
        if (len + strlen(buf) < sizeof(prompt_) - 1)
            strcat(prompt_, buf);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("+ Hex Dump (64B)"))
    {
        auto bytes = app.memoryReader.ReadBytes(app.processHandle, app.currentAddress, 64);
        std::string hex = "Memory Hex Dump at 0x" + helpers::FormatAddress(app.currentAddress, app.is64Bit) + ":\n" + helpers::BytesToHex(bytes.data(), bytes.size(), " ") + "\n";
        size_t len = strlen(prompt_);
        if (len + hex.size() < sizeof(prompt_) - 1)
            strcat(prompt_, hex.c_str());
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("+ PE Audit Req"))
    {
        std::string sum = "Audit PE module headers, exports, and sections for security risks or packing indicators:\n";
        size_t len = strlen(prompt_);
        if (len + sum.size() < sizeof(prompt_) - 1)
            strcat(prompt_, sum.c_str());
    }

    ImGui::Separator();
    ImGui::Text("Conversation");
    ImGui::BeginChild("AIConversation", ImVec2(0, -118), true, ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& message : app.aiService.Conversation())
    {
        bool user = message.role == "user";
        ImGui::TextColored(user ? ImVec4(0.00f, 0.90f, 1.00f, 1.0f) : ImVec4(0.73f, 0.53f, 0.99f, 1.0f),
            user ? "YOU" : "AI");
        ImGui::SameLine();
        ImGui::TextWrapped("%s", message.content.c_str());
        ImGui::Spacing();
    }
    ImGui::EndChild();

    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextMultiline("##prompt", prompt_, sizeof(prompt_), ImVec2(0, 70), ImGuiInputTextFlags_AllowTabInput);
    if (ImGui::Button("Send", ImVec2(90, 0)))
    {
        app.aiService.Configure(provider_, baseUrl_, model_);
        if (app.aiService.Send(prompt_, skills.empty() ? nullptr : &skills[(size_t)selectedSkill_],
                               app.GetAIContextSummary()))
            prompt_[0] = '\0';
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear chat")) app.aiService.ClearConversation();
    ImGui::SameLine();
    ImGui::TextDisabled("%s", app.aiService.Status().c_str());

    ImGui::End();
}

} // namespace openreverse::panels
