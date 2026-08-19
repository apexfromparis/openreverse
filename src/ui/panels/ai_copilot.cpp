#include "ai_copilot.h"
#include "app/application.h"
#include "ui/workspace_ui.h"

#include <imgui.h>
#include <cstring>

namespace openreverse::panels {

void AICopilotPanel::OpenSettings()
{
    settingsOpen_ = true;
}

void AICopilotPanel::RenderSettingsInline(Application& app)
{
    workspace_ui::CardBegin("##AICopilotConfigCard", ImVec2(0.0f, 320.0f));
    workspace_ui::TextHeading("AI Copilot Configuration (BYOK)", 2);
    workspace_ui::TextMuted("Connect your local (Ollama / LM Studio) or cloud (OpenRouter / OpenAI) model.");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    workspace_ui::SectionLabel("Provider presets");
    if (ImGui::Button("Ollama / Qwen Coder"))
    {
        strncpy_s(provider_, "Ollama", _TRUNCATE);
        strncpy_s(baseUrl_, "http://localhost:11434/v1", _TRUNCATE);
        strncpy_s(model_, "qwen2.5-coder:7b", _TRUNCATE);
    }
    ImGui::SameLine();
    if (ImGui::Button("LM Studio"))
    {
        strncpy_s(provider_, "LM Studio", _TRUNCATE);
        strncpy_s(baseUrl_, "http://localhost:1234/v1", _TRUNCATE);
        strncpy_s(model_, "qwen2.5-coder-7b-instruct", _TRUNCATE);
    }
    ImGui::SameLine();
    if (ImGui::Button("OpenRouter"))
    {
        strncpy_s(provider_, "OpenRouter", _TRUNCATE);
        strncpy_s(baseUrl_, "https://openrouter.ai/api/v1", _TRUNCATE);
        strncpy_s(model_, "qwen/qwen-2.5-coder-32b-instruct", _TRUNCATE);
    }

    workspace_ui::SectionLabel("Connection Settings");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Provider", provider_, sizeof(provider_));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Base URL", baseUrl_, sizeof(baseUrl_));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("Model", model_, sizeof(model_));
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputText("API key", apiKey_, sizeof(apiKey_), ImGuiInputTextFlags_Password);

    ImGui::Spacing();
    if (workspace_ui::PrimaryButton("Apply Configuration", ImVec2(160.0f, 32.0f)))
        app.aiService.Configure(provider_, baseUrl_, model_);
    ImGui::SameLine();
    if (workspace_ui::SecondaryButton("Save Key to Windows Vault", ImVec2(200.0f, 32.0f)))
    {
        app.aiService.Configure(provider_, baseUrl_, model_);
        if (app.aiService.SaveApiKey(apiKey_))
            apiKey_[0] = '\0';
    }
    ImGui::SameLine();
    if (workspace_ui::SecondaryButton("Forget Key", ImVec2(110.0f, 32.0f)))
        app.aiService.ClearApiKey();

    ImGui::Spacing();
    ImGui::TextDisabled("Status: %s", app.aiService.Status().c_str());
    workspace_ui::CardEnd();
}

void AICopilotPanel::RenderSettings(Application& app)
{
    if (!settingsOpen_)
        return;

    ImGui::SetNextWindowSize(ImVec2(520.0f, 430.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Settings > AI", &settingsOpen_))
    {
        ImGui::End();
        return;
    }

    RenderSettingsInline(app);
    ImGui::End();
}

void AICopilotPanel::Render(Application& app)
{
    ImGui::Begin("AI ASSISTANT", nullptr, ImGuiWindowFlags_None);
    workspace_ui::PanelHeader("AI ASSISTANT", model_);

    const auto& function = app.analysisPanel.GetActiveFunction();
    workspace_ui::SectionLabel("Current context");
    if (!app.isAttached)
    {
        ImGui::TextDisabled("Select a function or address to provide analysis context.");
    }
    else
    {
        ImGui::TextUnformatted(function.startAddress != 0 ? function.name.c_str() : app.attachedProcessName.c_str());
        if (function.startAddress != 0)
        {
            ImGui::TextDisabled("%zu decoded instructions  |  %d Xrefs",
                function.cfg.decodedInstructionCount, function.xrefCount);
        }
        else
        {
            ImGui::TextDisabled("Address 0x%llX", static_cast<unsigned long long>(app.currentAddress));
        }
    }

    const bool requestBusy = app.aiService.State() == ai::ChatState::Working;
    if (!app.isAttached || requestBusy) ImGui::BeginDisabled();
    const auto sendAction = [&](const char* request) {
        app.aiService.Configure(provider_, baseUrl_, model_);
        app.aiService.Send(request, app.GetAIContextSummary());
    };
    if (ImGui::Button("Explain"))
        sendAction("Explain the current selection using only the supplied analysis evidence.");
    ImGui::SameLine();
    if (ImGui::Button("Rename"))
        sendAction("Suggest a concise function name for the current selection and explain the evidence.");
    ImGui::SameLine();
    if (ImGui::Button("Analyze"))
        sendAction("Analyze the current selection and separate observations from hypotheses.");
    ImGui::SameLine();
    if (ImGui::Button("Structure"))
        sendAction("Review the current field and memory-access evidence for possible structure layout.");
    if (!app.isAttached || requestBusy) ImGui::EndDisabled();

    workspace_ui::SectionLabel("Conversation");
    const float footerHeight = 112.0f;
    ImGui::BeginChild("AIConversation", ImVec2(0.0f, -footerHeight), true);
    const auto conversation = app.aiService.Conversation();
    if (conversation.empty())
    {
        ImGui::TextDisabled("No conversation yet.");
    }
    for (const auto& message : conversation)
    {
        const bool user = message.role == "user";
        ImGui::TextColored(user ? ImVec4(0.12f, 0.58f, 0.95f, 1.0f) : ImVec4(0.82f, 0.86f, 0.89f, 1.0f),
            user ? "YOU" : "OPENREVERSE AI");
        ImGui::TextWrapped("%s", message.content.c_str());
        ImGui::Spacing();
    }
    ImGui::EndChild();

    ImGui::TextDisabled("Ask about the current selection");
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextMultiline("##prompt", prompt_, sizeof(prompt_), ImVec2(0.0f, 48.0f));
    const bool canSend = prompt_[0] != '\0' && !requestBusy;
    if (!canSend) ImGui::BeginDisabled();
    if (ImGui::Button("Send", ImVec2(80.0f, 0.0f)))
    {
        app.aiService.Configure(provider_, baseUrl_, model_);
        if (app.aiService.Send(prompt_, app.GetAIContextSummary()))
            prompt_[0] = '\0';
    }
    if (!canSend) ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Clear")) app.aiService.ClearConversation();
    ImGui::SameLine();
    ImGui::TextDisabled("%s", app.aiService.Status().c_str());

    ImGui::End();
    RenderSettings(app);
}

} // namespace openreverse::panels
