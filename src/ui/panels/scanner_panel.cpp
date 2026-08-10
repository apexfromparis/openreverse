// ============================================================================
// OpenReverse - UI Panel: Scanner Panel Implementation
// ============================================================================

#include "scanner_panel.h"
#include "app/application.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include <imgui.h>
#include <cstring>
#include <utility>

namespace openreverse { namespace panels {

void ScannerPanel::Render(Application& app)
{
    ImGui::Begin("Pattern Scanner", nullptr, ImGuiWindowFlags_None);

    if (targetGeneration_ != app.targetGeneration)
    {
        targetGeneration_ = app.targetGeneration;
        report_ = PatternScanReport{};
        selectedSection_ = 0;
        scanJobId_ = 0;
    }

    const AnalysisJobSnapshot scanJob = scanJobId_ != 0
        ? app.analysisScheduler.GetJob(scanJobId_) : AnalysisJobSnapshot{};
    const bool scanWorking = scanJob.state == AnalysisJobState::Queued || scanJob.state == AnalysisJobState::Running;

    UIManager::BeginToolbar();
    ImGui::Text("Preset");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(185.0f);
    const char* presets[] = {
        "Custom AOB...",
        "MSVC x64 Prologue (48 89 5C)",
        "MSVC x86 Prologue (55 8B EC)",
        "GCC x64 Prologue (55 48 89 E5)",
        "Intel CET Endbr64 (F3 0F 1E FA)",
        "MSVC Hotpatch Prologue (8B FF 55 8B)",
        "PE Magic DOS Header (4D 5A 90)",
        "UPX Packer Magic (55 50 58 30)",
        "Shellcode GetRIP (E8 ?? ?? 5E)"
    };
    const char* presetPatterns[] = {
        "",
        "48 89 5C 24 ?? 48 89 6C 24",
        "55 8B EC 83 EC",
        "55 48 89 E5",
        "F3 0F 1E FA",
        "8B FF 55 8B EC",
        "4D 5A 90 00",
        "55 50 58 30",
        "E8 ?? ?? ?? ?? 5E"
    };
    if (ImGui::Combo("##preset", &selectedPreset_, presets, 9))
    {
        if (selectedPreset_ > 0 && selectedPreset_ < 9)
        {
            strncpy(patternInput_, presetPatterns[selectedPreset_], sizeof(patternInput_) - 1);
            patternInput_[sizeof(patternInput_) - 1] = 0;
        }
    }
    ImGui::SameLine();
    ImGui::Text("AOB");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-135.0f);
    ImGui::InputTextWithHint("##pattern", "48 8B ?? ?? 74 0A  (?? = wildcard)", patternInput_, sizeof(patternInput_));
    if (app.attachedPID == 0 && app.offlinePEInfo.valid)
    {
        ImGui::SetNextItemWidth(170.0f);
        const char* scopes[] = {"Executable sections", "All mapped regions", "Specific section"};
        ImGui::Combo("##offlinescope", &offlineScope_, scopes, 3);
        if (offlineScope_ == 2 && !app.offlinePEInfo.sections.empty())
        {
            if (selectedSection_ >= static_cast<int>(app.offlinePEInfo.sections.size())) selectedSection_ = 0;
            ImGui::SameLine();
            ImGui::SetNextItemWidth(100.0f);
            const char* preview = app.offlinePEInfo.sections[selectedSection_].name;
            if (ImGui::BeginCombo("##scansection", preview))
            {
                for (int i = 0; i < static_cast<int>(app.offlinePEInfo.sections.size()); ++i)
                {
                    if (ImGui::Selectable(app.offlinePEInfo.sections[i].name, selectedSection_ == i))
                        selectedSection_ = i;
                }
                ImGui::EndCombo();
            }
        }
    }
    bool canScan = app.isAttached && strlen(patternInput_) > 0 && !scanWorking;
    if (!canScan) ImGui::BeginDisabled();
    if (ImGui::Button("Scan"))
    {
        auto pattern = PatternScanner::ParsePattern(patternInput_);
        if (!pattern.empty())
        {
            if (app.attachedPID == 0 && app.offlinePEInfo.valid)
            {
                OfflinePatternScanOptions options;
                options.scope = offlineScope_ == 1 ? OfflinePatternScanScope::AllMappedRegions :
                    (offlineScope_ == 2 ? OfflinePatternScanScope::SpecificSection :
                                          OfflinePatternScanScope::ExecutableSections);
                if (offlineScope_ == 2 && !app.offlinePEInfo.sections.empty())
                    options.sectionName = app.offlinePEInfo.sections[selectedSection_].name;
                options.patternIdentifier = selectedPreset_ > 0 ? presets[selectedPreset_] : "Custom AOB";
                const auto* image = &app.offlineImageBuffer;
                const PEInfo pe = app.offlinePEInfo;
                const size_t rawSize = app.offlineFileBuffer.size();
                scanJobId_ = app.analysisScheduler.Submit("Offline pattern scan",
                    [this, pattern = std::move(pattern), image, pe, rawSize, options](
                        const CancellationToken& cancellation,
                        const AnalysisScheduler::ProgressCallback& progress) mutable {
                        PatternScanner scanner;
                        auto result = scanner.ScanOffline(pattern, *image, pe, rawSize, options,
                                                          &cancellation, progress);
                        return [this, result = std::move(result)]() mutable {
                            report_ = std::move(result);
                            scanJobId_ = 0;
                        };
                    });
            }
            else
            {
                auto regions = app.memoryReader.GetCommittedRegions();
                const HANDLE processHandle = app.processHandle;
                scanJobId_ = app.analysisScheduler.Submit("Live pattern scan",
                    [this, pattern = std::move(pattern), regions = std::move(regions), processHandle](
                        const CancellationToken& cancellation,
                        const AnalysisScheduler::ProgressCallback& progress) mutable {
                        PatternScanner scanner;
                        PatternScanReport result;
                        result.results = scanner.ScanRegions(processHandle, pattern, regions, 1000,
                                                             &cancellation, progress);
                        return [this, result = std::move(result)]() mutable {
                            report_ = std::move(result);
                            scanJobId_ = 0;
                        };
                    });
            }
        }
        else
        {
            report_ = PatternScanReport{};
            report_.error = "Pattern syntax is invalid";
        }
    }
    if (!canScan) ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.7f, 0.5f, 1.0f), "%zu results", report_.results.size());
    if (scanWorking)
    {
        ImGui::SameLine();
        ImGui::ProgressBar(scanJob.progress, ImVec2(90.0f, 0.0f));
        ImGui::SameLine();
        if (ImGui::SmallButton("Cancel")) app.analysisScheduler.Cancel(scanJobId_);
    }
    else if (scanJobId_ != 0 && scanJob.state == AnalysisJobState::Failed)
    {
        report_.error = scanJob.error;
        scanJobId_ = 0;
    }
    else if (scanJobId_ != 0 && scanJob.state == AnalysisJobState::Cancelled)
    {
        report_.error = "Pattern scan cancelled";
        scanJobId_ = 0;
    }
    UIManager::EndToolbar();

    ImGui::Separator();

    if (!app.isAttached)
    {
        UIManager::EmptyState("Open a binary or attach to a process to scan byte patterns.");
        ImGui::End();
        return;
    }

    // Results table
    if (!report_.error.empty())
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.35f, 1.0f), "%s", report_.error.c_str());
    else if (report_.byteLimitReached)
        ImGui::TextDisabled("Partial results: byte budget reached after %zu bytes.", report_.bytesScanned);
    else if (report_.resultLimitReached)
        ImGui::TextDisabled("Partial results: result limit reached.");

    if (!report_.results.empty() && ImGui::BeginTable("ScanResults", 4,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
    {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160.0f);
        ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Raw", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableSetupColumn("Section / Module", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& res : report_.results)
        {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            std::string addr = helpers::FormatAddress(res.address, app.is64Bit);
            if (ImGui::Selectable(addr.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                app.NavigateToAddress(res.address);
            if (ImGui::BeginPopupContextItem("ScanResultCtx"))
            {
                if (ImGui::MenuItem("Go to"))
                    app.NavigateToAddress(res.address);
                auto* mod = app.moduleManager.FindModuleByAddress(res.address);
                if (mod)
                {
                    std::string offStr = helpers::FormatModuleOffset(mod->name, mod->baseAddress, res.address, app.is64Bit);
                    if (ImGui::MenuItem("Copy Module+Offset"))
                        ImGui::SetClipboardText(offStr.c_str());
                }
                if (ImGui::MenuItem("Add to Offsets & Structures"))
                    app.AddOffsetFromAddress(res.address);
                ImGui::EndPopup();
            }

            ImGui::TableSetColumnIndex(1);
            if (res.hasRva) ImGui::Text("0x%08X", res.rva); else ImGui::TextDisabled("-");
            ImGui::TableSetColumnIndex(2);
            if (res.hasRawOffset) ImGui::Text("0x%08zX", res.rawOffset); else ImGui::TextDisabled("virtual");
            ImGui::TableSetColumnIndex(3);
            auto* mod = app.moduleManager.FindModuleByAddress(res.address);
            if (!res.sectionName.empty())
            {
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f), "%s", res.sectionName.c_str());
            }
            else if (mod)
            {
                std::string offStr = helpers::FormatModuleOffset(mod->name, mod->baseAddress, res.address, app.is64Bit);
                ImGui::TextColored(ImVec4(0.35f, 0.85f, 0.55f, 1.0f), "%s", offStr.c_str());
            }
            else
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "(unknown)");
        }

        ImGui::EndTable();
    }

    if (ImGui::Button("Clear Results"))
        report_ = PatternScanReport{};

    ImGui::End();
}

}} // namespace openreverse::panels
