#include "offsets_panel.h"

#include "app/application.h"
#include "core/module_manager.h"
#include "core/pattern_scanner.h"
#include "core/signature_engine.h"
#include "ui/ui_manager.h"
#include "utils/helpers.h"
#include "utils/logger.h"

#include <commdlg.h>
#include <imgui.h>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace openreverse { namespace panels {

namespace {

const char* EvidenceName(EvidenceLevel level)
{
    switch (level)
    {
    case EvidenceLevel::Known: return "Known";
    case EvidenceLevel::Inferred: return "Inferred";
    case EvidenceLevel::Heuristic: return "Heuristic";
    case EvidenceLevel::Partial: return "Partial";
    default: return "Unknown";
    }
}

const char* OffsetKindName(OffsetKind kind)
{
    switch (kind)
    {
    case OffsetKind::GlobalRva: return "Global RVA";
    case OffsetKind::StructureField: return "Structure field";
    case OffsetKind::FunctionRva: return "Function RVA";
    case OffsetKind::ImportRva: return "Import RVA";
    case OffsetKind::ExportRva: return "Export RVA";
    case OffsetKind::PatternMatch: return "Pattern match";
    default: return "User defined";
    }
}

const char* SignatureStatusName(SignatureStatus status)
{
    switch (status)
    {
    case SignatureStatus::Unique: return "Unique";
    case SignatureStatus::Ambiguous: return "Ambiguous";
    case SignatureStatus::NotFound: return "Not found";
    default: return "Invalid";
    }
}

std::string OffsetLocation(const OffsetRecord& offset)
{
    std::ostringstream stream;
    stream << std::uppercase << std::hex;
    if (offset.kind == OffsetKind::StructureField)
    {
        const uint64_t magnitude = offset.fieldOffset < 0
            ? static_cast<uint64_t>(-(offset.fieldOffset + 1)) + 1
            : static_cast<uint64_t>(offset.fieldOffset);
        stream << (offset.fieldOffset < 0 ? "-0x" : "+0x")
               << magnitude;
    }
    else
        stream << "0x" << offset.rva;
    return stream.str();
}

} // namespace

void OffsetsPanel::AddFromAddress(Application& app, uint64_t address,
                                  const std::string& defaultName)
{
    const ModuleInfo* module = app.moduleManager.FindModuleByAddress(address);
    if (!module) return;
    OffsetRecord offset;
    offset.address = address;
    offset.rva = address - module->baseAddress;
    offset.name = defaultName.empty()
        ? "offset_" + helpers::FormatAddress(offset.rva, false).substr(2) : defaultName;
    offset.kind = OffsetKind::UserDefined;
    offset.module = module->name;
    offset.evidence = EvidenceLevel::Known;
    offset.evidenceScore = 1;
    offset.provenance.push_back("user selection");
    std::ostringstream stable;
    stable << "user:" << std::hex << offset.rva;
    offset.stableId = stable.str();
    if (!app.analysisDatabase.UpsertOffset(module->baseAddress, offset))
        Logger::Get().Log(LogLevel::Warning,
            "Analyze the module before adding a canonical offset record");
    else
        app.analysisSession.MarkDirty();
}

void OffsetsPanel::CopyJson(const ModuleAnalysisState& analysis) const
{
    OffsetProject project;
    project.module = analysis.identity;
    project.offsets = analysis.offsets;
    project.signatures = analysis.signatures;
    const std::string json = SerializeOffsetProject(project);
    ImGui::SetClipboardText(json.c_str());
}

void OffsetsPanel::CopyHeader(const ModuleAnalysisState& analysis) const
{
    OffsetProject project;
    project.module = analysis.identity;
    project.offsets = analysis.offsets;
    const std::string header = ExportOffsetHeader(project);
    ImGui::SetClipboardText(header.c_str());
}

void OffsetsPanel::SaveJson(const ModuleAnalysisState& analysis)
{
    char fileName[MAX_PATH] = "openreverse-offsets.json";
    OPENFILENAMEA dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = "OpenReverse offset JSON (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    dialog.lpstrFile = fileName;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    dialog.lpstrDefExt = "json";
    dialog.lpstrTitle = "Export canonical offsets and signatures";
    if (!GetSaveFileNameA(&dialog)) return;

    OffsetProject project;
    project.module = analysis.identity;
    project.offsets = analysis.offsets;
    project.signatures = analysis.signatures;
    std::ofstream stream(fileName, std::ios::binary | std::ios::trunc);
    const std::string json = SerializeOffsetProject(project);
    if (!stream || !stream.write(json.data(), static_cast<std::streamsize>(json.size())))
    {
        importStatus_ = "Export failed: the selected file could not be written.";
        return;
    }
    importStatus_ = std::string("Exported offset project to ") + fileName;
}

void OffsetsPanel::ImportJson()
{
    OPENFILENAMEA dialog{};
    char fileName[MAX_PATH] = "";
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = "OpenReverse offset JSON (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    dialog.lpstrFile = fileName;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    dialog.lpstrTitle = "Import known offsets and signatures";
    if (!GetOpenFileNameA(&dialog)) return;

    std::ifstream stream(fileName, std::ios::binary | std::ios::ate);
    if (!stream || stream.tellg() <= 0 || stream.tellg() > 16 * 1024 * 1024)
    {
        importStatus_ = "Import failed: file is empty, unreadable, or exceeds 16 MB.";
        return;
    }
    std::string json(static_cast<size_t>(stream.tellg()), '\0');
    stream.seekg(0);
    if (!stream.read(json.data(), json.size()))
    {
        importStatus_ = "Import failed: file could not be read completely.";
        return;
    }
    OffsetProject project;
    std::string error;
    if (!ParseOffsetProject(json, project, error))
    {
        importStatus_ = error;
        return;
    }
    importedProject_ = std::move(project);
    ++importRevision_;
    importStatus_ = "Imported " + std::to_string(importedProject_.offsets.size()) +
        " offsets and " + std::to_string(importedProject_.signatures.size()) + " signatures.";
}

void OffsetsPanel::RebuildMigration(Application& app, const ModuleAnalysisState& analysis)
{
    migrationRows_.clear();
    migrationAnalysisRevision_ = analysis.revision;
    migrationImportRevision_ = importRevision_;
    if (app.offlineImageBuffer.empty() || importedProject_.signatures.empty()) return;

    PatternScanner scanner;
    SignatureEngine signatureEngine;
    const size_t signatureLimit = std::min<size_t>(importedProject_.signatures.size(), 1000);
    for (size_t index = 0; index < signatureLimit; ++index)
    {
        const auto& signature = importedProject_.signatures[index];
        OfflinePatternScanOptions options;
        options.scope = OfflinePatternScanScope::ExecutableSections;
        options.patternIdentifier = signature.stableId;
        options.maxResults = 100;
        const auto report = scanner.ScanOffline(signature.pattern, app.offlineImageBuffer,
            analysis.pe, app.offlineFileBuffer.size(), options);
        MigrationDisplayRow row;
        row.stableId = signature.stableId;
        row.oldTarget = signature.targetOffset;
        row.matchCount = report.results.size();
        row.targetKind = signature.relationship.kind;
        row.status = !report.error.empty() ? SignatureStatus::Invalid :
            row.matchCount == 0 ? SignatureStatus::NotFound :
            row.matchCount == 1 ? SignatureStatus::Unique : SignatureStatus::Ambiguous;
        if (row.status == SignatureStatus::Unique)
        {
            const uint64_t match = report.results.front().address;
            const auto bytes = app.memoryReader.ReadBytes(nullptr, match, 64);
            const auto instructions = app.disassembler.Disassemble(
                bytes.data(), bytes.size(), match, 16);
            const auto resolved = signatureEngine.Resolve(signature, match, instructions);
            if (resolved.valid)
            {
                row.candidateAddress = resolved.address;
                row.candidateValue = resolved.value;
            }
            else
                row.status = SignatureStatus::Invalid;
        }
        migrationRows_.push_back(std::move(row));
    }
}

void OffsetsPanel::Render(Application& app)
{
    ImGui::Begin("OFFSETS & STRUCTURES###STRUCTURES", nullptr, ImGuiWindowFlags_None);
    UIManager::PanelHeader("OFFSETS & STRUCTURES");
    if (!app.isAttached)
    {
        UIManager::EmptyState("Open a binary or dump, or attach to an authorized process.");
        ImGui::End();
        return;
    }

    const ModuleAnalysisState* analysis = app.analysisDatabase.FindModuleContaining(app.currentAddress);
    if (!analysis && !app.analysisDatabase.GetModules().empty())
        analysis = &app.analysisDatabase.GetModules().begin()->second;
    if (!analysis)
    {
        UIManager::EmptyState("Analyze the current module to build deterministic offset evidence.");
        ImGui::End();
        return;
    }

    if (!ImGui::BeginTabBar("OffsetAnalysisTabs"))
    {
        ImGui::End();
        return;
    }

    if (ImGui::BeginTabItem("Offsets"))
    {
        if (analysis->offsets.empty())
            UIManager::EmptyState("No deterministic offsets are available for this module.");
        else if (ImGui::BeginTable("OffsetRecords", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY))
        {
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Kind");
            ImGui::TableSetupColumn("RVA / Field");
            ImGui::TableSetupColumn("Module");
            ImGui::TableSetupColumn("Source");
            ImGui::TableSetupColumn("Evidence");
            ImGui::TableHeadersRow();
            for (const auto& offset : analysis->offsets)
            {
                ImGui::PushID(offset.stableId.c_str());
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                const uint64_t navigation = offset.address != 0 ? offset.address : offset.sourceInstruction;
                if (ImGui::Selectable(offset.name.c_str(), false,
                    ImGuiSelectableFlags_SpanAllColumns) && navigation != 0)
                    app.NavigateToAddress(navigation);
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(OffsetKindName(offset.kind));
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(OffsetLocation(offset).c_str());
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(offset.module.c_str());
                ImGui::TableSetColumnIndex(4);
                if (offset.sourceInstruction != 0)
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(offset.sourceInstruction));
                else if (offset.sourceFunction != 0)
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(offset.sourceFunction));
                else ImGui::TextDisabled("-");
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%s · %u", EvidenceName(offset.evidence), offset.evidenceScore);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Copy JSON")) CopyJson(*analysis);
        ImGui::SameLine();
        if (ImGui::Button("Save JSON...")) SaveJson(*analysis);
        ImGui::SameLine();
        if (ImGui::Button("Copy C++ header")) CopyHeader(*analysis);
        ImGui::SameLine();
        if (ImGui::Button("Import JSON...")) ImportJson();
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Structures"))
    {
        if (analysis->structures.empty())
            UIManager::EmptyState("No compatible field groups were observed.");
        for (const auto& structure : analysis->structures)
        {
            ImGui::PushID(structure.name.c_str());
            const std::string evidence = std::string(EvidenceName(structure.evidence)) +
                " · score " + std::to_string(structure.evidenceScore);
            UIManager::SectionLabel(structure.name.c_str(), evidence.c_str());
            ImGui::TextDisabled("Base %s | Function 0x%llX | Minimum observed size 0x%llX",
                structure.baseRegister.c_str(),
                static_cast<unsigned long long>(structure.functionAddress),
                static_cast<unsigned long long>(structure.estimatedSize));
            if (ImGui::BeginTable("Fields", 5,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Offset"); ImGui::TableSetupColumn("Width");
                ImGui::TableSetupColumn("Reads"); ImGui::TableSetupColumn("Writes");
                ImGui::TableSetupColumn("References"); ImGui::TableHeadersRow();
                for (const auto& field : structure.fields)
                {
                    ImGui::TableNextRow();
                    const uint64_t magnitude = field.offset < 0
                        ? static_cast<uint64_t>(-(field.offset + 1)) + 1
                        : static_cast<uint64_t>(field.offset);
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%s0x%llX", field.offset < 0 ? "-" : "+",
                                static_cast<unsigned long long>(magnitude));
                    ImGui::TableSetColumnIndex(1); ImGui::Text("%u", field.size);
                    ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", field.readCount);
                    ImGui::TableSetColumnIndex(3); ImGui::Text("%zu", field.writeCount);
                    ImGui::TableSetColumnIndex(4);
                    if (!field.accessSites.empty())
                    {
                        const std::string label = std::to_string(field.accessSites.size()) + " refs";
                        if (ImGui::Selectable(label.c_str())) app.NavigateToAddress(field.accessSites.front());
                    }
                }
                ImGui::EndTable();
            }
            ImGui::PopID();
        }
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Globals"))
    {
        if (analysis->globals.empty())
            UIManager::EmptyState("No resolved references to non-executable sections were observed.");
        else if (ImGui::BeginTable("Globals", 6,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("RVA"); ImGui::TableSetupColumn("Section");
            ImGui::TableSetupColumn("Reads"); ImGui::TableSetupColumn("Writes");
            ImGui::TableSetupColumn("Xrefs"); ImGui::TableSetupColumn("Evidence");
            ImGui::TableHeadersRow();
            for (const auto& global : analysis->globals)
            {
                ImGui::PushID(static_cast<int>(global.rva)); ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                std::ostringstream rva; rva << "0x" << std::uppercase << std::hex << global.rva;
                if (ImGui::Selectable(rva.str().c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                    app.NavigateToAddress(global.address);
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(global.sectionName.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", global.readCount + global.addressCount);
                ImGui::TableSetColumnIndex(3); ImGui::Text("%zu", global.writeCount);
                ImGui::TableSetColumnIndex(4); ImGui::Text("%zu", global.xrefs.size());
                ImGui::TableSetColumnIndex(5); ImGui::Text("%s · %u", EvidenceName(global.evidence), global.evidenceScore);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Signatures"))
    {
        if (analysis->signatures.empty())
            UIManager::EmptyState("No decoded-instruction signatures were generated.");
        else if (ImGui::BeginTable("Signatures", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
        {
            ImGui::TableSetupColumn("Pattern"); ImGui::TableSetupColumn("Target");
            ImGui::TableSetupColumn("Matches"); ImGui::TableSetupColumn("Status");
            ImGui::TableHeadersRow();
            for (const auto& signature : analysis->signatures)
            {
                ImGui::PushID(signature.stableId.c_str()); ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                const std::string pattern = SignatureEngine::FormatPattern(signature.pattern);
                ImGui::TextUnformatted(pattern.c_str());
                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable(helpers::FormatAddress(signature.targetFunction, app.is64Bit).c_str()))
                    app.NavigateToAddress(signature.targetFunction);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", signature.matchCount);
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(SignatureStatusName(signature.status));
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::EndTabItem();
    }

    if (ImGui::BeginTabItem("Migration"))
    {
        if (!importStatus_.empty()) ImGui::TextWrapped("%s", importStatus_.c_str());
        if (importedProject_.module.sha256.empty() && importedProject_.signatures.empty())
            UIManager::EmptyState("Import an older OpenReverse JSON project to evaluate its signatures.");
        else if (app.offlineImageBuffer.empty())
            UIManager::EmptyState("Migration scanning is available for static binaries and dumps.");
        else
        {
            if (migrationAnalysisRevision_ != analysis->revision ||
                migrationImportRevision_ != importRevision_)
                RebuildMigration(app, *analysis);
            if (!importedProject_.module.sha256.empty() && !analysis->identity.sha256.empty())
                ImGui::TextDisabled("Module identity: %s",
                    importedProject_.module.sha256 == analysis->identity.sha256
                        ? "same SHA-256" : "different SHA-256; review candidates");
            if (migrationRows_.empty())
                UIManager::EmptyState("The imported project has no signatures to migrate.");
            else if (ImGui::BeginTable("MigrationRows", 5,
                ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
            {
                ImGui::TableSetupColumn("Signature"); ImGui::TableSetupColumn("Old target");
                ImGui::TableSetupColumn("Candidate"); ImGui::TableSetupColumn("Matches");
                ImGui::TableSetupColumn("Status"); ImGui::TableHeadersRow();
                for (const auto& row : migrationRows_)
                {
                    ImGui::PushID(row.stableId.c_str()); ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(row.stableId.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", static_cast<unsigned long long>(row.oldTarget));
                    ImGui::TableSetColumnIndex(2);
                    if (row.status == SignatureStatus::Unique)
                    {
                        if (row.targetKind == SignatureTargetKind::FieldDisplacement)
                            ImGui::Text("%+lld", static_cast<long long>(row.candidateValue));
                        else if (ImGui::Selectable(helpers::FormatAddress(row.candidateAddress, app.is64Bit).c_str()))
                            app.NavigateToAddress(row.candidateAddress);
                    }
                    else ImGui::TextDisabled("-");
                    ImGui::TableSetColumnIndex(3); ImGui::Text("%zu", row.matchCount);
                    ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(SignatureStatusName(row.status));
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
        if (ImGui::Button("Import old project...")) ImportJson();
        ImGui::EndTabItem();
    }

    ImGui::EndTabBar();
    ImGui::End();
}

}} // namespace openreverse::panels
