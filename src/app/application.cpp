#include "application.h"
#include "openreverse_version.h"
#include "utils/logger.h"
#include "utils/helpers.h"
#include "ui/panels/analysis_panel.h"
#include "ui/workspace_ui.h"
#include "analysis/disassembler.h"

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <exception>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <set>
#include <utility>
#include <cmath>
#include <filesystem>
#include <limits>

namespace openreverse {

namespace {

ProjectTargetKind ProjectKindFromTarget(AnalysisTargetKind kind)
{
    switch (kind)
    {
    case AnalysisTargetKind::MappedDump: return ProjectTargetKind::MappedDump;
    case AnalysisTargetKind::RawDump: return ProjectTargetKind::RawDump;
    case AnalysisTargetKind::MinidumpModule: return ProjectTargetKind::MinidumpModule;
    case AnalysisTargetKind::LiveProcess: return ProjectTargetKind::LiveProcess;
    default: return ProjectTargetKind::PEFile;
    }
}

std::string EnsureProjectExtension(std::string path)
{
    std::string extension = std::filesystem::path(path).extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    if (extension != ".orev") path += ".orev";
    return path;
}

bool SelectFilePath(const wchar_t* filter, const wchar_t* title, bool save,
                    std::string& path, const std::string& defaultName = {},
                    const wchar_t* defaultExtension = nullptr)
{
    std::vector<wchar_t> fileName(32768, L'\0');
    const std::wstring wideDefault = helpers::Utf8ToWide(defaultName);
    if (!wideDefault.empty())
        wcsncpy_s(fileName.data(), fileName.size(), wideDefault.c_str(), _TRUNCATE);
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.lpstrFilter = filter;
    dialog.lpstrFile = fileName.data();
    dialog.nMaxFile = static_cast<DWORD>(fileName.size());
    dialog.lpstrDefExt = defaultExtension;
    dialog.Flags = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER |
        (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
    dialog.lpstrTitle = title;
    const BOOL selected = save ? GetSaveFileNameW(&dialog) : GetOpenFileNameW(&dialog);
    if (!selected) return false;
    path = helpers::WideToUtf8(fileName.data());
    return !path.empty();
}

} // namespace

Application::Application()
    : analysisDatabase(analysisSession.Database())
{
    extensions::ExtensionHostServices services;
    services.currentTarget = [this](extensions::ExtensionTargetSnapshot& snapshot) {
        const ModuleAnalysisState* analysis = analysisDatabase.FindModuleContaining(currentAddress);
        if (!analysis && !analysisDatabase.GetModules().empty())
            analysis = &analysisDatabase.GetModules().begin()->second;
        if (!analysis) return false;
        snapshot.name = analysis->module.name;
        snapshot.path = analysis->module.path;
        snapshot.sha256 = analysis->identity.sha256;
        snapshot.architecture = analysis->is64Bit
            ? OPENREVERSE_ARCHITECTURE_X64 : OPENREVERSE_ARCHITECTURE_X86;
        snapshot.imageBase = analysis->module.baseAddress;
        snapshot.imageSize = analysis->module.size;
        snapshot.currentAddress = currentAddress;
        snapshot.analysisRevision = analysis->revision;
        snapshot.peTimestamp = analysis->pe.timestamp;
        snapshot.functionCount = static_cast<uint32_t>(std::min<size_t>(
            analysis->functions.size(), (std::numeric_limits<uint32_t>::max)()));
        return true;
    };
    services.functionByIndex = [this](uint32_t index, extensions::ExtensionFunctionSnapshot& snapshot) {
        const ModuleAnalysisState* analysis = analysisDatabase.FindModuleContaining(currentAddress);
        if (!analysis && !analysisDatabase.GetModules().empty())
            analysis = &analysisDatabase.GetModules().begin()->second;
        if (!analysis || index >= analysis->functions.size()) return false;
        const FunctionInfo& function = analysis->functions[index];
        snapshot.name = function.name;
        snapshot.address = function.startAddress;
        snapshot.rva = function.startAddress >= analysis->module.baseAddress
            ? function.startAddress - analysis->module.baseAddress : function.startAddress;
        snapshot.size = function.size;
        snapshot.instructionCount = static_cast<uint32_t>(std::min<size_t>(
            function.cfg.decodedInstructionCount, (std::numeric_limits<uint32_t>::max)()));
        snapshot.basicBlockCount = static_cast<uint32_t>(std::min<size_t>(
            function.cfg.basicBlocks.size(), (std::numeric_limits<uint32_t>::max)()));
        snapshot.directCallCount = static_cast<uint32_t>(std::min<size_t>(
            function.callTargets.size(), (std::numeric_limits<uint32_t>::max)()));
        snapshot.boundaryKnown = function.boundaryKnown;
        return true;
    };
    services.navigateToAddress = [this](uint64_t address) {
        const ModuleAnalysisState* analysis = analysisDatabase.FindModuleContaining(address);
        if (!analysis) return false;
        NavigateToAddress(address);
        return true;
    };
    services.hasProject = [this]() { return analysisSession.HasProject(); };
    services.projectPath = [this]() { return analysisSession.ProjectPath(); };
    services.getExtensionState = [this](const std::string& id, std::string& state) {
        const std::string* stored = analysisSession.ExtensionState(id);
        if (!stored) return false;
        state = *stored;
        return true;
    };
    services.setExtensionState = [this](const std::string& id, const std::string& state,
                                        std::string& error) {
        return analysisSession.SetExtensionState(id, state, error);
    };
    extensionManager.Configure(std::move(services), {kVersionMajor, kVersionMinor, kVersionPatch});
    extensionManager.DiscoverAndLoad(extensions::ExtensionManager::DefaultExtensionRoot());
    for (const auto& diagnostic : extensionManager.Diagnostics())
    {
        const LogLevel level = diagnostic.kind == extensions::ExtensionDiagnosticKind::Loaded
            ? LogLevel::Info : LogLevel::Warning;
        Logger::Get().Log(level, "Extension %s: %s", diagnostic.extensionId.empty()
            ? "discovery" : diagnostic.extensionId.c_str(), diagnostic.message.c_str());
    }
    Logger::Get().Log(LogLevel::Info, "OpenReverse initialized. Ready to analyze.");
}

Application::~Application()
{
    Shutdown();
}

void Application::Shutdown()
{
    if (shutdown_) return;
    shutdown_ = true;
    analysisScheduler.CancelAllAndWait();
    extensionManager.Shutdown();
    DetachFromProcess();
}

bool Application::AttachToProcess(DWORD pid)
{
    DetachFromProcess();
    HANDLE handle = processAccess.OpenProcess(pid);
    if (!handle)
    {
        Logger::Get().Log(LogLevel::Error, "Failed to open process PID %d", pid);
        return false;
    }

    processHandle = handle;
    attachedPID = pid;
    is64Bit = processAccess.IsProcess64Bit(handle);
    isAttached = true;
    targetKind = AnalysisTargetKind::LiveProcess;

    const auto procs = processAccess.ListProcesses();
    attachedProcessName = "Process_" + std::to_string(pid);
    for (const auto& p : procs)
    {
        if (p.pid == pid)
        {
            attachedProcessName = p.name;
            break;
        }
    }

    disassembler.Init(is64Bit);
    memoryReader.RefreshRegions(processHandle);
    moduleCatalog.RefreshModules(processHandle);

    Logger::Get().Log(LogLevel::Info, "Attached to %s (PID: %d, %s)",
        attachedProcessName.c_str(), pid, is64Bit ? "x64" : "x86");

    extensionManager.NotifySessionChanged(targetGeneration, true);
    activeNavView_ = AppNavView::Workspace;
    return true;
}

void Application::DetachFromProcess()
{
    analysisScheduler.CancelAllAndWait();
    offlineAnalysisJobId = 0;
    analysisDatabase.Clear();
    analysisPanel.ResetAnalysis();
    xrefScanner.Clear();
    stringResults.clear();
    selectedBytes.clear();
    moduleCatalog.Clear();
    aiService.ClearConversation();
    hexEditorPanel.Reset();
    disasmViewPanel.Reset();
    modulesPanel.Reset();
    ++targetGeneration;
    if (isAttached && processHandle)
    {
        processAccess.CloseProcess(processHandle);
        Logger::Get().Log(LogLevel::Info, "Detached from %s", attachedProcessName.c_str());
    }
    isAttached = false;
    targetKind = AnalysisTargetKind::None;
    attachedPID = 0;
    processHandle = nullptr;
    attachedProcessName.clear();
    loadedFilePath.clear();
    memoryReader.SetOfflineBuffer(nullptr, 0);
    offlineFileBuffer.clear();
    offlineImageBuffer.clear();
    offlinePEInfo = PEInfo{};
    is64Bit = false;
    currentAddress = 0;
    extensionManager.NotifySessionChanged(targetGeneration, false);
}

const ModuleAnalysisState* Application::CurrentAnalysis() const
{
    const ModuleAnalysisState* analysis = analysisDatabase.FindModuleContaining(currentAddress);
    if (!analysis && !analysisDatabase.GetModules().empty())
        analysis = &analysisDatabase.GetModules().begin()->second;
    return analysis;
}

void Application::PublishModuleAnalysis(ModuleAnalysisResult result)
{
    if (!result.success)
    {
        if (!result.cancelled)
            Logger::Get().Log(LogLevel::Error, "Module analysis failed: %s", result.error.c_str());
        return;
    }
    analysisSession.ApplyPersistedAnalysis(result);
    analysisDatabase.ReplaceModuleAnalysis(result.module, is64Bit, result.pe,
        result.functions, result.xrefs, result.strings, result.globals, result.fieldAccesses,
        result.structures, result.offsets, result.signatures, result.identity,
        result.symbols, result.symbolTypes, result.symbolIdentity);

    xrefScanner.ReplaceEntries(result.xrefs);
    stringResults = result.strings;
    Logger::Get().Log(LogLevel::Info,
        "Module analysis: %zu functions, %zu Xrefs, %zu strings, %zu globals, %zu structures, "
        "%lld ms (PE %lld, code %lld, CFG %lld, strings %lld)",
        result.functions.size(), result.xrefs.size(), result.strings.size(),
        result.globals.size(), result.structures.size(),
        static_cast<long long>(result.totalDuration.count()),
        static_cast<long long>(result.peDuration.count()),
        static_cast<long long>(result.codeDuration.count()),
        static_cast<long long>(result.cfgDuration.count()),
        static_cast<long long>(result.stringDuration.count()));
}

bool Application::AnalyzeCurrentModuleSynchronously()
{
    const ModuleInfo* module = moduleCatalog.FindModuleByAddress(currentAddress);
    if (!module && !moduleCatalog.GetModules().empty())
        module = &moduleCatalog.GetModules().front();
    if (!module) return false;

    ModuleAnalysisPipeline pipeline;
    ModuleAnalysisResult result;
    if (targetKind == AnalysisTargetKind::LiveProcess)
    {
        if (!processHandle) return false;
        result = pipeline.AnalyzeLive(processHandle, *module, is64Bit);
    }
    else
    {
        if (offlineImageBuffer.empty() || !offlinePEInfo.valid) return false;
        result = pipeline.AnalyzeMappedImage(offlineImageBuffer, offlineFileBuffer.size(), *module, offlinePEInfo);
    }
    if (!result.success)
    {
        Logger::Get().Log(LogLevel::Error, "Synchronous analysis failed: %s", result.error.c_str());
        return false;
    }
    PublishModuleAnalysis(std::move(result));
    return true;
}

void Application::ShowOpenFileDialog()
{
    std::string path;
    if (SelectFilePath(L"Supported PE binaries (*.sys;*.exe;*.dll)\0*.sys;*.exe;*.dll\0All Files (*.*)\0*.*\0",
                       L"Open PE binary or driver file", false, path))
    {
        OpenBinaryFile(path);
    }
}

void Application::ShowOpenDumpDialog()
{
    std::string path;
    if (SelectFilePath(L"Supported memory dumps (*.dmp;*.mdmp;*.bin)\0*.dmp;*.mdmp;*.bin\0All Files (*.*)\0*.*\0",
                       L"Open a mapped PE image, raw memory snapshot, or minidump", false, path))
    {
        pendingDumpPath_ = path;
        DumpLoader loader;
        DumpLoadResult probe = loader.Load(path, {});
        pendingDumpModules_ = probe.availableModules;
        pendingDumpModuleIndex_ = 0;
        dumpImportError_.clear();
        if (pendingDumpModules_.empty())
        {
            std::error_code sizeError;
            const uintmax_t size = std::filesystem::file_size(
                std::filesystem::u8path(path), sizeError);
            if (!sizeError)
            {
                snprintf(dumpModuleSizeBuf_, sizeof(dumpModuleSizeBuf_), "%llu",
                         static_cast<unsigned long long>(size));
            }
        }
        showDumpImportModal_ = true;
        requestDumpImportPopup_ = true;
    }
}

void Application::ShowOpenProjectDialog()
{
    std::string path;
    if (SelectFilePath(L"OpenReverse projects (*.orev)\0*.orev\0All Files (*.*)\0*.*\0",
                       L"Open an OpenReverse project", false, path, {}, L"orev"))
        OpenProjectFile(path);
}

bool Application::ShowProjectTargetDialog(std::string& filePath) const
{
    return SelectFilePath(
        L"Supported targets (*.sys;*.exe;*.dll;*.dmp;*.mdmp;*.bin)\0"
        L"*.sys;*.exe;*.dll;*.dmp;*.mdmp;*.bin\0All Files (*.*)\0*.*\0",
        L"Locate the target referenced by this project", false, filePath);
}

bool Application::OpenProjectFile(const std::string& filePath)
{
    OpenReverseProject project;
    std::string error;
    if (!ProjectStore::Load(filePath, project, error))
    {
        Logger::Get().Log(LogLevel::Error, "Project load failed: %s", error.c_str());
        MessageBoxA(nullptr, error.c_str(), "OpenReverse project", MB_OK | MB_ICONERROR);
        return false;
    }
    if (project.target.kind == ProjectTargetKind::LiveProcess)
    {
        error = "Live-process projects cannot be reopened automatically. Open the matching binary or attach manually.";
        Logger::Get().Log(LogLevel::Error, "%s", error.c_str());
        MessageBoxA(nullptr, error.c_str(), "OpenReverse project", MB_OK | MB_ICONWARNING);
        return false;
    }

    std::string targetPath = project.target.path;
    bool restoreTargetBoundState = false;
    for (;;)
    {
        const ProjectTargetVerification verification = ProjectStore::VerifyTarget(project, targetPath);
        if (verification.status == ProjectTargetVerificationStatus::Match)
        {
            restoreTargetBoundState = true;
            break;
        }
        if (verification.status == ProjectTargetVerificationStatus::HashMismatch)
        {
            const std::string message =
                "The selected target does not match the SHA-256 stored in this project.\n\n"
                "Yes: open it as a changed target without restoring target-bound annotations.\n"
                "No: locate the original target.\n"
                "Cancel: leave the current workspace unchanged.";
            const int choice = MessageBoxA(nullptr, message.c_str(), "Target identity mismatch",
                                           MB_YESNOCANCEL | MB_ICONWARNING);
            if (choice == IDYES)
            {
                restoreTargetBoundState = false;
                break;
            }
            if (choice == IDCANCEL) return false;
        }
        else
        {
            const std::string message = verification.error +
                "\n\nSelect OK to locate the referenced target, or Cancel to stop.";
            if (MessageBoxA(nullptr, message.c_str(), "Project target unavailable",
                            MB_OKCANCEL | MB_ICONWARNING) != IDOK)
                return false;
        }
        if (!ShowProjectTargetDialog(targetPath)) return false;
    }

    analysisSession.SetLoadedProject(project, filePath, restoreTargetBoundState);
    openingProjectTarget_ = true;
    bool opened = false;
    const ProjectTarget& target = analysisSession.Project().target;
    if (target.kind == ProjectTargetKind::PEFile)
    {
        opened = OpenBinaryFile(targetPath);
    }
    else
    {
        DumpImportOptions options;
        options.architecture = target.architecture == "x64"
            ? DumpArchitecture::X64 : DumpArchitecture::X86;
        options.imageBase = target.imageBase;
        options.moduleSize = target.moduleSize;
        options.minidumpModuleBase = target.selectedModuleBase;
        if (target.kind == ProjectTargetKind::MappedDump)
            options.representation = DumpRepresentation::MappedPEImage;
        else if (target.kind == ProjectTargetKind::RawDump)
            options.representation = DumpRepresentation::RawSnapshot;
        else
            options.representation = DumpRepresentation::Minidump;
        opened = OpenDumpFile(targetPath, options);
    }
    openingProjectTarget_ = false;
    if (!opened)
    {
        analysisSession.ClearProject();
        return false;
    }
    extensionManager.NotifyProjectOpened();
    Logger::Get().Log(LogLevel::Info, "Opened OpenReverse project: %s%s", filePath.c_str(),
        restoreTargetBoundState ? "" : " (changed target; annotations not restored)");
    activeNavView_ = AppNavView::Workspace;
    return true;
}

bool Application::SaveProjectFile(bool saveAs)
{
    if (!isAttached || targetKind == AnalysisTargetKind::LiveProcess)
    {
        MessageBoxA(nullptr,
            "Open an offline binary or dump before saving a project. Live-process projects are not persisted in version 1.",
            "Save OpenReverse project", MB_OK | MB_ICONINFORMATION);
        return false;
    }
    const ModuleAnalysisState* analysis = analysisDatabase.FindModuleContaining(currentAddress);
    if (!analysis && !analysisDatabase.GetModules().empty())
        analysis = &analysisDatabase.GetModules().begin()->second;
    if (!analysis)
    {
        MessageBoxA(nullptr, "Wait for target analysis to complete before saving the project.",
                    "Save OpenReverse project", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    std::string error;
    ProjectTarget target;
    target.kind = ProjectKindFromTarget(targetKind);
    target.path = loadedFilePath;
    target.architecture = is64Bit ? "x64" : "x86";
    target.imageBase = analysis->module.baseAddress;
    target.moduleSize = static_cast<uint32_t>(std::min<uint64_t>(
        analysis->module.size, (std::numeric_limits<uint32_t>::max)()));
    target.sha256 = analysis->identity.sha256;
    target.module.name = analysis->module.name;
    target.module.sha256 = target.sha256;
    target.module.imageBase = analysis->module.baseAddress;
    target.module.imageSize = static_cast<uint32_t>(std::min<uint64_t>(
        analysis->module.size, (std::numeric_limits<uint32_t>::max)()));
    if (target.module.peTimestamp == 0) target.module.peTimestamp = analysis->pe.timestamp;

    ProjectUiState ui;
    ui.currentRva = currentAddress >= analysis->module.baseAddress
        ? currentAddress - analysis->module.baseAddress : 0;
    ui.workspace = isDevMode ? "editor" : "reverse";
    if (showAnalysisPanel_) ui.openPanels.push_back("analysis");
    if (showMemoryMap_) ui.openPanels.push_back("memory-map");
    if (showScanner_) ui.openPanels.push_back("scanner");
    if (showStrings_) ui.openPanels.push_back("strings");
    if (showDataInspector_) ui.openPanels.push_back("data-inspector");
    if (showPEViewer_) ui.openPanels.push_back("pe-viewer");
    if (showBookmarks_) ui.openPanels.push_back("bookmarks");
    if (showConsole_) ui.openPanels.push_back("console");
    if (showVersionIntelligence_) ui.openPanels.push_back("version-intelligence");

    OpenReverseProject project = analysisSession.BuildSnapshot(target, *analysis, ui);
    std::string outputPath = analysisSession.ProjectPath();
    if (saveAs || outputPath.empty() || analysisSession.RequiresSaveAs())
    {
        std::string defaultName = std::filesystem::path(attachedProcessName).stem().string();
        if (defaultName.empty()) defaultName = "OpenReverseProject";
        for (char& character : defaultName)
            if (std::string("<>:\"/\\|?*").find(character) != std::string::npos) character = '_';
        defaultName += ".orev";
        if (!SelectFilePath(L"OpenReverse projects (*.orev)\0*.orev\0All Files (*.*)\0*.*\0",
                            L"Save OpenReverse project", true, outputPath,
                            defaultName, L"orev"))
            return false;
        outputPath = EnsureProjectExtension(std::move(outputPath));
    }
    if (!ProjectStore::SaveAtomic(outputPath, project, error))
    {
        Logger::Get().Log(LogLevel::Error, "Project save failed: %s", error.c_str());
        MessageBoxA(nullptr, error.c_str(), "Save OpenReverse project", MB_OK | MB_ICONERROR);
        return false;
    }
    const bool hadProject = analysisSession.HasProject();
    analysisSession.MarkSaved(std::move(project), outputPath);
    if (!hadProject) extensionManager.NotifyProjectOpened();
    Logger::Get().Log(LogLevel::Info, "Saved OpenReverse project: %s", outputPath.c_str());
    return true;
}

bool Application::OpenBinaryFile(const std::string& filePath)
{
    try
    {
        DetachFromProcess();
        if (!openingProjectTarget_)
        {
            if (analysisSession.HasProject()) extensionManager.NotifyProjectClosed();
            analysisSession.ClearProject();
        }
        std::cout << "[*] Parsing PE headers and mapping sections..." << std::endl;

        std::vector<uint8_t> rawFile;
        std::vector<uint8_t> mappedImage;
        PEInfo info = peParser.ParseFile(filePath, rawFile);
        if (!info.valid || rawFile.empty())
        {
            std::cout << "\033[1;31m[-] Failed to parse PE binary: " << filePath << "\033[0m" << std::endl;
            Logger::Get().Log(LogLevel::Error, "Failed to parse PE binary: %s", filePath.c_str());
            return false;
        }
        if (!PEParser::BuildMappedImage(rawFile, info, mappedImage))
        {
            Logger::Get().Log(LogLevel::Error, "Failed to build the RVA-mapped image: %s", filePath.c_str());
            return false;
        }

        offlineFileBuffer = std::move(rawFile);
        offlineImageBuffer = std::move(mappedImage);
        offlinePEInfo = info;
        loadedFilePath = filePath;
        is64Bit = info.is64bit;
        const size_t separator = filePath.find_last_of("/\\");
        attachedProcessName = separator == std::string::npos ? filePath : filePath.substr(separator + 1);
        isAttached = true;
        targetKind = AnalysisTargetKind::PEFile;
        attachedPID = 0;
        currentAddress = info.imageBase + info.entryPoint;
        extensionManager.NotifySessionChanged(targetGeneration, true);

        memoryReader.SetOfflineBuffer(&offlineImageBuffer, info.imageBase);
        disassembler.Init(is64Bit);
        moduleCatalog.Clear();
        moduleCatalog.AddModule(attachedProcessName, info.imageBase, info.sizeOfImage, loadedFilePath);

        if (ImGui::GetCurrentContext())
        {
            const uint64_t generation = targetGeneration;
            const auto mapped = offlineImageBuffer;
            const auto raw = offlineFileBuffer;
            const ModuleInfo module{attachedProcessName, loadedFilePath, info.imageBase, info.sizeOfImage};
            Application* application = this;
            offlineAnalysisJobId = analysisScheduler.Submit("Offline binary analysis",
                [application, generation, mapped, raw, module, info](
                    const CancellationToken& cancellation,
                    const AnalysisScheduler::ProgressCallback& progress) mutable {
                    ModuleAnalysisPipeline pipeline;
                    auto result = pipeline.AnalyzeMappedImage(
                        mapped, raw.size(), module, info, {}, &cancellation, progress);
                    return [application, generation, result = std::move(result)]() mutable {
                        if (application->targetGeneration != generation) return;
                        application->offlineAnalysisJobId = 0;
                        if (!result.success)
                        {
                            if (!result.cancelled)
                                Logger::Get().Log(LogLevel::Error,
                                    "Offline analysis failed: %s", result.error.c_str());
                            return;
                        }
                        application->analysisPanel.ApplyModuleAnalysis(
                            *application, std::move(result));
                        application->RestoreProjectUiAfterAnalysis();
                    };
                });
            Logger::Get().Log(LogLevel::Info, "Offline binary analysis queued: %s",
                attachedProcessName.c_str());
            activeNavView_ = AppNavView::Workspace;
            return true;
        }

        ModuleAnalysisPipeline pipeline;
        auto analysis = pipeline.AnalyzeMappedImage(
            offlineImageBuffer, offlineFileBuffer.size(),
            ModuleInfo{attachedProcessName, loadedFilePath, info.imageBase, info.sizeOfImage}, info);
        if (!analysis.success)
        {
            const std::string error = analysis.error.empty() ? "Analysis was cancelled" : analysis.error;
            Logger::Get().Log(LogLevel::Error, "Offline analysis failed: %s", error.c_str());
            DetachFromProcess();
            return false;
        }
        PublishModuleAnalysis(std::move(analysis));
        RestoreProjectUiAfterAnalysis();
        Logger::Get().Log(LogLevel::Info, "Opened offline target: %s (%s, %zu bytes)",
            attachedProcessName.c_str(), is64Bit ? "x64" : "x86", offlineFileBuffer.size());
        activeNavView_ = AppNavView::Workspace;
        return true;
    }
    catch (const std::exception& exception)
    {
        DetachFromProcess();
        Logger::Get().Log(LogLevel::Error, "Failed to open offline file: %s", exception.what());
        return false;
    }
}

bool Application::OpenDumpFile(const std::string& filePath, const DumpImportOptions& options)
{
    try
    {
        DumpLoader loader;
        DumpLoadResult dump = loader.Load(filePath, options);
        if (!dump.success)
        {
            Logger::Get().Log(LogLevel::Error, "Dump import failed: %s", dump.error.c_str());
            return false;
        }

        DetachFromProcess();
        if (!openingProjectTarget_)
        {
            if (analysisSession.HasProject()) extensionManager.NotifyProjectClosed();
            analysisSession.ClearProject();
        }

        loadedFilePath = filePath;
        attachedProcessName = dump.module.name;
        is64Bit = dump.architecture == DumpArchitecture::X64;
        isAttached = true;
        targetKind = dump.representation == DumpRepresentation::Minidump
            ? AnalysisTargetKind::MinidumpModule
            : dump.representation == DumpRepresentation::RawSnapshot
                ? AnalysisTargetKind::RawDump : AnalysisTargetKind::MappedDump;
        attachedPID = 0;
        offlineFileBuffer.clear();
        offlineImageBuffer = std::move(dump.imageBytes);
        offlinePEInfo = dump.pe;
        currentAddress = dump.pe.imageBase + dump.pe.entryPoint;
        extensionManager.NotifySessionChanged(targetGeneration, true);
        memoryReader.SetOfflineBuffer(&offlineImageBuffer, dump.pe.imageBase);
        disassembler.Init(is64Bit);
        moduleCatalog.Clear();
        moduleCatalog.AddModule(dump.module.name, dump.module.baseAddress,
                                dump.module.size, filePath);

        if (ImGui::GetCurrentContext())
        {
            const uint64_t generation = targetGeneration;
            const auto mapped = offlineImageBuffer;
            const ModuleInfo module = dump.module;
            const PEInfo pe = dump.pe;
            Application* application = this;
            offlineAnalysisJobId = analysisScheduler.Submit("Static dump analysis",
                [application, generation, mapped, module, pe](
                    const CancellationToken& cancellation,
                    const AnalysisScheduler::ProgressCallback& progress) mutable {
                    ModuleAnalysisPipeline pipeline;
                    auto result = pipeline.AnalyzeMappedImage(
                        mapped, 0, module, pe, {}, &cancellation, progress);
                    return [application, generation, result = std::move(result)]() mutable {
                        if (application->targetGeneration != generation) return;
                        application->offlineAnalysisJobId = 0;
                        if (!result.success)
                        {
                            if (!result.cancelled)
                                Logger::Get().Log(LogLevel::Error,
                                    "Dump analysis failed: %s", result.error.c_str());
                            return;
                        }
                        application->analysisPanel.ApplyModuleAnalysis(
                            *application, std::move(result));
                    };
                });
            Logger::Get().Log(LogLevel::Info, "Static dump analysis queued: %s",
                attachedProcessName.c_str());
            activeNavView_ = AppNavView::Workspace;
            return true;
        }

        ModuleAnalysisPipeline pipeline;
        auto analysis = pipeline.AnalyzeMappedImage(
            offlineImageBuffer, 0, dump.module, dump.pe);
        if (!analysis.success)
        {
            const std::string error = analysis.error.empty() ? "Dump analysis was cancelled" : analysis.error;
            Logger::Get().Log(LogLevel::Error, "Dump analysis failed: %s", error.c_str());
            DetachFromProcess();
            return false;
        }
        PublishModuleAnalysis(std::move(analysis));
        Logger::Get().Log(LogLevel::Info, "Loaded static dump: %s (%s, %zu bytes)",
            attachedProcessName.c_str(), is64Bit ? "x64" : "x86", offlineImageBuffer.size());
        activeNavView_ = AppNavView::Workspace;
        return true;
    }
    catch (const std::exception& exception)
    {
        DetachFromProcess();
        Logger::Get().Log(LogLevel::Error, "Dump import exception: %s", exception.what());
        return false;
    }
}

void Application::NavigateToAddress(uint64_t address)
{
    currentAddress = address;
    hexEditorPanel.SetAddress(address);
    disasmViewPanel.SetAddress(address);
}

void Application::Render()
{
    analysisScheduler.DrainCompletions();

    // Global Shortcuts
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O) && !ImGui::GetIO().WantTextInput)
    {
        if (ImGui::GetIO().KeyShift) ShowOpenProjectDialog();
        else ShowOpenFileDialog();
    }
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S) && !ImGui::GetIO().WantTextInput)
        SaveProjectFile(ImGui::GetIO().KeyShift);
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_P) && !ImGui::GetIO().WantTextInput)
        showQuickOpenModal_ = true;

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_1))
        activeNavView_ = AppNavView::Home;
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_2))
        activeNavView_ = AppNavView::Workspace;
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_3))
        activeNavView_ = AppNavView::Projects;
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_4))
        activeNavView_ = AppNavView::VersionIntelligence;
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_5))
        activeNavView_ = AppNavView::Extensions;
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_6))
        activeNavView_ = AppNavView::Settings;

    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_G) && ImGui::GetIO().KeyCtrl)
        showGotoModal_ = true;
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_I) && ImGui::GetIO().KeyCtrl)
    {
        activeNavView_ = AppNavView::Workspace;
        showAnalysisPanel_ = true;
        ImGui::SetWindowFocus("Analysis / Functions & CFG");
    }
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_X) && !ImGui::GetIO().WantCaptureKeyboard)
    {
        activeNavView_ = AppNavView::Workspace;
        analysisPanel.OpenXrefsForAddress(currentAddress);
        ImGui::SetWindowFocus("XREFS");
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F5))
        processListPanel.ForceRefresh();

    RenderAppShell();
}

void Application::RenderAppShell()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();

    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags rootFlags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoScrollbar;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("##OpenReverse_ShellRoot", nullptr, rootFlags);
    ImGui::PopStyleVar(3);

    const float topBarHeight = 44.0f;
    const float statusBarHeight = 24.0f;
    const float sidebarWidth = 210.0f;
    const float contentHeight = (std::max)(100.0f, viewport->WorkSize.y - topBarHeight - statusBarHeight);
    const float contentWidth = (std::max)(200.0f, viewport->WorkSize.x - sidebarWidth);

    // 1. Top Bar
    RenderTopBar(topBarHeight);

    // 2. Sidebar + Content Split
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, 0.0f));

    RenderSidebar(sidebarWidth, contentHeight);

    ImGui::SameLine();

    // Main Content Area
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(14.0f/255.0f, 15.0f/255.0f, 19.0f/255.0f, 1.0f));
    ImGui::BeginChild("##MainContentArea", ImVec2(contentWidth, contentHeight), false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    if (activeNavView_ == AppNavView::Home)
    {
        RenderHomeScreen();
    }
    else if (activeNavView_ == AppNavView::Projects)
    {
        RenderProjectsScreen();
    }
    else if (activeNavView_ == AppNavView::VersionIntelligence)
    {
        bool showVi = true;
        versionIntelligencePanel.Render(*this, &showVi);
    }
    else if (activeNavView_ == AppNavView::Extensions)
    {
        RenderExtensionsWindow();
    }
    else if (activeNavView_ == AppNavView::Settings)
    {
        RenderSettingsScreen();
    }
    else if (activeNavView_ == AppNavView::Workspace)
    {
        if (!isAttached && targetKind == AnalysisTargetKind::None)
        {
            ImGui::Spacing();
            ImGui::Spacing();
            ImGui::Indent(40.0f);
            workspace_ui::CardBegin("##WorkspaceEmptyCard", ImVec2(ImGui::GetContentRegionAvail().x - 40.0f, 290.0f));
            workspace_ui::TextHeading("No Target Loaded in Workspace", 1);
            workspace_ui::TextMuted("Open an executable, driver, memory dump, or attach to a live process to begin reverse engineering.");
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            if (workspace_ui::PrimaryButton("Open Binary File... (Ctrl+O)", ImVec2(200.0f, 36.0f)))
                ShowOpenFileDialog();
            ImGui::SameLine();
            if (workspace_ui::SecondaryButton("Open .orev Project...", ImVec2(180.0f, 36.0f)))
                ShowOpenProjectDialog();
            ImGui::SameLine();
            if (workspace_ui::SecondaryButton("Import Dump...", ImVec2(150.0f, 36.0f)))
                ShowOpenDumpDialog();

            ImGui::Spacing();
            ImGui::Spacing();
            workspace_ui::SectionLabel("Live Process Inspection (Optional)");
            if (workspace_ui::SecondaryButton("Explore Running Processes...", ImVec2(220.0f, 32.0f)))
            {
                processListPanel.ForceRefresh();
            }
            workspace_ui::CardEnd();
            ImGui::Unindent(40.0f);
        }
        else
        {
            RenderDockspace();

            processListPanel.Render(*this);
            hexEditorPanel.Render(*this);
            disasmViewPanel.Render(*this);
            analysisPanel.RenderXRefsPanel(*this);
            modulesPanel.Render(*this);
            offsetsPanel.Render(*this);
            aiCopilotPanel.Render(*this);
            if (isDevMode || showMemoryMap_) memoryMapPanel.Render(*this);
            if (isDevMode || showAnalysisPanel_) analysisPanel.Render(*this);
            if (isDevMode)
                openReverseEditorPanel.Render(*this, showOpenReverseEditor);
            if (isDevMode || showScanner_) scannerPanel.Render(*this);
            if (isDevMode || showStrings_) stringsPanel.Render(*this);
            if (isDevMode || showDataInspector_) dataInspectorPanel.Render(*this);
            if (isDevMode || showPEViewer_) peViewerPanel.Render(*this);
            if (isDevMode || showBookmarks_) bookmarksPanel.Render(*this);
            if (isDevMode || showConsole_) consolePanel.Render(*this);
        }
    }

    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();

    // 3. Status Bar
    RenderStatusBar();

    // 4. Overlays & Modals
    RenderProfileDropdown();
    RenderFirstLaunchModal();
    RenderQuickOpenModal();
    RenderDumpImportDialog();
    RenderExtensionPanels();

    ImGui::End();

    // Subtle window border
    const HWND hwnd = static_cast<HWND>(viewport->PlatformHandleRaw);
    const float rounding = hwnd && IsZoomed(hwnd) ? 0.0f : 6.0f;
    ImGui::GetForegroundDrawList(viewport)->AddRect(
        ImVec2(viewport->Pos.x + 0.5f, viewport->Pos.y + 0.5f),
        ImVec2(viewport->Pos.x + viewport->Size.x - 0.5f, viewport->Pos.y + viewport->Size.y - 0.5f),
        IM_COL32(42, 46, 58, 255), rounding, 0, 1.0f);
}

void Application::RenderTopBar(float height)
{
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(19.0f/255.0f, 21.0f/255.0f, 27.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(38.0f/255.0f, 42.0f/255.0f, 54.0f/255.0f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 6.0f));

    ImGui::BeginChild("##ShellTopBar", ImVec2(0.0f, height), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImU32 white = IM_COL32(245, 247, 252, 255);
    const ImU32 blue = IM_COL32(78, 117, 255, 255);

    // 1. Logo & Brand
    const ImVec2 c(origin.x + 10.0f, origin.y + 16.0f);
    draw->PathArcTo(c, 7.5f, 0.72f, 5.56f, 24);
    draw->PathStroke(white, 0, 2.0f);
    draw->AddLine(ImVec2(c.x + 2.0f, c.y - 5.0f), ImVec2(c.x + 9.0f, c.y - 5.0f), white, 2.0f);
    draw->AddLine(ImVec2(c.x + 9.0f, c.y - 5.0f), ImVec2(c.x + 9.0f, c.y + 1.0f), white, 2.0f);
    draw->AddLine(ImVec2(c.x + 9.0f, c.y + 1.0f), ImVec2(c.x + 1.0f, c.y + 1.0f), white, 2.0f);
    draw->AddLine(ImVec2(c.x + 5.0f, c.y + 1.0f), ImVec2(c.x + 10.0f, c.y + 7.0f), white, 2.0f);
    draw->AddTriangleFilled(ImVec2(c.x - 1.0f, c.y + 1.0f), ImVec2(c.x + 3.0f, c.y - 2.5f), ImVec2(c.x + 3.0f, c.y + 4.5f), white);

    const ImVec2 brandPos(origin.x + 28.0f, origin.y + 8.0f);
    draw->AddText(brandPos, white, "OPEN");
    const float openWidth = ImGui::CalcTextSize("OPEN").x;
    draw->AddText(ImVec2(brandPos.x + openWidth, brandPos.y), blue, "REVERSE");

    // 2. View Breadcrumb Indicator
    const float breadcrumbX = brandPos.x + openWidth + ImGui::CalcTextSize("REVERSE").x + 18.0f;
    draw->AddLine(ImVec2(breadcrumbX, origin.y + 8.0f), ImVec2(breadcrumbX, origin.y + 24.0f), IM_COL32(50, 55, 70, 255), 1.0f);

    std::string viewTitle;
    if (activeNavView_ == AppNavView::Home) viewTitle = "Home";
    else if (activeNavView_ == AppNavView::Workspace)
    {
        if (isAttached)
        {
            const auto* analysis = CurrentAnalysis();
            const size_t fnCount = analysis ? analysis->functions.size() : 0;
            char buf[256];
            snprintf(buf, sizeof(buf), "Workspace  /  %s (%s) • Base 0x%llX • %zu Functions",
                attachedProcessName.c_str(), is64Bit ? "x64" : "x86",
                static_cast<unsigned long long>(offlinePEInfo.imageBase != 0 ? offlinePEInfo.imageBase : currentAddress),
                fnCount);
            viewTitle = buf;
        }
        else viewTitle = "Workspace  /  No target loaded";
    }
    else if (activeNavView_ == AppNavView::Projects) viewTitle = "Projects  /  Workspace Persistence";
    else if (activeNavView_ == AppNavView::VersionIntelligence) viewTitle = "Version Intelligence  /  Binary Comparison & Migration";
    else if (activeNavView_ == AppNavView::Extensions) viewTitle = "Extensions  /  Native C Plugins";
    else if (activeNavView_ == AppNavView::Settings) viewTitle = "Settings  /  Preferences & Account";

    draw->AddText(ImVec2(breadcrumbX + 14.0f, origin.y + 8.0f), IM_COL32(165, 172, 188, 255), viewTitle.c_str());

    // 3. Quick Search Pill
    const float winWidth = ImGui::GetWindowWidth();
    const float searchWidth = 260.0f;
    const float searchX = (winWidth - searchWidth) * 0.5f;
    ImGui::SetCursorScreenPos(ImVec2(origin.x + searchX, origin.y + 4.0f));

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(27.0f/255.0f, 30.0f/255.0f, 38.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(35.0f/255.0f, 40.0f/255.0f, 52.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(45.0f/255.0f, 52.0f/255.0f, 68.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.58f, 0.65f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10.0f, 4.0f));

    if (ImGui::Button("Search commands, symbols... (Ctrl+P)", ImVec2(searchWidth, 24.0f)))
    {
        showQuickOpenModal_ = true;
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(4);

    // 4. Right: Plan badge + Profile button + Window Controls
    const HWND hwnd = static_cast<HWND>(ImGui::GetMainViewport()->PlatformHandleRaw);
    const float controlWidth = 32.0f;
    const float controlsStart = winWidth - controlWidth * 3.0f - 8.0f;
    const float controlsTop = origin.y + 4.0f;

    auto windowButton = [&](const char* id, int kind) {
        ImGui::SetCursorScreenPos(ImVec2(origin.x + controlsStart + kind * controlWidth, controlsTop));
        const ImVec2 p = ImGui::GetCursorScreenPos();
        const bool pressed = ImGui::InvisibleButton(id, ImVec2(controlWidth, height - 10.0f));
        const bool hovered = ImGui::IsItemHovered();
        if (hovered)
            draw->AddRectFilled(p, ImVec2(p.x + controlWidth, p.y + height - 10.0f),
                kind == 2 ? IM_COL32(188, 42, 55, 255) : IM_COL32(35, 40, 52, 255), 4.0f);

        const ImU32 icon = IM_COL32(205, 215, 222, 255);
        const ImVec2 center(p.x + controlWidth * 0.5f, p.y + (height - 10.0f) * 0.5f);
        if (kind == 0)
            draw->AddLine(ImVec2(center.x - 4.5f, center.y + 3.0f),
                ImVec2(center.x + 4.5f, center.y + 3.0f), icon, 1.0f);
        else if (kind == 1)
            draw->AddRect(ImVec2(center.x - 4.0f, center.y - 4.0f),
                ImVec2(center.x + 4.0f, center.y + 4.0f), icon, 0.0f, 0, 1.0f);
        else
        {
            draw->AddLine(ImVec2(center.x - 3.5f, center.y - 3.5f),
                ImVec2(center.x + 3.5f, center.y + 3.5f), icon, 1.1f);
            draw->AddLine(ImVec2(center.x + 3.5f, center.y - 3.5f),
                ImVec2(center.x - 3.5f, center.y + 3.5f), icon, 1.1f);
        }
        return pressed;
    };

    if (windowButton("##MinWin", 0) && hwnd)
        PostMessageW(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
    if (windowButton("##MaxWin", 1) && hwnd)
        ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
    if (windowButton("##CloseWin", 2) && hwnd)
        PostMessageW(hwnd, WM_CLOSE, 0, 0);

    // Profile Button
    const auth::AuthStatus authStatus = accountAuth_.Status();
    const float profileButtonWidth = authStatus.state == auth::AuthState::SignedIn ? 140.0f : 90.0f;
    const float profileX = controlsStart - profileButtonWidth - 12.0f;

    ImGui::SetCursorScreenPos(ImVec2(origin.x + profileX, origin.y + 5.0f));

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(27.0f/255.0f, 30.0f/255.0f, 38.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(38.0f/255.0f, 44.0f/255.0f, 56.0f/255.0f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 5.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.0f, 4.0f));

    if (authStatus.state == auth::AuthState::SignedIn)
    {
        std::string name = !authStatus.displayName.empty() ? authStatus.displayName : authStatus.email;
        if (name.size() > 12) name = name.substr(0, 10) + "..";
        std::string label = " " + name + " v";
        if (ImGui::Button(label.c_str(), ImVec2(profileButtonWidth, 24.0f)))
        {
            showProfileDropdown_ = !showProfileDropdown_;
        }
    }
    else
    {
        if (ImGui::Button("Sign In", ImVec2(profileButtonWidth, 24.0f)))
        {
            showProfileDropdown_ = !showProfileDropdown_;
        }
    }

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void Application::RenderSidebar(float width, float height)
{
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(17.0f/255.0f, 19.0f/255.0f, 24.0f/255.0f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(35.0f/255.0f, 38.0f/255.0f, 48.0f/255.0f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f, 12.0f));

    ImGui::BeginChild("##ShellSidebar", ImVec2(width, height), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImGui::Spacing();

    // 1. Navigation items
    if (workspace_ui::NavItem("##nav_home", "Home", "⌂", activeNavView_ == AppNavView::Home, width - 20.0f))
        activeNavView_ = AppNavView::Home;

    if (workspace_ui::NavItem("##nav_ws", "Workspace", "⚡", activeNavView_ == AppNavView::Workspace, width - 20.0f))
        activeNavView_ = AppNavView::Workspace;

    if (workspace_ui::NavItem("##nav_proj", "Projects", "📁", activeNavView_ == AppNavView::Projects, width - 20.0f))
        activeNavView_ = AppNavView::Projects;

    if (workspace_ui::NavItem("##nav_vi", "Version Intel", "🔄", activeNavView_ == AppNavView::VersionIntelligence, width - 20.0f))
        activeNavView_ = AppNavView::VersionIntelligence;

    if (workspace_ui::NavItem("##nav_ext", "Extensions", "🔌", activeNavView_ == AppNavView::Extensions, width - 20.0f))
        activeNavView_ = AppNavView::Extensions;

    if (workspace_ui::NavItem("##nav_set", "Settings", "⚙", activeNavView_ == AppNavView::Settings, width - 20.0f))
        activeNavView_ = AppNavView::Settings;

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // 2. Quick Action
    if (workspace_ui::SecondaryButton("+ Open Binary", ImVec2(width - 20.0f, 30.0f)))
    {
        ShowOpenFileDialog();
    }

    // 3. Bottom Status Card
    const float bottomCardHeight = 72.0f;
    ImGui::SetCursorPos(ImVec2(10.0f, height - bottomCardHeight - 12.0f));

    workspace_ui::CardBegin("##SidebarStatusCard", ImVec2(width - 20.0f, bottomCardHeight));
    if (isAttached)
    {
        ImDrawList* draw = ImGui::GetWindowDrawList();
        const ImVec2 p = ImGui::GetCursorScreenPos();
        draw->AddCircleFilled(ImVec2(p.x + 5.0f, p.y + 6.0f), 3.5f, IM_COL32(16, 185, 129, 255));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 14.0f);
        ImGui::TextColored(ImVec4(0.1f, 0.85f, 0.5f, 1.0f), "Target Active");
        std::string name = attachedProcessName;
        if (name.size() > 18) name = name.substr(0, 16) + "..";
        ImGui::TextUnformatted(name.c_str());
        ImGui::TextDisabled("%s", is64Bit ? "x64 PE" : "x86 PE");
    }
    else
    {
        ImGui::TextDisabled("Standby");
        ImGui::TextUnformatted("OpenReverse Community");
        ImGui::TextDisabled("v%s", kVersion);
    }
    workspace_ui::CardEnd();

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void Application::RenderHomeScreen()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(32.0f, 24.0f));
    ImGui::BeginChild("##HomeScreenScrollable", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_None);

    // Hero Section
    workspace_ui::TextHeading("Welcome to OpenReverse", 1);
    workspace_ui::TextMuted("Modern, deterministic reverse engineering, graphical control-flow graphs, and binary version intelligence.");
    ImGui::Spacing();

    workspace_ui::Badge("100% OFFLINE STATIC SAFETY", IM_COL32(30, 48, 40, 255), IM_COL32(52, 211, 153, 255));
    ImGui::SameLine();
    workspace_ui::Badge("COMMUNITY RELEASE", IM_COL32(35, 42, 60, 255), IM_COL32(129, 140, 248, 255));

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Spacing();

    // 4 Primary Action Cards
    const float availWidth = ImGui::GetContentRegionAvail().x;
    const float cardWidth = (availWidth - 24.0f) * 0.5f;
    const float cardHeight = 118.0f;

    // Row 1
    workspace_ui::CardBegin("##CardOpenBinary", ImVec2(cardWidth, cardHeight));
    workspace_ui::TextHeading("Open Binary File", 2);
    workspace_ui::TextMuted("Analyze PE32/PE32+ executables, DLLs, system drivers (.sys), or memory dumps.");
    ImGui::Spacing();
    if (workspace_ui::PrimaryButton("Select Binary... (Ctrl+O)", ImVec2(180.0f, 28.0f)))
        ShowOpenFileDialog();
    workspace_ui::CardEnd();

    ImGui::SameLine(0, 24.0f);

    workspace_ui::CardBegin("##CardOpenProject", ImVec2(cardWidth, cardHeight));
    workspace_ui::TextHeading("Open .orev Project", 2);
    workspace_ui::TextMuted("Load a saved workspace project with persisted offsets, bookmarks, and decisions.");
    ImGui::Spacing();
    if (workspace_ui::SecondaryButton("Open Project... (Ctrl+Shift+O)", ImVec2(200.0f, 28.0f)))
        ShowOpenProjectDialog();
    workspace_ui::CardEnd();

    ImGui::Spacing();
    ImGui::Spacing();

    // Row 2
    workspace_ui::CardBegin("##CardVersionIntel", ImVec2(cardWidth, cardHeight));
    workspace_ui::TextHeading("Version Intelligence", 2);
    workspace_ui::TextMuted("Compare two builds of a binary, match functions across mutations, and migrate offsets.");
    ImGui::Spacing();
    if (workspace_ui::SecondaryButton("Open Binary Diff...", ImVec2(180.0f, 28.0f)))
        activeNavView_ = AppNavView::VersionIntelligence;
    workspace_ui::CardEnd();

    ImGui::SameLine(0, 24.0f);

    workspace_ui::CardBegin("##CardExtensions", ImVec2(cardWidth, cardHeight));
    workspace_ui::TextHeading("Native Extension SDK", 2);
    workspace_ui::TextMuted("Extend analysis and UI with high-performance in-process Windows x64 C plugins.");
    ImGui::Spacing();
    if (workspace_ui::SecondaryButton("Browse Extensions...", ImVec2(180.0f, 28.0f)))
        activeNavView_ = AppNavView::Extensions;
    workspace_ui::CardEnd();

    ImGui::Spacing();
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::Spacing();

    // Bottom Two-Column Split
    const float splitWidth = (availWidth - 24.0f) * 0.5f;

    // Left Column: Active Session / Recent Target
    ImGui::BeginGroup();
    workspace_ui::TextHeading("Session Status", 2);
    ImGui::Spacing();
    workspace_ui::CardBegin("##HomeSessionCard", ImVec2(splitWidth, 200.0f));
    if (isAttached)
    {
        const auto* analysis = CurrentAnalysis();
        ImGui::TextColored(ImVec4(0.1f, 0.85f, 0.5f, 1.0f), "Target Loaded: %s", attachedProcessName.c_str());
        ImGui::Spacing();
        ImGui::TextDisabled("Path: %s", loadedFilePath.c_str());
        ImGui::TextDisabled("Architecture: %s", is64Bit ? "x64 (64-bit)" : "x86 (32-bit)");
        if (analysis)
        {
            ImGui::TextDisabled("Functions: %zu | Strings: %zu | Xrefs: %zu",
                analysis->functions.size(), analysis->strings.size(), analysis->xrefs.size());
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        if (workspace_ui::PrimaryButton("Go to Workspace (Ctrl+2)", ImVec2(180.0f, 32.0f)))
            activeNavView_ = AppNavView::Workspace;
    }
    else
    {
        ImGui::TextDisabled("No active target loaded.");
        ImGui::Spacing();
        ImGui::TextWrapped("Click 'Open Binary File' above or use the Command Palette (Ctrl+P) to select a PE executable or driver.");
    }
    workspace_ui::CardEnd();
    ImGui::EndGroup();

    ImGui::SameLine(0, 24.0f);

    // Right Column: Key Features Reference
    ImGui::BeginGroup();
    workspace_ui::TextHeading("Platform Highlights", 2);
    ImGui::Spacing();
    workspace_ui::CardBegin("##HomeHighlightsCard", ImVec2(splitWidth, 200.0f));
    ImGui::BulletText("Layered Graphical CFG with typed edge classification (fallthrough, branch, call, ret).");
    ImGui::BulletText("Version Intelligence multi-stage function matching and offset migration.");
    ImGui::BulletText("BYOK AI Copilot: Connect your local/OpenAI model with secure Credential Manager storage.");
    ImGui::BulletText("100% Offline Guarantee: Community analysis operates entirely on your local machine.");
    workspace_ui::CardEnd();
    ImGui::EndGroup();

    ImGui::EndChild();
    ImGui::PopStyleVar();
}

void Application::RenderProjectsScreen()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(32.0f, 24.0f));
    ImGui::BeginChild("##ProjectsScreenScrollable", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_None);

    workspace_ui::TextHeading("Project Workspace Persistence", 1);
    workspace_ui::TextMuted("Manage .orev workspace files containing target signatures, bookmarks, and accepted migrations.");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (analysisSession.HasProject())
    {
        const OpenReverseProject& proj = analysisSession.Project();
        workspace_ui::CardBegin("##ProjectDetailCard", ImVec2(0.0f, 280.0f));
        workspace_ui::TextHeading("Active Project", 2);
        ImGui::TextDisabled("File: %s", analysisSession.ProjectPath().c_str());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Text("Target Module: %s", proj.target.module.name.c_str());
        ImGui::TextDisabled("SHA-256: %s", proj.target.sha256.c_str());
        ImGui::Text("Saved Offsets: %zu", proj.analysis.offsets.size());
        ImGui::Text("Bookmarks: %zu", proj.user.bookmarks.size());
        ImGui::Text("Accepted Version Intelligence Decisions: %zu", proj.user.migrations.size());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (workspace_ui::PrimaryButton("Save Project (Ctrl+S)", ImVec2(160.0f, 32.0f)))
            SaveProjectFile(false);
        ImGui::SameLine();
        if (workspace_ui::SecondaryButton("Save Project As...", ImVec2(150.0f, 32.0f)))
            SaveProjectFile(true);
        ImGui::SameLine();
        if (workspace_ui::SecondaryButton("Open Another Project...", ImVec2(180.0f, 32.0f)))
            ShowOpenProjectDialog();

        workspace_ui::CardEnd();
    }
    else
    {
        workspace_ui::CardBegin("##NoProjectCard", ImVec2(0.0f, 200.0f));
        workspace_ui::TextHeading("No Active Project", 2);
        workspace_ui::TextMuted("You are currently analyzing a target without an associated .orev project file.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        if (isAttached && targetKind != AnalysisTargetKind::LiveProcess)
        {
            if (workspace_ui::PrimaryButton("Save Current Target as .orev Project...", ImVec2(280.0f, 34.0f)))
                SaveProjectFile(true);
            ImGui::SameLine();
        }
        if (workspace_ui::SecondaryButton("Open Existing .orev Project...", ImVec2(220.0f, 34.0f)))
            ShowOpenProjectDialog();
        workspace_ui::CardEnd();
    }

    ImGui::EndChild();
    ImGui::PopStyleVar();
}

void Application::RenderSettingsScreen()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(32.0f, 24.0f));
    ImGui::BeginChild("##SettingsScreenScrollable", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_None);

    workspace_ui::TextHeading("Settings & Configuration", 1);
    workspace_ui::TextMuted("Manage your account, AI Copilot connection, and desktop preferences.");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Tab buttons
    if (ImGui::Button("Account & Subscription", ImVec2(180.0f, 30.0f))) settingsTab_ = 0;
    ImGui::SameLine();
    if (ImGui::Button("AI Copilot (BYOK)", ImVec2(160.0f, 30.0f))) settingsTab_ = 1;
    ImGui::SameLine();
    if (ImGui::Button("General & Diagnostics", ImVec2(170.0f, 30.0f))) settingsTab_ = 2;

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (settingsTab_ == 0)
    {
        // Account Tab
        const auth::AuthStatus status = accountAuth_.Status();
        const auth::AccountServiceConfig& config = accountAuth_.Config();

        workspace_ui::CardBegin("##SettingsAccountCard", ImVec2(0.0f, 280.0f));
        workspace_ui::TextHeading("OpenReverse Account", 2);
        ImGui::Spacing();

        if (status.state == auth::AuthState::SignedIn)
        {
            ImGui::Text("User: %s", status.displayName.c_str());
            ImGui::TextDisabled("Email: %s", status.email.c_str());
            ImGui::TextDisabled("ID: %s", status.userId.c_str());
            ImGui::Spacing();

            if (status.isProActive)
            {
                workspace_ui::Badge("PLAN: OPENREVERSE PRO", IM_COL32(30, 48, 80, 255), IM_COL32(129, 140, 248, 255));
                if (!status.currentPeriodEnd.empty())
                    ImGui::TextDisabled("Renews: %s", status.currentPeriodEnd.c_str());
            }
            else
            {
                workspace_ui::Badge("PLAN: COMMUNITY", IM_COL32(35, 40, 52, 255), IM_COL32(160, 168, 185, 255));
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (workspace_ui::SecondaryButton("Manage Account (Web)", ImVec2(180.0f, 32.0f)))
            {
                const std::string url = config.accountManageUrl.empty() ? "https://openreverse.dev/account" : config.accountManageUrl;
                const std::wstring wideUrl(url.begin(), url.end());
                ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            ImGui::SameLine();
            if (workspace_ui::SecondaryButton("Sync Profile", ImVec2(130.0f, 32.0f)))
            {
                std::string err;
                accountAuth_.StartProfileRefresh(err);
            }
            ImGui::SameLine();
            if (workspace_ui::SecondaryButton("Sign Out", ImVec2(110.0f, 32.0f)))
            {
                std::string err;
                accountAuth_.SignOut(err);
            }
        }
        else
        {
            ImGui::TextDisabled("Not signed in.");
            ImGui::Spacing();
            ImGui::TextWrapped("Connect your OpenReverse account to sync Pro entitlements and settings.");
            ImGui::Spacing();
            if (workspace_ui::PrimaryButton("Sign in via Browser", ImVec2(180.0f, 34.0f)))
            {
                const std::string url = config.signupUrl.empty() ? "https://openreverse.dev/signup" : config.signupUrl;
                const std::wstring wideUrl(url.begin(), url.end());
                ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
        }
        workspace_ui::CardEnd();
    }
    else if (settingsTab_ == 1)
    {
        // AI Copilot Tab
        aiCopilotPanel.RenderSettingsInline(*this);
    }
    else
    {
        // General Tab
        workspace_ui::CardBegin("##SettingsGeneralCard", ImVec2(0.0f, 260.0f));
        workspace_ui::TextHeading("Environment & Diagnostics", 2);
        ImGui::Spacing();
        ImGui::Text("OpenReverse Desktop Version: %s", kVersion);
        ImGui::TextDisabled("Architecture: Windows x64 Native");
        ImGui::TextDisabled("Extension Directory: %s", extensions::ExtensionManager::DefaultExtensionRoot().string().c_str());
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Checkbox("Developer Code Editor Layout (Ctrl+1 / Ctrl+2)", &isDevMode))
        {
            SwitchToDevMode(isDevMode);
        }
        if (workspace_ui::SecondaryButton("Reset Workspace Docking Layout", ImVec2(240.0f, 30.0f)))
        {
            ResetLayout();
        }
        workspace_ui::CardEnd();
    }

    ImGui::EndChild();
    ImGui::PopStyleVar();
}

void Application::RenderProfileDropdown()
{
    if (!showProfileDropdown_) return;

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    const float cardWidth = 280.0f;
    const float cardX = viewport->WorkPos.x + viewport->WorkSize.x - cardWidth - 16.0f;
    const float cardY = viewport->WorkPos.y + 48.0f;

    ImGui::SetNextWindowPos(ImVec2(cardX, cardY));
    ImGui::SetNextWindowSize(ImVec2(cardWidth, 0.0f));

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings;

    ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(22.0f/255.0f, 24.0f/255.0f, 31.0f/255.0f, 0.98f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(45.0f/255.0f, 50.0f/255.0f, 65.0f/255.0f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 6.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14.0f, 14.0f));

    if (ImGui::Begin("##ProfileDropdownWindow", &showProfileDropdown_, flags))
    {
        const auth::AuthStatus status = accountAuth_.Status();
        const auth::AccountServiceConfig& config = accountAuth_.Config();

        if (status.state == auth::AuthState::SignedIn)
        {
            workspace_ui::TextHeading(!status.displayName.empty() ? status.displayName.c_str() : "Account", 2);
            if (!status.email.empty()) ImGui::TextDisabled("%s", status.email.c_str());
            ImGui::Spacing();

            if (status.isProActive)
                workspace_ui::Badge("OPENREVERSE PRO", IM_COL32(30, 48, 80, 255), IM_COL32(129, 140, 248, 255));
            else
                workspace_ui::Badge("COMMUNITY", IM_COL32(35, 40, 52, 255), IM_COL32(160, 168, 185, 255));

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();

            if (ImGui::MenuItem("Manage Account (Web)"))
            {
                const std::string url = config.accountManageUrl.empty() ? "https://openreverse.dev/account" : config.accountManageUrl;
                const std::wstring wideUrl(url.begin(), url.end());
                ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                showProfileDropdown_ = false;
            }
            if (ImGui::MenuItem("Settings & Copilot"))
            {
                activeNavView_ = AppNavView::Settings;
                showProfileDropdown_ = false;
            }
            if (ImGui::MenuItem("Documentation"))
            {
                const std::wstring wideUrl = L"https://openreverse.dev/docs";
                ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                showProfileDropdown_ = false;
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Sign Out"))
            {
                std::string err;
                accountAuth_.SignOut(err);
                showProfileDropdown_ = false;
            }
        }
        else
        {
            workspace_ui::TextHeading("OpenReverse Account", 2);
            workspace_ui::TextMuted("Sign in to synchronize your profile and subscriptions.");
            ImGui::Spacing();

            if (workspace_ui::PrimaryButton("Sign In via Browser", ImVec2(-1.0f, 32.0f)))
            {
                const std::string url = config.signupUrl.empty() ? "https://openreverse.dev/signup" : config.signupUrl;
                const std::wstring wideUrl(url.begin(), url.end());
                ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                showProfileDropdown_ = false;
            }

            ImGui::Spacing();
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::TextDisabled("Community features & local AI remain 100%% offline.");
        }
    }
    ImGui::End();

    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void Application::RenderFirstLaunchModal()
{
    if (!showFirstLaunchModal_) return;

    ImGui::OpenPopup("Welcome to OpenReverse");
    ImGui::SetNextWindowSize(ImVec2(680.0f, 420.0f), ImGuiCond_Always);

    if (ImGui::BeginPopupModal("Welcome to OpenReverse", &showFirstLaunchModal_,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
    {
        const float halfWidth = (ImGui::GetContentRegionAvail().x - 20.0f) * 0.5f;

        // Left Column
        ImGui::BeginChild("##FirstLaunchLeft", ImVec2(halfWidth, 0.0f), false);
        workspace_ui::TextHeading("Welcome to OpenReverse", 1);
        workspace_ui::TextMuted("The deterministic reverse engineering and version intelligence desktop platform.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::BulletText("Deterministic offline PE & dump analysis");
        ImGui::BulletText("Interactive graphical CFG & typed Xrefs");
        ImGui::BulletText("Version Intelligence build comparison");
        ImGui::BulletText("Versioned native C ABI extension SDK");

        ImGui::Spacing();
        ImGui::Spacing();

        const auth::AccountServiceConfig& config = accountAuth_.Config();
        if (workspace_ui::PrimaryButton("Sign In to OpenReverse", ImVec2(-1.0f, 36.0f)))
        {
            const std::string url = config.signupUrl.empty() ? "https://openreverse.dev/signup" : config.signupUrl;
            const std::wstring wideUrl(url.begin(), url.end());
            ShellExecuteW(nullptr, L"open", wideUrl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            showFirstLaunchModal_ = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::Spacing();
        if (workspace_ui::SecondaryButton("Continue without an account", ImVec2(-1.0f, 32.0f)))
        {
            showFirstLaunchModal_ = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndChild();

        ImGui::SameLine(0, 20.0f);

        // Right Column: Feature Preview Card
        ImGui::BeginChild("##FirstLaunchRight", ImVec2(halfWidth, 0.0f), false);
        workspace_ui::CardBegin("##PreviewVisualCard", ImVec2(0.0f, 330.0f));
        workspace_ui::TextHeading("Engine Overview", 2);
        ImGui::Spacing();
        ImGui::TextDisabled("• Capstone x86/x64 Disassembly");
        ImGui::TextDisabled("• Recursive Control-Flow Reconstruction");
        ImGui::TextDisabled("• Inferred Globals & Structure Provenance");
        ImGui::TextDisabled("• Persistent .orev Workspace Projects");
        ImGui::TextDisabled("• 100%% Offline Static Non-Executing Engine");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "OpenReverse Community Beta");
        workspace_ui::CardEnd();
        ImGui::EndChild();

        ImGui::EndPopup();
    }
}

void Application::RenderQuickOpenModal()
{
    if (!showQuickOpenModal_) return;

    ImGui::OpenPopup("Command Palette");
    ImGui::SetNextWindowSize(ImVec2(480.0f, 300.0f), ImGuiCond_Always);

    if (ImGui::BeginPopupModal("Command Palette", &showQuickOpenModal_,
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
    {
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        ImGui::InputTextWithHint("##QuickFilter", "Type a command, address, or view name...",
                                quickOpenFilter_, sizeof(quickOpenFilter_));

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        std::string filter = quickOpenFilter_;
        std::transform(filter.begin(), filter.end(), filter.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        auto actionRow = [&](const char* title, const char* category, auto callback) {
            std::string lowerTitle = title;
            std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (filter.empty() || lowerTitle.find(filter) != std::string::npos)
            {
                if (ImGui::Selectable(title, false, ImGuiSelectableFlags_None, ImVec2(0, 24.0f)))
                {
                    callback();
                    showQuickOpenModal_ = false;
                    quickOpenFilter_[0] = '\0';
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine(ImGui::GetWindowWidth() - 100.0f);
                ImGui::TextDisabled("%s", category);
            }
        };

        actionRow("Open Binary File (Ctrl+O)", "File", [this]() { ShowOpenFileDialog(); });
        actionRow("Open .orev Project (Ctrl+Shift+O)", "File", [this]() { ShowOpenProjectDialog(); });
        actionRow("Import Memory Dump", "File", [this]() { ShowOpenDumpDialog(); });
        actionRow("Switch to Home Screen (Ctrl+1)", "View", [this]() { activeNavView_ = AppNavView::Home; });
        actionRow("Switch to Workspace (Ctrl+2)", "View", [this]() { activeNavView_ = AppNavView::Workspace; });
        actionRow("Switch to Projects (Ctrl+3)", "View", [this]() { activeNavView_ = AppNavView::Projects; });
        actionRow("Switch to Version Intelligence (Ctrl+4)", "View", [this]() { activeNavView_ = AppNavView::VersionIntelligence; });
        actionRow("Switch to Extensions (Ctrl+5)", "View", [this]() { activeNavView_ = AppNavView::Extensions; });
        actionRow("Switch to Settings (Ctrl+6)", "View", [this]() { activeNavView_ = AppNavView::Settings; });

        if (isAttached)
        {
            actionRow("Go to Address (Ctrl+G)", "Navigation", [this]() { showGotoModal_ = true; });
            actionRow("Show Functions & CFG (Ctrl+I)", "Analysis", [this]() {
                activeNavView_ = AppNavView::Workspace;
                showAnalysisPanel_ = true;
            });
            actionRow("Show Xrefs for Current Address (Ctrl+X)", "Analysis", [this]() {
                activeNavView_ = AppNavView::Workspace;
                analysisPanel.OpenXrefsForAddress(currentAddress);
            });
        }

        ImGui::Spacing();
        ImGui::Separator();
        if (ImGui::Button("Close (Esc)", ImVec2(80.0f, 0.0f)))
        {
            showQuickOpenModal_ = false;
            quickOpenFilter_[0] = '\0';
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void Application::RenderExtensionPanels()
{
    for (const auto& panel : extensionManager.Panels())
    {
        if (!panel.visible) continue;
        bool visible = panel.visible;
        const std::string windowTitle = panel.title + "###extension-panel-" + panel.id;
        if (ImGui::Begin(windowTitle.c_str(), &visible))
        {
            std::string text;
            std::string error;
            if (extensionManager.RenderPanelText(panel.id, text, error) == OPENREVERSE_OK)
                ImGui::TextUnformatted(text.c_str());
            else
                ImGui::TextColored(ImVec4(0.94f, 0.28f, 0.28f, 1.0f), "%s", error.c_str());
        }
        ImGui::End();
        if (visible != panel.visible) extensionManager.SetPanelVisible(panel.id, visible);
    }
}

void Application::RenderExtensionsWindow()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(32.0f, 24.0f));
    ImGui::BeginChild("##ExtensionsScreenScrollable", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_None);

    workspace_ui::TextHeading("Extension Host & SDK", 1);
    workspace_ui::TextMuted("In-process versioned Windows x64 C ABI native extensions.");
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    const auto loaded = extensionManager.LoadedExtensions();
    workspace_ui::CardBegin("##LoadedExtensionsCard", ImVec2(0.0f, 180.0f));
    workspace_ui::TextHeading("Loaded Plugins", 2);
    ImGui::TextDisabled("Loaded: %zu active extension(s)", loaded.size());
    ImGui::Spacing();
    for (const auto& extension : loaded)
    {
        ImGui::BulletText("%s %u.%u.%u (%s)", extension.name.c_str(), extension.version.major,
            extension.version.minor, extension.version.patch, extension.id.c_str());
    }
    if (loaded.empty())
    {
        ImGui::TextDisabled("No external plugins loaded. Put native extension DLLs in the extensions directory.");
    }
    workspace_ui::CardEnd();

    ImGui::Spacing();

    workspace_ui::CardBegin("##ExtensionDiagCard", ImVec2(0.0f, 240.0f));
    workspace_ui::TextHeading("Discovery & Load Diagnostics", 2);
    ImGui::Spacing();
    if (ImGui::BeginTable("ExtensionDiagnostics", 3,
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable))
    {
        ImGui::TableSetupColumn("Extension");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Message");
        ImGui::TableHeadersRow();
        for (const auto& diagnostic : extensionManager.Diagnostics())
        {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(diagnostic.extensionId.empty() ? "Discovery" :
                diagnostic.extensionId.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(extensions::ExtensionDiagnosticKindName(diagnostic.kind));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextWrapped("%s", diagnostic.message.c_str());
        }
        ImGui::EndTable();
    }
    workspace_ui::CardEnd();

    ImGui::EndChild();
    ImGui::PopStyleVar();
}

void Application::RenderAccountWindow()
{
    settingsTab_ = 0;
    activeNavView_ = AppNavView::Settings;
}

void Application::NotifyExtensionsSessionChanged()
{
    extensionManager.NotifySessionChanged(targetGeneration, isAttached);
}

void Application::RenderDumpImportDialog()
{
    if (requestDumpImportPopup_)
    {
        ImGui::OpenPopup("Configure static dump import");
        requestDumpImportPopup_ = false;
    }
    if (!showDumpImportModal_) return;

    if (!ImGui::BeginPopupModal("Configure static dump import", &showDumpImportModal_,
                                ImGuiWindowFlags_AlwaysAutoResize))
    {
        return;
    }

    ImGui::Text("File: %s", pendingDumpPath_.c_str());
    ImGui::Spacing();

    if (!dumpImportError_.empty())
    {
        ImGui::TextColored(ImVec4(0.94f, 0.28f, 0.28f, 1.0f), "%s", dumpImportError_.c_str());
        ImGui::Spacing();
    }

    if (!pendingDumpModules_.empty())
    {
        ImGui::TextUnformatted("Select minidump module:");
        for (size_t index = 0; index < pendingDumpModules_.size(); ++index)
        {
            const auto& mod = pendingDumpModules_[index];
            char label[256];
            snprintf(label, sizeof(label), "%s (0x%llX, %u bytes)",
                     mod.name.c_str(),
                     static_cast<unsigned long long>(mod.imageBase),
                     mod.imageSize);
            if (ImGui::RadioButton(label, pendingDumpModuleIndex_ == static_cast<int>(index)))
                pendingDumpModuleIndex_ = static_cast<int>(index);
        }
    }
    else
    {
        ImGui::TextUnformatted("Architecture:");
        ImGui::RadioButton("x86", &dumpArchitectureIndex_, 0);
        ImGui::SameLine();
        ImGui::RadioButton("x64", &dumpArchitectureIndex_, 1);

        ImGui::TextUnformatted("Image Base (hex):");
        ImGui::InputText("##dumpBase", dumpImageBaseBuf_, sizeof(dumpImageBaseBuf_));

        ImGui::TextUnformatted("Module Size (bytes/hex):");
        ImGui::InputText("##dumpSize", dumpModuleSizeBuf_, sizeof(dumpModuleSizeBuf_));
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Import Dump", ImVec2(120.0f, 0.0f)))
    {
        DumpImportOptions options;
        if (!pendingDumpModules_.empty())
        {
            const auto& chosen = pendingDumpModules_[static_cast<size_t>(pendingDumpModuleIndex_)];
            options.representation = DumpRepresentation::Minidump;
            options.minidumpModuleBase = chosen.imageBase;
            options.imageBase = chosen.imageBase;
            options.moduleSize = chosen.imageSize;
        }
        else
        {
            options.representation = DumpRepresentation::RawSnapshot;
            options.architecture = dumpArchitectureIndex_ == 1
                ? DumpArchitecture::X64 : DumpArchitecture::X86;
            try
            {
                options.imageBase = std::stoull(dumpImageBaseBuf_, nullptr, 0);
                options.moduleSize = std::stoull(dumpModuleSizeBuf_, nullptr, 0);
            }
            catch (...)
            {
                dumpImportError_ = "Invalid base address or module size format.";
                return;
            }
        }
        if (OpenDumpFile(pendingDumpPath_, options))
        {
            showDumpImportModal_ = false;
            ImGui::CloseCurrentPopup();
        }
        else
        {
            dumpImportError_ = "Failed to parse dump module at specified bounds.";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(80.0f, 0.0f)))
    {
        showDumpImportModal_ = false;
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
}

void Application::RenderDockspace()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGuiID dockspace_id = ImGui::GetID("OpenReverse_DockspaceID");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    if (!layoutInitialized_)
    {
        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImVec2 workSize(viewport->WorkSize.x - 210.0f, viewport->WorkSize.y - 68.0f);
        ImGui::DockBuilderSetNodeSize(dockspace_id, workSize);

        ImGuiID main = dockspace_id;
        ImGuiID left  = ImGui::DockBuilderSplitNode(main, ImGuiDir_Left,  0.18f, nullptr, &main);
        ImGuiID right = ImGui::DockBuilderSplitNode(main, ImGuiDir_Right, 0.28f, nullptr, &main);

        if (isDevMode)
        {
            ImGuiID bottom = ImGui::DockBuilderSplitNode(main, ImGuiDir_Down, 0.22f, nullptr, &main);
            const ImGuiDockNodeFlags chromeFlags = ImGuiDockNodeFlags_NoWindowMenuButton |
                ImGuiDockNodeFlags_NoCloseButton;
            for (ImGuiID nodeId : {left, main, right, bottom})
            {
                if (ImGuiDockNode* node = ImGui::DockBuilderGetNode(nodeId))
                    node->LocalFlags |= chromeFlags;
            }
            ImGui::DockBuilderDockWindow("OpenReverse Editor", main);

            ImGui::DockBuilderDockWindow("PROCESSES", left);
            ImGui::DockBuilderDockWindow("MODULES", left);
            ImGui::DockBuilderDockWindow("Bookmarks", left);

            ImGui::DockBuilderDockWindow("Console", bottom);

            ImGui::DockBuilderDockWindow("Analysis / Functions & CFG", right);
            ImGui::DockBuilderDockWindow("HEX VIEW", right);
            ImGui::DockBuilderDockWindow("DISASSEMBLY", right);
            ImGui::DockBuilderDockWindow("AI ASSISTANT", right);
            ImGui::DockBuilderDockWindow("PE Header", right);
            ImGui::DockBuilderDockWindow("Data Inspector", right);
            ImGui::DockBuilderDockWindow("Pattern Scanner", right);
            ImGui::DockBuilderDockWindow("Strings", right);
            ImGui::DockBuilderDockWindow("STRUCTURES", right);
        }
        else
        {
            ImGuiID leftTop = left;
            ImGuiID leftBottom = ImGui::DockBuilderSplitNode(leftTop, ImGuiDir_Down, 0.58f, nullptr, &leftTop);
            ImGuiID rightTop = right;
            ImGuiID rightBottom = ImGui::DockBuilderSplitNode(rightTop, ImGuiDir_Down, 0.41f, nullptr, &rightTop);
            ImGuiID rightMiddle = ImGui::DockBuilderSplitNode(rightTop, ImGuiDir_Down, 0.48f, nullptr, &rightTop);
            ImGuiID mainTop = main;
            ImGuiID mainBottom = ImGui::DockBuilderSplitNode(mainTop, ImGuiDir_Down, 0.36f, nullptr, &mainTop);

            const ImGuiDockNodeFlags panelFlags = ImGuiDockNodeFlags_NoTabBar |
                ImGuiDockNodeFlags_NoWindowMenuButton | ImGuiDockNodeFlags_NoCloseButton;
            for (ImGuiID nodeId : {leftTop, leftBottom, mainTop, mainBottom, rightTop, rightMiddle, rightBottom})
            {
                if (ImGuiDockNode* node = ImGui::DockBuilderGetNode(nodeId))
                    node->LocalFlags |= panelFlags;
            }

            ImGui::DockBuilderDockWindow("PROCESSES", leftTop);
            ImGui::DockBuilderDockWindow("MODULES", leftBottom);

            ImGui::DockBuilderDockWindow("DISASSEMBLY", mainTop);

            ImGui::DockBuilderDockWindow("HEX VIEW", mainBottom);

            ImGui::DockBuilderDockWindow("XREFS", rightTop);
            ImGui::DockBuilderDockWindow("STRUCTURES", rightMiddle);
            ImGui::DockBuilderDockWindow("AI ASSISTANT", rightBottom);
        }

        ImGui::DockBuilderFinish(dockspace_id);
        layoutInitialized_ = true;
    }
}

void Application::RenderBrandBar()
{
}

void Application::RenderToolbar()
{
}

void Application::RenderMenuBar()
{
}

void Application::ShowGotoAddressDialog()
{
    showGotoModal_ = true;
}

void Application::AddOffsetFromAddress(uint64_t address, const std::string& name)
{
    offsetsPanel.AddFromAddress(*this, address, name);
}

void Application::RestoreProjectUiAfterAnalysis()
{
    if (!analysisSession.HasProject() || !analysisSession.RestoresTargetBoundState()) return;
    const ProjectUiState& ui = analysisSession.Project().ui;
    SwitchToDevMode(ui.workspace == "editor");
    const auto isOpen = [&](const char* panel) {
        return std::find(ui.openPanels.begin(), ui.openPanels.end(), panel) != ui.openPanels.end();
    };
    showAnalysisPanel_ = isOpen("analysis");
    showMemoryMap_ = isOpen("memory-map");
    showScanner_ = isOpen("scanner");
    showStrings_ = isOpen("strings");
    showDataInspector_ = isOpen("data-inspector");
    showPEViewer_ = isOpen("pe-viewer");
    showBookmarks_ = isOpen("bookmarks");
    showConsole_ = isOpen("console");
    showVersionIntelligence_ = isOpen("version-intelligence");

    const ModuleAnalysisState* analysis = nullptr;
    if (!analysisDatabase.GetModules().empty())
        analysis = &analysisDatabase.GetModules().begin()->second;
    if (analysis && ui.currentRva < analysis->module.size)
        NavigateToAddress(analysis->module.baseAddress + ui.currentRva);
}

void Application::RenderStatusBar()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - 24.0f));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, 24.0f));

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoSavedSettings;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 3.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(17.0f/255.0f, 19.0f/255.0f, 24.0f/255.0f, 1.0f));

    ImGui::Begin("##StatusBar", nullptr, flags);

    if (isAttached)
    {
        ImGui::Text("%s", attachedProcessName.c_str());
        ImGui::SameLine(0, 8);
        ImGui::TextDisabled("• %s", is64Bit ? "x64" : "x86");

        if (attachedPID != 0)
        {
            ImGui::SameLine(0, 8);
            ImGui::TextDisabled("• PID %d", attachedPID);
        }

        ImGui::SameLine(0, 8);
        const ModuleInfo* curMod = moduleCatalog.FindModuleByAddress(currentAddress);
        if (curMod)
        {
            std::string offStr = helpers::FormatModuleOffset(curMod->name, curMod->baseAddress, currentAddress, is64Bit);
            ImGui::TextDisabled("• %s", offStr.c_str());
        }
        else
            ImGui::TextDisabled("• %s", helpers::FormatAddress(currentAddress, is64Bit).c_str());
    }
    else
    {
        ImGui::TextDisabled("Standby — No target attached");
    }

    if (analysisSession.HasProject())
    {
        ImGui::SameLine(0, 8);
        const std::string projectName = analysisSession.ProjectPath().empty()
            ? "Unsaved project" : std::filesystem::path(analysisSession.ProjectPath()).filename().string();
        ImGui::TextColored(ImVec4(0.35f, 0.65f, 1.0f, 1.0f), "• %s%s",
                           projectName.c_str(), analysisSession.IsDirty() ? " *" : "");
    }

    const AnalysisJobSnapshot offlineJob = offlineAnalysisJobId != 0
        ? analysisScheduler.GetJob(offlineAnalysisJobId) : AnalysisJobSnapshot{};
    std::string state = isAttached ? "Ready" : "Idle";
    if (offlineAnalysisJobId != 0 &&
        (offlineJob.state == AnalysisJobState::Queued || offlineJob.state == AnalysisJobState::Running))
    {
        state = offlineJob.name + " " + std::to_string(static_cast<int>(offlineJob.progress * 100.0f)) + "%";
    }
    const float stateWidth = ImGui::CalcTextSize(state.c_str()).x;
    ImGui::SameLine(ImGui::GetWindowWidth() - stateWidth - 14.0f);
    ImGui::TextColored(isAttached ? ImVec4(0.3f, 0.8f, 1.0f, 1.0f)
                                  : ImVec4(0.5f, 0.55f, 0.6f, 1.0f), "%s", state.c_str());

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}

std::string Application::GetAIContextSummary()
{
    if (!isAttached && attachedProcessName.empty())
    {
        return "[Active Target Context: no process or binary is attached in OpenReverse. Ask the user to open a binary or attach to a process before analyzing the current target.]\n\n";
    }

    std::stringstream ss;
    ss << "=== ACTIVE TARGET PROGRAM CONTEXT ===\n";
    ss << "Target Executable/Process Name: " << (attachedProcessName.empty() ? "Unknown" : attachedProcessName) << "\n";
    ss << "Architecture: " << (is64Bit ? "x64 (64-bit)" : "x86 (32-bit)") << " Windows PE executable\n";
    if (attachedPID != 0)
        ss << "Process ID (PID): " << attachedPID << "\n";
    if (currentAddress != 0)
    {
        ss << "Current Memory Address / Entry Point: 0x" << std::hex << currentAddress << std::dec << "\n";
    }

    const ModuleAnalysisState* analysis = analysisDatabase.FindModuleContaining(currentAddress);
    if (!analysis && !analysisDatabase.GetModules().empty())
        analysis = &analysisDatabase.GetModules().begin()->second;
    if (analysis && !analysis->functions.empty())
    {
        const auto& funcs = analysis->functions;
        ss << "Analyzed Functions (" << funcs.size() << " detected): ";
        size_t limit = funcs.size() < 6 ? funcs.size() : 6;
        for (size_t i = 0; i < limit; ++i)
        {
            if (i > 0) ss << ", ";
            ss << funcs[i].name << " (0x" << std::hex << funcs[i].startAddress << std::dec << ")";
        }
        ss << "\n";
    }

    const auto& strings = analysis ? analysis->strings : stringResults;
    if (!strings.empty())
    {
        ss << "Notable Strings in Target Memory (" << strings.size() << " total): ";
        size_t limit = strings.size() < 6 ? strings.size() : 6;
        for (size_t i = 0; i < limit; ++i)
        {
            if (i > 0) ss << " | ";
            ss << "\"" << strings[i].value << "\"";
        }
        ss << "\n";
    }

    if (analysis)
    {
        ss << "Detected Xrefs: " << analysis->xrefs.size()
           << " | inferred globals: " << analysis->globals.size()
           << " | inferred structures: " << analysis->structures.size()
           << " | typed offsets: " << analysis->offsets.size()
           << " | signatures: " << analysis->signatures.size() << "\n";
        const size_t globalLimit = std::min<size_t>(analysis->globals.size(), 6);
        for (size_t index = 0; index < globalLimit; ++index)
        {
            const auto& global = analysis->globals[index];
            ss << "Inferred global RVA 0x" << std::hex << global.rva << std::dec
               << " in " << global.sectionName << ": reads=" << global.readCount
               << ", writes=" << global.writeCount
               << ", address refs=" << global.addressCount
               << ", evidence score=" << global.evidenceScore << "\n";
        }
        const size_t structureLimit = std::min<size_t>(analysis->structures.size(), 4);
        for (size_t index = 0; index < structureLimit; ++index)
        {
            const auto& structure = analysis->structures[index];
            ss << "Inferred structure candidate " << structure.name << " at function 0x"
               << std::hex << structure.functionAddress << std::dec << ": "
               << structure.fields.size() << " fields, evidence score="
               << structure.evidenceScore << "\n";
        }
    }

    if (currentAddress != 0 && isAttached && processHandle != nullptr)
    {
        ss << "\n--- LIVE MEMORY DISASSEMBLY AT CURRENT ADDRESS (0x" << std::hex << currentAddress << std::dec << ") ---\n";
        auto bytes = memoryReader.ReadBytes(processHandle, currentAddress, 128);
        if (!bytes.empty())
        {
            auto insns = disassembler.Disassemble(bytes.data(), bytes.size(), currentAddress, 15);
            for (const auto& ins : insns)
            {
                ss << "0x" << std::hex << ins.address << std::dec << ":  " << ins.mnemonic << " " << ins.operands << "\n";
            }
        }
    }

    if (analysisPanel.GetActiveFunction().startAddress != 0)
    {
        const auto& fn = analysisPanel.GetActiveFunction();
        ss << "\n--- CURRENT ACTIVE FUNCTION IN OPENREVERSE ---\n";
        ss << "Function: " << fn.name << " at 0x" << std::hex << fn.startAddress << "\n";
        if (fn.boundaryKnown)
            ss << "Known boundary size: " << std::dec << fn.size << " bytes\n";
        else
            ss << "Boundary unknown; analyzed extent: " << std::dec << fn.analyzedSize << " bytes\n";
        if (!analysisPanel.GetActiveAssemblySummary().empty())
        {
            ss << "Decoded control-flow evidence:\n```asm\n"
               << analysisPanel.GetActiveAssemblySummary() << "\n```\n";
        }
    }
    ss << "=== END TARGET PROGRAM CONTEXT ===\n\n";
    ss << "The context above was collected from the selected target. Use it as evidence, distinguish observations from inferences, and state when data is missing.\n\n";

    return ss.str();
}

void Application::SwitchToDevMode(bool enable)
{
    isDevMode = enable;
    showOpenReverseEditor = true;
    layoutInitialized_ = false;
    Logger::Get().Log(LogLevel::Info, "%s", enable ? "[Mode Switch] Switched to DEV MODE (Full Screen Code Editor Layout)." : "[Mode Switch] Switched to REVERSE ENGINEERING MODE (Analysis Layout).");
}

} // namespace openreverse
