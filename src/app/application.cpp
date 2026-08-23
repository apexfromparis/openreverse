#include "application.h"
#include "openreverse_version.h"
#include "utils/logger.h"
#include "utils/helpers.h"
#include "ui/panels/analysis_panel.h"
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
    if (shutdown_)
        return;
    shutdown_ = true;
    analysisScheduler.Shutdown();
    DetachFromProcess();
    if (analysisSession.HasProject()) extensionManager.NotifyProjectClosed();
    extensionManager.Shutdown();
}

bool Application::AttachToProcess(DWORD pid)
{
    DetachFromProcess();
    if (analysisSession.HasProject()) extensionManager.NotifyProjectClosed();
    analysisSession.ClearProject();

    processHandle = processAccess.OpenProcess(pid);
    if (!processHandle)
    {
        const DWORD error = GetLastError();
        const std::string message = ProcessOpenFailureMessage(error);
        Logger::Get().Log(LogLevel::Error, "%s", message.c_str());
        return false;
    }

    attachedPID = pid;
    isAttached = true;
    targetKind = AnalysisTargetKind::LiveProcess;
    is64Bit = processAccess.IsProcess64Bit(processHandle);
    memoryReader.SetOfflineBuffer(nullptr, 0);

    auto processes = processAccess.ListProcesses();
    for (auto& p : processes)
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
    if (result.codeBudgetReached || result.instructionBudgetReached ||
        result.cfgInstructionBudgetReached || result.functionLimitReached ||
        result.stringBudgetReached || result.timeBudgetReached)
        Logger::Get().Log(LogLevel::Warning, "Module analysis stopped at a configured limit");
    RestoreProjectUiAfterAnalysis();
    NotifyExtensionsSessionChanged();
}

bool Application::AnalyzeCurrentModuleSynchronously()
{
    if (!isAttached || !processHandle) return false;
    const ModuleInfo* module = moduleCatalog.FindModuleByAddress(currentAddress);
    if (!module && !moduleCatalog.GetModules().empty())
        module = &moduleCatalog.GetModules().front();
    if (!module)
    {
        Logger::Get().Log(LogLevel::Warning, "No module found to analyze.");
        return false;
    }
    ModuleAnalysisPipeline pipeline;
    auto result = pipeline.AnalyzeLive(processHandle, *module, is64Bit);
    if (!result.success)
    {
        if (!result.cancelled)
            Logger::Get().Log(LogLevel::Error, "Module analysis failed: %s", result.error.c_str());
        return false;
    }
    PublishModuleAnalysis(std::move(result));
    return true;
}

void Application::ShowOpenFileDialog()
{
    std::string path;
    if (SelectFilePath(
        L"PE Executable & Driver Files (*.sys;*.exe;*.dll)\0*.sys;*.exe;*.dll\0"
        L"Windows Driver (.sys)\0*.sys\0All Files (*.*)\0*.*\0",
        L"Open Windows Kernel Driver (.sys) or Executable (.exe/.dll)", false, path))
        OpenBinaryFile(path);
}

void Application::ShowOpenDumpDialog()
{
    std::string path;
    if (SelectFilePath(L"Memory dumps (*.dmp;*.mdmp;*.bin)\0*.dmp;*.mdmp;*.bin\0"
                       L"All Files (*.*)\0*.*\0",
                       L"Open a mapped image, raw snapshot, or Windows minidump", false, path))
    {
        DumpLoader loader;
        const auto detected = loader.Load(path);
        if (detected.success)
        {
            OpenDumpFile(path);
            return;
        }

        pendingDumpPath_ = path;
        pendingDumpModules_ = detected.availableModules;
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

    project.target.path = targetPath;
    if (analysisSession.HasProject()) extensionManager.NotifyProjectClosed();
    analysisSession.SetLoadedProject(std::move(project), filePath, restoreTargetBoundState);
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

    ProjectTarget target;
    target.kind = ProjectKindFromTarget(targetKind);
    target.path = loadedFilePath;
    target.architecture = is64Bit ? "x64" : "x86";
    target.imageBase = analysis->module.baseAddress;
    target.moduleSize = analysis->module.size;
    if (target.kind == ProjectTargetKind::MinidumpModule)
        target.selectedModuleBase = analysis->module.baseAddress;
    std::string error;
    if (!ProjectStore::ComputeFileSha256(target.path, target.sha256, error))
    {
        Logger::Get().Log(LogLevel::Error, "Project save failed: %s", error.c_str());
        MessageBoxA(nullptr, error.c_str(), "Save OpenReverse project", MB_OK | MB_ICONERROR);
        return false;
    }
    target.module = analysis->identity;
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
        NavigateToAddress(currentAddress);

        if (ImGui::GetCurrentContext())
        {
            const uint64_t generation = targetGeneration;
            const auto mapped = offlineImageBuffer;
            const auto raw = offlineFileBuffer;
            const ModuleInfo module{attachedProcessName, loadedFilePath, info.imageBase, info.sizeOfImage};
            Application* application = this;
            offlineAnalysisJobId = analysisScheduler.Submit("Offline PE analysis",
                [application, generation, mapped, raw, module, info](
                    const CancellationToken& cancellation,
                    const AnalysisScheduler::ProgressCallback& progress) mutable {
                    ModuleAnalysisOptions options;
                    options.maxCodeBytes = 16ULL * 1024ULL * 1024ULL;
                    options.maxStringBytes = 64ULL * 1024ULL * 1024ULL;
                    ModuleAnalysisPipeline pipeline;
                    auto result = pipeline.AnalyzeMappedImage(
                        mapped, raw.size(), module, info, options, &cancellation, progress);
                    std::string identityError;
                    ModuleIdentity identity;
                    if (result.success && ComputeModuleIdentity(raw, info, module.name,
                                                                 identity, identityError))
                        result.identity = std::move(identity);
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
                    };
                });
            Logger::Get().Log(LogLevel::Info, "Offline analysis queued: %s",
                attachedProcessName.c_str());
            return true;
        }

        std::cout << "[*] Running deterministic mapped-image analysis..." << std::endl;
        ModuleInfo module{attachedProcessName, loadedFilePath, info.imageBase, info.sizeOfImage};
        ModuleAnalysisOptions options;
        options.maxCodeBytes = 16ULL * 1024ULL * 1024ULL;
        options.maxStringBytes = 64ULL * 1024ULL * 1024ULL;
        ModuleAnalysisPipeline pipeline;
        auto result = pipeline.AnalyzeMappedImage(
            offlineImageBuffer, offlineFileBuffer.size(), module, info, options);
        if (!result.success)
        {
            const std::string error = result.error.empty() ? "Offline analysis was cancelled" : result.error;
            Logger::Get().Log(LogLevel::Error, "Offline analysis failed: %s", error.c_str());
            std::cout << "\033[1;31m[-] " << error << "\033[0m" << std::endl;
            DetachFromProcess();
            return false;
        }

        std::string identityError;
        ModuleIdentity fileIdentity;
        if (ComputeModuleIdentity(offlineFileBuffer, info, attachedProcessName,
                                  fileIdentity, identityError))
            result.identity = std::move(fileIdentity);
        else
            Logger::Get().Log(LogLevel::Warning, "%s", identityError.c_str());

        PublishModuleAnalysis(std::move(result));
        Logger::Get().Log(LogLevel::Info,
            "Loaded offline PE: %s (%s, %zu bytes, %zu sections)",
            attachedProcessName.c_str(), is64Bit ? "x64" : "x86",
            offlineFileBuffer.size(), info.sections.size());
        std::cout << "[+] Analysis completed successfully!" << std::endl;
        return true;
    }
    catch (const std::exception& exception)
    {
        DetachFromProcess();
        Logger::Get().Log(LogLevel::Error, "Offline analysis exception: %s", exception.what());
        std::cout << "\033[1;31m[-] Offline analysis failed: " << exception.what()
                  << "\033[0m" << std::endl;
        return false;
    }
    catch (...)
    {
        DetachFromProcess();
        Logger::Get().Log(LogLevel::Error, "Offline analysis failed with an unknown error");
        std::cout << "\033[1;31m[-] Offline analysis failed with an unknown error\033[0m" << std::endl;
        return false;
    }
}

bool Application::OpenDumpFile(const std::string& filePath, const DumpImportOptions& options)
{
    try
    {
        DumpLoader loader;
        auto dump = loader.Load(filePath, options);
        if (!dump.success)
        {
            Logger::Get().Log(LogLevel::Error, "Dump import failed: %s", dump.error.c_str());
            if (!dump.availableModules.empty())
                Logger::Get().Log(LogLevel::Info,
                    "The minidump contains %zu modules; select one by base address",
                    dump.availableModules.size());
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
        NavigateToAddress(currentAddress);

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

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O) && !ImGui::GetIO().WantTextInput)
    {
        if (ImGui::GetIO().KeyShift) ShowOpenProjectDialog();
        else ShowOpenFileDialog();
    }
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S) && !ImGui::GetIO().WantTextInput)
        SaveProjectFile(ImGui::GetIO().KeyShift);
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_G) && ImGui::GetIO().KeyCtrl)
        showGotoModal_ = true;
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_I) && ImGui::GetIO().KeyCtrl)
    {
        showAnalysisPanel_ = true;
        ImGui::SetWindowFocus("Analysis / Functions & CFG");
    }
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_X) && !ImGui::GetIO().WantCaptureKeyboard)
    {
        analysisPanel.OpenXrefsForAddress(currentAddress);
        ImGui::SetWindowFocus("XREFS");
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F5))
        processListPanel.ForceRefresh();

    RenderDockspace();
    RenderDumpImportDialog();

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
    if (showVersionIntelligence_) versionIntelligencePanel.Render(*this, &showVersionIntelligence_);
    RenderExtensionPanels();
    if (showExtensions_) RenderExtensionsWindow();
    RenderStatusBar();
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
    if (!ImGui::Begin("Extensions", &showExtensions_))
    {
        ImGui::End();
        return;
    }
    ImGui::Text("Extension API v%u", OPENREVERSE_EXTENSION_API_VERSION);
    ImGui::TextDisabled("Native extensions run in-process and must be trusted.");
    ImGui::Separator();
    const auto loaded = extensionManager.LoadedExtensions();
    ImGui::Text("Loaded extensions: %zu", loaded.size());
    for (const auto& extension : loaded)
        ImGui::BulletText("%s %u.%u.%u (%s)", extension.name.c_str(), extension.version.major,
            extension.version.minor, extension.version.patch, extension.id.c_str());
    ImGui::Separator();
    ImGui::TextUnformatted("Load diagnostics");
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
    ImGui::End();
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
        return;

    ImGui::TextWrapped("OpenReverse could not identify this file as a complete mapped PE image. "
                       "The file will only be read as static data and will never be executed.");
    ImGui::Separator();
    if (!pendingDumpModules_.empty())
    {
        ImGui::TextUnformatted("Select a captured minidump module:");
        const auto moduleLabel = [](const DumpModuleMetadata& module) {
            std::ostringstream stream;
            stream << module.name << " @ 0x" << std::hex << std::uppercase << module.imageBase
                   << " (" << std::dec << module.imageSize << " bytes)";
            return stream.str();
        };
        const std::string preview = moduleLabel(pendingDumpModules_[pendingDumpModuleIndex_]);
        if (ImGui::BeginCombo("Module", preview.c_str()))
        {
            for (int index = 0; index < static_cast<int>(pendingDumpModules_.size()); ++index)
            {
                const std::string label = moduleLabel(pendingDumpModules_[index]);
                if (ImGui::Selectable(label.c_str(), index == pendingDumpModuleIndex_))
                    pendingDumpModuleIndex_ = index;
            }
            ImGui::EndCombo();
        }
    }
    else
    {
        ImGui::TextUnformatted("Raw snapshots require explicit metadata:");
        ImGui::Combo("Architecture", &dumpArchitectureIndex_, "x86\0x64\0");
        ImGui::InputText("Image base", dumpImageBaseBuf_, sizeof(dumpImageBaseBuf_));
        ImGui::InputText("Module size", dumpModuleSizeBuf_, sizeof(dumpModuleSizeBuf_));
        ImGui::TextDisabled("Values may be decimal or 0x-prefixed. Module size cannot exceed the file size.");
    }
    if (!dumpImportError_.empty())
        ImGui::TextColored(ImVec4(1.0f, 0.42f, 0.38f, 1.0f), "%s", dumpImportError_.c_str());

    if (ImGui::Button("Analyze statically"))
    {
        DumpImportOptions options;
        if (!pendingDumpModules_.empty())
        {
            options.representation = DumpRepresentation::Minidump;
            options.minidumpModuleBase = pendingDumpModules_[pendingDumpModuleIndex_].imageBase;
        }
        else
        {
            options.representation = DumpRepresentation::RawSnapshot;
            options.architecture = dumpArchitectureIndex_ == 0
                ? DumpArchitecture::X86 : DumpArchitecture::X64;
            try
            {
                size_t baseParsed = 0;
                size_t sizeParsed = 0;
                options.imageBase = std::stoull(dumpImageBaseBuf_, &baseParsed, 0);
                options.moduleSize = std::stoull(dumpModuleSizeBuf_, &sizeParsed, 0);
                if (baseParsed != std::strlen(dumpImageBaseBuf_) ||
                    sizeParsed != std::strlen(dumpModuleSizeBuf_) ||
                    options.imageBase == 0 || options.moduleSize == 0)
                    throw std::invalid_argument("metadata");
            }
            catch (...)
            {
                dumpImportError_ = "Enter a non-zero image base and module size.";
                ImGui::EndPopup();
                return;
            }
        }
        if (OpenDumpFile(pendingDumpPath_, options))
        {
            showDumpImportModal_ = false;
            pendingDumpPath_.clear();
            pendingDumpModules_.clear();
            ImGui::CloseCurrentPopup();
        }
        else
            dumpImportError_ = "Import failed. Check the metadata and the Console for the exact reason.";
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel"))
    {
        showDumpImportModal_ = false;
        pendingDumpPath_.clear();
        pendingDumpModules_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void Application::RenderDockspace()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();

    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - 22.0f));
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags dockFlags =
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("OpenReverse_Dockspace", nullptr, dockFlags);
    ImGui::PopStyleVar(3);

    RenderBrandBar();
    RenderMenuBar();
    RenderToolbar();

    ImGuiID dockspace_id = ImGui::GetID("OpenReverse_DockspaceID");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    if (!layoutInitialized_)
    {
        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImVec2 workSize(viewport->WorkSize.x, viewport->WorkSize.y - 22.0f);
        ImGui::DockBuilderSetNodeSize(dockspace_id, workSize);

        ImGuiID main = dockspace_id;
        ImGuiID left  = ImGui::DockBuilderSplitNode(main, ImGuiDir_Left,  0.17f, nullptr, &main);
        ImGuiID right = ImGui::DockBuilderSplitNode(main, ImGuiDir_Right, 0.27f, nullptr, &main);

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

    ImGui::End();

    const HWND hwnd = static_cast<HWND>(viewport->PlatformHandleRaw);
    const float rounding = hwnd && IsZoomed(hwnd) ? 0.0f : 7.0f;
    ImGui::GetForegroundDrawList(viewport)->AddRect(
        ImVec2(viewport->Pos.x + 0.5f, viewport->Pos.y + 0.5f),
        ImVec2(viewport->Pos.x + viewport->Size.x - 0.5f,
            viewport->Pos.y + viewport->Size.y - 0.5f),
        IM_COL32(31, 93, 128, 255), rounding, 0, 1.0f);
}

void Application::RenderBrandBar()
{
    constexpr float barHeight = 31.0f;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.012f, 0.027f, 0.040f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.06f, 0.23f, 0.34f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f, 4.0f));
    ImGui::BeginChild("##OpenReverseBrandBar", ImVec2(0.0f, barHeight), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const ImU32 white = IM_COL32(242, 247, 252, 255);
    const ImU32 blue = IM_COL32(0, 132, 255, 255);

    const ImVec2 c(origin.x + 11.0f, origin.y + 11.0f);
    draw->PathArcTo(c, 8.5f, 0.72f, 5.56f, 24);
    draw->PathStroke(white, 0, 2.0f);
    draw->AddLine(ImVec2(c.x + 2.0f, c.y - 5.5f), ImVec2(c.x + 10.0f, c.y - 5.5f), white, 2.0f);
    draw->AddLine(ImVec2(c.x + 10.0f, c.y - 5.5f), ImVec2(c.x + 10.0f, c.y + 1.0f), white, 2.0f);
    draw->AddLine(ImVec2(c.x + 10.0f, c.y + 1.0f), ImVec2(c.x + 1.0f, c.y + 1.0f), white, 2.0f);
    draw->AddLine(ImVec2(c.x + 6.0f, c.y + 1.0f), ImVec2(c.x + 11.0f, c.y + 7.0f), white, 2.0f);
    draw->AddTriangleFilled(ImVec2(c.x - 1.0f, c.y + 1.0f), ImVec2(c.x + 3.5f, c.y - 2.5f), ImVec2(c.x + 3.5f, c.y + 4.5f), white);

    const ImVec2 brandPos(origin.x + 31.0f, origin.y + 3.0f);
    draw->AddText(brandPos, white, "OPEN");
    const float openWidth = ImGui::CalcTextSize("OPEN").x;
    draw->AddText(ImVec2(brandPos.x + openWidth, brandPos.y), blue, "REVERSE");

    const HWND hwnd = static_cast<HWND>(ImGui::GetMainViewport()->PlatformHandleRaw);
    const float controlWidth = 35.0f;
    const float controlsStart = ImGui::GetWindowPos().x + ImGui::GetWindowWidth() - controlWidth * 3.0f - 1.0f;
    const float controlsTop = ImGui::GetWindowPos().y + 1.0f;
    auto windowButton = [&](const char* id, int kind) {
        ImGui::SetCursorScreenPos(ImVec2(controlsStart + kind * controlWidth, controlsTop));
        const ImVec2 p = ImGui::GetCursorScreenPos();
        const bool pressed = ImGui::InvisibleButton(id, ImVec2(controlWidth, barHeight - 2.0f));
        const bool hovered = ImGui::IsItemHovered();
        if (hovered)
            draw->AddRectFilled(p, ImVec2(p.x + controlWidth, p.y + barHeight - 2.0f),
                kind == 2 ? IM_COL32(188, 42, 55, 255) : IM_COL32(20, 53, 72, 255));

        const ImU32 icon = IM_COL32(205, 215, 222, 255);
        const ImVec2 center(p.x + controlWidth * 0.5f, p.y + (barHeight - 2.0f) * 0.5f);
        if (kind == 0)
            draw->AddLine(ImVec2(center.x - 5.0f, center.y + 3.0f),
                ImVec2(center.x + 5.0f, center.y + 3.0f), icon, 1.0f);
        else if (kind == 1)
            draw->AddRect(ImVec2(center.x - 4.5f, center.y - 4.5f),
                ImVec2(center.x + 4.5f, center.y + 4.5f), icon, 0.0f, 0, 1.0f);
        else
        {
            draw->AddLine(ImVec2(center.x - 4.0f, center.y - 4.0f),
                ImVec2(center.x + 4.0f, center.y + 4.0f), icon, 1.1f);
            draw->AddLine(ImVec2(center.x + 4.0f, center.y - 4.0f),
                ImVec2(center.x - 4.0f, center.y + 4.0f), icon, 1.1f);
        }
        return pressed;
    };

    if (windowButton("##MinimizeWindow", 0) && hwnd)
        PostMessageW(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
    if (windowButton("##MaximizeWindow", 1) && hwnd)
        ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
    if (windowButton("##CloseWindow", 2) && hwnd)
        PostMessageW(hwnd, WM_CLOSE, 0, 0);

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void Application::RenderToolbar()
{
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.020f, 0.039f, 0.052f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.06f, 0.18f, 0.25f, 1.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(9.0f, 4.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4.0f, 0.0f));
    ImGui::BeginChild("##MainToolbar", ImVec2(0.0f, 35.0f), true,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

    auto toolButton = [&](const char* id, const char* label, int icon, bool enabled = true) {
        const ImVec2 p = ImGui::GetCursorScreenPos();
        if (!enabled) ImGui::BeginDisabled();
        const bool clicked = ImGui::InvisibleButton(id, ImVec2(28.0f, 25.0f));
        const bool hovered = ImGui::IsItemHovered();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        if (hovered && enabled)
            dl->AddRectFilled(p, ImVec2(p.x + 28.0f, p.y + 25.0f), IM_COL32(12, 59, 91, 255), 3.0f);
        const ImU32 col = !enabled ? IM_COL32(66, 78, 86, 255) :
            (hovered ? IM_COL32(20, 157, 255, 255) : IM_COL32(165, 181, 192, 255));
        const ImVec2 m(p.x + 14.0f, p.y + 12.5f);
        if (icon == 0) { dl->AddRect(ImVec2(m.x-6,m.y-5), ImVec2(m.x+6,m.y+5), col, 1.5f); dl->AddLine(ImVec2(m.x-3,m.y-7),ImVec2(m.x+5,m.y-7),col,1.5f); }
        if (icon == 1) { dl->AddRect(ImVec2(m.x-6,m.y-5), ImVec2(m.x+6,m.y+6), col, 1.0f, 0, 1.5f); dl->AddLine(ImVec2(m.x-3,m.y+2),ImVec2(m.x+3,m.y+2),col,1.5f); }
        if (icon == 2) { dl->AddTriangle(ImVec2(m.x-4,m.y-7),ImVec2(m.x-4,m.y+7),ImVec2(m.x+7,m.y),col,1.5f); }
        if (icon == 3) { dl->AddCircle(m,6.0f,col,16,1.5f); dl->AddCircleFilled(m,2.0f,col); }
        if (icon == 4) { dl->AddLine(ImVec2(m.x-7,m.y),ImVec2(m.x+7,m.y),col,1.5f); dl->AddLine(ImVec2(m.x,m.y-7),ImVec2(m.x,m.y+7),col,1.5f); }
        if (icon == 5) { dl->AddCircle(m,6.0f,col,16,1.5f); dl->AddLine(ImVec2(m.x+4,m.y+4),ImVec2(m.x+8,m.y+8),col,1.5f); }
        if (icon == 6) { dl->AddCircle(m,5.0f,col,16,1.3f); dl->AddCircle(m,1.8f,col,12,1.2f); for (int i=0;i<8;++i) { const float a=0.7854f*i; dl->AddLine(ImVec2(m.x+6.0f*cosf(a),m.y+6.0f*sinf(a)),ImVec2(m.x+8.0f*cosf(a),m.y+8.0f*sinf(a)),col,1.2f); } }
        if (icon == 7) { dl->AddRectFilled(ImVec2(m.x-5,m.y-5),ImVec2(m.x+5,m.y+5),col,1.0f); }
        if (icon == 8) { dl->AddCircle(ImVec2(m.x-3,m.y),4.5f,col,14,1.3f); dl->AddCircle(ImVec2(m.x+3,m.y),4.5f,col,14,1.3f); }
        if (icon == 9) { dl->AddLine(ImVec2(m.x-5,m.y+5),ImVec2(m.x,m.y-5),col,1.2f); dl->AddLine(ImVec2(m.x,m.y-5),ImVec2(m.x+6,m.y+4),col,1.2f); dl->AddCircleFilled(ImVec2(m.x-5,m.y+5),2.0f,col); dl->AddCircleFilled(ImVec2(m.x,m.y-5),2.0f,col); dl->AddCircleFilled(ImVec2(m.x+6,m.y+4),2.0f,col); }
        if (icon == 10) { dl->AddRect(ImVec2(m.x-7,m.y-5),ImVec2(m.x+7,m.y+5),col,1.0f,0,1.3f); for (int i=-3;i<=3;i+=3) dl->AddLine(ImVec2(m.x+i,m.y-5),ImVec2(m.x+i,m.y+5),col,1.0f); }
        if (icon == 11) { dl->AddLine(ImVec2(m.x-7,m.y-3),ImVec2(m.x-7,m.y-7),col,1.2f); dl->AddLine(ImVec2(m.x-7,m.y-7),ImVec2(m.x-3,m.y-7),col,1.2f); dl->AddLine(ImVec2(m.x+7,m.y-3),ImVec2(m.x+7,m.y-7),col,1.2f); dl->AddLine(ImVec2(m.x+7,m.y-7),ImVec2(m.x+3,m.y-7),col,1.2f); dl->AddLine(ImVec2(m.x-7,m.y+3),ImVec2(m.x-7,m.y+7),col,1.2f); dl->AddLine(ImVec2(m.x-7,m.y+7),ImVec2(m.x-3,m.y+7),col,1.2f); dl->AddLine(ImVec2(m.x+7,m.y+3),ImVec2(m.x+7,m.y+7),col,1.2f); dl->AddLine(ImVec2(m.x+7,m.y+7),ImVec2(m.x+3,m.y+7),col,1.2f); dl->AddCircleFilled(m,1.8f,col); }
        if (icon == 12) { for (int i=-4;i<=4;i+=4) { dl->AddCircleFilled(ImVec2(m.x-6,m.y+i),1.0f,col); dl->AddLine(ImVec2(m.x-3,m.y+i),ImVec2(m.x+7,m.y+i),col,1.2f); } }
        if (icon == 13) { dl->AddRect(ImVec2(m.x-6,m.y-6),ImVec2(m.x+6,m.y+6),col,1.0f,0,1.2f); dl->AddLine(ImVec2(m.x,m.y-6),ImVec2(m.x,m.y+6),col,1.0f); dl->AddLine(ImVec2(m.x-6,m.y),ImVec2(m.x+6,m.y),col,1.0f); }
        if (icon == 14) { dl->AddRect(ImVec2(m.x-6,m.y-7),ImVec2(m.x+5,m.y+7),col,1.0f,0,1.2f); dl->AddLine(ImVec2(m.x-3,m.y-2),ImVec2(m.x+2,m.y-2),col,1.0f); dl->AddLine(ImVec2(m.x-3,m.y+2),ImVec2(m.x+2,m.y+2),col,1.0f); }
        if (icon == 15) { const ImVec2 points[5] = {ImVec2(m.x-5,m.y-7),ImVec2(m.x+5,m.y-7),ImVec2(m.x+5,m.y+7),ImVec2(m.x,m.y+3),ImVec2(m.x-5,m.y+7)}; dl->AddPolyline(points,5,col,ImDrawFlags_Closed,1.3f); }
        if (icon == 16) { dl->AddLine(ImVec2(m.x,m.y-8),ImVec2(m.x,m.y+8),col,1.2f); dl->AddLine(ImVec2(m.x-8,m.y),ImVec2(m.x+8,m.y),col,1.2f); dl->AddLine(ImVec2(m.x-5,m.y-5),ImVec2(m.x+5,m.y+5),col,1.0f); dl->AddLine(ImVec2(m.x+5,m.y-5),ImVec2(m.x-5,m.y+5),col,1.0f); dl->AddCircleFilled(m,2.0f,col); }
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", label);
        if (!enabled) ImGui::EndDisabled();
        ImGui::SameLine();
        return clicked && enabled;
    };

    auto toolbarDivider = [&]() {
        const ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddLine(ImVec2(p.x + 3.0f, p.y + 4.0f),
            ImVec2(p.x + 3.0f, p.y + 21.0f), IM_COL32(35, 58, 72, 255), 1.0f);
        ImGui::Dummy(ImVec2(7.0f, 25.0f));
        ImGui::SameLine();
    };

    if (toolButton("##open", "Open binary", 0)) ShowOpenFileDialog();
    if (toolButton("##attach", "Attach to a process", 1)) ImGui::SetWindowFocus("PROCESSES");
    if (toolButton("##analyze", "Analyze active module", 2, processHandle != nullptr))
        analysisPanel.StartAnalyzeCurrentModule(*this);
    if (toolButton("##refresh", "Refresh current target", 5, isAttached))
    {
        processListPanel.ForceRefresh();
        if (processHandle) moduleCatalog.RefreshModules(processHandle);
        NavigateToAddress(currentAddress);
    }
    toolbarDivider();
    if (toolButton("##detach", "Detach from process", 7, isAttached)) DetachFromProcess();
    if (toolButton("##goto", "Go to address", 4, isAttached)) showGotoModal_ = true;
    if (toolButton("##xrefs", "Cross-references for selection", 8, isAttached))
    {
        analysisPanel.OpenXrefsForAddress(currentAddress);
        ImGui::SetWindowFocus("XREFS");
    }
    if (toolButton("##functions", "Functions and control-flow graph", 9, isAttached))
    {
        showAnalysisPanel_ = true;
        ImGui::SetWindowFocus("Analysis / Functions & CFG");
    }
    toolbarDivider();
    if (toolButton("##memorymap", "Memory map", 10, isAttached)) showMemoryMap_ = true;
    if (toolButton("##scanner", "Pattern scanner", 11, isAttached)) showScanner_ = true;
    if (toolButton("##strings", "Strings", 12, isAttached)) showStrings_ = true;
    if (toolButton("##inspector", "Data inspector", 13, isAttached)) showDataInspector_ = true;
    if (toolButton("##peheader", "PE header", 14, isAttached)) showPEViewer_ = true;
    if (toolButton("##bookmarks", "Bookmarks", 15, isAttached)) showBookmarks_ = true;
    if (toolButton("##assistant", "AI assistant", 16)) ImGui::SetWindowFocus("AI ASSISTANT");

    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 143.0f, 9.0f));
    ImGui::TextDisabled("Workspace");
    ImGui::SameLine();
    if (toolButton("##settings", "AI settings", 6))
        aiCopilotPanel.OpenSettings();

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

void Application::RenderMenuBar()
{
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.016f, 0.031f, 0.042f, 1.0f));
    ImGui::BeginChild("##ApplicationMenu", ImVec2(0.0f, 25.0f), false,
        ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    if (!ImGui::BeginMenuBar())
    {
        ImGui::EndChild();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();
        return;
    }

    if (ImGui::BeginMenu("File"))
    {
        if (ImGui::MenuItem("Open Project (.orev)...", "Ctrl+Shift+O"))
            ShowOpenProjectDialog();
        if (ImGui::MenuItem("Open Binary / Driver File (.sys, .exe, .dll)...", "Ctrl+O"))
        {
            ShowOpenFileDialog();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Open Windows File Manager to analyze any PE file or kernel driver (.sys) offline");
        if (ImGui::MenuItem("Open Dump (.dmp, .mdmp, .bin)..."))
            ShowOpenDumpDialog();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Static analysis only; mapped PE images and Windows minidumps are never executed");
        ImGui::Separator();
        if (ImGui::MenuItem("Save Project", "Ctrl+S", false,
                            isAttached && targetKind != AnalysisTargetKind::LiveProcess))
            SaveProjectFile(false);
        if (ImGui::MenuItem("Save Project As...", "Ctrl+Shift+S", false,
                            isAttached && targetKind != AnalysisTargetKind::LiveProcess))
            SaveProjectFile(true);
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))
            PostQuitMessage(0);
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View"))
    {
        ImGui::MenuItem("Functions and CFG", nullptr, &showAnalysisPanel_);
        ImGui::MenuItem("Memory Map", nullptr, &showMemoryMap_);
        ImGui::MenuItem("PE Header", nullptr, &showPEViewer_);
        ImGui::MenuItem("Data Inspector", nullptr, &showDataInspector_);
        ImGui::MenuItem("Bookmarks", nullptr, &showBookmarks_);
        ImGui::MenuItem("Console", nullptr, &showConsole_);
        ImGui::MenuItem("Version Intelligence", nullptr, &showVersionIntelligence_);
        const auto extensionPanels = extensionManager.Panels();
        if (!extensionPanels.empty() && ImGui::BeginMenu("Extension panels"))
        {
            for (const auto& panel : extensionPanels)
            {
                bool visible = panel.visible;
                ImGui::PushID(panel.id.c_str());
                if (ImGui::MenuItem(panel.title.c_str(), nullptr, &visible))
                    extensionManager.SetPanelVisible(panel.id, visible);
                ImGui::PopID();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Analysis"))
    {
        if (ImGui::MenuItem("Analyze active module", nullptr, false, processHandle != nullptr))
            analysisPanel.StartAnalyzeCurrentModule(*this);
        if (ImGui::MenuItem("Functions and CFG", "Ctrl+I"))
            showAnalysisPanel_ = true;
        if (ImGui::MenuItem("Compare Versions..."))
            showVersionIntelligence_ = true;
        if (ImGui::MenuItem("Go to address...", "Ctrl+G", false, isAttached))
            showGotoModal_ = true;
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Debug"))
    {
        if (ImGui::MenuItem("Attach to process...", nullptr, false, !isAttached))
            ImGui::SetWindowFocus("PROCESSES");
        if (ImGui::MenuItem("Detach", nullptr, false, isAttached)) DetachFromProcess();
        if (ImGui::MenuItem("Refresh process list", "F5")) processListPanel.ForceRefresh();
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Tools"))
    {
        if (ImGui::MenuItem("Pattern Scanner")) showScanner_ = true;
        if (ImGui::MenuItem("Strings")) showStrings_ = true;
        if (ImGui::MenuItem("AI Assistant")) ImGui::SetWindowFocus("AI ASSISTANT");
        ImGui::Separator();
        if (ImGui::MenuItem("Extensions...")) showExtensions_ = true;
        const auto extensionCommands = extensionManager.Commands();
        if (!extensionCommands.empty() && ImGui::BeginMenu("Extension commands"))
        {
            for (const auto& command : extensionCommands)
            {
                bool available = false;
                std::string error;
                extensionManager.IsCommandAvailable(command.id, available, error);
                ImGui::PushID(command.id.c_str());
                if (ImGui::MenuItem(command.displayName.c_str(), nullptr, false, available))
                {
                    if (extensionManager.ExecuteCommand(command.id, error) != OPENREVERSE_OK)
                        Logger::Get().Log(LogLevel::Warning, "Extension command %s: %s",
                            command.id.c_str(), error.c_str());
                }
                ImGui::PopID();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Settings"))
    {
        if (ImGui::MenuItem("AI...")) aiCopilotPanel.OpenSettings();
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Window"))
    {
        if (ImGui::MenuItem("Reset workspace layout")) ResetLayout();
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Help"))
    {
        if (ImGui::MenuItem("About OpenReverse"))
        {
            ImGui::OpenPopup("About OpenReverse");
        }
        ImGui::EndMenu();
    }

    ImGui::EndMenuBar();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();

    if (showGotoModal_)
    {
        ImGui::OpenPopup("Goto Address");
        showGotoModal_ = false;
    }
    if (ImGui::BeginPopupModal("Goto Address", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("Enter address (hex):");
        ImGui::SetNextItemWidth(220.0f);
        bool enterPressed = ImGui::InputText("##addr", gotoAddressBuf_, sizeof(gotoAddressBuf_),
            ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue);
        if (ImGui::Button("OK", ImVec2(80, 0)) || enterPressed)
        {
            if (const auto address = helpers::TryParseAddress(gotoAddressBuf_))
            {
                NavigateToAddress(*address);
                ImGui::CloseCurrentPopup();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(80, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if (ImGui::BeginPopupModal("About OpenReverse", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("OpenReverse - Reverse Engineering Workspace");
        ImGui::Text("Version %s", openreverse::kVersion);
        ImGui::Separator();
        ImGui::Text("Read and analyze process memory, decoded control flow, and optional AI context.");
        if (ImGui::Button("OK", ImVec2(80, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
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
    SwitchToDevMode(false);
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
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - 22.0f));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, 22.0f));

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoSavedSettings;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(9.0f, 3.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.02f, 0.045f, 0.065f, 1.0f));

    ImGui::Begin("##StatusBar", nullptr, flags);

    if (isAttached)
    {
        ImGui::Text("%s", attachedProcessName.c_str());
        ImGui::SameLine(0, 7);
        ImGui::TextDisabled("- %s", is64Bit ? "x64" : "x86");

        if (attachedPID != 0)
        {
            ImGui::SameLine(0, 7);
            ImGui::TextDisabled("- PID %d", attachedPID);
        }

        ImGui::SameLine(0, 7);
        const ModuleInfo* curMod = moduleCatalog.FindModuleByAddress(currentAddress);
        if (curMod)
        {
            std::string offStr = helpers::FormatModuleOffset(curMod->name, curMod->baseAddress, currentAddress, is64Bit);
            ImGui::TextDisabled("- %s", offStr.c_str());
        }
        else
            ImGui::TextDisabled("- %s", helpers::FormatAddress(currentAddress, is64Bit).c_str());
    }
    else
    {
        ImGui::TextDisabled("No target attached");
    }

    if (analysisSession.HasProject())
    {
        ImGui::SameLine(0, 7);
        const std::string projectName = analysisSession.ProjectPath().empty()
            ? "Unsaved project" : std::filesystem::path(analysisSession.ProjectPath()).filename().string();
        ImGui::TextColored(ImVec4(0.25f, 0.67f, 0.96f, 1.0f), "- %s%s",
                           projectName.c_str(), analysisSession.IsDirty() ? " *" : "");
    }

    const AnalysisJobSnapshot offlineJob = offlineAnalysisJobId != 0
        ? analysisScheduler.GetJob(offlineAnalysisJobId) : AnalysisJobSnapshot{};
    std::string state = isAttached ? "Analysis ready" : "Idle";
    if (offlineAnalysisJobId != 0 &&
        (offlineJob.state == AnalysisJobState::Queued || offlineJob.state == AnalysisJobState::Running))
    {
        state = offlineJob.name + " " + std::to_string(static_cast<int>(offlineJob.progress * 100.0f)) + "%";
    }
    const float stateWidth = ImGui::CalcTextSize(state.c_str()).x;
    ImGui::SameLine(ImGui::GetWindowWidth() - stateWidth - 14.0f);
    ImGui::TextColored(isAttached ? ImVec4(0.20f, 0.66f, 0.96f, 1.0f)
                                  : ImVec4(0.42f, 0.47f, 0.51f, 1.0f), "%s", state.c_str());

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
