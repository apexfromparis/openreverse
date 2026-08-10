// ============================================================================
// OpenReverse - Application Implementation
// ============================================================================

#include "application.h"
#include "utils/logger.h"
#include "utils/helpers.h"
#include "ui/panels/ida_pro_panel.h"
#include "core/disassembler.h"

#include <windows.h>
#include <commdlg.h>
#include <imgui.h>
#include <imgui_internal.h>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include <iostream>
#include <exception>
#include <set>
#include <utility>

namespace openreverse {

Application::Application()
{
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
}

bool Application::AttachToProcess(DWORD pid)
{
    DetachFromProcess();

    processHandle = processManager.OpenProcess(pid);
    if (!processHandle)
    {
        Logger::Get().Log(LogLevel::Error, "Failed to open process PID %d", pid);
        return false;
    }

    attachedPID = pid;
    isAttached = true;
    is64Bit = processManager.IsProcess64Bit(processHandle);
    memoryReader.SetOfflineBuffer(nullptr, 0);

    // Get process name
    auto processes = processManager.ListProcesses();
    for (auto& p : processes)
    {
        if (p.pid == pid)
        {
            attachedProcessName = p.name;
            break;
        }
    }

    // Initialize disassembler for correct architecture
    disassembler.Init(is64Bit);

    // Load memory regions and modules
    memoryReader.RefreshRegions(processHandle);
    moduleManager.RefreshModules(processHandle);

    Logger::Get().Log(LogLevel::Info, "Attached to %s (PID: %d, %s)",
        attachedProcessName.c_str(), pid, is64Bit ? "x64" : "x86");

    return true;
}

void Application::DetachFromProcess()
{
    analysisScheduler.CancelAllAndWait();
    analysisDatabase.Clear();
    idaProPanel.ResetAnalysis();
    xrefScanner.Clear();
    stringResults.clear();
    selectedBytes.clear();
    moduleManager.Clear();
    aiService.ClearConversation();
    hexEditorPanel.Reset();
    disasmViewPanel.Reset();
    modulesPanel.Reset();
    ++targetGeneration;
    if (isAttached && processHandle)
    {
        processManager.CloseProcess(processHandle);
        Logger::Get().Log(LogLevel::Info, "Detached from %s", attachedProcessName.c_str());
    }
    isAttached = false;
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
}

void Application::ShowOpenFileDialog()
{
    OPENFILENAMEA ofn = {};
    char fileName[MAX_PATH] = "";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = "PE Executable & Driver Files (*.sys;*.exe;*.dll)\0*.sys;*.exe;*.dll\0Windows Driver (.sys)\0*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = "Open Windows Kernel Driver (.sys) or Executable (.exe/.dll)";

    if (GetOpenFileNameA(&ofn))
    {
        OpenBinaryFile(fileName);
    }
}

bool Application::OpenBinaryFile(const std::string& filePath)
{
    try {
        DetachFromProcess();
        std::cout << "[*] Reading and parsing PE headers from disk..." << std::endl;

        std::vector<uint8_t> rawFile;
        std::vector<uint8_t> mappedImage;
        PEInfo info = peParser.ParseFile(filePath, rawFile);
        if (!info.valid || rawFile.empty())
        {
            std::cout << "\033[1;31m[-] Failed to parse PE binary or driver file: " << filePath << "\033[0m" << std::endl;
            Logger::Get().Log(LogLevel::Error, "Failed to parse PE binary or driver file: %s", filePath.c_str());
            return false;
        }
        if (!PEParser::BuildMappedImage(rawFile, info, mappedImage))
        {
            Logger::Get().Log(LogLevel::Error, "Failed to map PE sections for offline analysis: %s", filePath.c_str());
            return false;
        }
        offlineFileBuffer = std::move(rawFile);
        offlineImageBuffer = std::move(mappedImage);
        offlinePEInfo = info;

        loadedFilePath = filePath;
        is64Bit = info.is64bit;
        attachedProcessName = filePath.substr(filePath.find_last_of("/\\") + 1);
        isAttached = true;
        attachedPID = 0; // 0 indicates offline PE / kernel driver file analysis
        currentAddress = info.imageBase + info.entryPoint;

        memoryReader.SetOfflineBuffer(&offlineImageBuffer, info.imageBase);
        disassembler.Init(is64Bit);

        moduleManager.Clear();
        moduleManager.AddModule(attachedProcessName, info.imageBase, info.sizeOfImage, loadedFilePath);

        std::cout << "[*] Discovering PE entry point and exported functions..." << std::endl;
        std::vector<FunctionInfo> discoveredFuncs;
        const auto isExecutableRva = [&](uint32_t rva) {
            for (const auto& section : info.sections)
            {
                const uint64_t span = std::max<uint64_t>(section.virtualSize, section.rawDataSize);
                if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && rva >= section.virtualAddress &&
                    static_cast<uint64_t>(rva) - section.virtualAddress < span)
                    return true;
            }
            return false;
        };

        if (info.entryPoint != 0 && isExecutableRva(static_cast<uint32_t>(info.entryPoint)))
        {
            FunctionInfo entryFn;
            entryFn.name = "entry_point";
            entryFn.startAddress = info.imageBase + info.entryPoint;
            entryFn.size = 128;
            entryFn.endAddress = entryFn.startAddress + entryFn.size;
            discoveredFuncs.push_back(entryFn);
        }

        for (const auto& exp : info.exports)
        {
            if (exp.isForwarder || !isExecutableRva(exp.rva))
                continue;
            FunctionInfo fn;
            fn.name = exp.name.empty() ? ("sub_" + helpers::FormatAddress(info.imageBase + exp.rva, false)) : exp.name;
            fn.startAddress = info.imageBase + exp.rva;
            fn.size = 64;
            fn.endAddress = fn.startAddress + fn.size;
            fn.isExported = true;
            discoveredFuncs.push_back(fn);
        }

        std::cout << "[*] Decoding executable sections for function and Xref discovery..." << std::endl;
        constexpr size_t kAutomaticCodeAnalysisLimit = 16ULL * 1024ULL * 1024ULL;
        constexpr size_t kAutomaticInstructionLimit = 250000;
        constexpr size_t kAutomaticFunctionLimit = 10000;
        size_t remainingCodeBudget = kAutomaticCodeAnalysisLimit;
        size_t remainingInstructionBudget = kAutomaticInstructionLimit;
        std::vector<std::pair<uint64_t, uint64_t>> analyzedCodeRanges;
        std::vector<FieldAccessCandidate> fieldAccesses;
        std::set<uint64_t> discoveredFunctionAddresses;
        for (const auto& function : discoveredFuncs)
            discoveredFunctionAddresses.insert(function.startAddress);
        xrefScanner.Clear();
        for (const auto& section : info.sections)
        {
            if (remainingCodeBudget == 0 || remainingInstructionBudget == 0)
                break;
            if ((section.characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 ||
                section.virtualAddress >= offlineImageBuffer.size())
                continue;

            const size_t sectionSize = std::min<size_t>({section.rawDataSize,
                offlineImageBuffer.size() - section.virtualAddress, remainingCodeBudget});
            if (sectionSize == 0)
                continue;

            const uint8_t* sectionData = offlineImageBuffer.data() + section.virtualAddress;
            const uint64_t sectionBase = info.imageBase + section.virtualAddress;
            analyzedCodeRanges.push_back({sectionBase, sectionBase + sectionSize});
            remainingCodeBudget -= sectionSize;
            if (discoveredFuncs.size() < kAutomaticFunctionLimit)
            {
                auto scanFuncs = functionAnalyzer.DiscoverFunctions(sectionData, sectionSize, sectionBase, is64Bit,
                    kAutomaticFunctionLimit - discoveredFuncs.size(), 0);
                for (const auto& fn : scanFuncs)
                {
                    if (discoveredFunctionAddresses.insert(fn.startAddress).second)
                        discoveredFuncs.push_back(fn);
                }
            }

            const auto instructions = disassembler.Disassemble(sectionData, sectionSize, sectionBase,
                std::min(remainingInstructionBudget, sectionSize));
            remainingInstructionBudget -= std::min(remainingInstructionBudget, instructions.size());
            xrefScanner.ScanInstructions(instructions, attachedProcessName);
            auto sectionFields = FindFieldAccesses(
                instructions, 100000 - std::min<size_t>(fieldAccesses.size(), 100000));
            fieldAccesses.insert(fieldAccesses.end(), sectionFields.begin(), sectionFields.end());
        }

        std::vector<uint64_t> decodedCallTargets;
        for (const auto& xref : xrefScanner.GetAllEntries())
            if (xref.type == XRefType::Call)
                decodedCallTargets.push_back(xref.toAddress);
        for (const auto& range : analyzedCodeRanges)
        {
            discoveredFuncs = functionAnalyzer.DiscoverFunctionsFromXRefs(
                discoveredFuncs, decodedCallTargets, range.first, range.second, is64Bit,
                kAutomaticFunctionLimit);
        }
        if (discoveredFuncs.size() > kAutomaticFunctionLimit)
            discoveredFuncs.resize(kAutomaticFunctionLimit);
        if (remainingCodeBudget == 0)
            Logger::Get().Log(LogLevel::Warning, "Automatic code analysis reached the 16 MB safety limit.");
        if (remainingInstructionBudget == 0)
            Logger::Get().Log(LogLevel::Warning, "Automatic code analysis reached the instruction limit.");
        if (discoveredFuncs.size() >= kAutomaticFunctionLimit)
            Logger::Get().Log(LogLevel::Warning, "Automatic code analysis reached the function limit.");

        std::sort(discoveredFuncs.begin(), discoveredFuncs.end(), [](const FunctionInfo& a, const FunctionInfo& b) {
            return a.startAddress < b.startAddress;
        });
        AssignFieldFunctions(fieldAccesses, discoveredFuncs);
        const auto structures = InferStructures(fieldAccesses);

        std::cout << "[*] Scanning offline binary strings..." << std::endl;
        constexpr size_t kAutomaticStringScanLimit = 64ULL * 1024ULL * 1024ULL;
        size_t remainingStringBudget = kAutomaticStringScanLimit;
        stringResults.clear();
        for (const auto& section : info.sections)
        {
            if (stringResults.size() >= 5000 || remainingStringBudget == 0)
                break;
            if (section.rawDataSize == 0 || section.virtualAddress >= offlineImageBuffer.size())
                continue;
            const size_t sectionSize = std::min<size_t>({section.rawDataSize,
                offlineImageBuffer.size() - section.virtualAddress, remainingStringBudget});
            remainingStringBudget -= sectionSize;
            auto sectionStrings = stringScanner.ScanBuffer(
                offlineImageBuffer.data() + section.virtualAddress, sectionSize,
                info.imageBase + section.virtualAddress, 5, true, true, 5000 - stringResults.size());
            stringResults.insert(stringResults.end(), sectionStrings.begin(), sectionStrings.end());
        }

        std::cout << "[*] Disassembling entry point instructions..." << std::endl;
        std::vector<Instruction> insns;
        size_t entrySize = 0;
        if (info.entryPoint < offlineImageBuffer.size())
        {
            for (const auto& section : info.sections)
            {
                if (info.entryPoint < section.virtualAddress)
                    continue;
                const uint64_t delta = info.entryPoint - section.virtualAddress;
                if (delta < section.rawDataSize)
                {
                    entrySize = std::min<size_t>(section.rawDataSize - static_cast<size_t>(delta),
                                                 offlineImageBuffer.size() - static_cast<size_t>(info.entryPoint));
                    break;
                }
            }
        }

        if (entrySize != 0)
        {
            insns = disassembler.Disassemble(offlineImageBuffer.data() + info.entryPoint, entrySize, currentAddress, 500);
        }

        std::cout << "[*] Updating OpenReverse analysis panels..." << std::endl;
        ModuleInfo analyzedModule{attachedProcessName, loadedFilePath, info.imageBase, info.sizeOfImage};
        const auto globals = FindGlobalCandidates(analyzedModule, info, xrefScanner.GetAllEntries());
        analysisDatabase.ReplaceModuleAnalysis(analyzedModule, is64Bit, info, discoveredFuncs,
                                               xrefScanner.GetAllEntries(), stringResults, globals, fieldAccesses,
                                               structures);
        idaProPanel.SetPEAnalysisResult(insns, info.sections, info.imports, info.exports, is64Bit, discoveredFuncs);
        if (!discoveredFuncs.empty())
        {
            idaProPanel.SelectFunction(*this, discoveredFuncs[0].startAddress);
        }

        Logger::Get().Log(LogLevel::Info, "Loaded PE/Driver file: %s (%s, %zu bytes, %zu sections, %zu imports, %zu functions, %zu strings)",
            attachedProcessName.c_str(), is64Bit ? "x64" : "x86", offlineFileBuffer.size(), info.sections.size(), info.imports.size(), discoveredFuncs.size(), stringResults.size());

        std::cout << "[+] Analysis completed successfully!" << std::endl;
        return true;
    }
    catch (const std::exception& e)
    {
        DetachFromProcess();
        std::cout << "\033[1;31m[-] Exception during OpenBinaryFile: " << e.what() << "\033[0m" << std::endl;
        return false;
    }
    catch (...)
    {
        DetachFromProcess();
        std::cout << "\033[1;31m[-] Unknown exception/crash during OpenBinaryFile\033[0m" << std::endl;
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
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_G) && ImGui::GetIO().KeyCtrl)
        showGotoModal_ = true;
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_I) && ImGui::GetIO().KeyCtrl)
        ImGui::SetWindowFocus("Analysis / Functions & CFG");
    if (isAttached && ImGui::IsKeyPressed(ImGuiKey_X) && !ImGui::GetIO().WantCaptureKeyboard)
    {
        idaProPanel.OpenXrefsForAddress(currentAddress);
        ImGui::SetWindowFocus("Analysis / Functions & CFG");
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F5))
        processListPanel.ForceRefresh();

    RenderDockspace();

    // Render all panels
    processListPanel.Render(*this);
    memoryMapPanel.Render(*this);
    hexEditorPanel.Render(*this);
    disasmViewPanel.Render(*this);
    idaProPanel.Render(*this);
    openReverseEditorPanel.Render(*this, showOpenReverseEditor);
    modulesPanel.Render(*this);
    scannerPanel.Render(*this);
    stringsPanel.Render(*this);
    dataInspectorPanel.Render(*this);
    peViewerPanel.Render(*this);
    bookmarksPanel.Render(*this);
    offsetsPanel.Render(*this);
    consolePanel.Render(*this);
    aiCopilotPanel.Render(*this);

    RenderStatusBar();
}

void Application::RenderDockspace()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();

    // Reserve space for status bar (25px)
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, viewport->WorkSize.y - 25.0f));
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags dockFlags =
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_MenuBar |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("OpenReverse_Dockspace", nullptr, dockFlags);
    ImGui::PopStyleVar(3);

    RenderMenuBar();

    ImGuiID dockspace_id = ImGui::GetID("OpenReverse_DockspaceID");
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    // Default layout: all windows docked, none floating
    if (!layoutInitialized_)
    {
        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImVec2 workSize(viewport->WorkSize.x, viewport->WorkSize.y - 25.0f);
        ImGui::DockBuilderSetNodeSize(dockspace_id, workSize);

        ImGuiID main = dockspace_id;
        ImGuiID left  = ImGui::DockBuilderSplitNode(main, ImGuiDir_Left,  0.20f, nullptr, &main);
        ImGuiID right = ImGui::DockBuilderSplitNode(main, ImGuiDir_Right, 0.24f, nullptr, &main);
        ImGuiID bottom = ImGui::DockBuilderSplitNode(main, ImGuiDir_Down, 0.22f, nullptr, &main);

        if (isDevMode)
        {
            // ─── DEV STUDIO LAYOUT (OpenReverse Editor takes MAIN central screen) ───
            ImGui::DockBuilderDockWindow("OpenReverse Editor", main);

            ImGui::DockBuilderDockWindow("Processes", left);
            ImGui::DockBuilderDockWindow("Modules", left);
            ImGui::DockBuilderDockWindow("Bookmarks", left);

            ImGui::DockBuilderDockWindow("Console", bottom);

            // Stack reverse engineering tools in right sidebar tabs
            ImGui::DockBuilderDockWindow("Analysis / Functions & CFG", right);
            ImGui::DockBuilderDockWindow("Hex Editor", right);
            ImGui::DockBuilderDockWindow("Disassembly", right);
            ImGui::DockBuilderDockWindow("AI Copilot", right);
            ImGui::DockBuilderDockWindow("PE Header", right);
            ImGui::DockBuilderDockWindow("Data Inspector", right);
            ImGui::DockBuilderDockWindow("Pattern Scanner", right);
            ImGui::DockBuilderDockWindow("Strings", right);
            ImGui::DockBuilderDockWindow("Offsets & Structures", right);
        }
        else
        {
            // ─── REVERSE ENGINEERING LAYOUT ───
            ImGuiID mainTop = main;
            ImGuiID mainBottom = ImGui::DockBuilderSplitNode(mainTop, ImGuiDir_Down, 0.38f, nullptr, &mainTop);

            // Left Sidebar: Navigation & Target info
            ImGui::DockBuilderDockWindow("Processes", left);
            ImGui::DockBuilderDockWindow("Modules", left);
            ImGui::DockBuilderDockWindow("Memory Map", left);
            ImGui::DockBuilderDockWindow("Bookmarks", left);

            // Main Top (62% of center): functions, CFG, pseudocode, and disassembly
            ImGui::DockBuilderDockWindow("Analysis / Functions & CFG", mainTop);
            ImGui::DockBuilderDockWindow("Disassembly", mainTop);

            // Main Bottom (38% of center): Hex Editor & Live Memory View
            ImGui::DockBuilderDockWindow("Hex Editor", mainBottom);
            ImGui::DockBuilderDockWindow("Data Inspector", mainBottom);

            // Right Sidebar (24%): Analysis & Automation Tools
            ImGui::DockBuilderDockWindow("PE Header", right);
            ImGui::DockBuilderDockWindow("Strings", right);
            ImGui::DockBuilderDockWindow("Pattern Scanner", right);
            ImGui::DockBuilderDockWindow("Offsets & Structures", right);
            ImGui::DockBuilderDockWindow("AI Copilot", right);
            ImGui::DockBuilderDockWindow("OpenReverse Editor", right);

            // Bottom Console (22%): Output & Debug Logs
            ImGui::DockBuilderDockWindow("Console", bottom);
        }

        ImGui::DockBuilderFinish(dockspace_id);
        layoutInitialized_ = true;
    }

    ImGui::End();
}

void Application::RenderMenuBar()
{
    if (!ImGui::BeginMenuBar())
        return;

    if (ImGui::BeginMenu("File"))
    {
        if (ImGui::MenuItem("Open Binary / Driver File (.sys, .exe, .dll)...", "Ctrl+O"))
        {
            ShowOpenFileDialog();
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Open Windows File Manager to analyze any PE file or kernel driver (.sys) offline");
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))
            PostQuitMessage(0);
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Dev Section"))
    {
        if (ImGui::MenuItem("DEV MODE (Full Code Editor & Script Studio Layout)", "F12", isDevMode))
        {
            SwitchToDevMode(!isDevMode);
        }
        if (ImGui::MenuItem("Open Editor in Separate Floating Window ('à part')", "Ctrl+Shift+E", isEditorFloating))
        {
            isEditorFloating = !isEditorFloating;
            showOpenReverseEditor = true;
            Logger::Get().Log(LogLevel::Info, "%s", isEditorFloating ? "[Dev Section] Opened OpenReverse Editor in standalone floating window." : "[Dev Section] Docked OpenReverse Editor back into IDE.");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Show OpenReverse Editor Panel", "Ctrl+E", showOpenReverseEditor))
        {
            showOpenReverseEditor = !showOpenReverseEditor;
            if (showOpenReverseEditor)
                ImGui::SetWindowFocus("OpenReverse Editor");
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Reload Workspace Scripts from Disk"))
        {
            openReverseEditorPanel.ScanWorkspaceFolder();
            Logger::Get().Log(LogLevel::Info, "[Dev Section] Re-scanned disk workspace directory.");
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Process"))
    {
        if (ImGui::MenuItem("Attach...", nullptr, false, !isAttached))
            showGotoModal_ = false; // ensure process list is used
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Open the Processes panel and double-click a process to attach.");
        if (ImGui::MenuItem("Detach", nullptr, false, isAttached))
            DetachFromProcess();
        ImGui::Separator();
        if (ImGui::MenuItem("Refresh process list"))
            processListPanel.ForceRefresh();
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View"))
    {
        if (ImGui::BeginMenu("Workspace Layout"))
        {
            if (ImGui::MenuItem("1. Reverse Engineering Layout", "Ctrl+1", !isDevMode))
            {
                SwitchToDevMode(false);
            }
            if (ImGui::MenuItem("2. Dev Studio & Scripting Layout (Code Editor)", "Ctrl+2", isDevMode))
            {
                SwitchToDevMode(true);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Reset & Auto-Arrange All Windows"))
            {
                ResetLayout();
            }
            ImGui::EndMenu();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Analysis (Functions, CFG & XREFs)", "Ctrl+I"))
            ImGui::SetWindowFocus("Analysis / Functions & CFG");
        if (ImGui::MenuItem("OpenReverse Editor Panel", "Ctrl+E"))
            ImGui::SetWindowFocus("OpenReverse Editor");
        if (ImGui::MenuItem("Goto Address...", "Ctrl+G", false, isAttached))
            showGotoModal_ = true;
        if (ImGui::MenuItem("Reset layout"))
            ResetLayout();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("Dock all windows back to default arrangement");
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Help"))
    {
        if (ImGui::MenuItem("About OpenReverse Studio"))
        {
            ImGui::OpenPopup("About OpenReverse Studio");
        }
        ImGui::EndMenu();
    }

    ImGui::EndMenuBar();

    // Goto Address modal
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
            uint64_t addr = (uint64_t)strtoull(gotoAddressBuf_, nullptr, 16);
            NavigateToAddress(addr);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(80, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // About popup
    if (ImGui::BeginPopupModal("About OpenReverse Studio", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
    {
        ImGui::Text("OpenReverse Studio - Memory Analysis & Reverse Engineering");
        ImGui::Text("Version 2.0");
        ImGui::Separator();
        ImGui::Text("Read and analyze process memory, experimental pseudocode, and optional AI context.");
        ImGui::Text("Type '/gui' in the shell or use the menu to switch views.");
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

void Application::RenderStatusBar()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y + viewport->WorkSize.y - 25.0f));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, 25.0f));

    ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoSavedSettings;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10.0f, 4.0f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.07f, 0.07f, 0.10f, 1.0f));

    ImGui::Begin("##StatusBar", nullptr, flags);

    if (isAttached)
    {
        ImGui::TextColored(ImVec4(0.30f, 0.90f, 0.45f, 1.0f), "●");
        ImGui::SameLine(0, 4);
        ImGui::Text("%s", attachedProcessName.c_str());
        ImGui::SameLine(0, 8);
        ImGui::TextDisabled("|");
        ImGui::SameLine(0, 8);
        ImGui::TextDisabled("%s", is64Bit ? "x64" : "x86");

        if (attachedPID != 0)
        {
            ImGui::SameLine(0, 8);
            ImGui::TextDisabled("|");
            ImGui::SameLine(0, 8);
            ImGui::TextDisabled("PID %d", attachedPID);
        }

        ImGui::SameLine(0, 8);
        ImGui::TextDisabled("|");
        ImGui::SameLine(0, 8);
        const ModuleInfo* curMod = moduleManager.FindModuleByAddress(currentAddress);
        if (curMod)
        {
            std::string offStr = helpers::FormatModuleOffset(curMod->name, curMod->baseAddress, currentAddress, is64Bit);
            ImGui::TextColored(ImVec4(0.35f, 0.80f, 0.55f, 1.0f), "%s", offStr.c_str());
        }
        else
            ImGui::TextColored(ImVec4(0.50f, 0.65f, 0.85f, 1.0f), "%s", helpers::FormatAddress(currentAddress, is64Bit).c_str());
    }
    else
    {
        ImGui::TextColored(ImVec4(0.45f, 0.45f, 0.50f, 1.0f), "○");
        ImGui::SameLine(0, 4);
        ImGui::TextDisabled("No target attached");
    }

    // Right-aligned local configuration indicators
    ImGui::SameLine(ImGui::GetWindowWidth() - 330.0f);
    const std::string aiProvider = aiService.Provider();
    ImGui::TextDisabled("AI: %s", aiProvider.c_str());
    ImGui::SameLine(0, 12);
    ImGui::TextDisabled("|");
    ImGui::SameLine(0, 12);
    ImGui::TextDisabled("v2.0");

    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
}

std::string Application::GetAIContextSummary()
{
    if (!isAttached && attachedProcessName.empty())
    {
        return "[Active Target Context: NO PROCESS OR BINARY IS CURRENTLY ATTACHED in OpenReverse Studio. CRITICAL INSTRUCTION: If the user asks to analyze 'this program' or 'this binary', do NOT give a generic refusal! Instead, tell the user in French: 'Vous n'avez pas encore rattaché de processus ou chargé de binaire dans OpenReverse Studio ! Allez dans le menu Process -> Attach (ou l'onglet Process List) pour sélectionner une cible, puis reposez votre question.']\n\n";
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
    const auto& funcs = analysis ? analysis->functions : idaProPanel.GetFunctions();
    if (!funcs.empty())
    {
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

    // ── Live Memory Disassembly at Current Address ──
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

    // ── Selected OpenReverse Function & Pseudocode ──
    if (idaProPanel.GetActiveFunction().startAddress != 0)
    {
        const auto& fn = idaProPanel.GetActiveFunction();
        ss << "\n--- CURRENT ACTIVE FUNCTION IN OPENREVERSE ---\n";
        ss << "Function: " << fn.name << " at 0x" << std::hex << fn.startAddress << " (Size: " << std::dec << fn.size << " bytes)\n";
        if (!idaProPanel.GetActivePseudocode().empty())
        {
            ss << "Experimental C Pseudocode:\n```c\n" << idaProPanel.GetActivePseudocode() << "\n```\n";
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
