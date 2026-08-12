#include "application.h"
#include "openreverse_version.h"
#include "utils/logger.h"
#include "utils/helpers.h"
#include "ui/panels/analysis_panel.h"
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
#include <cmath>

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

    auto processes = processManager.ListProcesses();
    for (auto& p : processes)
    {
        if (p.pid == pid)
        {
            attachedProcessName = p.name;
            break;
        }
    }

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
    analysisPanel.ResetAnalysis();
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
        analysisPanel.SetPEAnalysisResult(insns, info.sections, info.imports, info.exports, is64Bit, discoveredFuncs);
        if (!discoveredFuncs.empty())
        {
            analysisPanel.SelectFunction(*this, discoveredFuncs[0].startAddress);
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
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O) && !ImGui::GetIO().WantTextInput)
        ShowOpenFileDialog();
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_1))
        SwitchToDevMode(false);
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_2))
        SwitchToDevMode(true);
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

    RenderStatusBar();
}

void Application::RenderDockspace()
{
    ImGuiViewport* viewport = ImGui::GetMainViewport();

    // Reserve space for the compact status bar.
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

    // Default layout: all windows docked, none floating
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

            // Stack reverse engineering tools in right sidebar tabs
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
            // Reference layout: navigation left, code/hex center, context and AI right.
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

            // Left Sidebar: Navigation & Target info
            ImGui::DockBuilderDockWindow("PROCESSES", leftTop);
            ImGui::DockBuilderDockWindow("MODULES", leftBottom);

            // Main Top (62% of center): functions, CFG, pseudocode, and disassembly
            ImGui::DockBuilderDockWindow("DISASSEMBLY", mainTop);

            // Main Bottom (38% of center): Hex Editor & Live Memory View
            ImGui::DockBuilderDockWindow("HEX VIEW", mainBottom);

            // Right Sidebar (24%): Analysis & Automation Tools
            ImGui::DockBuilderDockWindow("XREFS", rightTop);
            ImGui::DockBuilderDockWindow("STRUCTURES", rightMiddle);
            ImGui::DockBuilderDockWindow("AI ASSISTANT", rightBottom);
        }

        ImGui::DockBuilderFinish(dockspace_id);
        layoutInitialized_ = true;
    }

    ImGui::End();

    // A restrained blue edge defines the application frame from the black
    // desktop without creating the heavy native Windows border.
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

    // Compact vector CR monogram inspired by the product mark.
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

    // Native window actions, rendered inside the branded title bar.
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
        if (processHandle) moduleManager.RefreshModules(processHandle);
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

    // Workspace switcher and settings mirror the compact controls in the
    // reference toolbar; both are wired to real application actions.
    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 192.0f, 4.0f));
    ImGui::SetNextItemWidth(145.0f);
    const char* workspace = isDevMode ? "Editor workspace" : "Workspace";
    if (ImGui::BeginCombo("##Workspace", workspace))
    {
        if (ImGui::Selectable("Reverse workspace", !isDevMode)) SwitchToDevMode(false);
        if (ImGui::Selectable("Editor workspace", isDevMode)) SwitchToDevMode(true);
        ImGui::EndCombo();
    }
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

    if (ImGui::BeginMenu("View"))
    {
        if (ImGui::MenuItem("Reverse workspace", "Ctrl+1", !isDevMode)) SwitchToDevMode(false);
        if (ImGui::MenuItem("Editor workspace", "Ctrl+2", isDevMode)) SwitchToDevMode(true);
        ImGui::Separator();
        ImGui::MenuItem("Functions and CFG", nullptr, &showAnalysisPanel_);
        ImGui::MenuItem("Memory Map", nullptr, &showMemoryMap_);
        ImGui::MenuItem("PE Header", nullptr, &showPEViewer_);
        ImGui::MenuItem("Data Inspector", nullptr, &showDataInspector_);
        ImGui::MenuItem("Bookmarks", nullptr, &showBookmarks_);
        ImGui::MenuItem("Console", nullptr, &showConsole_);
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Analysis"))
    {
        if (ImGui::MenuItem("Analyze active module", nullptr, false, processHandle != nullptr))
            analysisPanel.StartAnalyzeCurrentModule(*this);
        if (ImGui::MenuItem("Functions and CFG", "Ctrl+I"))
            showAnalysisPanel_ = true;
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
        if (ImGui::MenuItem("AI Settings...")) aiCopilotPanel.OpenSettings();
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
        ImGui::Text("Read and analyze process memory, experimental pseudocode, and optional AI context.");
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
        const ModuleInfo* curMod = moduleManager.FindModuleByAddress(currentAddress);
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

    const char* state = isAttached ? "Analysis ready" : "Idle";
    const float stateWidth = ImGui::CalcTextSize(state).x;
    ImGui::SameLine(ImGui::GetWindowWidth() - stateWidth - 14.0f);
    ImGui::TextColored(isAttached ? ImVec4(0.20f, 0.66f, 0.96f, 1.0f)
                                  : ImVec4(0.42f, 0.47f, 0.51f, 1.0f), "%s", state);

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
    const auto& funcs = analysis ? analysis->functions : analysisPanel.GetFunctions();
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
        ss << "Function: " << fn.name << " at 0x" << std::hex << fn.startAddress << " (Size: " << std::dec << fn.size << " bytes)\n";
        if (!analysisPanel.GetActivePseudocode().empty())
        {
            ss << "Experimental C Pseudocode:\n```c\n" << analysisPanel.GetActivePseudocode() << "\n```\n";
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
