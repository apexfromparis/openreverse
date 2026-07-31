# OpenReverse Studio (v2.0.0)
### *The Next-Generation Agentic Reverse Engineering & AI Hex-Rays Suite*

<div align="center">
  <pre>
█▀▀█ █▀▀█ █▀▀█ █▀▀▄ █▀▀▄ █▀▀▀ █  █ █▀▀▀ █▀▀▄ █▀▀▀ █▀▀▀
█  █ █  █ █▀▀▀ █  █ █▀▀▄ █▀▀  ▀▄▄▀ █▀▀  █▀▀▄ ▀▀▀█ █▀▀ 
▀▀▀▀ █▀▀▀ ▀▀▀▀ ▀  ▀ ▀  ▀ ▀▀▀▀  ▀▀  ▀▀▀▀ ▀  ▀ ▀▀▀▀ ▀▀▀▀
  </pre>
  <p><b>Agentic Reverse Engineering Shell & Automated Hex-Rays Analysis Platform</b></p>
  <p>
    <a href="#features">Features</a> •
    <a href="#installation--quickstart">Quickstart</a> •
    <a href="#interactive-slash-command-palette">Command Palette</a> •
    <a href="#ai-copilot--local-models">AI Copilot</a> •
    <a href="#architecture">Architecture</a>
  </p>
</div>

---

## ⚡ Overview

**OpenReverse** is a next-generation **Agentic Reverse Engineering suite** designed to supersede legacy tools like IDA Pro, Ghidra, and Binary Ninja. Combining advanced static disassembling, Hex-Rays C/C++ pseudocode decompilation, and dynamic memory analysis with an **autonomous LLM AI Copilot**, OpenReverse turns complex binary reverse engineering into a natural, interactive conversation.

Whether you are auditing malware, hunting 0-day vulnerabilities, or analyzing proprietary protocols, OpenReverse works seamlessly from a modern **Interactive Terminal Shell (TUI)** or a full **Graphical Studio GUI**.

---

## 🔥 Key Killer Features (Making the Market Difference)

- **🚀 AI Zero-Click Threat Triage (`/triage`)**  
  Instantly evaluate any binary with a single command. Generates an executive threat assessment, computes an automated **Threat Score (0–100)**, and maps observed API behaviors directly to the **MITRE ATT&CK Matrix** (e.g., *T1055 Process Injection*, *T1056 Input Capture*).

- **🧠 Global AI Name & Type Inference (`/auto-rename`)**  
  Say goodbye to `sub_140001230` and `var_18`. OpenReverse analyzes API call graphs, string references, and parameter flows across all discovered functions to automatically infer readable C/C++ symbol signatures and struct layouts.

- **⚡ Instant Hex-Rays C/C++ Decompilation (`/decompile <addr>`)**  
  Built-in x64 assembly decompilation engine that transforms raw machine code into clean, highly readable C/C++ pseudocode on the fly.

- **🎯 Interactive Agentic RE Shell (`openreverse`)**  
  A sleek, terminal-first interactive RE workspace inspired by modern developer CLI tools. Features an **OpenCode-style Command Palette** triggered instantly by pressing `/`, complete with real-time fuzzy search, keyboard arrow navigation, and multi-session workspaces.

- **🛡️ Automated Security & Vulnerability Auditing (`/vuln`)**  
  Direct AI Copilot auditing of decompiled C pseudocode to spot buffer overflows, format string vulnerabilities, integer overflows, logic flaws, and license-check routines.

- **🔌 Universal AI Provider Support (`/connect`, `/models`)**  
  Runs 100% offline with **Local Ollama** (`qwen2.5-coder`, `deepseek-r1`, `llama3`) or connects natively to **Groq Cloud**, **OpenRouter**, **OpenAI**, and **Anthropic Claude**.

---

## 📦 Installation & Quickstart

### 1. Global Command-Line Access
OpenReverse installs cleanly into your user directory and is available system-wide:
```powershell
# OpenReverse executable path:
C:\Users\<user>\.openreverse\bin\openreverse.exe
```

### 2. Launching the Interactive Shell
Open any terminal and type:
```powershell
openreverse
```
You will be greeted by the minimal OpenReverse banner:
```
  OpenReverse v2.0.0 (agentic reverse engineering shell)
  Type / to open command palette (/open, /attach, /decompile...) or type to chat with AI Copilot.

[s1:no target] / openreverse> 
```

### 3. Quick Reverse Engineering Workflow
```powershell
# 1. Open and analyze a target binary automatically
[s1:no target] / openreverse> /open C:\Windows\System32\notepad.exe

# 2. Run a Zero-Click Threat Assessment & MITRE ATT&CK mapping
[s1:notepad.exe] / openreverse> /triage

# 3. List discovered functions & entry points
[s1:notepad.exe] / openreverse> /functions

# 4. Decompile a function address into readable C/C++ Hex-Rays code
[s1:notepad.exe] / openreverse> /decompile 0x140001000

# 5. Ask AI Copilot to explain the logic in detail
[s1:notepad.exe] / openreverse> /explain 0x140001000

# 6. Audit for security vulnerabilities
[s1:notepad.exe] / openreverse> /vuln 0x140001000
```

---

## 🎨 Interactive Slash Command Palette

Press **`/`** at any time in the terminal to instantly launch the visual command palette:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  /triage     AI Zero-Click Threat Report & automatic MITRE ATT&CK...     │
│  /auto-rename Global AI name & type inference across all functions       │
│  /open       Open binary file & launch automated Hex-Rays analysis       │
│  /attach     Attach to running Windows process PID for dynamic analysis  │
│  /functions  List discovered functions & entry points in target binary   │
│  /decompile  Decompile x64 assembly into readable Hex-Rays C pseudocode  │
│  /explain    Ask AI Copilot to explain current function logic in detail  │
│  /rename     Ask AI to suggest descriptive variable & function names     │
│  /vuln       Audit decompiled C code for vulnerabilities / license check │
└──────────────────────────────────────────────────────────────────────────┘
  Build · qwen2.5-coder:7b Free Local Ollama
  tab sessions   ctrl+p commands
```

### Reference Table

| Command | Description |
| :--- | :--- |
| **`/triage`** | AI Zero-Click Threat Report & automatic MITRE ATT&CK mapping |
| **`/auto-rename`** | Global AI semantic name & type inference across all functions |
| **`/open <exe>`** | Open binary file & launch automated Hex-Rays analysis |
| **`/attach <pid>`** | Attach to running Windows process PID for dynamic analysis |
| **`/functions`** | List discovered functions & entry points in target binary |
| **`/decompile <addr>`** | Decompile x64 assembly into readable Hex-Rays C pseudocode |
| **`/explain <addr>`** | Ask AI Copilot to explain current function logic in detail |
| **`/rename <addr>`** | Ask AI to suggest descriptive variable & function names |
| **`/vuln <addr>`** | Audit decompiled C code for vulnerabilities / license check |
| **`/xrefs <addr>`** | Show all cross-references (`CALL`, `JUMP`, `MEM`) to/from address |
| **`/strings`** | List extracted ASCII/UTF-16 strings (URLs, C2, Registry keys) |
| **`/sessions`** | Manage OpenReverse interactive RE & multi-session workspaces |
| **`/new`** | Create a new clean session workspace (`/switch <id>` to change) |
| **`/account`** | Check subscription tier, ODNC license token & Dev SDK access status |
| **`/login <key>`** | Authenticate with ODNC server token to unlock Pro/Dev tiers |
| **`/hub`** | Browse OpenReverse Developer Community Hub & Marketplace |
| **`/install <name>`** | Install a community plugin or skill from the OpenReverse Hub |
| **`/plugins`** | List installed community scripts, skills & plugins |
| **`/models`** | Switch AI Copilot LLM model (`qwen2.5-coder`, `deepseek-r1`, `claude`...) |
| **`/connect`** | Connect AI provider (`Ollama`, `OpenRouter`, `Groq Cloud`...) |
| **`/setup`** | One-click interactive AI setup & local model auto-installer |
| **`/gui`** | Handover session immediately to OpenReverse Graphical Studio UI |
| **`/clear`** | Clear terminal screen |
| **`/exit`** | Quit OpenReverse Studio |

---

## 💎 ODNC Subscription Tiers & Developer Marketplace

OpenReverse operates on a modern hybrid open-core model (similar to Cursor AI, Burp Suite, or IDA Pro):

1. **Community Free Tier**: Run 100% offline with local models (Ollama, LM Studio), basic static/dynamic RE, and standard TUI command palette.
2. **Pro Analyst Tier**: Connect to ODNC Cloud AI Cluster for zero-latency GPT-4o / Claude 3.5 Sonnet / DeepSeek-R1, automated `/triage` MITRE ATT&CK threat reports, and Zero-Click Exploit PoC generation.
3. **Dev Creator Tier (The Community Hub Subscription)**:
   - **Embedded GUI Studio Script Editor & AI Assistant**: Open the Graphical Studio (`/gui`) and access the dedicated **ODNC Dev Creator Studio** tab. Code custom C++/Python/Lua heuristics in a live multi-line code editor and chat with an embedded AI Assistant that has full context of both your script code and the loaded target executable!
   - **Early SDK Access**: Access to private C++/Python plugin APIs and symbol hooks.
   - **Marketplace Publishing Rights**: Submit plugins to the **OpenReverse Community Hub (`/hub`)** and earn **Revenue Share** when Pro analysts use your tools!
   - **Sandbox Testing**: Access ODNC cloud malware sandboxes to test scripts safely.

```powershell
# Authenticate your ODNC license token in the terminal:
[s1:notepad.exe] / openreverse> /login OPENREVERSE-DEV-COMMUNITY-2026
[+] Authenticated successfully with ODNC server! Unlocked DEV CREATOR TIER.

# Browse community-created plugins:
[s1:notepad.exe] / openreverse> /hub
```

---

## 🤖 Natural AI Chat & Copilot

Any text typed into the console **without** a `/` prefix is automatically routed to your AI Reverse Engineering Copilot with full context of your currently loaded binary, active PID, and decompiled functions:

```
[s1:notepad.exe] / openreverse> How does this binary handle command-line arguments?
```

---

## 🏗️ Architecture & Build

OpenReverse is built in modern **C++20** for Windows x64, leveraging:
- **Capstone Disassembler Engine** for x86/x64 instruction decoding.
- **Custom Hex-Rays AST Decompiler** for C/C++ pseudocode generation.
- **ImGui & DirectX 11** for the Graphical Studio interface.
- **Native ANSI / TUI Console Buffer Engine** for zero-latency interactive terminal menus.

### Compiling from Source
```powershell
cd "powerfull ida/kyv utils"
cmake -B build -A x64
cmake --build build --config Release --parallel
```
The compiled binaries are generated in `build/bin/Release/openreverse.exe` and `build/bin/Release/KYV.exe`.

---

## 📄 License & Contributing

Distributed under the **MIT License**. Created and maintained by **Apex (@apexfromparis)**.  
Pull requests, vulnerability research contributions, and new AI heuristics are welcome!
