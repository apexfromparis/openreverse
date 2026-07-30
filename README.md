# OPENREVERSE Studio v2.0 🏴

**OPENREVERSE Studio** is an advanced, AI-powered **x64 Reverse Engineering Engine & Interactive CLI REPL** for Windows. Built for security researchers, reverse engineers, and malware analysts, it combines Hex-Rays style C/C++ decompilation, control flow graphs, x64 disassembly, and deep AI Copilot integration in a compact, zero-color monochrome terminal experience.

```text
=================================================================================
   ___  ____  _____ _   _ ____  _____ __     _____ ____  ____  _____ 
  / _ \|  _ \| ____| \ | |  _ \| ____|\ \   / / ____|  _ \/ ___|| ____|
 | | | | |_) |  _| |  \| | |_) |  _|   \ \ / /|  _| | |_) \___ \|  _|  
 | |_| |  __/| |___| |\  |  _ <| |___   \ V / | |___|  _ < ___) | |___ 
  \___/|_|   |_____|_| \_|_| \_\_____|   \_/  |_____|_| \_\____/|_____|
---------------------------------------------------------------------------------
   OPENREVERSE Studio v2.0 | x64 Interactive CLI REPL | AI-Powered Reverse Engine 
=================================================================================
```

---

## ⚡ One-Line Installation (Recommended)

Install **OPENREVERSE CLI** globally on any Windows 10/11 machine with a single PowerShell command (just like `opencode`, `bun`, or `scoop`):

```powershell
irm https://raw.githubusercontent.com/apexfromparis/powerfull-ida/main/install.ps1 | iex
```

After installation, open any new CMD or PowerShell terminal and type:
```bash
openreverse
```

### Alternative Installation Methods

#### 1. Scoop Package Manager
If you use Scoop:
```powershell
scoop install https://raw.githubusercontent.com/apexfromparis/powerfull-ida/main/openreverse.json
```

#### 2. Manual Installation / GitHub Releases
1. Download the latest `openreverse.exe` from [GitHub Releases](https://github.com/apexfromparis/powerfull-ida/releases).
2. Place it in `%USERPROFILE%\.openreverse\bin`.
3. Add `%USERPROFILE%\.openreverse\bin` to your User Environment `PATH`.

---

## 🤖 AI Copilot & Model Commands

OPENREVERSE features native integration with any OpenAI-compatible API, Ollama, OpenRouter, Claude, or DeepSeek model:

| Command | Description & Example |
| :--- | :--- |
| `ai-config <prov> <url> <model>` | Configure AI provider, base URL, and default model.<br>`ai-config OpenAI-compatible https://api.openai.com/v1 gpt-4o` |
| `ai-key <api_key>` | Securely store your API key in **Windows Credential Manager**. |
| `ai-model <model_name>` | Instantly switch models (`gpt-4o`, `claude-3-5-sonnet`, `deepseek-coder`). |
| `ai-status` | Display active provider, base URL, model, key status, and message history. |
| `ai-ask <question>` | Ask any reverse engineering or assembly question directly in the CLI. |
| `ai-explain <func>` | Decompile a function to Hex-Rays pseudocode and get a detailed AI explanation. |
| `ai-rename <func>` | Have AI suggest descriptive function and variable names in a Markdown table. |
| `ai-vuln <func>` | Automatically audit a decompiled function for security vulnerabilities. |

---

## 🛠️ Interactive CLI REPL Commands

| Command | Description |
| :--- | :--- |
| `open <path.exe>` | Load binary into memory and run full automated analysis |
| `attach <PID>` | Attach to a live running process and analyze functions |
| `functions [filter]` | List discovered functions (Address, Name, Size, V(G), XREFs) |
| `decompile <addr\|name>` | Generate clean Hex-Rays style C/C++ pseudocode |
| `cfg <addr\|name>` | Display ASCII Control Flow Graph & basic block branching |
| `xrefs <addr\|name>` | Show Cross-References (CALL, JUMP, READ, WRITE) |
| `strings [filter]` | Scan memory for strings (highlights URLs, Registry, C2) |
| `disasm <addr> [cnt]` | Disassemble x64 machine code at specified address |
| `modules` | List loaded PE modules and base addresses |
| `report [file.md]` | Export comprehensive Markdown decompilation report |
| `gui` | Hand over session immediately to the Graphical User Interface |
| `exit / quit` | Exit OPENREVERSE Studio |

---

## 🏗️ Building from Source

Prerequisites: **Visual Studio 2022 (x64)**, **CMake 3.20+**, and **Ninja**.

```cmd
git clone https://github.com/apexfromparis/powerfull-ida.git
cd "powerfull-ida\powerfull ida\kyv utils"
cmake -B build_ninja -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build_ninja --config Release
```

To install your custom build globally:
```powershell
.\install.ps1
```
