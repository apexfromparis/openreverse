import React, { useState, useRef, useEffect } from 'react';
import { Terminal as TerminalIcon, CornerDownLeft } from 'lucide-react';

interface TabSession {
  id: string;
  name: string;
  target: string;
  arch: string;
}

const SESSIONS: TabSession[] = [
  { id: 's1', name: 'notepad.exe', target: '0x140001230', arch: 'x64 PE32+' },
  { id: 's2', name: 'kernel_driver.sys', target: '0xFFFFF8002010', arch: 'x64 Windows Driver' },
  { id: 's3', name: 'crackme_challenge.exe', target: '0x00401000', arch: 'x86 Win32' },
];

const COMMAND_RESPONSES: Record<string, string> = {
  '/triage': `
<div class="inline-block px-2 py-0.5 rounded bg-[#fb923c]/20 border border-[#fb923c]/40 text-[#fb923c] font-mono text-xs my-1">
  MITRE ATT&CK — T1055 Process Injection & T1056 Input Capture
</div>
<p class="text-white font-semibold mt-2">AI Automated Threat Assessment:</p>
<p class="text-[#a1a1aa] text-xs">Target binary exhibits suspicious self-decryption and memory injection routines. Observed Win32 API sequence: <code>VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread</code> targeting <code>explorer.exe</code>.</p>
<pre class="bg-black/60 p-3 rounded border border-[#27272a] text-[#34d399] font-mono text-xs my-2">
[Score: 88/100 HIGH RISK]
  ├── Heuristic 1: PEB BeingDebugged & RDTSC timing checks present
  ├── Heuristic 2: Hardcoded AES-256 payload in .rsrc section
  └── Recommendation: Run /vuln or install @community/anti-debug-nuke
</pre>`,

  '/decompile 0x140001230': `
<p class="text-white font-semibold">Synthesizing Hex-Rays C/C++ AST for address 0x140001230...</p>
<pre class="bg-black/60 p-3 rounded border border-[#27272a] text-[#38bdf8] font-mono text-xs my-2">
// Decompiled by OpenReverse AI Hex-Rays Engine v2.0
bool __fastcall VerifyLicenseSignature(LicenseContext* ctx) {
    if (!ctx || !ctx->pKeyBuffer) return false;

    // Anti-debug trap detected and annotated by AI:
    if (IsDebuggerPresent()) {
        TerminateProcess(GetCurrentProcess(), 0xDEADCODE);
    }
    return CryptoVerifyRSA(ctx->pKeyBuffer + 0x10);
}
</pre>`,

  '/auto-rename': `
<p class="text-white font-semibold">Running Global AI Symbol & Type Inference across all functions...</p>
<pre class="bg-black/60 p-3 rounded border border-[#27272a] text-[#34d399] font-mono text-xs my-2">
[+] Reconstructed 18 struct definitions from memory offsets.
[+] Renamed symbols:
  ├── sub_140001230()  ➔  VerifyLicenseSignature(LicenseContext* ctx)
  ├── sub_1400038A0()  ➔  DecryptPayloadAES(uint8_t* cipher, size_t len)
  └── var_18           ➔  ctx->pKeyBuffer
</pre>`,

  '/vuln 0x140001230': `
<p class="text-white font-semibold">AI Security Audit Report for 0x140001230:</p>
<pre class="bg-black/60 p-3 rounded border border-[#f87171]/40 text-[#f87171] font-mono text-xs my-2">
[!] CRITICAL VULNERABILITY FOUND — Buffer Overflow in strcpy()
  Line 18: strcpy(local_buf, ctx->untrustedUserString);
  Exploitability: HIGH (No stack canary detected / GS cookie missing).
  Fix Suggestion: Replace with strncpy_s(local_buf, sizeof(local_buf), ...);
</pre>`,

  '/hub': `
<p class="text-white font-semibold">OpenReverse Cloud Developer Community Hub — Available 1-Click Plugins:</p>
<pre class="bg-black/60 p-3 rounded border border-[#27272a] text-[#a1a1aa] font-mono text-xs my-2">
  @community/anti-debug-nuke       [OpenReverse Cloud PRO]    ★ 2.4k installs
  @community/crackme-sandbox-shield [OpenReverse Cloud PRO]    ★ 5.8k installs
  @community/kernel-driver-byovd   [DEV CREATOR] ★ 1.9k installs
  @community/auto-ctf-flag-solver  [OpenReverse Cloud PRO]    ★ 3.1k installs
</pre>
<p class="text-[#fb923c] text-xs font-mono">⚡ Note: Installing plugins requires a Pro Analyst subscription ($29/mo) or above.</p>`,

  '/install @community/crackme-sandbox-shield': `
<p class="text-white font-semibold">Installing @community/crackme-sandbox-shield...</p>
<div class="bg-black/80 p-3 rounded border border-[#fb923c]/60 text-[#fb923c] font-mono text-xs my-2">
[!] OpenReverse Cloud Access Denied: Installing community plugins requires a 'Pro Analyst' ($29/mo) or 'Dev Creator Pro' ($79/mo) subscription.<br/>
[*] Type <code>/login &lt;your-token&gt;</code> in your IDE with your Pro token to unlock OpenReverse Cloud plugins.
</div>`
};

export const InteractiveTerminal: React.FC = () => {
  const [activeSession, setActiveSession] = useState<TabSession>(SESSIONS[0]);
  const [commandInput, setCommandInput] = useState<string>('');
  const [currentCmd, setCurrentCmd] = useState<string>('/triage');
  const [outputHTML, setOutputHTML] = useState<string>(COMMAND_RESPONSES['/triage']);

  const outputRef = useRef<HTMLDivElement>(null);

  const handleRunCommand = (cmdText: string) => {
    const trimmed = cmdText.trim();
    if (!trimmed) return;

    setCurrentCmd(trimmed);
    setOutputHTML(`<p class="text-[#71717a] italic">⚡ Executing <code>${trimmed}</code> in OpenReverse AI-assisted Engine...</p>`);

    setTimeout(() => {
      const response = COMMAND_RESPONSES[trimmed] || `
<p class="text-white font-semibold">AI Reverse Engineering Copilot:</p>
<p class="text-[#a1a1aa] text-xs">Analyzed current binary context for: <em>"${trimmed}"</em>.</p>
<pre class="bg-black/60 p-3 rounded border border-[#27272a] text-[#34d399] font-mono text-xs my-2">
[+] Cross-referenced 12 call sites across main binary and ntdll.dll.
[+] No obfuscation layer detected on this target address.
</pre>`;
      setOutputHTML(response);
    }, 400);
  };

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [outputHTML]);

  return (
    <section id="AI-assisted-shell" className="py-16 px-6 max-w-5xl mx-auto">
      <div className="minimal-card overflow-hidden shadow-2xl shadow-black/80">
        {/* Terminal Window Header */}
        <div className="bg-[#121214] border-b border-[#27272a] px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-[#3f3f46]" />
            <span className="w-3 h-3 rounded-full bg-[#3f3f46]" />
            <span className="w-3 h-3 rounded-full bg-[#3f3f46]" />
          </div>

          <div className="flex items-center gap-1 font-mono text-xs text-[#a1a1aa]">
            <TerminalIcon className="w-3.5 h-3.5" />
            <span>[{activeSession.id}:{activeSession.name}] / openreverse-shell</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono bg-[#34d399]/15 text-[#34d399] border border-[#34d399]/30 px-2 py-0.5 rounded">
              AI CONNECTED
            </span>
          </div>
        </div>

        {/* Sessions Tab Bar */}
        <div className="bg-[#09090b] border-b border-[#27272a] px-4 py-2 flex items-center gap-2 overflow-x-auto">
          <span className="text-xs font-mono text-[#71717a] mr-2">Target:</span>
          {SESSIONS.map((s) => (
            <button
              key={s.id}
              onClick={() => {
                setActiveSession(s);
                handleRunCommand('/triage');
              }}
              className={`text-xs font-mono px-3 py-1 rounded transition-colors ${
                activeSession.id === s.id
                  ? 'bg-[#18181b] text-white border border-[#3f3f46]'
                  : 'text-[#71717a] hover:text-[#a1a1aa]'
              }`}
            >
              {s.name} <span className="opacity-50">({s.arch})</span>
            </button>
          ))}
        </div>

        {/* Quick Slash Command Chips */}
        <div className="bg-[#0e0e11] border-b border-[#27272a] px-4 py-2.5 flex items-center gap-2 overflow-x-auto">
          <span className="text-xs font-mono text-[#71717a] mr-1">Quick Commands:</span>
          {['/triage', '/decompile 0x140001230', '/auto-rename', '/vuln 0x140001230', '/hub', '/install @community/crackme-sandbox-shield'].map((cmd) => (
            <button
              key={cmd}
              onClick={() => {
                setCommandInput(cmd);
                handleRunCommand(cmd);
              }}
              className={`text-xs font-mono px-2.5 py-1 rounded border transition-colors ${
                currentCmd === cmd
                  ? 'bg-white/10 text-white border-white/30'
                  : 'bg-black/40 text-[#a1a1aa] border-[#27272a] hover:border-[#3f3f46]'
              }`}
            >
              {cmd}
            </button>
          ))}
        </div>

        {/* Terminal Content Body */}
        <div
          ref={outputRef}
          className="p-6 min-h-[260px] max-h-[360px] overflow-y-auto font-mono text-sm leading-relaxed"
        >
          <div className="text-[#71717a] text-xs mb-3">
            // Connected to {activeSession.name} ({activeSession.arch}). Ready for slash commands or AI prompts.
          </div>
          <div className="flex items-center gap-2 mb-3">
            <span className="text-[#38bdf8] font-semibold">[{activeSession.id}:{activeSession.name}] &gt;</span>
            <span className="text-white font-bold">{currentCmd}</span>
          </div>
          <div
            className="pl-3 border-l-2 border-[#27272a] text-[#a1a1aa] text-xs"
            dangerouslySetInnerHTML={{ __html: outputHTML }}
          />
        </div>

        {/* Terminal Prompt Input Bar */}
        <div className="bg-[#09090b] border-t border-[#27272a] px-4 py-3 flex items-center gap-3">
          <span className="text-[#38bdf8] font-mono font-bold">❯</span>
          <input
            type="text"
            value={commandInput}
            onChange={(e) => setCommandInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                handleRunCommand(commandInput);
                setCommandInput('');
              }
            }}
            placeholder="Type a slash command (/triage, /decompile, /vuln...) or ask AI anything..."
            className="flex-1 bg-transparent border-none text-white font-mono text-xs outline-none placeholder-[#52525b]"
          />
          <button
            onClick={() => {
              handleRunCommand(commandInput);
              setCommandInput('');
            }}
            className="btn btn-secondary text-xs py-1.5 px-3"
          >
            <span>Run</span>
            <CornerDownLeft className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </section>
  );
};
