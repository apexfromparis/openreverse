#include "reverse_skills.h"

namespace kyv::ai {

ReverseSkillRegistry::ReverseSkillRegistry()
    : skills_{
        {"disasm", "Disassembly analyst", "Explains instructions, operands, calling conventions and control flow.",
            "Act as a senior x86/x64 reverse engineer. Explain instructions precisely, preserve addresses, and distinguish observed facts from hypotheses."},
        {"pe-audit", "PE security audit", "Reviews PE headers, imports, sections, permissions and suspicious indicators.",
            "Audit Windows PE structures defensively. Highlight malformed headers, dangerous imports, executable writable sections and suspicious behavior. Do not invent fields that are not present."},
        {"memory-map", "Memory map investigator", "Interprets mapped regions, protections, modules and pointer relationships.",
            "Analyze memory maps defensively. Explain region permissions and pointer relationships, and call out uncertainty. Never suggest modifying a live process."},
        {"pattern-hunter", "Pattern hunter", "Finds byte patterns, strings, cross-references and likely function boundaries.",
            "Search the supplied bytes and symbols for defensible patterns. Return exact offsets and a confidence level. Do not fabricate matches."},
        {"decompiler", "C pseudocode reviewer", "Produces cautious pseudocode and names assumptions explicitly.",
            "Produce readable C-like pseudocode from the supplied disassembly only. Preserve unknown behavior as comments and flag calling-convention or type uncertainty."},
        {"vuln-review", "Vulnerability reviewer", "Reviews a function for memory-safety and dangerous API usage.",
            "Perform a defensive vulnerability review. Focus on bounds, integer overflow, lifetime, format strings, dangerous parsing and trust boundaries. Give evidence and severity."},
        {"anti-debug", "Anti-Debugging & VM Detection Analyst", "Analyzes code and imports for anti-debugging checks, timing traps, and VM detection.",
            "Identify anti-debugging and anti-VM techniques defensively. Check for PEB BeingDebugged flags, NtQueryInformationProcess, RDTSC timing deltas, exception handler tricks, and hypervisor signatures."},
        {"crypto-ident", "Cryptographic Algorithm Identifier", "Identifies crypto algorithms, S-Boxes, hash constants, and custom encryption loops.",
            "Identify cryptographic primitives from constants and instructions. Look for AES S-Boxes, SHA256 K-tables, CRC32 polynomials, RC4 KSA/PRGA loops, and custom XOR obfuscation schemes."},
        {"shellcode-analyst", "Shellcode & Process Injection Investigator", "Examines position-independent code, unbacked RWX regions, and API hashing.",
            "Analyze shellcode and process injection techniques. Examine PIC GetEIP prologues, PEB Ldr module walking, ROR13/CRC32 dynamic API hashing, and unbacked executable private pages."},
        {"c2-protocol", "C2 Protocol & Network Structure Reviewer", "Inspects network communications, socket buffers, URL patterns, and command dispatchers.",
            "Examine network-related disassembly and strings. Detail WinINet/WinHTTP/Winsock API usage, C2 packet serialization, beacon sleep intervals, and command dispatch tables."},
        {"unpack-assistant", "PE Unpacker & Import Reconstruction Guide", "Analyzes high-entropy packers, OEP tail jumps, and IAT reconstruction heuristics.",
            "Guide PE unpacking and import table reconstruction. Identify Original Entry Point (OEP) tail jumps, pushad/popad stubs, high-entropy section transitions, and broken IAT thunks."},
        {"win32-api", "Windows API & COM Interface Expert", "Explains Win32/NTDLL API semantics, handle lifecycles, and COM/RPC structures.",
            "Explain Win32 and native NTDLL system calls in depth. Detail parameter types, calling conventions (x64 fastcall, stdcall), return codes, handle lifecycles, and COM/RPC interfaces."}
    }
{}

const ReverseSkill* ReverseSkillRegistry::Find(const std::string& id) const
{
    for (const auto& skill : skills_)
        if (skill.id == id)
            return &skill;
    return nullptr;
}

} // namespace kyv::ai
