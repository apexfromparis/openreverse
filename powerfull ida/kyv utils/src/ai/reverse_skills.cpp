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
            "Perform a defensive vulnerability review. Focus on bounds, integer overflow, lifetime, format strings, dangerous parsing and trust boundaries. Give evidence and severity."}
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
