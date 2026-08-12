#pragma once
// OpenReverse - Utils: Helpers
// Formatting and conversion utilities

#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <cstdio>
#include <windows.h>

namespace openreverse {
namespace helpers {

// Format address as hex string (e.g. "0x00007FF612340000")
inline std::string FormatAddress(uint64_t address, bool is64bit = true)
{
    char buf[32];
    if (is64bit)
        snprintf(buf, sizeof(buf), "0x%016llX", (unsigned long long)address);
    else
        snprintf(buf, sizeof(buf), "0x%08X", (unsigned int)address);
    return buf;
}

// Format as "ModuleName+0xOFFSET" for pasters/cheat tables (offset from module base)
inline std::string FormatModuleOffset(const std::string& moduleName, uint64_t moduleBase, uint64_t address, bool is64bit = true)
{
    if (moduleName.empty()) return FormatAddress(address, is64bit);
    uint64_t offset = (address >= moduleBase) ? (address - moduleBase) : 0;
    char buf[128];
    if (is64bit)
        snprintf(buf, sizeof(buf), "%s+0x%llX", moduleName.c_str(), (unsigned long long)offset);
    else
        snprintf(buf, sizeof(buf), "%s+0x%X", moduleName.c_str(), (unsigned int)offset);
    return buf;
}

// Format size as human-readable (e.g. "4.00 KB", "16.00 MB")
inline std::string FormatSize(uint64_t size)
{
    char buf[64];
    if (size >= 1024ULL * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.2f GB", size / (1024.0 * 1024.0 * 1024.0));
    else if (size >= 1024ULL * 1024)
        snprintf(buf, sizeof(buf), "%.2f MB", size / (1024.0 * 1024.0));
    else if (size >= 1024ULL)
        snprintf(buf, sizeof(buf), "%.2f KB", size / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)size);
    return buf;
}

// Convert bytes to hex string (e.g. "48 8B 05 ...")
inline std::string BytesToHex(const uint8_t* data, size_t size, const char* sep = " ")
{
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i)
    {
        if (i > 0) oss << sep;
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return oss.str();
}

// Convert bytes to C array string
inline std::string BytesToCArray(const uint8_t* data, size_t size)
{
    std::ostringstream oss;
    oss << "{ ";
    for (size_t i = 0; i < size; ++i)
    {
        if (i > 0) oss << ", ";
        oss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    oss << " }";
    return oss.str();
}

// Parse hex string to uint64_t address
inline std::optional<uint64_t> TryParseAddress(const std::string& str)
{
    if (str.empty()) return std::nullopt;
    std::string s = str;

    // Trim whitespace
    while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
    while (!s.empty() && isspace((unsigned char)s.back())) s.pop_back();
    if (s.empty()) return std::nullopt;

    bool hasHexPrefix = false;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        hasHexPrefix = true;
        s = s.substr(2);
    }

    // Check if string contains only hex digits (0-9, a-f, A-F)
    for (char c : s)
    {
        if (!isxdigit((unsigned char)c))
            return std::nullopt;
    }

    // If it's a short token without 0x prefix and contains only ASCII letters (e.g. "OpenReverse", "exit"), don't treat as hex address unless prefixed
    if (!hasHexPrefix && s.size() <= 4)
    {
        bool allLetters = true;
        for (char c : s)
        {
            if (!isalpha((unsigned char)c))
            {
                allLetters = false;
                break;
            }
        }
        if (allLetters) return std::nullopt;
    }

    uint64_t addr = 0;
    std::istringstream iss(s);
    iss >> std::hex >> addr;
    if (iss.fail() || !iss.eof()) return std::nullopt;
    return addr;
}

inline std::optional<uint64_t> TryParseAddress(const char* str)
{
    return str ? TryParseAddress(std::string(str)) : std::nullopt;
}

inline uint64_t ParseAddress(const std::string& str)
{
    return TryParseAddress(str).value_or(0);
}

inline uint64_t ParseAddress(const char* str)
{
    return str ? ParseAddress(std::string(str)) : 0;
}

// Check if a character is printable ASCII
inline char PrintableChar(uint8_t c)
{
    return (c >= 32 && c <= 126) ? (char)c : '.';
}

// String to lowercase
inline std::string ToLower(const std::string& s)
{
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

// Get memory protection flags as string
inline std::string ProtectionToString(DWORD protect)
{
    std::string result;
    switch (protect & 0xFF)
    {
        case PAGE_NOACCESS:          result = "---"; break;
        case PAGE_READONLY:          result = "R--"; break;
        case PAGE_READWRITE:         result = "RW-"; break;
        case PAGE_WRITECOPY:         result = "RWC"; break;
        case PAGE_EXECUTE:           result = "--X"; break;
        case PAGE_EXECUTE_READ:      result = "R-X"; break;
        case PAGE_EXECUTE_READWRITE: result = "RWX"; break;
        case PAGE_EXECUTE_WRITECOPY: result = "RWXC"; break;
        default:                     result = "???"; break;
    }
    if (protect & PAGE_GUARD)   result += " +G";
    if (protect & PAGE_NOCACHE) result += " +NC";
    return result;
}

// Get memory state as string
inline std::string StateToString(DWORD state)
{
    switch (state)
    {
        case MEM_COMMIT:  return "Commit";
        case MEM_RESERVE: return "Reserve";
        case MEM_FREE:    return "Free";
        default:          return "Unknown";
    }
}

// Get memory type as string
inline std::string TypeToString(DWORD type)
{
    switch (type)
    {
        case MEM_IMAGE:   return "Image";
        case MEM_MAPPED:  return "Mapped";
        case MEM_PRIVATE: return "Private";
        default:          return "Unknown";
    }
}

// Open native "Save As" dialog. Returns true if user chose a file, path written to outPath.
bool OpenSaveFileDialog(char* outPath, int outPathSize, const char* defaultName = "dump.bin");

} // namespace helpers
} // namespace openreverse
