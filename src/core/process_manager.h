#pragma once
// OpenReverse - Core: Process Manager
// Enumerate, open, close Windows processes

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>

namespace openreverse {

struct ProcessInfo {
    DWORD       pid;
    std::string name;
    std::string path;
    bool        is64bit;
    size_t      memoryUsage; // in bytes
};

class ProcessManager {
public:
    // List all running processes
    std::vector<ProcessInfo> ListProcesses();

    // Open a process for reading
    HANDLE OpenProcess(DWORD pid);

    // Close a process handle
    void CloseProcess(HANDLE handle);

    // Check if process is 64-bit
    bool IsProcess64Bit(HANDLE handle);
};

} // namespace openreverse
