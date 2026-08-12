#pragma once

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>

namespace openreverse {

std::string ProcessOpenFailureMessage(DWORD error);

struct ProcessInfo {
    DWORD       pid;
    std::string name;
    std::string path;
    bool        is64bit;
    size_t      memoryUsage;
};

class ProcessManager {
public:
    std::vector<ProcessInfo> ListProcesses();

    HANDLE OpenProcess(DWORD pid);

    void CloseProcess(HANDLE handle);

    bool IsProcess64Bit(HANDLE handle);
};

} // namespace openreverse
