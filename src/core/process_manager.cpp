#include "process_manager.h"

namespace openreverse {

std::string ProcessOpenFailureMessage(DWORD error)
{
    if (error == ERROR_ACCESS_DENIED)
        return "Access to the target process was denied by Windows or another protection mechanism. "
               "Open the binary from disk, analyze a user-provided dump, or open a saved OpenReverse project.";
    if (error == ERROR_INVALID_PARAMETER)
        return "The target process does not exist or has already exited.";
    return "Windows could not open the target process for read-only analysis (error " +
        std::to_string(error) + ").";
}

std::vector<ProcessInfo> ProcessManager::ListProcesses()
{
    std::vector<ProcessInfo> result;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return result;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;

            char name[MAX_PATH];
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, MAX_PATH, nullptr, nullptr);
            info.name = name;
            info.is64bit = false;
            info.memoryUsage = 0;
            info.path.clear();

            HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
            if (hProc)
            {
                wchar_t pathBuf[MAX_PATH];
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, pathBuf, &pathSize))
                {
                    char pathNarrow[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, pathNarrow, MAX_PATH, nullptr, nullptr);
                    info.path = pathNarrow;
                }

                BOOL isWow64 = FALSE;
                if (IsWow64Process(hProc, &isWow64))
                {
                    info.is64bit = !isWow64;
                }

                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                {
                    info.memoryUsage = pmc.WorkingSetSize;
                }

                ::CloseHandle(hProc);
            }

            result.push_back(info);
        }
        while (Process32NextW(snapshot, &pe));
    }

    ::CloseHandle(snapshot);
    return result;
}

HANDLE ProcessManager::OpenProcess(DWORD pid)
{
    return ::OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
}

void ProcessManager::CloseProcess(HANDLE handle)
{
    if (handle && handle != INVALID_HANDLE_VALUE)
        ::CloseHandle(handle);
}

bool ProcessManager::IsProcess64Bit(HANDLE handle)
{
    BOOL isWow64 = FALSE;
    if (IsWow64Process(handle, &isWow64))
        return !isWow64;
    return true; // assume 64-bit if can't determine
}

} // namespace openreverse
