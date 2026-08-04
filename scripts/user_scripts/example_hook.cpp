// OpenReverse Studio v2.0 - Automated Hook & Memory Injection Script
#include <windows.h>
#include "api/openreverse_api.h"

void OnModuleLoaded(const char* moduleName, uint64_t baseAddress) {
    OpenReverse::Log("[+] Intercepted module load: %s at 0x%llX", moduleName, baseAddress);
    // Example NOP patch on security check:
    OpenReverse::PatchBytes(baseAddress + 0x1042, "\x90\x90\x90", 3);
}
