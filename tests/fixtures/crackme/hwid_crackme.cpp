#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iterator>

const char* g_c2Url = "http://c2.openreverse-security.local/verify_hwid_license";
const char* g_regPath = "Software\\OpenReverse\\License\\ActivationKey";
const char* g_xorSecret = "OpenReverse_SECRET_XOR_KEY_2026";

enum class FixtureMode : uint32_t
{
    Alpha = 1,
    Omega = 7
};

struct FixturePacket
{
    uint32_t flags;
    FixtureMode mode;
    uint64_t payload;
};

uint64_t __declspec(noinline) ReadFixturePacket(const FixturePacket& packet)
{
    return packet.flags == 0x4F524556 && packet.mode == FixtureMode::Omega
        ? packet.payload : 0;
}

std::string GetMachineHWID()
{
    char computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);

    DWORD volumeSerialNumber = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerialNumber, nullptr, nullptr, nullptr, 0);

    uint32_t hash = 0x539;
    for (size_t i = 0; i < strlen(computerName); ++i)
    {
        hash = ((hash << 5) + hash) ^ computerName[i];
    }
    hash ^= volumeSerialNumber;

    std::ostringstream ss;
    ss << "OpenReverse-" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << hash;
    return ss.str();
}

std::string GenerateExpectedKey(const std::string& hwid)
{
    std::string expected;
    size_t xorLen = strlen(g_xorSecret);
    for (size_t i = 0; i < hwid.length(); ++i)
    {
        char c = hwid[i] ^ g_xorSecret[i % xorLen];
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X", (unsigned char)c);
        expected += hex;
    }
    return expected;
}

void __declspec(noinline) SecretPayload()
{
    std::cout << "\n==========================================================\n";
    std::cout << " [+++] SUCCESS! LICENSE FULLY ACTIVATED [+++]\n";
    std::cout << " [+++] Welcome to the OpenReverse Secret Payload Function [+++]\n";
    std::cout << " [+++] HWID verification passed. Reverse Engineering OK! [+++]\n";
    std::cout << "==========================================================\n\n";
}

bool __declspec(noinline) VerifyLicenseKey(const std::string& userKey, const std::string& expectedKey)
{
    if (userKey.length() != expectedKey.length())
    {
        return false;
    }

    for (size_t i = 0; i < userKey.length(); ++i)
    {
        if (userKey[i] != expectedKey[i])
        {
            return false;
        }
    }

    return true;
}

int main(int argc, char** argv)
{
    const FixturePacket packet{0x4F524556, FixtureMode::Omega, 0x1020304050607080ULL};
    volatile uint64_t fixtureTypeAnchor = ReadFixturePacket(packet);
    (void)fixtureTypeAnchor;
    wchar_t sentinelPath[32768]{};
    const DWORD sentinelLength = GetEnvironmentVariableW(
        L"OPENREVERSE_EXECUTION_SENTINEL", sentinelPath,
        static_cast<DWORD>(std::size(sentinelPath)));
    if (sentinelLength > 0 && sentinelLength < std::size(sentinelPath))
    {
        HANDLE sentinel = CreateFileW(sentinelPath, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (sentinel != INVALID_HANDLE_VALUE)
        {
            constexpr char marker[] = "fixture executed";
            DWORD written = 0;
            (void)WriteFile(sentinel, marker, static_cast<DWORD>(sizeof(marker) - 1),
                            &written, nullptr);
            CloseHandle(sentinel);
        }
    }

    SetConsoleTitleA("OpenReverse Target: HWID & License Key CrackMe (x64)");

    std::cout << "==========================================================\n";
    std::cout << "       OpenReverse TARGET: HWID & LICENSE KEY CRACKME (x64)      \n";
    std::cout << "==========================================================\n";
    std::cout << "[+] Connecting to C2: " << g_c2Url << "\n";
    std::cout << "[+] Checking Registry: " << g_regPath << "\n\n";

    std::string hwid = GetMachineHWID();
    std::string expectedKey = GenerateExpectedKey(hwid);

    std::cout << "[*] Detected Machine HWID: " << hwid << "\n";
    std::cout << "[?] To activate, reverse this executable using OpenReverse\n";
    std::cout << "    or attach OpenReverse to PID: " << GetCurrentProcessId() << "\n\n";

    for (int i = 1; i < argc; ++i)
    {
        if (std::string(argv[i]) == "--daemon")
        {
            std::cout << "[*] Running in daemon mode for automated OpenReverse analysis...\n";
            while (true)
            {
                Sleep(1000);
            }
            return 0;
        }
    }

    while (true)
    {
        std::cout << "Enter License Key (or type 'exit' to quit): ";
        std::string inputKey;
        if (!std::getline(std::cin, inputKey) || inputKey == "exit")
        {
            break;
        }

        if (inputKey.empty())
            continue;

        if (VerifyLicenseKey(inputKey, expectedKey))
        {
            SecretPayload();
            break;
        }
        else
        {
            std::cout << " [-] ACCESS DENIED! Invalid License Key for HWID: " << hwid << "\n\n";
        }
    }

    std::cout << "\nPress ENTER to close...\n";
    std::cin.get();
    return 0;
}
