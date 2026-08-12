#include "string_scanner.h"
#include <algorithm>

namespace openreverse {

bool StringScanner::IsPrintableAscii(uint8_t c)
{
    return c >= 32 && c <= 126;
}

void StringScanner::ScanAsciiStrings(const uint8_t* data, size_t dataSize, uint64_t baseAddr,
                                      size_t minLength, std::vector<StringResult>& results, size_t maxResults)
{
    size_t start = 0;
    bool inString = false;

    for (size_t i = 0; i <= dataSize && results.size() < maxResults; ++i)
    {
        bool printable = (i < dataSize) && IsPrintableAscii(data[i]);

        if (printable && !inString)
        {
            start = i;
            inString = true;
        }
        else if (!printable && inString)
        {
            size_t len = i - start;
            if (len >= minLength)
            {
                StringResult sr;
                sr.address = baseAddr + start;
                sr.value = std::string((char*)data + start, len);
                sr.encoding = StringEncoding::ASCII;
                sr.length = len;
                ClassifyString(sr);
                results.push_back(sr);
            }
            inString = false;
        }
    }
}

void StringScanner::ScanUnicodeStrings(const uint8_t* data, size_t dataSize, uint64_t baseAddr,
                                        size_t minLength, std::vector<StringResult>& results, size_t maxResults)
{
    size_t start = 0;
    bool inString = false;

    for (size_t i = 0; i + 1 <= dataSize && results.size() < maxResults; i += 2)
    {
        bool printable = (i + 1 < dataSize) && IsPrintableAscii(data[i]) && data[i + 1] == 0;

        if (printable && !inString)
        {
            start = i;
            inString = true;
        }
        else if (!printable && inString)
        {
            size_t charCount = (i - start) / 2;
            if (charCount >= minLength)
            {
                StringResult sr;
                sr.address = baseAddr + start;
                sr.encoding = StringEncoding::Unicode;
                sr.length = charCount;

                // Convert to narrow string for display
                sr.value.reserve(charCount);
                for (size_t j = start; j < i; j += 2)
                    sr.value += (char)data[j];

                ClassifyString(sr);
                results.push_back(sr);
            }
            inString = false;
        }
    }
}

std::vector<StringResult> StringScanner::Scan(HANDLE processHandle,
                                                uint64_t startAddress, uint64_t endAddress,
                                                size_t minLength,
                                                bool scanAscii, bool scanUnicode,
                                                size_t maxResults)
{
    std::vector<StringResult> results;
    progress_ = 0.0f;

    const size_t chunkSize = 256 * 1024; // 256KB chunks
    std::vector<uint8_t> buffer(chunkSize);
    uint64_t totalRange = endAddress - startAddress;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t addr = startAddress;

    while (addr < endAddress && results.size() < maxResults)
    {
        if (!VirtualQueryEx(processHandle, (LPCVOID)addr, &mbi, sizeof(mbi)))
            break;

        uint64_t regionEnd = (uint64_t)mbi.BaseAddress + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            mbi.Protect != PAGE_NOACCESS)
        {
            uint64_t scanAddr = (std::max)(addr, (uint64_t)mbi.BaseAddress);
            while (scanAddr < regionEnd && results.size() < maxResults)
            {
                size_t toRead = (size_t)(std::min)((uint64_t)chunkSize, regionEnd - scanAddr);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(processHandle, (LPCVOID)scanAddr, buffer.data(), toRead, &bytesRead))
                {
                    if (scanAscii)
                        ScanAsciiStrings(buffer.data(), bytesRead, scanAddr, minLength, results, maxResults);
                    if (scanUnicode)
                        ScanUnicodeStrings(buffer.data(), bytesRead, scanAddr, minLength, results, maxResults);
                }

                scanAddr += toRead;
            }
        }

        addr = regionEnd;
        if (totalRange > 0)
            progress_ = (float)(addr - startAddress) / (float)totalRange;
    }

    progress_ = 1.0f;
    return results;
}

void StringScanner::ClassifyString(StringResult& sr)
{
    const std::string& val = sr.value;
    if (val.size() < 3)
    {
        sr.category = "General";
        sr.riskLevel = 0;
        return;
    }

    if (val.find("http://") != std::string::npos || val.find("https://") != std::string::npos ||
        val.find(".com/") != std::string::npos || val.find(".net/") != std::string::npos ||
        val.find(".org/") != std::string::npos || val.find("127.0.0.1") != std::string::npos)
    {
        sr.category = "URL";
        sr.riskLevel = 1;
    }
    else if (val.find("cmd.exe") != std::string::npos || val.find("powershell") != std::string::npos ||
             val.find("CreateProcess") != std::string::npos || val.find("VirtualAlloc") != std::string::npos ||
             val.find("WriteProcessMemory") != std::string::npos || val.find("CreateRemoteThread") != std::string::npos)
    {
        sr.category = "Process / Memory API";
        sr.riskLevel = 1;
    }
    else if (val.find("HKEY_") != std::string::npos || val.find("Software\\") != std::string::npos ||
             val.find("CurrentControlSet") != std::string::npos || val.find("RegOpenKey") != std::string::npos)
    {
        sr.category = "Registry Path";
        sr.riskLevel = 1;
    }
    else if (val.find("-----BEGIN") != std::string::npos || val.find("RSA") != std::string::npos ||
             val.find("AES") != std::string::npos || val.find("SHA256") != std::string::npos)
    {
        sr.category = "Crypto Related";
        sr.riskLevel = 1;
    }
    else if (val.find("C:\\") != std::string::npos || val.find("D:\\") != std::string::npos ||
             val.find("\\Windows\\") != std::string::npos || val.find("\\System32\\") != std::string::npos ||
             val.find(".dll") != std::string::npos || val.find(".exe") != std::string::npos || val.find(".sys") != std::string::npos)
    {
        sr.category = "Path";
        sr.riskLevel = 1;
    }
    else
    {
        sr.category = "General";
        sr.riskLevel = 0;
    }
}

std::vector<StringResult> StringScanner::ScanBuffer(const uint8_t* data, size_t dataSize, uint64_t baseAddr,
                                                    size_t minLength, bool scanAscii, bool scanUnicode, size_t maxResults)
{
    std::vector<StringResult> results;
    if (!data || dataSize == 0)
        return results;

    progress_ = 0.0f;
    if (scanAscii)
        ScanAsciiStrings(data, dataSize, baseAddr, minLength, results, maxResults);
    if (scanUnicode && results.size() < maxResults)
        ScanUnicodeStrings(data, dataSize, baseAddr, minLength, results, maxResults);

    progress_ = 1.0f;
    return results;
}

} // namespace openreverse
