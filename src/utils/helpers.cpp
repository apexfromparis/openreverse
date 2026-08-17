#include "helpers.h"
#include <commdlg.h>
#include <cstring>
#include <cwchar>
#include <limits>

namespace openreverse {
namespace helpers {

std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty() || value.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
        return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), length) == length ? result : std::wstring{};
}

std::string WideToUtf8(const wchar_t* value)
{
    if (!value || !*value) return {};
    const size_t size = std::wcslen(value);
    if (size > static_cast<size_t>((std::numeric_limits<int>::max)())) return {};
    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(size), nullptr, 0, nullptr, nullptr);
    if (length <= 0) return {};
    std::string result(static_cast<size_t>(length), '\0');
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(size), result.data(), length, nullptr, nullptr) == length
        ? result : std::string{};
}

bool OpenSaveFileDialog(std::string& outPath, const char* defaultName)
{
    outPath.clear();
    std::vector<wchar_t> buffer(32768, L'\0');
    if (defaultName && defaultName[0])
    {
        const std::wstring wideDefault = Utf8ToWide(defaultName);
        if (wideDefault.empty()) return false;
        wcsncpy_s(buffer.data(), buffer.size(), wideDefault.c_str(), _TRUNCATE);
    }
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = L"Binary (*.bin)\0*.bin\0All (*.*)\0*.*\0";
    ofn.lpstrFile = buffer.data();
    ofn.nMaxFile = static_cast<DWORD>(buffer.size());
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
    ofn.lpstrDefExt = L"bin";

    if (!GetSaveFileNameW(&ofn)) return false;
    outPath = WideToUtf8(buffer.data());
    return !outPath.empty();
}

} // namespace helpers
} // namespace openreverse
