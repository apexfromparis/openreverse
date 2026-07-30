// ============================================================================
// KYV - Utils: Helpers
// ============================================================================
#include "helpers.h"
#include <commdlg.h>
#include <cstring>

namespace kyv {
namespace helpers {

bool OpenSaveFileDialog(char* outPath, int outPathSize, const char* defaultName)
{
    if (!outPath || outPathSize <= 0) return false;
    outPath[0] = '\0';
    char buf[1024];
    buf[0] = '\0';
    if (defaultName && defaultName[0])
        strncpy_s(buf, defaultName, _TRUNCATE);    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = "Binary (*.bin)\0*.bin\0All (*.*)\0*.*\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = sizeof(buf);
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = "bin";

    if (!GetSaveFileNameA(&ofn))
        return false;
    strncpy_s(outPath, (size_t)outPathSize, buf, _TRUNCATE);
    return true;
}

} // namespace helpers
} // namespace kyv
