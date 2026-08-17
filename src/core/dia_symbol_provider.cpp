#include "core/dia_symbol_provider.h"
#include "core/offset_model.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <limits>
#include <sstream>
#include <vector>
#include <windows.h>

#ifndef OPENREVERSE_HAS_DIA
#define OPENREVERSE_HAS_DIA 0
#endif

#if OPENREVERSE_HAS_DIA
#include <dia2.h>
#include <oleauto.h>
#endif

namespace openreverse {

namespace {

std::wstring Utf8ToWide(const std::string& value)
{
    if (value.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           value.data(), static_cast<int>(value.size()),
                                           nullptr, 0);
    if (length <= 0) return {};
    std::wstring result(static_cast<size_t>(length), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            value.data(), static_cast<int>(value.size()),
                            result.data(), length) != length)
        return {};
    return result;
}

std::string WideToUtf8(const wchar_t* value, size_t length)
{
    if (!value || length == 0) return {};
    const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(length), result.data(), required, nullptr, nullptr) != required)
        return {};
    return result;
}

std::string FormatGuid(const GUID& guid)
{
    char buffer[37]{};
    std::snprintf(buffer, sizeof(buffer),
        "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        static_cast<unsigned long>(guid.Data1), guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buffer;
}

std::string NormalizeGuid(std::string value)
{
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) {
        return c == '{' || c == '}' || c == '-';
    }), value.end());
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

#if OPENREVERSE_HAS_DIA

template<typename T>
void ReleaseInterface(T*& value)
{
    if (value)
    {
        value->Release();
        value = nullptr;
    }
}

std::string BstrToUtf8(BSTR value)
{
    return value ? WideToUtf8(value, SysStringLen(value)) : std::string{};
}

std::string SymbolName(IDiaSymbol* symbol)
{
    BSTR value = nullptr;
    if (!symbol || FAILED(symbol->get_name(&value)) || !value)
        return {};
    std::string result = BstrToUtf8(value);
    SysFreeString(value);
    return result;
}

std::string HResultText(const char* operation, HRESULT result)
{
    std::ostringstream message;
    message << operation << " failed (HRESULT 0x" << std::hex << std::uppercase
            << static_cast<unsigned long>(result) << ')';
    return message.str();
}

#endif

} // namespace

struct DiaSymbolProvider::Impl {
    std::vector<SymbolRecord> symbols;
    std::vector<SymbolTypeRecord> types;
    SymbolProviderIdentity identity;
    std::string lastError;
#if OPENREVERSE_HAS_DIA
    IDiaDataSource* source = nullptr;
    IDiaSession* session = nullptr;
    IDiaSymbol* global = nullptr;
    HMODULE diaModule = nullptr;
    bool ownsComInitialization = false;

    void ResetCom()
    {
        ReleaseInterface(global);
        ReleaseInterface(session);
        ReleaseInterface(source);
        if (diaModule)
        {
            FreeLibrary(diaModule);
            diaModule = nullptr;
        }
        if (ownsComInitialization)
        {
            CoUninitialize();
            ownsComInitialization = false;
        }
    }
#endif

    ~Impl()
    {
#if OPENREVERSE_HAS_DIA
        ResetCom();
#endif
    }
};

DiaSymbolProvider::DiaSymbolProvider() : impl_(std::make_unique<Impl>()) {}
DiaSymbolProvider::~DiaSymbolProvider() = default;

bool DiaSymbolProvider::IsAvailable()
{
    return OPENREVERSE_HAS_DIA != 0;
}

bool DiaSymbolProvider::Load(const std::string& modulePath, const ModuleIdentity& expectedIdentity)
{
    impl_->symbols.clear();
    impl_->types.clear();
    impl_->identity = {};
    impl_->lastError.clear();
#if !OPENREVERSE_HAS_DIA
    (void)modulePath;
    (void)expectedIdentity;
    impl_->lastError = "This build was configured without the Microsoft DIA SDK";
    return false;
#else
    impl_->ResetCom();
    if (modulePath.empty())
    {
        impl_->lastError = "DIA requires a module or PDB path";
        return false;
    }
    const std::wstring widePath = Utf8ToWide(modulePath);
    if (widePath.empty())
    {
        impl_->lastError = "DIA module path is not valid UTF-8";
        return false;
    }

    const HRESULT comResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(comResult) && comResult != RPC_E_CHANGED_MODE)
    {
        impl_->lastError = HResultText("COM initialization", comResult);
        return false;
    }
    impl_->ownsComInitialization = comResult == S_OK || comResult == S_FALSE;

    HRESULT result = CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_IDiaDataSource,
                                      reinterpret_cast<void**>(&impl_->source));
    if (result == REGDB_E_CLASSNOTREG)
    {
        impl_->diaModule = LoadLibraryExW(L"msdia140.dll", nullptr,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (impl_->diaModule)
        {
            using DllGetClassObjectFunction = HRESULT(WINAPI*)(REFCLSID, REFIID, void**);
            const auto getClassObject = reinterpret_cast<DllGetClassObjectFunction>(
                GetProcAddress(impl_->diaModule, "DllGetClassObject"));
            IClassFactory* factory = nullptr;
            if (getClassObject && SUCCEEDED(getClassObject(
                    CLSID_DiaSource, IID_IClassFactory,
                    reinterpret_cast<void**>(&factory))) && factory)
            {
                result = factory->CreateInstance(nullptr, IID_IDiaDataSource,
                    reinterpret_cast<void**>(&impl_->source));
                factory->Release();
            }
        }
    }
    if (FAILED(result) || !impl_->source)
    {
        impl_->lastError = HResultText("DIA source creation", result);
        return false;
    }

    const bool pdbPath = modulePath.size() >= 4 &&
        _stricmp(modulePath.c_str() + modulePath.size() - 4, ".pdb") == 0;
    result = pdbPath
        ? impl_->source->loadDataFromPdb(widePath.c_str())
        : impl_->source->loadDataForExe(widePath.c_str(), nullptr, nullptr);
    if (FAILED(result))
    {
        impl_->lastError = HResultText(pdbPath ? "DIA PDB load" : "DIA executable/PDB association", result);
        return false;
    }
    if (FAILED(result = impl_->source->openSession(&impl_->session)) || !impl_->session ||
        FAILED(result = impl_->session->get_globalScope(&impl_->global)) || !impl_->global)
    {
        impl_->lastError = HResultText("DIA session open", result);
        return false;
    }

    GUID guid{};
    DWORD age = 0;
    if (SUCCEEDED(impl_->global->get_guid(&guid))) impl_->identity.guid = FormatGuid(guid);
    if (SUCCEEDED(impl_->global->get_age(&age))) impl_->identity.age = age;
    BSTR symbolFile = nullptr;
    if (SUCCEEDED(impl_->global->get_symbolsFileName(&symbolFile)) && symbolFile)
    {
        impl_->identity.pdbPath = BstrToUtf8(symbolFile);
        SysFreeString(symbolFile);
    }
    if (!expectedIdentity.pdbGuid.empty() &&
        NormalizeGuid(expectedIdentity.pdbGuid) != NormalizeGuid(impl_->identity.guid))
    {
        impl_->lastError = "DIA rejected a PDB whose GUID does not match the PE CodeView record";
        return false;
    }
    if (expectedIdentity.pdbAge != 0 && expectedIdentity.pdbAge != impl_->identity.age)
    {
        impl_->lastError = "DIA rejected a PDB whose age does not match the PE CodeView record";
        return false;
    }
    impl_->identity.executableAssociationValidated = !pdbPath;

    const auto enumerateSymbols = [&](enum SymTagEnum tag, SymbolKind kind, size_t maximum) {
        IDiaEnumSymbols* enumeration = nullptr;
        if (FAILED(impl_->global->findChildren(tag, nullptr, nsNone, &enumeration)) || !enumeration)
            return;
        ULONG fetched = 0;
        IDiaSymbol* symbol = nullptr;
        while (impl_->symbols.size() < maximum &&
               enumeration->Next(1, &symbol, &fetched) == S_OK && fetched == 1)
        {
            DWORD rva = 0;
            ULONGLONG length = 0;
            const std::string name = SymbolName(symbol);
            if (!name.empty() && SUCCEEDED(symbol->get_relativeVirtualAddress(&rva)))
            {
                (void)symbol->get_length(&length);
                impl_->symbols.push_back({kind, name, rva, length,
                                          SymbolProvenance::ProgramDatabase});
            }
            ReleaseInterface(symbol);
        }
        ReleaseInterface(symbol);
        ReleaseInterface(enumeration);
    };
    enumerateSymbols(SymTagFunction, SymbolKind::Function, 500000);
    enumerateSymbols(SymTagPublicSymbol, SymbolKind::Public, 750000);
    enumerateSymbols(SymTagData, SymbolKind::Data, 1000000);

    IDiaEnumSymbols* userTypes = nullptr;
    if (SUCCEEDED(impl_->global->findChildren(SymTagUDT, nullptr, nsNone, &userTypes)) && userTypes)
    {
        ULONG fetched = 0;
        IDiaSymbol* type = nullptr;
        while (impl_->types.size() < 100000 &&
               userTypes->Next(1, &type, &fetched) == S_OK && fetched == 1)
        {
            SymbolTypeRecord record;
            record.name = SymbolName(type);
            ULONGLONG length = 0;
            (void)type->get_length(&length);
            record.size = length;
            DWORD udtKind = UdtStruct;
            if (SUCCEEDED(type->get_udtKind(&udtKind)))
                record.kind = udtKind == UdtClass ? SymbolTypeKind::Class :
                    udtKind == UdtUnion ? SymbolTypeKind::Union : SymbolTypeKind::Structure;

            IDiaEnumSymbols* members = nullptr;
            if (SUCCEEDED(type->findChildren(SymTagData, nullptr, nsNone, &members)) && members)
            {
                ULONG memberFetched = 0;
                IDiaSymbol* member = nullptr;
                while (record.fields.size() < 10000 &&
                       members->Next(1, &member, &memberFetched) == S_OK && memberFetched == 1)
                {
                    DWORD dataKind = DataIsUnknown;
                    LONG offset = 0;
                    if (SUCCEEDED(member->get_dataKind(&dataKind)) && dataKind == DataIsMember &&
                        SUCCEEDED(member->get_offset(&offset)))
                    {
                        SymbolFieldRecord field;
                        field.name = SymbolName(member);
                        field.offset = offset;
                        IDiaSymbol* fieldType = nullptr;
                        if (SUCCEEDED(member->get_type(&fieldType)) && fieldType)
                        {
                            field.typeName = SymbolName(fieldType);
                            ULONGLONG fieldLength = 0;
                            if (SUCCEEDED(fieldType->get_length(&fieldLength))) field.size = fieldLength;
                            ReleaseInterface(fieldType);
                        }
                        if (!field.name.empty()) record.fields.push_back(std::move(field));
                    }
                    ReleaseInterface(member);
                }
                ReleaseInterface(member);
                ReleaseInterface(members);
            }
            if (!record.name.empty()) impl_->types.push_back(std::move(record));
            ReleaseInterface(type);
        }
        ReleaseInterface(type);
        ReleaseInterface(userTypes);
    }

    IDiaEnumSymbols* enums = nullptr;
    if (SUCCEEDED(impl_->global->findChildren(SymTagEnum, nullptr, nsNone, &enums)) && enums)
    {
        ULONG fetched = 0;
        IDiaSymbol* type = nullptr;
        while (impl_->types.size() < 100000 &&
               enums->Next(1, &type, &fetched) == S_OK && fetched == 1)
        {
            SymbolTypeRecord record;
            record.name = SymbolName(type);
            record.kind = SymbolTypeKind::Enum;
            ULONGLONG length = 0;
            (void)type->get_length(&length);
            record.size = length;
            IDiaEnumSymbols* values = nullptr;
            if (SUCCEEDED(type->findChildren(SymTagData, nullptr, nsNone, &values)) && values)
            {
                ULONG valueFetched = 0;
                IDiaSymbol* value = nullptr;
                while (record.enumValues.size() < 10000 &&
                       values->Next(1, &value, &valueFetched) == S_OK && valueFetched == 1)
                {
                    VARIANT variant;
                    VariantInit(&variant);
                    VARIANT converted;
                    VariantInit(&converted);
                    if (SUCCEEDED(value->get_value(&variant)) &&
                        SUCCEEDED(VariantChangeType(&converted, &variant, 0, VT_I8)))
                    {
                        const std::string name = SymbolName(value);
                        if (!name.empty()) record.enumValues.emplace_back(name, converted.llVal);
                    }
                    VariantClear(&converted);
                    VariantClear(&variant);
                    ReleaseInterface(value);
                }
                ReleaseInterface(value);
                ReleaseInterface(values);
            }
            if (!record.name.empty()) impl_->types.push_back(std::move(record));
            ReleaseInterface(type);
        }
        ReleaseInterface(type);
        ReleaseInterface(enums);
    }

    std::sort(impl_->symbols.begin(), impl_->symbols.end(), [](const auto& left, const auto& right) {
        if (left.rva != right.rva) return left.rva < right.rva;
        if (left.kind != right.kind) return left.kind < right.kind;
        return left.name < right.name;
    });
    impl_->symbols.erase(std::unique(impl_->symbols.begin(), impl_->symbols.end(),
        [](const auto& left, const auto& right) {
            return left.rva == right.rva && left.kind == right.kind && left.name == right.name;
        }), impl_->symbols.end());
    return true;
#endif
}

const std::vector<SymbolRecord>& DiaSymbolProvider::Symbols() const { return impl_->symbols; }
const std::vector<SymbolTypeRecord>& DiaSymbolProvider::Types() const { return impl_->types; }
const SymbolProviderIdentity& DiaSymbolProvider::Identity() const { return impl_->identity; }
const std::string& DiaSymbolProvider::LastError() const { return impl_->lastError; }

} // namespace openreverse
