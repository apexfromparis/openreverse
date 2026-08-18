#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <utility>

namespace openreverse {

struct ModuleIdentity;

enum class SymbolKind {
    Function,
    Public,
    Data
};

enum class SymbolProvenance {
    ProgramDatabase
};

enum class SymbolTypeKind {
    Unknown,
    Structure,
    Class,
    Union,
    Enum
};

struct SymbolRecord {
    SymbolKind kind = SymbolKind::Public;
    std::string name;
    uint64_t rva = 0;
    uint64_t size = 0;
    SymbolProvenance provenance = SymbolProvenance::ProgramDatabase;
};

struct SymbolFieldRecord {
    std::string name;
    int64_t offset = 0;
    uint64_t size = 0;
    std::string typeName;
};

struct SymbolTypeRecord {
    std::string name;
    uint64_t size = 0;
    SymbolTypeKind kind = SymbolTypeKind::Unknown;
    std::vector<SymbolFieldRecord> fields;
    std::vector<std::pair<std::string, int64_t>> enumValues;
};

struct SymbolProviderIdentity {
    std::string pdbPath;
    std::string guid;
    uint32_t age = 0;
    bool executableAssociationValidated = false;
};

class ISymbolProvider {
public:
    virtual ~ISymbolProvider() = default;

    virtual bool Load(const std::string& modulePath,
                      const ModuleIdentity& identity) = 0;
    virtual const std::vector<SymbolRecord>& Symbols() const = 0;
    virtual const std::vector<SymbolTypeRecord>& Types() const = 0;
    virtual const SymbolProviderIdentity& Identity() const = 0;
    virtual const std::string& LastError() const = 0;
};

} // namespace openreverse
