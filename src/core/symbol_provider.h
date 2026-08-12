#pragma once

#include "core/offset_model.h"

#include <cstdint>
#include <string>
#include <vector>

namespace openreverse {

enum class SymbolKind {
    Function,
    Public,
    Data
};

struct SymbolRecord {
    SymbolKind kind = SymbolKind::Public;
    std::string name;
    uint64_t rva = 0;
    uint64_t size = 0;
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
    std::vector<SymbolFieldRecord> fields;
};

class ISymbolProvider {
public:
    virtual ~ISymbolProvider() = default;

    virtual bool Load(const std::string& modulePath,
                      const ModuleIdentity& identity) = 0;
    virtual const std::vector<SymbolRecord>& Symbols() const = 0;
    virtual const std::vector<SymbolTypeRecord>& Types() const = 0;
    virtual const std::string& LastError() const = 0;
};

} // namespace openreverse
