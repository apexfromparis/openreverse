#pragma once

#include "analysis/symbol_provider.h"

#include <memory>

namespace openreverse {

class DiaSymbolProvider final : public ISymbolProvider {
public:
    DiaSymbolProvider();
    ~DiaSymbolProvider() override;
    DiaSymbolProvider(const DiaSymbolProvider&) = delete;
    DiaSymbolProvider& operator=(const DiaSymbolProvider&) = delete;

    static bool IsAvailable();

    bool Load(const std::string& modulePath,
              const ModuleIdentity& identity) override;
    const std::vector<SymbolRecord>& Symbols() const override;
    const std::vector<SymbolTypeRecord>& Types() const override;
    const SymbolProviderIdentity& Identity() const override;
    const std::string& LastError() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace openreverse
