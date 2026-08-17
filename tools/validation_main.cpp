#include "core/module_analyzer.h"
#include "core/pe_parser.h"
#include "core/project.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <system_error>
#include <vector>

namespace {

using json = nlohmann::json;
namespace fs = std::filesystem;

constexpr size_t kDefaultMaximumFiles = 10000;

bool IsPECandidate(const fs::path& path)
{
    std::string extension = path.extension().u8string();
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char value) {
        return static_cast<char>(std::tolower(value));
    });
    return extension == ".exe" || extension == ".dll" || extension == ".sys" ||
           extension == ".ocx" || extension == ".cpl" || extension == ".scr";
}

long long Milliseconds(std::chrono::steady_clock::duration duration)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

json AnalyzeFile(const fs::path& root, const fs::path& path)
{
    json record;
    std::error_code filesystemError;
    const auto relative = fs::relative(path, root, filesystemError);
    record["path"] = (filesystemError ? path.filename() : relative).generic_u8string();
    record["status"] = "failure";
    record["errors"] = json::array();

    const auto overallStarted = std::chrono::steady_clock::now();
    const auto parseStarted = overallStarted;
    openreverse::PEParser parser;
    std::vector<uint8_t> raw;
    const auto pe = parser.ParseFile(path.u8string(), raw);
    const auto parseFinished = std::chrono::steady_clock::now();
    record["file_size"] = raw.size();
    record["timings_ms"]["pe_parse"] = Milliseconds(parseFinished - parseStarted);
    if (!pe.valid)
    {
        record["errors"].push_back("not a supported bounded PE32/PE32+ image");
        record["timings_ms"]["total"] = Milliseconds(std::chrono::steady_clock::now() - overallStarted);
        return record;
    }

    record["architecture"] = pe.is64bit ? "x64" : "x86";
    std::string sha256;
    std::string hashError;
    if (openreverse::ProjectStore::ComputeFileSha256(path.u8string(), sha256, hashError))
        record["sha256"] = sha256;
    else
        record["errors"].push_back("SHA-256: " + hashError);

    const auto mappingStarted = std::chrono::steady_clock::now();
    std::vector<uint8_t> mapped;
    if (!openreverse::PEParser::BuildMappedImage(raw, pe, mapped))
    {
        record["errors"].push_back("PE image mapping failed");
        record["timings_ms"]["mapping"] = Milliseconds(
            std::chrono::steady_clock::now() - mappingStarted);
        record["timings_ms"]["total"] = Milliseconds(
            std::chrono::steady_clock::now() - overallStarted);
        return record;
    }
    const auto mappingFinished = std::chrono::steady_clock::now();
    record["timings_ms"]["mapping"] = Milliseconds(mappingFinished - mappingStarted);

    openreverse::ModuleInfo module;
    module.name = path.filename().u8string();
    module.path = path.u8string();
    module.baseAddress = pe.imageBase;
    module.size = pe.sizeOfImage;

    openreverse::ModuleAnalysisOptions options;
    options.maxCodeBytes = 64ULL * 1024ULL * 1024ULL;
    options.maxStringBytes = 16ULL * 1024ULL * 1024ULL;
    options.maxInstructions = 2000000;
    options.maxCfgInstructions = 750000;
    options.maxInstructionsPerFunction = 4096;
    options.maxFunctionBytes = 65536;
    options.maxFunctions = 50000;
    options.maxStrings = 50000;
    options.maxDuration = std::chrono::seconds(60);

    openreverse::ModuleAnalyzer analyzer;
    const auto result = analyzer.AnalyzeMappedImage(mapped, raw.size(), module, pe, options);
    record["functions"] = result.functions.size();
    record["cfg_functions"] = result.cfgFunctionsAnalyzed;
    record["cfg_instructions"] = result.cfgInstructionsAnalyzed;
    record["xrefs"] = result.xrefs.size();
    record["strings"] = result.strings.size();
    record["globals"] = result.globals.size();
    record["field_accesses"] = result.fieldAccesses.size();
    record["structures"] = result.structures.size();
    record["signatures"] = result.signatures.size();
    record["symbols_loaded"] = result.symbolsLoaded;
    record["budgets"] = {
        {"code_bytes", result.codeBudgetReached},
        {"instructions", result.instructionBudgetReached},
        {"cfg_instructions", result.cfgInstructionBudgetReached},
        {"functions", result.functionLimitReached},
        {"strings", result.stringBudgetReached},
        {"time", result.timeBudgetReached}
    };
    record["timings_ms"]["disassembly_and_discovery"] = result.codeDuration.count();
    record["timings_ms"]["cfg"] = result.cfgDuration.count();
    record["timings_ms"]["data_and_structures"] = result.dataDuration.count();
    record["timings_ms"]["strings"] = result.stringDuration.count();
    record["timings_ms"]["signatures"] = result.signatureDuration.count();
    record["timings_ms"]["analysis"] = result.totalDuration.count();
    record["timings_ms"]["total"] = Milliseconds(std::chrono::steady_clock::now() - overallStarted);

    if (!result.error.empty()) record["errors"].push_back(result.error);
    const bool limited = result.codeBudgetReached || result.instructionBudgetReached ||
        result.cfgInstructionBudgetReached || result.functionLimitReached ||
        result.stringBudgetReached || result.timeBudgetReached;
    if (result.success && !limited && record["errors"].empty())
        record["status"] = "success";
    else if (result.success || !result.functions.empty())
        record["status"] = "partial";
    return record;
}

void PrintUsage()
{
    std::cerr << "Usage: OpenReverseValidation <directory> [--output report.json] [--max-files N]\n";
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        PrintUsage();
        return 2;
    }

    fs::path root = argv[1];
    fs::path output = "openreverse-validation.json";
    size_t maximumFiles = kDefaultMaximumFiles;
    for (int index = 2; index < argc; ++index)
    {
        const std::wstring argument = argv[index];
        if (argument == L"--output" && index + 1 < argc)
            output = argv[++index];
        else if (argument == L"--max-files" && index + 1 < argc)
        {
            try
            {
                const unsigned long long value = std::stoull(argv[++index]);
                if (value == 0 || value > kDefaultMaximumFiles) throw std::out_of_range("max-files");
                maximumFiles = static_cast<size_t>(value);
            }
            catch (const std::exception&)
            {
                std::cerr << "--max-files must be between 1 and " << kDefaultMaximumFiles << "\n";
                return 2;
            }
        }
        else
        {
            PrintUsage();
            return 2;
        }
    }

    std::error_code error;
    if (!fs::is_directory(root, error))
    {
        std::cerr << "Input is not a readable directory.\n";
        return 2;
    }
    root = fs::absolute(root, error);
    if (error)
    {
        std::cerr << "Unable to resolve the input directory.\n";
        return 2;
    }

    std::vector<fs::path> candidates;
    fs::recursive_directory_iterator iterator(root,
        fs::directory_options::skip_permission_denied, error);
    const fs::recursive_directory_iterator end;
    while (!error && iterator != end && candidates.size() < maximumFiles)
    {
        const auto entry = *iterator;
        if (entry.is_regular_file(error) && !error && IsPECandidate(entry.path()))
            candidates.push_back(entry.path());
        error.clear();
        iterator.increment(error);
    }
    std::sort(candidates.begin(), candidates.end(), [](const fs::path& left, const fs::path& right) {
        return left.generic_u8string() < right.generic_u8string();
    });

    json report;
    report["schema_version"] = 1;
    report["static_analysis_only"] = true;
    report["limits"]["maximum_files"] = maximumFiles;
    report["limits"]["per_file_seconds"] = 60;
    report["files"] = json::array();
    size_t success = 0;
    size_t partial = 0;
    size_t failure = 0;
    size_t exceptions = 0;
    for (const auto& path : candidates)
    {
        try
        {
            auto record = AnalyzeFile(root, path);
            const std::string status = record.value("status", "failure");
            if (status == "success") ++success;
            else if (status == "partial") ++partial;
            else ++failure;
            report["files"].push_back(std::move(record));
        }
        catch (const std::exception& exception)
        {
            ++exceptions;
            report["files"].push_back({
                {"path", fs::relative(path, root, error).generic_u8string()},
                {"status", "exception"},
                {"errors", json::array({exception.what()})}
            });
        }
        catch (...)
        {
            ++exceptions;
            report["files"].push_back({
                {"path", fs::relative(path, root, error).generic_u8string()},
                {"status", "exception"},
                {"errors", json::array({"unknown exception"})}
            });
        }
    }
    report["summary"] = {
        {"candidates", candidates.size()},
        {"success", success},
        {"partial", partial},
        {"failure", failure},
        {"exceptions", exceptions},
        {"truncated", candidates.size() >= maximumFiles}
    };

    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream)
    {
        std::cerr << "Unable to create the JSON report.\n";
        return 3;
    }
    stream << report.dump(2) << '\n';
    if (!stream)
    {
        std::cerr << "Unable to finish the JSON report.\n";
        return 3;
    }

    std::cout << "Analyzed " << candidates.size() << " candidate(s): "
              << success << " success, " << partial << " partial, "
              << failure << " failure, " << exceptions << " exception.\n";
    return exceptions == 0 ? 0 : 1;
}
