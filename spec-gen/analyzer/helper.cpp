#include "helper.hpp"

#include <cstdint>
#include <unordered_set>

using namespace clang;
using namespace clang::tooling;
using json = nlohmann::json;

std::mutex mutex;

struct EntryFingerprint {
  std::uint64_t low = 0;
  std::uint64_t high = 0;

  bool operator==(const EntryFingerprint &other) const {
    return low == other.low && high == other.high;
  }
};

struct EntryFingerprintHasher {
  std::size_t operator()(const EntryFingerprint &value) const {
    return static_cast<std::size_t>(value.low ^ (value.high << 1));
  }
};

std::unordered_set<EntryFingerprint, EntryFingerprintHasher>
    existing_fingerprints;
std::size_t dedup_cache_limit = 200000;

namespace {

std::string trim(const std::string &value) {
  const auto start = value.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) {
    return "";
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(start, end - start + 1);
}

constexpr std::uint64_t kFnv64OffsetBasis = 1469598103934665603ULL;
constexpr std::uint64_t kFnv64Prime = 1099511628211ULL;

void hash_update(std::uint64_t &state, const std::string &value) {
  for (unsigned char ch : value) {
    state ^= static_cast<std::uint64_t>(ch);
    state *= kFnv64Prime;
  }
  state ^= 0xFF;
  state *= kFnv64Prime;
}

EntryFingerprint make_fingerprint(const std::string &filename,
                                  const std::string &name,
                                  const std::string &output_file_name,
                                  const std::string &alias_name) {
  EntryFingerprint fingerprint;
  fingerprint.low = kFnv64OffsetBasis;
  fingerprint.high = kFnv64OffsetBasis ^ 0x9e3779b97f4a7c15ULL;

  hash_update(fingerprint.low, filename);
  hash_update(fingerprint.low, name);
  hash_update(fingerprint.low, output_file_name);
  hash_update(fingerprint.low, alias_name);

  hash_update(fingerprint.high, output_file_name);
  hash_update(fingerprint.high, alias_name);
  hash_update(fingerprint.high, filename);
  hash_update(fingerprint.high, name);
  return fingerprint;
}

std::string uppercase(std::string value) {
  for (char &ch : value) {
    ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
  }
  return value;
}

bool parse_bool_value(const std::string &value, bool default_value) {
  const std::string normalized = uppercase(trim(value));
  if (normalized == "1" || normalized == "TRUE" || normalized == "YES" ||
      normalized == "ON") {
    return true;
  }
  if (normalized == "0" || normalized == "FALSE" || normalized == "NO" ||
      normalized == "OFF") {
    return false;
  }
  return default_value;
}

int parse_int_value(const std::string &value, int default_value) {
  const std::string normalized = trim(value);
  if (normalized.empty()) {
    return default_value;
  }
  char *end = nullptr;
  const long parsed = std::strtol(normalized.c_str(), &end, 10);
  if (end == normalized.c_str() || (end != nullptr && *end != '\0')) {
    return default_value;
  }
  if (parsed <= 0 || parsed > std::numeric_limits<int>::max()) {
    return default_value;
  }
  return static_cast<int>(parsed);
}

std::map<std::string, std::string>
read_env_file(const std::filesystem::path &env_path) {
  std::map<std::string, std::string> values;
  std::ifstream env_file(env_path);
  std::string line;
  while (std::getline(env_file, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const auto pos = line.find('=');
    if (pos == std::string::npos) {
      continue;
    }

    std::string key = trim(line.substr(0, pos));
    std::string value = trim(line.substr(pos + 1));
    if (value.size() >= 2 &&
        ((value.front() == '"' && value.back() == '"') ||
         (value.front() == '\'' && value.back() == '\''))) {
      value = value.substr(1, value.size() - 2);
    }
    if (!key.empty()) {
      values[key] = value;
    }
  }
  return values;
}

} // namespace

int AnalyzerConfig::resolved_max_threads() const {
  int resolved = max_threads > 0 ? max_threads : 1;
  if (limit_by_cpu) {
    const unsigned int cpu_count = std::thread::hardware_concurrency();
    if (cpu_count > 0) {
      resolved = std::min(resolved, static_cast<int>(cpu_count));
    }
  }
  return resolved > 0 ? resolved : 1;
}

int AnalyzerConfig::resolved_batch_size(int fallback) const {
  const int normalized_fallback = fallback > 0 ? fallback : 1;
  if (batch_size <= 0) {
    return normalized_fallback;
  }
  return batch_size;
}

int AnalyzerConfig::resolved_dedup_cache_max_entries() const {
  if (dedup_cache_max_entries <= 0) {
    return 1;
  }
  return dedup_cache_max_entries;
}

AnalyzerConfig load_analyzer_config(const char *argv0,
                                    const std::string &tool_name) {
  AnalyzerConfig config;
  const auto exe_path = std::filesystem::absolute(argv0).parent_path();
  const auto env_path = exe_path / ".env";
  config.env_path = env_path;
  if (!std::filesystem::exists(env_path)) {
    return config;
  }

  config.env_loaded = true;
  const auto values = read_env_file(env_path);
  const auto tool_upper = uppercase(tool_name);

  auto get_value = [&](const std::string &key) -> std::string {
    auto it = values.find(key);
    return it == values.end() ? "" : it->second;
  };

  const std::string common_threads = get_value("ANALYZER_MAX_THREADS");
  const std::string tool_threads = get_value(tool_upper + "_MAX_THREADS");
  const std::string common_batch_size = get_value("ANALYZER_BATCH_SIZE");
  const std::string tool_batch_size = get_value(tool_upper + "_BATCH_SIZE");
  const std::string common_dedup_max =
      get_value("ANALYZER_DEDUP_CACHE_MAX_ENTRIES");
  const std::string tool_dedup_max =
      get_value(tool_upper + "_DEDUP_CACHE_MAX_ENTRIES");
  const std::string common_limit = get_value("ANALYZER_LIMIT_BY_CPU");
  const std::string tool_limit = get_value(tool_upper + "_LIMIT_BY_CPU");

  if (!common_threads.empty()) {
    config.max_threads = parse_int_value(common_threads, config.max_threads);
  }
  if (!tool_threads.empty()) {
    config.max_threads = parse_int_value(tool_threads, config.max_threads);
  }
  if (!common_batch_size.empty()) {
    config.batch_size = parse_int_value(common_batch_size, config.batch_size);
  }
  if (!tool_batch_size.empty()) {
    config.batch_size = parse_int_value(tool_batch_size, config.batch_size);
  }
  if (!common_dedup_max.empty()) {
    config.dedup_cache_max_entries =
        parse_int_value(common_dedup_max, config.dedup_cache_max_entries);
  }
  if (!tool_dedup_max.empty()) {
    config.dedup_cache_max_entries =
        parse_int_value(tool_dedup_max, config.dedup_cache_max_entries);
  }
  if (!common_limit.empty()) {
    config.limit_by_cpu = parse_bool_value(common_limit, config.limit_by_cpu);
  }
  if (!tool_limit.empty()) {
    config.limit_by_cpu = parse_bool_value(tool_limit, config.limit_by_cpu);
  }

  return config;
}

void set_output_decl_cache_limit(std::size_t max_entries) {
  std::lock_guard<std::mutex> lock(mutex);
  dedup_cache_limit = max_entries > 0 ? max_entries : 1;
  if (existing_fingerprints.size() > dedup_cache_limit) {
    existing_fingerprints.clear();
  }
}

void clear_output_decl_cache() {
  std::lock_guard<std::mutex> lock(mutex);
  existing_fingerprints.clear();
}

std::string get_decl_code(const NamedDecl *decl) {
  SourceManager &srcMgr = decl->getASTContext().getSourceManager();
  SourceLocation startLoc = decl->getBeginLoc();
  SourceLocation endLoc = decl->getEndLoc();

  if (!startLoc.isInvalid() && !endLoc.isInvalid()) {
    // Convert the source locations to file locations
    startLoc = srcMgr.getSpellingLoc(startLoc);
    endLoc = srcMgr.getSpellingLoc(endLoc);

    // Get file path and line number
    std::string filePath = srcMgr.getFilename(startLoc).str();
    unsigned int lineNumber = srcMgr.getSpellingLineNumber(startLoc);

    // Extract the source code text
    bool invalid = false;
    StringRef text =
        Lexer::getSourceText(CharSourceRange::getTokenRange(startLoc, endLoc),
                             srcMgr, LangOptions(), &invalid);

    if (!invalid) {
      std::string sourceCode = text.str();
      // Now you have filePath, lineNumber, and sourceCode
      // Store or process them as needed
      return sourceCode;
    }
  }
  return "";
}

void output_decl(const NamedDecl *decl, std::string output_file_name,
                 bool is_typedef, std::string alias_name) {
  // Add a lock
  std::lock_guard<std::mutex> lock(mutex);

  auto name = decl->getNameAsString();
  std::string sourceCode = get_decl_code(decl);

  json j;
  j["name"] = name;
  j["source"] = sourceCode;

  // Get the SourceLocation for the beginning of the declaration
  SourceLocation beginLoc = decl->getBeginLoc();

  // Retrieve the SourceManager from the AST context
  SourceManager &sourceManager = decl->getASTContext().getSourceManager();

  std::stringstream filenameWithLine;
  if (const FileEntry *fileEntry =
          sourceManager.getFileEntryForID(sourceManager.getFileID(beginLoc))) {
    filenameWithLine << fileEntry->tryGetRealPathName().str();
  } else {
    filenameWithLine << decl->getBeginLoc().printToString(
        decl->getASTContext().getSourceManager());
  }
  // Append line number
  unsigned lineNumber = sourceManager.getSpellingLineNumber(beginLoc);
  filenameWithLine << ":" << lineNumber;

  std::string filename = filenameWithLine.str();
  const EntryFingerprint fingerprint =
      make_fingerprint(filename, name, output_file_name, alias_name);
  if (existing_fingerprints.size() >= dedup_cache_limit) {
    existing_fingerprints.clear();
  }
  if (!existing_fingerprints.insert(fingerprint).second) {
    return;
  }
  j["filename"] = filename;

  if (is_typedef) {
    j["alias"] = alias_name;
  }

  std::ofstream output_file;
  output_file.open(output_file_name, std::ios_base::app);
  auto json_str = j.dump();
  output_file << json_str << std::endl;
  output_file.flush();
  output_file.close();
}
