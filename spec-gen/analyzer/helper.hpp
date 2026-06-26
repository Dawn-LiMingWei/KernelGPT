#ifndef HELPER_HPP
#define HELPER_HPP

#include "json.hpp"
#include "clang/AST/Decl.h"
#include "clang/AST/TemplateName.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <cstddef>
#include <map>
#include <mutex>
#include <limits>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

class Semaphore {
public:
  Semaphore(int count) : count(count) {}

  inline void notify() {
    std::unique_lock<std::mutex> lock(mtx);
    count++;
    cv.notify_one();
  }

  inline void wait() {
    std::unique_lock<std::mutex> lock(mtx);
    while (count == 0) {
      cv.wait(lock);
    }
    count--;
  }

private:
  std::mutex mtx;
  std::condition_variable cv;
  int count;
};

struct AnalyzerConfig {
  int max_threads = 100;
  int batch_size = 0;
  int dedup_cache_max_entries = 200000;
  bool limit_by_cpu = false;
  std::filesystem::path env_path;
  bool env_loaded = false;

  int resolved_max_threads() const;
  int resolved_batch_size(int fallback) const;
  int resolved_dedup_cache_max_entries() const;
};

std::string get_decl_code(const clang::NamedDecl *);
void output_decl(const clang::NamedDecl *decl, std::string output_file_name,
                 bool is_typedef = false, std::string alias_name = "");
AnalyzerConfig load_analyzer_config(const char *argv0,
                                    const std::string &tool_name);
void set_output_decl_cache_limit(std::size_t max_entries);
void clear_output_decl_cache();

#endif
