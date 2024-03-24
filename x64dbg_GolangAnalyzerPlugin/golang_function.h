#pragma once

#include "gopclntab.h"
#include "x64dbg_GolangAnalyzerPlugin.h"

struct GoFunc
{
    uint64_t addr;
    uint64_t size;
    std::string name;
    uint32_t args_size;
    std::map<uint64_t, std::string> file_line_map;
    std::map<uint64_t, uint64_t> sp_map;
};


bool analyze_functions(const GOPCLNTAB& gopclntab, std::vector<GoFunc>* go_func_list, bool is_file_line_enabled);
void set_functions_info(const std::vector<GoFunc>& go_func_list);
bool get_target_function(const std::vector<GoFunc>& go_func_list, duint target_pc, GoFunc* target_func);
bool get_target_stack_size(const GoFunc& go_func, duint target_pc, duint* target_size);
