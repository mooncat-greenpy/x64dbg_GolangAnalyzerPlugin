#pragma once

#include "x64dbg_GolangAnalyzerPlugin.h"

struct GOPCLNTAB
{
    unsigned char magic[4];
    unsigned char unknown[2];
    unsigned char quantum;
    unsigned char pointer_size;
    duint addr;
    unsigned int func_num;
    duint func_list_base;
    unsigned long long func_info_offset;
    duint file_name_table;
};


bool get_gopclntab(GOPCLNTAB* gopclntab);
bool analyze_file_name(const GOPCLNTAB* gopclntab);
bool pc_to_file_name(const GOPCLNTAB* gopclntab, unsigned long long func_info_offset, unsigned long long target_pc_offset, char* file_name, size_t file_name_size);
std::map<unsigned long long, std::string> init_file_line_map(const GOPCLNTAB* gopclntab, unsigned long long func_info_offset, unsigned long long* func_size);
std::map<unsigned long long, std::string> init_sp_map(const GOPCLNTAB* gopclntab, unsigned long long func_info_offset);
