#pragma once

#include "x64dbg_GolangAnalyzerPlugin.h"

enum GO_VERSION
{
    UNKNOWN,
    GO_112,
    GO_116,
};

struct GOPCLNTAB
{
    unsigned char magic[4] = { 0 };
    unsigned char unknown[2] = { 0 };
    unsigned char quantum = 0;
    unsigned char pointer_size = 0;

    GO_VERSION version = UNKNOWN;
    duint addr = 0;
    unsigned int func_num = 0;
    duint func_list_base = 0;
    unsigned long long func_info_offset = 0;
    duint file_name_table = 0;
};


bool get_gopclntab(GOPCLNTAB* gopclntab);
bool analyze_file_name(const GOPCLNTAB* gopclntab);
bool pc_to_file_name(const GOPCLNTAB* gopclntab, unsigned long long func_info_offset, unsigned long long target_pc_offset, char* file_name, size_t file_name_size);
std::map<unsigned long long, std::string> init_file_line_map(const GOPCLNTAB* gopclntab, duint func_info_addr, unsigned long long* func_size);
std::map<unsigned long long, std::string> init_sp_map(const GOPCLNTAB* gopclntab, duint func_info_addr);
