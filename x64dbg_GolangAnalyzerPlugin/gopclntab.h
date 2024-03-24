#pragma once

#include "x64dbg_GolangAnalyzerPlugin.h"

enum class GO_VERSION
{
    UNKNOWN,
    GO_12,
    GO_116,
    GO_118,
    GO_120,
};

struct GOPCLNTAB
{
    uint8_t magic[4] = { 0 };
    uint8_t unknown[2] = { 0 };
    uint8_t quantum = 0;
    uint8_t pointer_size = 0;

    GO_VERSION version = GO_VERSION::UNKNOWN;
    duint addr = 0;
    uint32_t func_num = 0;
    duint func_list_base = 0;
    uint64_t func_info_offset = 0;
    duint file_name_table = 0;

    std::vector<std::string> file_name_list;
};


bool get_gopclntab(GOPCLNTAB* gopclntab);
bool analyze_file_name(GOPCLNTAB* gopclntab);
