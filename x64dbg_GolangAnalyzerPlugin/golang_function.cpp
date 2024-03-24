#include "golang_function.h"


uint32_t read_pc_data(duint addr, uint32_t* i)
{
    if (!DbgMemIsValidReadPtr(addr)) {
        return 0;
    }
    uint32_t value = 0;
    for (uint32_t shift = 0;; shift += 7) {
        uint32_t tmp = 0;
        if (!read_dbg_memory(addr + (*i)++, &tmp, 1))
        {
            tmp = 0;
        }
        value |= (tmp & 0x7f) << shift;
        if ((tmp & 0x80) == 0) {
            break;
        }
    }
    return value;
}

int32_t zig_zag_decode(uint32_t value)
{
    if ((value & 1) != 0) {
        value = (value >> 1) + 1;
        return value * -1;
    }
    else {
        return value >> 1;
    }
}

bool pc_to_file_name(const GOPCLNTAB& gopclntab, duint func_info_addr, uint64_t target_pc_offset, char* file_name, size_t file_name_size)
{
    duint functab_field_size = gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120 ? 4 : gopclntab.pointer_size;

    uint32_t pcfile_offset = 0;
    read_dbg_memory(func_info_addr + functab_field_size + 4 * 4, &pcfile_offset, 4);
    duint pcfile_base = gopclntab.addr + pcfile_offset;
    if (gopclntab.version == GO_VERSION::GO_116 || gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
    {
        uint64_t tmp_value = 0;
        if (!read_dbg_memory(gopclntab.addr + 8 + gopclntab.pointer_size * (gopclntab.version == GO_VERSION::GO_116 ? 5 : 6), &tmp_value, gopclntab.pointer_size))
        {
            return false;
        }
        pcfile_base = gopclntab.addr + (duint)tmp_value + pcfile_offset;
    }

    int64_t file_no = -1;
    uint32_t i = 0;
    boolean first = true;
    uint64_t pc_offset = 0;
    while (true)
    {
        uint32_t decoded_file_no_add = read_pc_data(pcfile_base, &i);
        uint32_t byte_size = read_pc_data(pcfile_base, &i);
        if (decoded_file_no_add == 0 && !first) {
            break;
        }
        first = false;
        int32_t file_no_add = zig_zag_decode(decoded_file_no_add);
        file_no += file_no_add;
        pc_offset += (uint64_t)byte_size * gopclntab.quantum;

        if (target_pc_offset <= pc_offset)
        {
            if (gopclntab.version == GO_VERSION::GO_116 || gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
            {
                uint32_t cu_offset = 0;
                if (!read_dbg_memory(func_info_addr + functab_field_size + 4 * 7, &cu_offset, 4))
                {
                    return false;
                }
                uint64_t tmp_value = 0;
                if (!read_dbg_memory(gopclntab.addr + 8 + gopclntab.pointer_size * (gopclntab.version == GO_VERSION::GO_116 ? 3 : 4), &tmp_value, gopclntab.pointer_size))
                {
                    return false;
                }
                duint cutab_base = gopclntab.addr + (duint)tmp_value;
                uint32_t file_no_offset = 0;
                if (!read_dbg_memory(cutab_base + (cu_offset + (duint)file_no) * 4, &file_no_offset, 4))
                {
                    return false;
                }
                if (!read_dbg_memory(gopclntab.addr + 8 + gopclntab.pointer_size * (gopclntab.version == GO_VERSION::GO_116 ? 4 : 5), &tmp_value, gopclntab.pointer_size))
                {
                    return false;
                }
                duint file_name_addr = gopclntab.addr + (duint)tmp_value + file_no_offset;
                char tmp_file_name[MAX_PATH] = {};
                if (!read_dbg_memory(file_name_addr, tmp_file_name, sizeof(tmp_file_name)))
                {
                    return false;
                }
                strncpy_s(file_name, file_name_size, tmp_file_name, _TRUNCATE);
                return true;
            }
            if (file_no - 1 < 0 || gopclntab.file_name_list.size() <= (size_t)file_no - 1)
            {
                goanalyzer_logprintf("Error file name list index out of range: %d\n", file_no - 1);
                return false;
            }
            strncpy_s(file_name, file_name_size, gopclntab.file_name_list.at((size_t)file_no - 1).c_str(), _TRUNCATE);
            return true;
        }
    }
    return false;
}

std::map<uint64_t, std::string> init_file_line_map(const GOPCLNTAB& gopclntab, duint func_info_addr, uint64_t* func_size)
{
    std::map<uint64_t, std::string> file_line_comment_map;
    file_line_comment_map.clear();

    duint functab_field_size = gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120 ? 4 : gopclntab.pointer_size;
    uint32_t pcln_offset = 0;
    read_dbg_memory(func_info_addr + functab_field_size + 5 * 4, &pcln_offset, 4);
    duint pcln_base;
    if (gopclntab.version == GO_VERSION::GO_116 || gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
    {
        uint64_t tmp_value = 0;
        if (!read_dbg_memory(gopclntab.addr + 8 + (uint32_t)gopclntab.pointer_size * (gopclntab.version == GO_VERSION::GO_116 ? 5 : 6), &tmp_value, gopclntab.pointer_size))
        {
            return file_line_comment_map;
        }
        pcln_base = gopclntab.addr + (duint)tmp_value + pcln_offset;
    }
    else
    {
        pcln_base = gopclntab.addr + pcln_offset;
    }

    int64_t line_num = -1;
    uint32_t i = 0;
    bool first = true;
    uint64_t pc_offset = 0;
    while (true) {
        uint32_t decoded_line_num_add = read_pc_data(pcln_base, &i);
        uint32_t byte_size = read_pc_data(pcln_base, &i);
        if (decoded_line_num_add == 0 && !first)
        {
            break;
        }

        first = false;
        uint64_t key = pc_offset;
        int32_t line_num_add = zig_zag_decode(decoded_line_num_add);
        line_num += line_num_add;
        pc_offset += (uint64_t)byte_size * gopclntab.quantum;

        if (get_line_enabled())
        {
            char file_name[MAX_PATH] = "not found";
            if (!pc_to_file_name(gopclntab, func_info_addr, pc_offset, file_name, sizeof(file_name))) {
                strncpy_s(file_name, sizeof(file_name), "not found", _TRUNCATE);
            }

            char line_string[MAX_PATH] = { 0 };
            _snprintf_s(line_string, sizeof(line_string), MAX_PATH, "%s:%lld", file_name, line_num);
            file_line_comment_map[key] = line_string;
        }
    }
    *func_size = pc_offset;
    return file_line_comment_map;
}

std::map<uint64_t, uint64_t> init_sp_map(const GOPCLNTAB& gopclntab, duint func_info_addr, uint64_t* func_size)
{
    std::map<uint64_t, uint64_t> sp_comment_map;

    duint functab_field_size = gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120 ? 4 : gopclntab.pointer_size;
    uint32_t pcsp_offset = 0;
    read_dbg_memory(func_info_addr + functab_field_size + 3 * 4, &pcsp_offset, 4);
    duint pcsp_base = gopclntab.addr + pcsp_offset;
    if (gopclntab.version == GO_VERSION::GO_116 || gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
    {
        uint64_t tmp_value = 0;
        if (!read_dbg_memory(gopclntab.addr + 8 + gopclntab.pointer_size * (gopclntab.version == GO_VERSION::GO_116 ? 5 : 6), &tmp_value, gopclntab.pointer_size))
        {
            return sp_comment_map;
        }
        pcsp_base = gopclntab.addr + (duint)tmp_value + pcsp_offset;
    }

    int64_t sp_size = -1;
    uint32_t i = 0;
    bool first = true;
    uint64_t pc_offset = 0;
    while (true) {
        uint32_t decoded_sp_size_add = read_pc_data(pcsp_base, &i);
        uint32_t byte_size = read_pc_data(pcsp_base, &i);
        if (decoded_sp_size_add == 0 && !first)
        {
            break;
        }

        first = false;
        uint64_t key = pc_offset;
        int32_t sp_size_add = zig_zag_decode(decoded_sp_size_add);
        sp_size += sp_size_add;
        pc_offset += (uint64_t)byte_size * gopclntab.quantum;

        sp_comment_map[key] = sp_size;
    }
    *func_size = pc_offset;
    return sp_comment_map;
}

bool analyze_functions(const GOPCLNTAB& gopclntab, std::vector<GoFunc>* go_func_list, bool is_file_line_enabled)
{
    for (uint32_t i = 0; i < gopclntab.func_num; i++)
    {
        duint functab_field_size = gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120 ? 4 : gopclntab.pointer_size;

        uint64_t func_addr_value = 0;
        if (!read_dbg_memory(gopclntab.func_list_base + (duint)i * functab_field_size * 2, &func_addr_value, functab_field_size))
        {
            return false;
        }
        if (gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
        {
            uint64_t text_addr = 0;
            if (!read_dbg_memory(gopclntab.addr + 8 + (uint32_t)gopclntab.pointer_size * 2, &text_addr, gopclntab.pointer_size))
            {
                return false;
            }
            func_addr_value += text_addr;
        }
        uint64_t func_info_offset = 0;
        if (!read_dbg_memory(gopclntab.func_list_base + (duint)i * functab_field_size * 2 + functab_field_size, &func_info_offset, functab_field_size))
        {
            return false;
        }
        duint func_info_addr = gopclntab.addr + (duint)func_info_offset;
        if (gopclntab.version == GO_VERSION::GO_116 || gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
        {
            func_info_addr = gopclntab.func_list_base + (duint)func_info_offset;
        }
        uint64_t func_name_offset = 0;
        if (!read_dbg_memory(func_info_addr + functab_field_size, &func_name_offset, 4))
        {
            return false;
        }

        char func_name[MAX_PATH] = { 0 };
        duint func_name_base = gopclntab.addr;
        if (gopclntab.version == GO_VERSION::GO_116 || gopclntab.version == GO_VERSION::GO_118 || gopclntab.version == GO_VERSION::GO_120)
        {
            uint64_t tmp_value = 0;
            if (!read_dbg_memory(gopclntab.addr + 8 + (uint32_t)gopclntab.pointer_size * (gopclntab.version == GO_VERSION::GO_116 ? 2 : 3), &tmp_value, gopclntab.pointer_size))
            {
                return false;
            }
            func_name_base = gopclntab.addr + (duint)tmp_value;
        }
        if (!read_dbg_memory(func_name_base + (duint)func_name_offset, func_name, sizeof(func_name)))
        {
            return false;
        }
        func_name[sizeof(func_name) - 1] = '\0';

        uint32_t args_size = 0;
        if (!read_dbg_memory(func_info_addr + functab_field_size + 4, &args_size, 4))
        {
            return false;
        }
        if (args_size >= 0x80000000)
        {
            args_size = 0;
        }

        uint64_t func_size = 0;
        std::map<uint64_t, std::string> file_line_map;
        if (is_file_line_enabled)
        {
            file_line_map = init_file_line_map(gopclntab, func_info_addr, &func_size);
        }
        std::map<uint64_t, uint64_t> sp_map = init_sp_map(gopclntab, func_info_addr, &func_size);

        GoFunc go_func = { func_addr_value, func_size, func_name, args_size, file_line_map, sp_map };
        go_func_list->push_back(go_func);
    }
    return true;
}


void make_comment_map(const std::map<uint64_t, std::string>& file_line_map, const std::map<uint64_t, uint64_t>& sp_map, std::map<uint64_t, std::string>* comment_map)
{
    for (auto& i : file_line_map)
    {
        if (comment_map->count(i.first))
        {
            (*comment_map)[i.first] += " " + i.second;
        }
        else
        {
            (*comment_map)[i.first] = i.second;
        }
    }

    for (auto& i : sp_map)
    {
        char sp_string[MAX_PATH] = { 0 };
        _snprintf_s(sp_string, sizeof(sp_string), MAX_PATH, "sp:%#llx", i.second);
        if (comment_map->count(i.first))
        {
            (*comment_map)[i.first] += " " + std::string(sp_string);
        }
        else
        {
            (*comment_map)[i.first] = std::string(sp_string);
        }
    }
}

void set_functions_info(const std::vector<GoFunc>& go_func_list)
{
    for (auto go_func : go_func_list)
    {
        DbgSetLabelAt((duint)go_func.addr, go_func.name.c_str());
        DbgFunctionAdd((duint)go_func.addr, (duint)go_func.addr + (duint)go_func.size - 1);

        if (!get_line_enabled())
        {
            continue;
        }
        std::map<uint64_t, std::string> comment_map;
        make_comment_map(go_func.file_line_map, go_func.sp_map, &comment_map);
        if (comment_map.size() == 0)
        {
            continue;
        }
        for (auto& j : comment_map)
        {
            DbgSetCommentAt((duint)go_func.addr + (duint)j.first, j.second.c_str());
        }
        char func_comment[MAX_COMMENT_SIZE] = { 0 };
        _snprintf_s(func_comment, sizeof(func_comment), _TRUNCATE, "%s args:%d %s", go_func.name.c_str(), go_func.args_size, comment_map.at(0).c_str());
        DbgSetCommentAt((duint)go_func.addr, func_comment);
    }
}


bool get_target_function(const std::vector<GoFunc>& go_func_list, duint target_pc, GoFunc* target_func)
{
    for (auto& go_func : go_func_list)
    {
        if (go_func.addr <= target_pc && target_pc < go_func.addr + go_func.size)
        {
            *target_func = go_func;
            return true;
        }
    }
    return false;
}

bool get_target_stack_size(const GoFunc& go_func, duint target_pc, duint* target_size)
{
    if (target_pc < go_func.addr && go_func.addr + go_func.size <= target_pc)
    {
        return false;
    }
    duint stack_size = 0;
    for (auto& i : go_func.sp_map)
    {
        if (i.first > target_pc - go_func.addr)
        {
            break;
        }
        stack_size = i.second;
    }
    *target_size = stack_size;
    return true;
}
