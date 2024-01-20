#include "gopclntab.h"


bool make_gopclntab(duint target_addr, GO_VERSION version, GOPCLNTAB* gopclntab)
{
    gopclntab->version = version;

    uint8_t* tmp_gopclntab_base = (uint8_t*)target_addr;
    if (!read_dbg_memory((duint)tmp_gopclntab_base, gopclntab, 8))
    {
        return false;
    }

    if ((gopclntab->quantum != 1 && gopclntab->quantum != 2 && gopclntab->quantum != 4) ||
        (gopclntab->pointer_size != sizeof(duint))) {
        return false;
    }
    if (!read_dbg_memory((duint)tmp_gopclntab_base + 8, &gopclntab->func_num, 4))
    {
        return false;
    }

    uint8_t* func_list_base;
    if (gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
    {
        uint8_t* tmp_addr = tmp_gopclntab_base + 8 + (uint32_t)gopclntab->pointer_size * 7;
        uint64_t tmp_value = 0;
        if (!read_dbg_memory((duint)tmp_addr, &tmp_value, gopclntab->pointer_size))
        {
            return false;
        }
        func_list_base = tmp_gopclntab_base + tmp_value;
    }
    else if (gopclntab->version == GO_VERSION::GO_116)
    {
        uint8_t* tmp_addr = tmp_gopclntab_base + 8 + (uint32_t)gopclntab->pointer_size * 6;
        uint64_t tmp_value = 0;
        if (!read_dbg_memory((duint)tmp_addr, &tmp_value, gopclntab->pointer_size))
        {
            return false;
        }
        func_list_base = tmp_gopclntab_base + tmp_value;
    }
    else
    {
        func_list_base = tmp_gopclntab_base + 8 + gopclntab->pointer_size;
    }

    uint64_t functab_field_size = gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 ? 4 : gopclntab->pointer_size;
    uint64_t func_info_offset = 0;
    if (!read_dbg_memory((duint)func_list_base + functab_field_size, &func_info_offset, functab_field_size))
    {
        return false;
    }

    uint64_t func_addr_value = 0;
    if (!read_dbg_memory((duint)func_list_base, &func_addr_value, functab_field_size))
    {
        return false;
    }

    uint64_t func_entry_value = 0;
    uint8_t* func_entry_value_base;
    if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
    {
        func_entry_value_base = func_list_base;
    }
    else
    {
        func_entry_value_base = tmp_gopclntab_base;
    }
    if (!read_dbg_memory((duint)func_entry_value_base + func_info_offset, &func_entry_value, functab_field_size))
    {
        return false;
    }
    if (func_addr_value == func_entry_value && (gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 || func_addr_value != 0)) {
        gopclntab->addr = (duint)tmp_gopclntab_base;
        gopclntab->func_list_base = (duint)func_list_base;
        gopclntab->func_info_offset = func_info_offset;
        uint32_t file_name_table_offset = 0;
        duint file_name_table_offset_addr = gopclntab->func_list_base + (duint)gopclntab->func_num * gopclntab->pointer_size * 2 + gopclntab->pointer_size;
        if (!read_dbg_memory(file_name_table_offset_addr, &file_name_table_offset, 4))
        {
            return false;
        }
        gopclntab->file_name_table = gopclntab->addr + file_name_table_offset;

        if (get_line_enabled())
        {
            return analyze_file_name(gopclntab);
        }
        return true;
    }
    return false;
}

bool get_gopclntab(GOPCLNTAB* gopclntab)
{
#define GOPCLNTAB_MAGIC_COUNT 4
    uint8_t gopclntab_magic[GOPCLNTAB_MAGIC_COUNT][4] = {
        { 0xfb, 0xff, 0xff, 0xff },
        { 0xfa, 0xff, 0xff, 0xff },
        { 0xf0, 0xff, 0xff, 0xff },
        { 0xf1, 0xff, 0xff, 0xff },
    };
    GO_VERSION go_version[GOPCLNTAB_MAGIC_COUNT] = {
        GO_VERSION::GO_12,
        GO_VERSION::GO_116,
        GO_VERSION::GO_118,
        GO_VERSION::GO_120,
    };

    for (int i = 0; i < GOPCLNTAB_MAGIC_COUNT; i++)
    {
        std::vector<duint> gopclntab_addr_list;
        search_dbg_memory(gopclntab_addr_list, 0, gopclntab_magic[i], sizeof(gopclntab_magic[i]));

        for (auto addr : gopclntab_addr_list)
        {
            if (make_gopclntab(addr, go_version[i], gopclntab))
            {
                return true;
            }
        }
    }
    return false;
}


bool analyze_file_name(GOPCLNTAB* gopclntab)
{
    if (gopclntab == NULL)
    {
        return false;
    }
    if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
    {
        return true;
    }

    uint32_t size = 0;
    if (!read_dbg_memory(gopclntab->file_name_table, &size, 4))
    {
        goanalyzer_logputs("Failed to get size");
        return false;
    }

    gopclntab->file_name_list.clear();
    for (uint32_t i = 1; i < size; i++)
    {
        duint offset_addr = gopclntab->file_name_table + (duint)i * 4;
        uint32_t offset = 0;
        if (!read_dbg_memory(offset_addr, &offset, 4))
        {
            goanalyzer_logprintf("Failed to get offset %p\n", offset_addr);
            return false;
        }

        duint file_name_addr = gopclntab->addr + offset;
        size_t file_name_size = MAX_PATH;
        char file_name[MAX_PATH] = { 0 };
        if (!DbgMemIsValidReadPtr(file_name_addr))
        {
            goanalyzer_logprintf("Failed to get file_name %p\n", file_name_addr);
            return false;
        }

        while (file_name_size > 1)
        {
            if (DbgMemIsValidReadPtr(file_name_addr + file_name_size))
            {
                break;
            }
            file_name_size--;
        }

        if (!read_dbg_memory(file_name_addr, file_name, file_name_size))
        {
            return false;
        }
        file_name[sizeof(file_name) - 1] = '\0';
        gopclntab->file_name_list.push_back(file_name);
    }
    return true;
}


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


bool pc_to_file_name(const GOPCLNTAB* gopclntab, uint64_t func_info_addr, uint64_t target_pc_offset, char* file_name, size_t file_name_size)
{
    uint64_t functab_field_size = gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 ? 4 : gopclntab->pointer_size;

    uint32_t pcfile_offset = 0;
    read_dbg_memory(func_info_addr + functab_field_size + 4 * 4, &pcfile_offset, 4);
    duint pcfile_base = gopclntab->addr + pcfile_offset;
    if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
    {
        uint64_t tmp_value = 0;
        if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * (gopclntab->version == GO_VERSION::GO_116 ? 5 : 6), &tmp_value, gopclntab->pointer_size))
        {
            return false;
        }
        pcfile_base = gopclntab->addr + (duint)tmp_value + pcfile_offset;
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
        pc_offset += (uint64_t)byte_size * gopclntab->quantum;

        if (target_pc_offset <= pc_offset)
        {
            if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
            {
                uint32_t cu_offset = 0;
                if (!read_dbg_memory(func_info_addr + functab_field_size + 4 * 7, &cu_offset, 4))
                {
                    return false;
                }
                uint64_t tmp_value = 0;
                if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * (gopclntab->version == GO_VERSION::GO_116 ? 3 : 4), &tmp_value, gopclntab->pointer_size))
                {
                    return false;
                }
                duint cutab_base = gopclntab->addr + (duint)tmp_value;
                uint32_t file_no_offset = 0;
                if (!read_dbg_memory(cutab_base + (cu_offset + (duint)file_no) * 4, &file_no_offset, 4))
                {
                    return false;
                }
                if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * (gopclntab->version == GO_VERSION::GO_116 ? 4 : 5), &tmp_value, gopclntab->pointer_size))
                {
                    return false;
                }
                duint file_name_addr = gopclntab->addr + (duint)tmp_value + file_no_offset;
                char tmp_file_name[MAX_PATH] = {};
                if (!read_dbg_memory(file_name_addr, tmp_file_name, sizeof(tmp_file_name)))
                {
                    return false;
                }
                strncpy_s(file_name, file_name_size, tmp_file_name, _TRUNCATE);
                return true;
            }
            if (file_no - 1 < 0 || gopclntab->file_name_list.size() <= (size_t)file_no - 1)
            {
                goanalyzer_logprintf("Error file name list index out of range: %d\n", file_no - 1);
                return false;
            }
            strncpy_s(file_name, file_name_size, gopclntab->file_name_list.at((size_t)file_no - 1).c_str(), _TRUNCATE);
            return true;
        }
    }
    return false;
}


std::map<uint64_t, std::string> init_file_line_map(const GOPCLNTAB* gopclntab, duint func_info_addr, uint64_t* func_size)
{
    std::map<uint64_t, std::string> file_line_comment_map;
    file_line_comment_map.clear();

    uint64_t functab_field_size = gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 ? 4 : gopclntab->pointer_size;
    uint32_t pcln_offset = 0;
    read_dbg_memory(func_info_addr + functab_field_size + 5 * 4, &pcln_offset, 4);
    duint pcln_base;
    if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
    {
        uint64_t tmp_value = 0;
        if (!read_dbg_memory(gopclntab->addr + 8 + (uint32_t)gopclntab->pointer_size * (gopclntab->version == GO_VERSION::GO_116 ? 5 : 6), &tmp_value, gopclntab->pointer_size))
        {
            return file_line_comment_map;
        }
        pcln_base = gopclntab->addr + (duint)tmp_value + pcln_offset;
    }
    else
    {
        pcln_base = gopclntab->addr + pcln_offset;
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
        pc_offset += (uint64_t)byte_size * gopclntab->quantum;

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


std::map<uint64_t, uint64_t> init_sp_map(const GOPCLNTAB* gopclntab, duint func_info_addr, uint64_t* func_size)
{
    std::map<uint64_t, uint64_t> sp_comment_map;

    uint64_t functab_field_size = gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 ? 4 : gopclntab->pointer_size;
    uint32_t pcsp_offset = 0;
    read_dbg_memory(func_info_addr + functab_field_size + 3 * 4, &pcsp_offset, 4);
    duint pcsp_base = gopclntab->addr + pcsp_offset;
    if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
    {
        uint64_t tmp_value = 0;
        if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * (gopclntab->version == GO_VERSION::GO_116 ? 5 : 6), &tmp_value, gopclntab->pointer_size))
        {
            return sp_comment_map;
        }
        pcsp_base = gopclntab->addr + (duint)tmp_value + pcsp_offset;
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
        pc_offset += (uint64_t)byte_size * gopclntab->quantum;

        sp_comment_map[key] = sp_size;
    }
    *func_size = pc_offset;
    return sp_comment_map;
}
