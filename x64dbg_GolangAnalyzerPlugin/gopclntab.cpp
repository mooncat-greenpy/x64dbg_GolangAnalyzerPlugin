#include "gopclntab.h"

static std::vector<std::string> file_name_list;


bool get_gopclntab(GOPCLNTAB* gopclntab)
{
    if (gopclntab == NULL)
    {
        return false;
    }

    MEMMAP memory_map = { 0 };
    if (!DbgMemMap(&memory_map) || memory_map.page == NULL)
    {
        return false;
    }

    for (int i = 0; i < memory_map.count; i++)
    {
        unsigned char* mem_addr = (unsigned char*)memory_map.page[i].mbi.BaseAddress;
        size_t resion_size = memory_map.page[i].mbi.RegionSize;
        if (resion_size <= 0)
        {
            continue;
        }

        unsigned char* mem_data = new unsigned char[resion_size];
        if (!read_dbg_memory((duint)mem_addr, mem_data, resion_size))
        {
            delete[] mem_data;
            continue;
        }

        unsigned char go12_gopclntab_magic[] = { 0xfb, 0xff, 0xff, 0xff };
        unsigned char go16_gopclntab_magic[] = { 0xfa, 0xff, 0xff, 0xff };
        for (size_t j = 0; j < resion_size - sizeof(go12_gopclntab_magic) - 32; j++)
        {
            *gopclntab = {};
            if (memcmp(mem_data + j, go12_gopclntab_magic, sizeof(go12_gopclntab_magic)))
            {
                if (memcmp(mem_data + j, go16_gopclntab_magic, sizeof(go16_gopclntab_magic)))
                {
                    continue;
                }
                gopclntab->version = GO_VERSION::GO_116;
            }
            else
            {
                gopclntab->version = GO_VERSION::GO_112;
            }
            unsigned char* tmp_gopclntab_base = mem_data + j;
            memcpy_s(gopclntab, sizeof(GOPCLNTAB), tmp_gopclntab_base, 8);

            if ((gopclntab->quantum != 1 && gopclntab->quantum != 2 && gopclntab->quantum != 4) ||
                (gopclntab->pointer_size != 4 && gopclntab->pointer_size != 8)) {
                continue;
            }
            memcpy_s(&gopclntab->func_num, sizeof(gopclntab->func_num), tmp_gopclntab_base + 8, 4);// gopclntab->pointer_size);

            unsigned char* func_list_base = tmp_gopclntab_base + 8 + gopclntab->pointer_size;
            if (gopclntab->version == GO_116)
            {
                unsigned char* tmp_addr = tmp_gopclntab_base + 8 + gopclntab->pointer_size * 6;
                unsigned long long tmp_value = 0;
                memcpy_s(&tmp_value, sizeof(tmp_value), tmp_addr, gopclntab->pointer_size);
                func_list_base = tmp_gopclntab_base + tmp_value;
            }
            unsigned long long func_info_offset = 0;
            memcpy_s(&func_info_offset, sizeof(func_info_offset), func_list_base + gopclntab->pointer_size, gopclntab->pointer_size);
            if (tmp_gopclntab_base + func_info_offset + 8 >= mem_data + resion_size)
            {
                continue;
            }

            unsigned long long func_addr_value = 0;
            memcpy_s(&func_addr_value, sizeof(func_addr_value), func_list_base, gopclntab->pointer_size);
            unsigned long long func_entry_value = 0;
            unsigned char* func_entry_value_base = tmp_gopclntab_base;
            if (gopclntab->version == GO_116)
            {
                func_entry_value_base = func_list_base;
            }
            memcpy_s(&func_entry_value, sizeof(func_entry_value), func_entry_value_base + func_info_offset, gopclntab->pointer_size);
            if (func_addr_value == func_entry_value && func_addr_value != 0) {
                gopclntab->addr = (duint)(tmp_gopclntab_base - mem_data + mem_addr);
                gopclntab->func_list_base = (duint)(func_list_base - mem_data + mem_addr);
                gopclntab->func_info_offset = func_info_offset;
                unsigned int file_name_table_offset = 0;
                duint file_name_table_offset_addr = gopclntab->func_list_base + (duint)gopclntab->func_num * gopclntab->pointer_size * 2 + gopclntab->pointer_size;
                if (!read_dbg_memory(file_name_table_offset_addr, &file_name_table_offset, 4))
                {
                    continue;
                }
                gopclntab->file_name_table = gopclntab->addr + file_name_table_offset;
                delete[] mem_data;
                return true;
            }
        }
        delete[] mem_data;
    }
    return false;
}


bool analyze_file_name(const GOPCLNTAB* gopclntab)
{
    if (gopclntab == NULL)
    {
        return false;
    }
    if (gopclntab->version == GO_116)
    {
        return true;
    }

    unsigned int size = 0;
    if (!read_dbg_memory(gopclntab->file_name_table, &size, 4))
    {
        goanalyzer_logputs("Failed to get size");
        return false;
    }
    file_name_list.clear();
    for (unsigned int i = 1; i < size; i++)
    {
        duint offset_addr = gopclntab->file_name_table + (duint)i * 4;
        unsigned int offset = 0;
        if (!read_dbg_memory(offset_addr, &offset, 4))
        {
            goanalyzer_logprintf("Failed to get offset %p\n", offset_addr);
            return false;
        }

        duint file_name_addr = gopclntab->addr + offset;
        int file_name_size = MAX_PATH;
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
        file_name_list.push_back(file_name);
    }
    return true;
}


unsigned int read_pc_data(duint addr, unsigned int* i)
{
    if (!DbgMemIsValidReadPtr(addr)) {
        return 0;
    }
    unsigned int value = 0;
    for (unsigned int shift = 0;; shift += 7) {
        unsigned int tmp = 0;
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


bool pc_to_file_name(const GOPCLNTAB* gopclntab, duint func_info_addr, unsigned long long target_pc_offset, char* file_name, size_t file_name_size)
{
    unsigned int pcfile_offset = 0;
    read_dbg_memory(func_info_addr + gopclntab->pointer_size + 4 * 4, &pcfile_offset, 4);
    duint pcfile_base = gopclntab->addr + pcfile_offset;
    if (gopclntab->version == GO_116)
    {
        unsigned long long tmp_value = 0;
        if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * 5, &tmp_value, gopclntab->pointer_size))
        {
            return false;
        }
        pcfile_base = gopclntab->addr + tmp_value + pcfile_offset;
    }

    long long file_no = -1;
    unsigned int i = 0;
    boolean first = true;
    unsigned long long pc_offset = 0;
    while (true)
    {
        unsigned int decoded_file_no_add = read_pc_data(pcfile_base, &i);
        unsigned int byte_size = read_pc_data(pcfile_base, &i);
        if (decoded_file_no_add == 0 && !first) {
            break;
        }
        first = false;
        int file_no_add = zig_zag_decode(decoded_file_no_add);
        file_no += file_no_add;
        pc_offset += (unsigned long long)byte_size * gopclntab->quantum;

        if (target_pc_offset <= pc_offset)
        {
            if (gopclntab->version == GO_116)
            {
                unsigned int cu_offset = 0;
                if (!read_dbg_memory(func_info_addr + gopclntab->pointer_size + 4 * 7, &cu_offset, 4))
                {
                    return false;
                }
                unsigned long long tmp_value = 0;
                if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * 3, &tmp_value, gopclntab->pointer_size))
                {
                    return false;
                }
                duint cutab_base = gopclntab->addr + tmp_value;
                unsigned int file_no_offset = 0;
                if (!read_dbg_memory(cutab_base + (cu_offset + file_no) * 4, &file_no_offset, 4))
                {
                    return false;
                }
                if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * 4, &tmp_value, gopclntab->pointer_size))
                {
                    return false;
                }
                duint file_name_addr = gopclntab->addr + tmp_value + file_no_offset;
                char tmp_file_name[MAX_PATH] = {};
                if (!read_dbg_memory(file_name_addr, tmp_file_name, sizeof(tmp_file_name)))
                {
                    return false;
                }
                strncpy_s(file_name, file_name_size, tmp_file_name, _TRUNCATE);
                return true;
            }
            if ((int)file_no - 1 < 0 || file_name_list.size() <= (size_t)file_no - 1)
            {
                goanalyzer_logprintf("Error file name list index out of range: %#x\n", (int)file_no - 1);
                return false;
            }
            strncpy_s(file_name, file_name_size, file_name_list.at((size_t)file_no - 1).c_str(), _TRUNCATE);
            return true;
        }
    }
    return false;
}


std::map<unsigned long long, std::string> init_file_line_map(const GOPCLNTAB* gopclntab, duint func_info_addr, unsigned long long* func_size)
{
    std::map<unsigned long long, std::string> file_line_comment_map;
    file_line_comment_map.clear();

    unsigned int pcln_offset = 0;
    read_dbg_memory(func_info_addr + gopclntab->pointer_size + 5 * 4, &pcln_offset, 4);
    duint pcln_base = gopclntab->addr + pcln_offset;
    if (gopclntab->version == GO_116)
    {
        unsigned long long tmp_value = 0;
        if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * 5, &tmp_value, gopclntab->pointer_size))
        {
            return file_line_comment_map;
        }
        pcln_base = gopclntab->addr + tmp_value + pcln_offset;
    }

    long long line_num = -1;
    unsigned int i = 0;
    bool first = true;
    unsigned long long pc_offset = 0;
    while (true) {
        unsigned int decoded_line_num_add = read_pc_data(pcln_base, &i);
        unsigned int byte_size = read_pc_data(pcln_base, &i);
        if (decoded_line_num_add == 0 && !first)
        {
            break;
        }

        first = false;
        unsigned long long key = pc_offset;
        int line_num_add = zig_zag_decode(decoded_line_num_add);
        line_num += line_num_add;
        pc_offset += (unsigned long long)byte_size * gopclntab->quantum;

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


std::map<unsigned long long, std::string> init_sp_map(const GOPCLNTAB* gopclntab, duint func_info_addr)
{
    std::map<unsigned long long, std::string> sp_comment_map;

    unsigned int pcsp_offset = 0;
    read_dbg_memory(func_info_addr + gopclntab->pointer_size + 3 * 4, &pcsp_offset, 4);
    duint pcsp_base = gopclntab->addr + pcsp_offset;
    if (gopclntab->version == GO_116)
    {
        unsigned long long tmp_value = 0;
        if (!read_dbg_memory(gopclntab->addr + 8 + gopclntab->pointer_size * 5, &tmp_value, gopclntab->pointer_size))
        {
            return sp_comment_map;
        }
        pcsp_base = gopclntab->addr + tmp_value + pcsp_offset;
    }

    long long sp_size = -1;
    unsigned int i = 0;
    bool first = true;
    unsigned long long pc_offset = 0;
    while (true) {
        unsigned int decoded_sp_size_add = read_pc_data(pcsp_base, &i);
        unsigned int byte_size = read_pc_data(pcsp_base, &i);
        if (decoded_sp_size_add == 0 && !first)
        {
            break;
        }

        first = false;
        unsigned long long key = pc_offset;
        int sp_size_add = zig_zag_decode(decoded_sp_size_add);
        sp_size += sp_size_add;
        pc_offset += (unsigned long long)byte_size * gopclntab->quantum;

        if (get_line_enabled())
        {
            char sp_string[MAX_PATH] = { 0 };
            _snprintf_s(sp_string, sizeof(sp_string), MAX_PATH, "sp:%lld", sp_size);
            sp_comment_map[key] = sp_string;
        }
    }
    return sp_comment_map;
}
