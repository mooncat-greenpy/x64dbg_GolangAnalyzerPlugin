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
        for (size_t j = 0; j < resion_size - sizeof(go12_gopclntab_magic) - 32; j++)
        {
            if (memcmp(mem_data + j, go12_gopclntab_magic, sizeof(go12_gopclntab_magic)))
            {
                continue;
            }
            unsigned char* tmp_gopclntab_base = mem_data + j;
            memcpy_s(gopclntab, sizeof(GOPCLNTAB), tmp_gopclntab_base, 8);

            if ((gopclntab->quantum != 1 && gopclntab->quantum != 2 && gopclntab->quantum != 4) ||
                (gopclntab->pointer_size != 4 && gopclntab->pointer_size != 8)) {
                continue;
            }
            memcpy_s(&gopclntab->func_num, sizeof(gopclntab->func_num), tmp_gopclntab_base + 8, 4);// gopclntab->pointer_size);

            unsigned char* func_list_base = tmp_gopclntab_base + 8 + gopclntab->pointer_size;
            unsigned long long func_info_offset = 0;
            memcpy_s(&func_info_offset, sizeof(func_info_offset), func_list_base + gopclntab->pointer_size, gopclntab->pointer_size);
            if (tmp_gopclntab_base + func_info_offset + 8 >= mem_data + resion_size)
            {
                continue;
            }

            unsigned long long func_addr_value = 0;
            memcpy_s(&func_addr_value, sizeof(func_addr_value), func_list_base, gopclntab->pointer_size);
            unsigned long long func_entry_value = 0;
            memcpy_s(&func_entry_value, sizeof(func_entry_value), tmp_gopclntab_base + func_info_offset, gopclntab->pointer_size);
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
    return true;
}


bool analyze_file_name(const GOPCLNTAB* gopclntab)
{
    if (gopclntab == NULL)
    {
        return false;
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


bool pc_to_file_name(const GOPCLNTAB* gopclntab, unsigned long long func_info_offset, unsigned long long target_pc_offset, char* file_name, size_t file_name_size)
{
    unsigned int pcfile_offset = 0;
    read_dbg_memory(gopclntab->addr + (duint)func_info_offset + gopclntab->pointer_size + 4 * 4, &pcfile_offset, 4);
    long long file_no = -1;
    unsigned int i = 0;
    boolean first = true;
    unsigned long long pc_offset = 0;
    while (true)
    {
        unsigned int decoded_file_no_add = read_pc_data(gopclntab->addr + pcfile_offset, &i);
        unsigned int byte_size = read_pc_data(gopclntab->addr + pcfile_offset, &i);
        if (decoded_file_no_add == 0 && !first) {
            break;
        }
        first = false;
        int file_no_add = zig_zag_decode(decoded_file_no_add);
        file_no += file_no_add;
        pc_offset += (unsigned long long)byte_size * gopclntab->quantum;

        if (target_pc_offset <= pc_offset)
        {
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


std::map<unsigned long long, std::string> init_file_line_map(const GOPCLNTAB* gopclntab, unsigned long long func_info_offset, unsigned long long* func_size)
{
    std::map<unsigned long long, std::string> file_line_comment_map;
    file_line_comment_map.clear();

    unsigned int pcln_offset = 0;
    read_dbg_memory(gopclntab->addr + (duint)func_info_offset + gopclntab->pointer_size + 5 * 4, &pcln_offset, 4);
    long long line_num = -1;
    unsigned int i = 0;
    bool first = true;
    unsigned long long pc_offset = 0;
    while (true) {
        unsigned int decoded_line_num_add = read_pc_data(gopclntab->addr + pcln_offset, &i);
        unsigned int byte_size = read_pc_data(gopclntab->addr + pcln_offset, &i);
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
            if (!pc_to_file_name(gopclntab, func_info_offset, pc_offset, file_name, sizeof(file_name))) {
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
