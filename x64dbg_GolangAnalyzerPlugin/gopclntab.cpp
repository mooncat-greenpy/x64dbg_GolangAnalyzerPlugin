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

    duint functab_field_size = gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 ? 4 : gopclntab->pointer_size;
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

bool analyze_file_name(GOPCLNTAB* gopclntab)
{
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
        search_dbg_memory(&gopclntab_addr_list, gopclntab_magic[i], sizeof(gopclntab_magic[i]));

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
