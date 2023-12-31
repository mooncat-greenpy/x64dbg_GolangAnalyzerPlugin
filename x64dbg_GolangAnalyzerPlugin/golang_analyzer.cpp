#include "golang_analyzer.h"


void make_comment_map(std::map<uint64_t, std::string>& comment_map, uint64_t* func_size, const GOPCLNTAB* gopclntab, duint func_info_addr)
{
    comment_map.clear();

    std::vector<std::map<uint64_t, std::string>> comment_info;
    comment_info.push_back(init_file_line_map(gopclntab, func_info_addr, func_size));
    comment_info.push_back(init_sp_map(gopclntab, func_info_addr));

    for (auto& i : comment_info)
    {
        for (auto& j : i)
        {
            if (comment_map.count(j.first))
            {
                comment_map[j.first] += " " + j.second;
            }
            else
            {
                comment_map[j.first] = j.second;
            }
        }
    }
}


bool analyze_functions(const GOPCLNTAB* gopclntab)
{
    if (gopclntab == NULL)
    {
        return false;
    }

    for (uint32_t i = 0; i < gopclntab->func_num; i++)
    {
        uint64_t functab_field_size = gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120 ? 4 : gopclntab->pointer_size;

        uint64_t func_addr_value = 0;
        if (!read_dbg_memory(gopclntab->func_list_base + (duint)i * functab_field_size * 2, &func_addr_value, functab_field_size))
        {
            return false;
        }
        if (gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
        {
            uint64_t text_addr = 0;
            if (!read_dbg_memory(gopclntab->addr + 8 + (uint32_t)gopclntab->pointer_size * 2, &text_addr, gopclntab->pointer_size))
            {
                return false;
            }
            func_addr_value += text_addr;
        }
        uint64_t func_info_offset = 0;
        if (!read_dbg_memory(gopclntab->func_list_base + (duint)i * functab_field_size * 2 + functab_field_size, &func_info_offset, functab_field_size))
        {
            return false;
        }
        duint func_info_addr = gopclntab->addr + (duint)func_info_offset;
        if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
        {
            func_info_addr = gopclntab->func_list_base + (duint)func_info_offset;
        }
        uint64_t func_entry_value = 0;
        if (!read_dbg_memory(func_info_addr, &func_entry_value, functab_field_size))
        {
            return false;
        }
        uint64_t func_name_offset = 0;
        if (!read_dbg_memory(func_info_addr + functab_field_size, &func_name_offset, 4))
        {
            return false;
        }

        char func_name[MAX_PATH] = { 0 };
        duint func_name_base = gopclntab->addr;
        if (gopclntab->version == GO_VERSION::GO_116 || gopclntab->version == GO_VERSION::GO_118 || gopclntab->version == GO_VERSION::GO_120)
        {
            uint64_t tmp_value = 0;
            if (!read_dbg_memory(gopclntab->addr + 8 + (uint32_t)gopclntab->pointer_size * (gopclntab->version == GO_VERSION::GO_116 ? 2 : 3), &tmp_value, gopclntab->pointer_size))
            {
                return false;
            }
            func_name_base = gopclntab->addr + (duint)tmp_value;
        }
        if (!read_dbg_memory(func_name_base + (duint)func_name_offset, func_name, sizeof(func_name)))
        {
            return false;
        }
        func_name[sizeof(func_name) - 1] = '\0';
        DbgSetLabelAt((duint)func_addr_value, func_name);

        uint32_t args_num = 0;
        if (!read_dbg_memory(func_info_addr + functab_field_size + 4, &args_num, 4))
        {
            return false;
        }
        if (args_num >= 0x80000000)
        {
            args_num = 0;
        }

        uint64_t func_size = 0;
        std::map<uint64_t, std::string> comment_map;
        make_comment_map(comment_map, &func_size, gopclntab, func_info_addr);

        DbgFunctionAdd((duint)func_addr_value, (duint)func_addr_value + (duint)func_size - 1);

        if (get_line_enabled() && comment_map.size() > 0)
        {
            for (auto& j : comment_map)
            {
                DbgSetCommentAt((duint)func_addr_value + (duint)j.first, j.second.c_str());
            }
            char func_comment[MAX_COMMENT_SIZE] = { 0 };
            char comment[MAX_COMMENT_SIZE] = { 0 };
            DbgGetCommentAt((duint)func_addr_value, comment);
            _snprintf_s(func_comment, sizeof(func_comment), _TRUNCATE, "%s args:%d %s", func_name, args_num, comment_map.at(0).c_str());
            DbgSetCommentAt((duint)func_addr_value, func_comment);
        }
    }

    return true;
}


struct MODULE_DATA
{
    duint type_addr = 0;
    duint typelink_addr = 0;
    duint typelink_len = 0;
    duint text_addr = 0;
};

struct DATATYPE
{
    std::string name;
};

bool get_type_string(std::string& str, duint addr, uint8_t tflag)
{
    uint8_t mem[0x103] = {};
    if (!read_dbg_memory(addr, mem, sizeof(mem)))
    {
        return false;
    }

    uint32_t name_idx = 2;
    uint8_t str_size = mem[1];
    if (str_size == 0)
    {
        // TODO: check go version
        name_idx = 3;
        str_size = mem[2];
        if (str_size == 0)
        {
            return false;
        }
    }
    mem[name_idx + str_size] = '\0';
    bool is_extrastar = str_size > 0 && (tflag & 1 << 1) > 0;
    str = (char*)&mem[name_idx + (is_extrastar ? 1 : 0)];
    return true;
}

bool parse_datatype(DATATYPE* datatype, const GOPCLNTAB* gopclntab, duint type_base, uint32_t offset)
{
    uint8_t mem[8 * 50] = {};
    if (!read_dbg_memory(type_base + offset, mem, sizeof(mem)))
    {
        return false;
    }

    uint8_t tflag = mem[gopclntab->pointer_size * 2 + 4];
    uint32_t name_off = *(uint32_t*)(mem + gopclntab->pointer_size * 4 + 4 + 1 * 4);

    if (!get_type_string(datatype->name, type_base + name_off, tflag))
    {
        return false;
    }

    DbgSetLabelAt(type_base + offset, datatype->name.c_str());
    return true;
}

bool parse_module_data(MODULE_DATA* module_data, const GOPCLNTAB* gopclntab, duint module_data_base)
{
    uint8_t mem[8 * 50] = {};
    if (!read_dbg_memory(module_data_base, mem, sizeof(mem)))
    {
        return false;
    }

    if (gopclntab->version == GO_VERSION::GO_120)
    {
        if (memcpy_s(&module_data->type_addr, sizeof(module_data->type_addr), &mem[37 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_addr, sizeof(module_data->type_addr), &mem[44 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_len, sizeof(module_data->type_addr), &mem[45 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->text_addr, sizeof(module_data->type_addr), &mem[22 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
    }
    else if (gopclntab->version == GO_VERSION::GO_118)
    {
        if (memcpy_s(&module_data->type_addr, sizeof(module_data->type_addr), &mem[35 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_addr, sizeof(module_data->type_addr), &mem[42 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_len, sizeof(module_data->type_addr), &mem[43 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->text_addr, sizeof(module_data->type_addr), &mem[22 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
    }
    else if (gopclntab->version == GO_VERSION::GO_116)
    {
        if (memcpy_s(&module_data->type_addr, sizeof(module_data->type_addr), &mem[35 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_addr, sizeof(module_data->type_addr), &mem[40 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_len, sizeof(module_data->type_addr), &mem[41 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->text_addr, sizeof(module_data->type_addr), &mem[22 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
    }
    else
    {
        if (memcpy_s(&module_data->type_addr, sizeof(module_data->type_addr), &mem[25 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_addr, sizeof(module_data->type_addr), &mem[30 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->typelink_len, sizeof(module_data->type_addr), &mem[31 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
        if (memcpy_s(&module_data->text_addr, sizeof(module_data->type_addr), &mem[12 * gopclntab->pointer_size], gopclntab->pointer_size))
        {
            return false;
        }
    }
    /*else if (gopclntab->version == GO_VERSION::GO_18)
    {

    }
    else if (gopclntab->version == GO_VERSION::GO_17)
    {

    }*/
    if (!DbgMemIsValidReadPtr(module_data->type_addr) ||
        !DbgMemIsValidReadPtr(module_data->typelink_addr) ||
        !DbgMemIsValidReadPtr(module_data->text_addr))
    {
        return false;
    }

    DATATYPE datatype = {};
    duint offset = 0;
    if (!read_dbg_memory(module_data->typelink_addr, &offset, 4 < sizeof(duint) ? 4 : sizeof(duint)))
    {
        return false;
    }

    if (!parse_datatype(&datatype, gopclntab, module_data->type_addr, offset))
    {
        return false;
    }
    return true;
}

bool analyze_datatypes(const GOPCLNTAB* gopclntab)
{
    std::vector<duint> module_data_base_list;
    search_dbg_memory(module_data_base_list, 0, (uint8_t*)&gopclntab->addr, gopclntab->pointer_size);

    for (duint module_data_base : module_data_base_list)
    {
        MODULE_DATA module_data = {};
        if (!parse_module_data(&module_data, gopclntab, module_data_base))
        {
            continue;
        }

        uint8_t* mem = new uint8_t[module_data.typelink_len * 4];
        if (!read_dbg_memory(module_data.typelink_addr, mem, module_data.typelink_len * 4))
        {
            delete[] mem;
            continue;
        }

        for (duint i = 0; i < module_data.typelink_len; i++)
        {
            duint offset = ((uint32_t*)mem)[i];
            DATATYPE datatype = {};
            parse_datatype(&datatype, gopclntab, module_data.type_addr, offset);
        }
        delete[] mem;
    }
}

duint get_go_routine_id(bool* result)
{
    if (sizeof(duint) == 4)// gopclntab.pointer_size
    {
        return DbgEval("[[fs:[0x14]]+0x50]", result);
    }
    else {
        duint sp = DbgEval("rsp", result);
        if (!result)
        {
            return false;
        }
        bool lo_result = false;
        bool hi_result = false;
        duint lo = DbgEval("[[gs:[0x28]]+0x0]", &lo_result);
        duint hi = DbgEval("[[gs:[0x28]]+0x8]", &hi_result);
        if (lo <= sp && sp < hi)
        {
            return DbgEval("[[gs:[0x28]]+0x98]", result);
        }
        lo = DbgEval("[r14+0x0]", &lo_result);
        hi = DbgEval("[r14+0x8]", &hi_result);
        if (lo <= sp && sp < hi)
        {
            return DbgEval("[r14+0x98]", result);
        }
        *result = false;
        return 0;
    }
}


bool command_callback(int argc, char* argv[])
{
    if (argc < 1)
    {
        return false;
    }

    if (strstr(argv[0], "help"))
    {
        goanalyzer_logputs("Golang Analyzer: Help\n"
            "Command:\n"
            "    GoAnalyzer.help\n"
            "    GoAnalyzer.analyze\n"
            "    GoAnalyzer.line.enable\n"
            "    GoAnalyzer.line.disable");
    }
    else if (strstr(argv[0], "analyze"))
    {
        GOPCLNTAB gopclntab_base = {};
        if (!get_gopclntab(&gopclntab_base))
        {
            goanalyzer_logputs("Golang Analyzer: Failed to get gopclntab");
            return false;
        }
        if (!analyze_file_name(&gopclntab_base))
        {
            goanalyzer_logputs("Golang Analyzer: Failed to get file name");
            return false;
        }
        if (!analyze_functions(&gopclntab_base))
        {
            goanalyzer_logputs("Golang Analyzer: Failed to analyze functions");
            return false;
        }
        if (!analyze_datatypes(&gopclntab_base))
        {
            goanalyzer_logputs("Golang Analyzer: Failed to analyze datatypes");
            return false;
        }
        goanalyzer_logputs("Golang Analyzer: Analyze");
    }
    else if (strstr(argv[0], "line.enable"))
    {
        set_line_enabled(true);
    }
    else if (strstr(argv[0], "line.disable"))
    {
        set_line_enabled(false);
    }
    else if (strstr(argv[0], "gid"))
    {
        bool result = false;
        duint gid = get_go_routine_id(&result);
        if (result)
        {
            goanalyzer_logprintf("Golang Analyzer: gid = %p\n", gid);
        }
        else
        {
            goanalyzer_logprintf("Golang Analyzer: Failed to get gid\n");
        }
        return result;
    }

    return true;
}


bool init_analyzer_plugin()
{
    _plugin_registercommand(pluginHandle, "GoAnalyzer.help", command_callback, false);
    _plugin_registercommand(pluginHandle, "GoAnalyzer.analyze", command_callback, false);
    _plugin_registercommand(pluginHandle, "GoAnalyzer.line.enable", command_callback, false);
    _plugin_registercommand(pluginHandle, "GoAnalyzer.line.disable", command_callback, false);
    _plugin_registercommand(pluginHandle, "GoAnalyzer.gid", command_callback, false);

    return true;
}


bool stop_analyzer_plugin()
{
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.help");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.analyze");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.line.enable");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.line.disable");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.gid");

    return true;
}


void setup_analyzer_plugin()
{
}
