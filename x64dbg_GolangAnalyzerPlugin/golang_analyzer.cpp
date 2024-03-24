#include "golang_analyzer.h"
#include "golang_function.h"


duint get_go_routine_id(const GOPCLNTAB& gopclntab, bool* result)
{
    if (gopclntab.pointer_size == 4)
    {
        return DbgEval("[[fs:[0x14]]+0x50]", result);
    }
    else if(gopclntab.pointer_size == 8)
    {
        duint sp = DbgEval("rsp", result);
        if (!result)
        {
            return false;
        }
        bool lo_result = false;
        bool hi_result = false;
        if (gopclntab.version < GO_VERSION::GO_118)// < GO_117
        {
            duint lo = DbgEval("[[gs:[0x28]]+0x0]", &lo_result);
            duint hi = DbgEval("[[gs:[0x28]]+0x8]", &hi_result);
            if (lo <= sp && sp < hi)
            {
                return DbgEval("[[gs:[0x28]]+0x98]", result);
            }
        }
        if (gopclntab.version > GO_VERSION::GO_116)//  >= GO_117
        {
            duint lo = DbgEval("[r14+0x0]", &lo_result);
            duint hi = DbgEval("[r14+0x8]", &hi_result);
            if (lo <= sp && sp < hi)
            {
                return DbgEval("[r14+0x98]", result);
            }
        }
        *result = false;
        return 0;
    }
    else
    {
        *result = false;
        return 0;
    }
}


void print_call_stack(const std::vector<GoFunc>& go_func_list, duint pc, duint sp)
{
    bool result = false;
    for (int i = 0; i < 0x20; i++)
    {
        GoFunc go_func = {};
        if (!get_target_function(go_func_list, pc, &go_func))
        {
            return;
        }
        duint stack_size = 0;
        if (!get_target_stack_size(go_func, pc, &stack_size))
        {
            return;
        }
        sp += stack_size;
        char query[MAX_PATH] = {};
        _snprintf_s(query, sizeof(query), MAX_PATH, "[%p]", (void*)sp);
        duint ret_addr = DbgEval(query, &result);
        if (!result)
        {
            return;
        }
        goanalyzer_logprintf("Golang Analyzer: name=%s ip=%p sp=%s ret=%p\n", go_func.name.c_str(), pc, query, ret_addr);

        pc = ret_addr;
        sp += sizeof(duint);
    }
}


bool analyze_command()
{
    GOPCLNTAB gopclntab = {};
    if (!get_gopclntab(&gopclntab))
    {
        goanalyzer_logputs("Golang Analyzer: Failed to get gopclntab");
        return false;
    }
    std::vector<GoFunc> go_func_list;
    if (!analyze_functions(gopclntab, &go_func_list, get_line_enabled()))
    {
        goanalyzer_logputs("Golang Analyzer: Failed to analyze functions");
        return false;
    }
    set_functions_info(go_func_list);
    if (!analyze_datatypes(&gopclntab))
    {
        goanalyzer_logputs("Golang Analyzer: Failed to analyze datatypes");
        return false;
    }
    goanalyzer_logputs("Golang Analyzer: Analyze");
    return true;
}

bool gid_command()
{
    GOPCLNTAB gopclntab = {};
    if (!get_gopclntab(&gopclntab))
    {
        goanalyzer_logputs("Golang Analyzer: Failed to get gopclntab");
        return false;
    }

    bool result = false;
    duint gid = get_go_routine_id(gopclntab, &result);
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

bool callstack_command(duint ip, duint sp)
{
    GOPCLNTAB gopclntab_base = {};
    if (!get_gopclntab(&gopclntab_base))
    {
        goanalyzer_logputs("Golang Analyzer: Failed to get gopclntab");
        return false;
    }
    std::vector<GoFunc> go_func_list;
    if (!analyze_functions(gopclntab_base, &go_func_list, false))
    {
        goanalyzer_logputs("Golang Analyzer: Failed to analyze functions");
        return false;
    }

    print_call_stack(go_func_list, ip, sp);
    return true;
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
            "    GoAnalyzer.line.disable\n"
            "    GoAnalyzer.gid\n"
            "    GoAnalyzer.callstack [ip, sp]");
    }
    else if (strstr(argv[0], "analyze"))
    {
        return analyze_command();
    }
    else if (strstr(argv[0], "line.enable"))
    {
        set_line_enabled(true);
        goanalyzer_logputs("Golang Analyzer: Enabled");
    }
    else if (strstr(argv[0], "line.disable"))
    {
        set_line_enabled(false);
        goanalyzer_logputs("Golang Analyzer: Disabled");
    }
    else if (strstr(argv[0], "gid"))
    {
        return gid_command();
    }
    else if (strstr(argv[0], "callstack"))
    {
        bool result = false;
        duint ip = 0;
        duint sp = 0;
        if (argc > 2)
        {
            ip = DbgEval(argv[1], &result);
        }
        else
        {
            ip = DbgEval("cip", &result);
        }
        if (!result)
        {
            goanalyzer_logputs("Golang Analyzer: Failed to get ip");
            return false;
        }
        if (argc > 2)
        {
            sp = DbgEval(argv[2], &result);
        }
        else
        {
            sp = DbgEval("csp", &result);
        }
        if (!result)
        {
            goanalyzer_logputs("Golang Analyzer: Failed to get sp");
            return false;
        }
        goanalyzer_logprintf("Golang Analyzer: ip = %p, sp = %p\n", ip, sp);

        return callstack_command(ip, sp);
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
    _plugin_registercommand(pluginHandle, "GoAnalyzer.callstack", command_callback, false);

    return true;
}


bool stop_analyzer_plugin()
{
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.help");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.analyze");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.line.enable");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.line.disable");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.gid");
    _plugin_unregistercommand(pluginHandle, "GoAnalyzer.callstack");

    return true;
}


void setup_analyzer_plugin()
{
}
