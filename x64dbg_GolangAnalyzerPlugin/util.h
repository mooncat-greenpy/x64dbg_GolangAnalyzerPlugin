#pragma once

#include "x64dbg_GolangAnalyzerPlugin.h"

#define PLUGIN_NAME_LOG_HEADER "[" PLUGIN_NAME "] "
#define goanalyzer_logprintf(format, ...) _plugin_logprintf(PLUGIN_NAME_LOG_HEADER format, __VA_ARGS__)
#define goanalyzer_logputs(text) _plugin_logputs(PLUGIN_NAME_LOG_HEADER text)
#define logprintf(format, ...) _plugin_logprintf(format, __VA_ARGS__)
#define logputs(text) _plugin_logputs(text)


int zig_zag_decode(unsigned int);
bool read_dbg_memory(duint va, void* dest, duint size);
