#include "util.h"


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


bool read_dbg_memory(duint va, void* dest, duint size)
{
    if (!DbgMemIsValidReadPtr(va) || !DbgMemRead(va, dest, size))
    {
        return false;
    }
    return true;
}
