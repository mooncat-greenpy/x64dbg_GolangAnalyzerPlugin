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

void search_dbg_memory(std::vector<duint>& result, duint base, uint8_t* target, int target_size)
{
    MEMMAP memory_map = {};
    if (!DbgMemMap(&memory_map) || memory_map.page == NULL)
    {
        return;
    }

    for (int i = 0; i < memory_map.count; i++)
    {
        uint8_t* mem_addr = (uint8_t*)memory_map.page[i].mbi.BaseAddress;
        size_t resion_size = memory_map.page[i].mbi.RegionSize;
        if (resion_size <= 0 || memory_map.page[i].mbi.Protect == 0)
        {
            continue;
        }

        uint8_t* mem_data = new uint8_t[resion_size];
        if (!read_dbg_memory((duint)mem_addr, mem_data, resion_size))
        {
            delete[] mem_data;
            continue;
        }

        for (size_t j = 0; j < resion_size - target_size; j++)
        {
            if (!memcmp(mem_data + j, target, target_size))
            {
                result.push_back((duint)(mem_addr + j));
            }
        }
        delete[] mem_data;
    }
}
