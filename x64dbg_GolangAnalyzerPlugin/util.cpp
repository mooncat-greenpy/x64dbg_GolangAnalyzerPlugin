#include "util.h"


bool read_dbg_memory(duint va, void* dest, duint size)
{
    if (!DbgMemIsValidReadPtr(va) || !DbgMemRead(va, dest, size))
    {
        return false;
    }
    return true;
}

void search_dbg_memory(std::vector<duint>* result, const uint8_t* target, int target_size)
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
        if (resion_size <= 0 || resion_size > 0x10000000)
        {
            continue;
        }

        std::vector<uint8_t> mem_data(resion_size, 0);
        if (!read_dbg_memory((duint)mem_addr, mem_data.data(), mem_data.size()))
        {
            continue;
        }

        for (size_t j = 0; j < mem_data.size() - target_size; j++)
        {
            if (!memcmp(mem_data.data() + j, target, target_size))
            {
                result->push_back((duint)(mem_addr + j));
            }
        }
    }
}
