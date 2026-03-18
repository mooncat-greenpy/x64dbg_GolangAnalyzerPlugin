#include "util.h"


bool read_dbg_memory(duint va, void* dest, duint size)
{
    if (!DbgMemRead(va, dest, size))
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

    std::vector<int> bm_table(256, target_size);
    for (int i = 0; i < target_size - 1; ++i)
    {
        bm_table[target[i]] = target_size - i - 1;
    }

    for (int i = 0; i < memory_map.count; i++)
    {
        uint8_t* mem_addr = (uint8_t*)memory_map.page[i].mbi.BaseAddress;
        size_t region_size = memory_map.page[i].mbi.RegionSize;
        if (region_size <= 0 || region_size > 0x10000000)
        {
            continue;
        }

        std::vector<uint8_t> mem_data(region_size, 0);
        if (!read_dbg_memory((duint)mem_addr, mem_data.data(), mem_data.size()))
        {
            continue;
        }

        size_t j = 0;
        while (j <= mem_data.size() - target_size)
        {
            int k = target_size - 1;
            while (k >= 0 && target[k] == mem_data[j + k])
            {
                --k;
            }
            if (k < 0)
            {
                result->push_back((duint)(mem_addr + j));
                j += target_size;
            }
            else
            {
                j += max(1, bm_table[mem_data[j + target_size - 1]] - (target_size - 1 - k));
            }
        }
    }
}

duint get_section_start(const char* sec)
{
    duint mod = DbgValFromString("mod.main()");
    if (!mod)
    {
        return 0;
    }

    MEMMAP map{};
    if (!DbgMemMap(&map))
    {
        return 0;
    }

    duint ret = 0;
    char name[MAX_SECTION_SIZE * 5]{};
    for (int i = 0; i < map.count; i++)
    {
        duint addr = (duint)map.page[i].mbi.BaseAddress;
        if (DbgFunctions()->ModBaseFromAddr(addr) != mod)
        {
            continue;
        }
        if (!DbgFunctions()->SectionFromAddr(addr, name))
        {
            continue;
        }
        if (std::strcmp(name, sec))
        {
            continue;
        }
        if (!ret || addr < ret)
        {
            ret = addr;
        }
    }

    if (map.page)
    {
        BridgeFree(map.page);
    }
    return ret;
}
