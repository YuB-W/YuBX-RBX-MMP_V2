#pragma once
#include <cstdint>
#include <iostream>
#include <string>

namespace cfgoffsets
{

#define RELOC_FLAG(RelInfo) (((RelInfo) >> 12) == IMAGE_REL_BASED_DIR64)

#define CFG_PAGE_HASH_KEY       0xe852b98e
#define CFG_VALIDATION_XOR      0xd7

#define HashPage(Page) \
    ((((uintptr_t)(Page) >> 12) ^ CFG_PAGE_HASH_KEY))

#define ValidationByte(Page) \
    ((((uintptr_t)(Page) >> 44) ^ CFG_VALIDATION_XOR))

#define BatchWhitelistRegion(Start, Size)                                                      \
{                                                                                              \
    uint8_t stack_block[0x40] = {};                                                            \
    uintptr_t AlignedStart = (uintptr_t)(Start) & ~0xFFFULL;                                   \
    uintptr_t AlignedEnd   = ((uintptr_t)(Start) + (Size) + 0xFFFULL) & ~0xFFFULL;             \
    for (uintptr_t Page = AlignedStart; Page < AlignedEnd; Page += 0x1000)                     \
    {                                                                                          \
        uint32_t page_hash = HashPage(Page);                                                   \
        uint8_t validation = ValidationByte(Page);                                             \
        *reinterpret_cast<uint32_t*>(stack_block + 0x18) = page_hash;                          \
        *reinterpret_cast<uint8_t*>(stack_block + 0x1C) = validation;                          \
        insert_set(whitelist,                                                                  \
                   stack_block + 0x28,                                                         \
                   stack_block + 0x18);                                                        \
    }                                                                                          \
}

}