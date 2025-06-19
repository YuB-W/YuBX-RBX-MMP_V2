#pragma once
#include "Windows.h"
#include <cstdint>

namespace Whitelist_Offsets
{
	// these offsets change every update
	static const uintptr_t set_insert = 0xD0D0F0;
	static const uintptr_t Bitmap = 0x2A6938;
	static const uintptr_t whitelist_page = 0x2A5A70;
}
