#pragma once
#include "Windows.h"
#include <cstdint>

namespace Whitelist_Offsets
{
	// these offsets change every update
	static const uintptr_t set_insert = 0xD868E0;
	static const uintptr_t Bitmap = 0x2B6660;
	static const uintptr_t whitelist_page = 0x2a2280;
}
