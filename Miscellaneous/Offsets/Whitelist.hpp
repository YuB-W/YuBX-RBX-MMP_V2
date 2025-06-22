#pragma once
#include "Windows.h"
#include <cstdint>

namespace Whitelist_Offsets
{
	// these offsets change every update
	static const uintptr_t set_insert = 0xDA4E70;
	static const uintptr_t Bitmap = 0x298668;
	static const uintptr_t whitelist_page = 0x297EC8;
}
