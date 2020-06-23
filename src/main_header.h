#pragma once
#include <iostream>
#include <stdint.h>
#include "memory/memory_handlers.h"


namespace Edmapper{
	using namespace memory;
}


// remove this from global if possible
std::uint32_t g_process_id;
std::uintptr_t g_base;