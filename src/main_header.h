#pragma once
#include <iostream>
#include <stdint.h>
#include "memory/memory_handlers.h"
#include "pe/portable_executable.h"

namespace Edmapper{
	using namespace memory;
	using namespace portable_exe;
}


// remove this from global if possible
std::uint32_t g_process_id;
std::uintptr_t g_base;
std::uint8_t* raw_data;
std::size_t raw_dataSize;