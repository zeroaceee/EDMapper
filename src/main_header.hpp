#pragma once
#include <iostream>
#include <stdint.h>
#include <thread>
#include <chrono>
#include "memory/memory_handlers.hpp"
#include "pe/portable_executable.hpp"

namespace Edmapper{
	using namespace memory;
	using namespace portable_exe;
}


// remove this from global 
std::uint32_t g_process_id;
std::uintptr_t g_base;
std::uint8_t* rawDll_data;
std::size_t rawDll_dataSize;

