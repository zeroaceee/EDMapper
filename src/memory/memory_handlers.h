#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include <memory>
#include <string_view>
#include <stdint.h>
#include <fstream>
#include <vector>

#pragma warning( disable : 6289)

struct close_handle {
	using pointer = HANDLE;
	void operator()(HANDLE handle)
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
			CloseHandle(handle);
	}
};

// make those private later lol and make code look cleaner
using process_handle = std::unique_ptr<HANDLE, close_handle>;
std::unique_ptr<HANDLE,close_handle> gProc_handle;

namespace memory{
	inline std::uint32_t GetProcessID(std::wstring_view process_name);
	inline process_handle OpenProcessHandle(const std::uint32_t process_id);
	inline std::uintptr_t GetModuleBase(std::wstring_view module_name);
	inline bool GetRawDataFromFile(std::wstring_view file_name);

	template<class T>
	inline T Read(std::uintptr_t address)
	{
		T buffer;
		ReadProcessMemory(gProc_handle.get(), reinterpret_cast<LPVOID>(address), & buffer, sizeof(T), std::nullptr_t);
		return buffer;
	}

	template<class H>
	inline bool Write(std::uintptr_t address, H value)
	{
		if (WriteProcessMemory(gProc_handle.get(), reinterpret_cast<LPVOID>(address),&value,sizeof(H),std::nullptr_t))
			return true;
		else
			return false;
	}
}


std::uint32_t memory::GetProcessID(std::wstring_view process_name) {
	PROCESSENTRY32 processentry;

	const std::unique_ptr<HANDLE, close_handle>
		snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return 0;

	processentry.dwSize = sizeof(PROCESSENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE) {
		if (process_name.compare(processentry.szExeFile) == 0)
			return processentry.th32ProcessID;
	}
	return 0;
}


process_handle memory::OpenProcessHandle(const std::uint32_t process_id)
{
	if (process_id == 0)
		return nullptr;

	process_handle handle(OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, process_id));

	if (handle.get() == nullptr)
		return nullptr;

	return handle;
}


extern std::uint32_t g_process_id;

std::uintptr_t memory::GetModuleBase(std::wstring_view module_name)
{
	const std::unique_ptr<HANDLE, close_handle> 
		snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, g_process_id));
	
	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);

	while (Module32Next(snapshot_handle.get(), &entry)) {
		if (!wcscmp(entry.szModule, module_name.data()))
			return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
	}
	return 0;
}


extern std::vector<wchar_t> raw_data;
extern std::size_t raw_dataSize;



bool memory::GetRawDataFromFile(std::wstring_view file_name)
{
    std::wifstream file(file_name.data(), std::wifstream::binary);

	if (file)
	{
		file.seekg(0, file.end);
		raw_dataSize = file.tellg();
		file.seekg(0, file.beg);
		
		// resize our vector to allocate enough space for our raw data capactiy will be extended automatically
		 raw_data.resize(raw_dataSize);

		file.read(raw_data.data(), raw_dataSize);
		
		file.close();
		return true;
	}
	else
	{
		return false;
	}
	
}