#pragma once

#include <Windows.h>
#include <tlhelp32.h>
#include <memory>
#include <string_view>
#include <stdint.h>
#include <fstream>

#pragma warning( disable : 6289)
#pragma warning( disable : 4996)


namespace memory{
	inline bool GetProcessID(const std::string_view process_name);
	inline std::uintptr_t GetModuleBase(const std::string_view module_name);
	inline bool GetRawDataFromFile(const std::string_view file_name,std::uint8_t* &raw_data,std::size_t &sizeOfRawData);

	

	namespace {
		// this struct will get called whenever a handle needs to be closed.
		struct close_handle {
			using pointer = HANDLE;
			void operator()(HANDLE handle)
			{
				if (handle)
					CloseHandle(handle);
			}
		};

		std::uint32_t process_id;
		using process_handle = std::unique_ptr<HANDLE, close_handle>;
		std::unique_ptr<HANDLE, close_handle> proc_handle;
	}

	// what is inline here?
	// https://stackoverflow.com/questions/22102919/static-vs-inline-for-functions-implemented-in-header-files
	inline HANDLE get_handle()
	{
		return proc_handle.get();
	}


	inline std::uint32_t return_processid()
	{
		return process_id;
	}

	inline void set_processid(std::uint32_t pid)
	{
		process_id = pid;
	}

	inline bool OpenProcessHandle(const std::uint32_t process_id)
	{
		if (process_id == 0)
			return false;

		process_handle handle(OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, process_id));

		if (handle.get() == nullptr)
			return false;

		// move ownership of object to ours.
		proc_handle = std::move(handle);

		return true;
	}

	
	inline bool Read(std::uintptr_t address, void* buffer, size_t size)
	{
		return ReadProcessMemory(memory::get_handle(), reinterpret_cast<LPVOID>(address), buffer, size, nullptr);
	}

	inline bool Write(std::uintptr_t address, void* buffer, size_t size)
	{
		return WriteProcessMemory(memory::get_handle(), reinterpret_cast<LPVOID>(address), buffer, size, nullptr);
	}

	inline bool VirtualprotectExPage(std::uintptr_t address, size_t size,DWORD protection,PDWORD old_protection)
	{
		return VirtualProtectEx(memory::get_handle(), reinterpret_cast<LPVOID>(address), size, protection, old_protection);
	}

	inline std::size_t VirtualQueryExPage(std::uintptr_t address,MEMORY_BASIC_INFORMATION &mb)
	{
		return VirtualQueryEx(memory::get_handle(), reinterpret_cast<LPVOID>(address), &mb,sizeof(mb));
	}
}


bool memory::GetProcessID(const std::string_view process_name) {
	PROCESSENTRY32 processentry;

	const std::unique_ptr<HANDLE, close_handle>
		snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return false;

	processentry.dwSize = sizeof(PROCESSENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE) {
		if (process_name.compare(processentry.szExeFile) == 0) 
		{
			memory::set_processid(processentry.th32ProcessID);
			return true;
		}
	}
	return false;
}


std::uintptr_t memory::GetModuleBase(const std::string_view module_name)
{
	const std::unique_ptr<HANDLE, close_handle> 
		snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, memory::return_processid()));
	
	MODULEENTRY32 entry;
	entry.dwSize = sizeof(MODULEENTRY32);

	while (Module32Next(snapshot_handle.get(), &entry)) {
		if (!strcmp(entry.szModule, module_name.data()))
			return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
	}
	return 0;
}



bool memory::GetRawDataFromFile(const std::string_view file_name, std::uint8_t* &raw_data, std::size_t &sizeOfRawData)
{
    std::ifstream file(file_name.data(), std::ifstream::binary);

	if (file)
	{
		file.seekg(0, file.end);
		sizeOfRawData = file.tellg();
		file.seekg(0, file.beg);

		raw_data = new std::uint8_t[sizeOfRawData];

		if (!raw_data)
			return false;
		
		file.read(reinterpret_cast<char*>(raw_data), sizeOfRawData);

		// fstream already closes our file when it goes out of scoop
		// if we tried to close it we will get an exception
		return true;
	}
	else
		return false;
}

