#include "../memory/memory_handlers.hpp"
#include "shellcode.hpp"
#include <thread>         
#include <chrono>         


inline std::uint64_t get_ptr_to_iatfunc(std::uintptr_t process_base_address, const std::string_view import_name)
{
	// check if we got valid args
	if (import_name.empty() || !process_base_address)
	{
		std::cerr << "get_iat_function_pointer : invalid args passed." << '\n';
		return 0;
	}

	IMAGE_DOS_HEADER dos_header = { 0 };

	if (!memory::Read(process_base_address, &dos_header, sizeof(dos_header)))
		return 0;

	// check if we got valid PE file
	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) 
		return 0;

	IMAGE_NT_HEADERS nt_headers = { 0 };

	if (!memory::Read(process_base_address + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)))
		return 0;

	// check if we got valid nt headers
	if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	// check if we got a 64 bit image
	if (nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 0;

	IMAGE_IMPORT_DESCRIPTOR import_desc = { 0 };

	const auto rva_to_iat = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	const auto iat_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

	int i = 0;
	char ModuleName[100]; // set this to 100 so it can hold 100 char's i don't think that dll names would require more than that.
	char import_function_name[200]; // holds imported function names

	do
	{
		// read offset to our .idata section 
		// we need to loop through all imported dll's each dll has its own struct which is the IMAGE_IMPORT_DESCRIPTOR struct
		// to read all structs we need to advance to next struct each time we finish reading imports from a specific dll
		// todo that we use this calculation where var i = 0 which means read the first struct in memory
		// after that var (i) will be 1 so 1 * the size of the struct means go to next struct of memory 
		// because when we add the size of struct 1 time we are saying like skip this struct and go to the other in memory i hope it makes since
		// because they are in contiguous memory meaning that they are after each other in memory
		if (!memory::Read(process_base_address + rva_to_iat + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), &import_desc, sizeof(import_desc)))
			return 0;

		// read current imported dll name
		if (!memory::Read(process_base_address + import_desc.Name,&ModuleName,sizeof(ModuleName)))
			return 0;

		
		auto ModuleBase = LoadLibraryA(ModuleName);
		if (!ModuleBase) return 0;
	
		int func_index = 0; 

		IMAGE_THUNK_DATA originalfirst_thunk = { 0 };
		if (!memory::Read(process_base_address + import_desc.OriginalFirstThunk, &originalfirst_thunk, sizeof(originalfirst_thunk)))
			return 0;

		int n = 1; // since we already read the first struct in line 69 & 72 we set this to start looping from the second struct which is 1
		// everytime this loops strats n will be set to 1.
		while (originalfirst_thunk.u1.AddressOfData != NULL)
		{
			// if import by ordinal then go to next import and don't try to read the name of this since its ordinal
			if (IMAGE_SNAP_BY_ORDINAL(originalfirst_thunk.u1.Ordinal))
				goto nextstruct;

			// read function name
			if (!memory::Read(process_base_address + originalfirst_thunk.u1.AddressOfData + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),&import_function_name,sizeof(import_function_name)))
				return 0;
				
			// std::cout << "Module :" << ModuleName << " " << "Function ->" << "[" << import_function_name << "]" << '\n';

			/*
			what are we doing here?
			basically if we read the memory at : process_base_address + import_desc.FirstThunk 
			we will be dereferencing the pointer that points to the (iat function ADDRESS) and will give us 
			the address to the first instruction inside the function but since we don't want to hook there (although we could)
			but its going to be messy since we need a fixed amount of bytes to replace and it changes from 1 function to another 
			instead what we will do is return the pointer address that POINTS to iat function address and we will replace it to point to our OWN function address
			how can we do that?
			simple just don't read process_base_address + import_desc.FirstThunk from memory(aka derf it) just get the pointer address as it is
			*/

			// NOTE : this ptr is placed in .rdata (aka readonly) section

			// don't let this confuse you this checks if strcmp will return 0 meaning that our string matched with the function name!
			if (!strcmp(import_function_name, import_name.data()))
				return process_base_address + import_desc.FirstThunk + func_index * sizeof(ULONGLONG);
			

			// go to next function aka next IMAGE_IMPORT_BY_NAME struct in memory
		    nextstruct:
			if (!memory::Read(process_base_address + import_desc.OriginalFirstThunk + n * sizeof(IMAGE_THUNK_DATA),&originalfirst_thunk,sizeof(originalfirst_thunk)))
				break;

			n++;
		}

		i++; // advance to second struct that contains the second imported dll.
	} while (import_desc.Name != NULL);

	return 0;
}



inline bool hook_iat_function(std::uint64_t iat_function_ptr, void* ptr_to_shellcode)
{
	if (!iat_function_ptr || ptr_to_shellcode == nullptr)
		return false;

	MEMORY_BASIC_INFORMATION mb = { 0 };
	if (!memory::VirtualQueryExPage(iat_function_ptr, mb))
		return false;


	DWORD old_protection = 0;

	if (mb.Protect == PAGE_EXECUTE_READ || mb.Protect == PAGE_READONLY)
	{
		// if DEP is enabled we are going to crash with access violation
		// change protection of page to read/write so we can change function ptr with WriteprocessMemory
		if (!memory::VirtualprotectExPage(iat_function_ptr,sizeof(std::uint64_t), PAGE_READWRITE,&old_protection))
			return false;
	}

	// save old function ptr
	const auto original_func_ptr = iat_function_ptr;

	std::printf("[+] original function ptr : %p \n", (void*)original_func_ptr);

	// write func ptr and wait for shellcode to finish
	if (!memory::Write(iat_function_ptr, &ptr_to_shellcode, sizeof(void*)))
		return false;
		
	// check if shellcode finished executing
	byte signal = 0;
	const auto offset_byte = assembly::signal_byte_offset(ptr_to_shellcode);

	std::printf("[+] byte address : %p \n", (void*)offset_byte);

	for (;;)
	{
		if (!memory::Read(offset_byte, &signal, sizeof(byte)))
		{
			std::cerr << "failed to read signal byte." << '\n';
			return false; // failed to read from address
		}

		// signaled.
		if (signal == 1)
			break;
	}

	// restore protection to iat_func_ptr in .rdata section
	if (!memory::VirtualprotectExPage(iat_function_ptr, sizeof(std::uint64_t), old_protection, &old_protection))
		return false;

	return true;
}