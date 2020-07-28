#include "../memory/memory_handlers.hpp"


inline bool hook_iat_function(std::uintptr_t process_base_address,const std::string_view import_name, void* pointerToShellcode)
{
	// check if we got valid args or use assert??
	if (!pointerToShellcode || import_name.empty() || !process_base_address)
		return false;


	IMAGE_DOS_HEADER dos_header = { 0 };

	if (!memory::Read(process_base_address, &dos_header, sizeof(dos_header)))
		return false;

	// check if we got valid PE file
	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) 
		return false;

	IMAGE_NT_HEADERS nt_headers = { 0 };

	if (!memory::Read(process_base_address + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)))
		return false;

	// check if we got valid nt headers
	if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return false;

	// check if we got a 64 bit image
	if (nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return false;

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
			return false;

		// read current imported dll name
		if (!memory::Read(process_base_address + import_desc.Name,&ModuleName,sizeof(ModuleName)))
			return false;

		
		auto ModuleBase = LoadLibraryA(ModuleName);
		if (!ModuleBase) return false;
	
		IMAGE_THUNK_DATA first_thunk = { 0 };
		IMAGE_THUNK_DATA originalfirst_thunk = { 0 };

		if (!memory::Read(process_base_address + import_desc.FirstThunk,&first_thunk,sizeof(first_thunk)))
			return false;

		if (!memory::Read(process_base_address + import_desc.OriginalFirstThunk, &originalfirst_thunk, sizeof(originalfirst_thunk)))
			return false;

		int n = 1; // since we already read the first struct in line 65 & 68 we set this to start looping from the second struct which is 1
		// everytime this loops strats n will be set to 1.

		while (originalfirst_thunk.u1.AddressOfData != NULL)
		{
			// if import by ordinal then go to next import and don't try to read the name of this since its ordinal
			if (IMAGE_SNAP_BY_ORDINAL(originalfirst_thunk.u1.Ordinal))
				goto nextstruct;

			// read function name
			if (!memory::Read(process_base_address + originalfirst_thunk.u1.AddressOfData + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name),&import_function_name,sizeof(import_function_name)))
				return false;
				
			// std::cout << "Module :" << ModuleName << " " << "Function ->" << "[" << import_function_name << "]" << '\n';


			// don't let this confuse you this checks if strcmp will return 0 meaning that our string matched with the function name!
			if (!strcmp(import_function_name, import_name.data()))
			{
				std::cout << "Hooking ->" << import_function_name << '\n';

				// we are checking the page that has our offset to function pointer that we are going to hook
				// basically we are using FIELD_OFFSET to get a field offset inside a struct aka get offset to that member of struct
				// and checking if memory is writable before trying to write to it because almost everytime its going to be PAGE readonly
				MEMORY_BASIC_INFORMATION mb = { 0 };
				if (!memory::VirtualQueryExPage(process_base_address + import_desc.FirstThunk + FIELD_OFFSET(IMAGE_THUNK_DATA, u1.Function),mb))
					return false;

				DWORD old_protection = 0;
				if (mb.Protect == PAGE_READONLY)
				{
					// page is read only
					// size is 8 bytes since u1.Function is actually 8 bytes long
					// set page to be readable and writeable
					if (!memory::VirtualprotectExPage(process_base_address + import_desc.FirstThunk + FIELD_OFFSET(IMAGE_THUNK_DATA, u1.Function),sizeof(void*),PAGE_READWRITE,&old_protection))
						return false;
				}

				// here we are over-writting the original function pointer with our shellcode pointer
				if (!memory::Write(process_base_address + import_desc.FirstThunk + FIELD_OFFSET(IMAGE_THUNK_DATA, u1.Function),&pointerToShellcode,sizeof(void*)))
					return false;

				// restore original pointer??



				// restore protection to readonly
				if (!memory::VirtualprotectExPage(process_base_address + import_desc.FirstThunk + FIELD_OFFSET(IMAGE_THUNK_DATA, u1.Function),sizeof(void*),old_protection,&old_protection))
					return false;

				return true;
			}

			// go to next function aka next IMAGE_IMPORT_BY_NAME struct in memory
		    nextstruct:
			if (!memory::Read(process_base_address + import_desc.FirstThunk + n * sizeof(IMAGE_THUNK_DATA),&first_thunk,sizeof(first_thunk)))
				break;

			if (!memory::Read(process_base_address + import_desc.OriginalFirstThunk + n * sizeof(IMAGE_THUNK_DATA),&originalfirst_thunk,sizeof(originalfirst_thunk)))
				break;

			n++;
		}


		i++; // advance to second struct that contains the second imported dll.
	} while (import_desc.Name != NULL);

	return false;
}