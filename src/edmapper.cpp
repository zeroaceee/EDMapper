#include "edmapper.hpp"


Edmapper::dll_map::~dll_map()
{
	if(this->rawDll_data)
		delete[] this->rawDll_data; // free allocated raw dll data
	
	if(this->l_image)
		VirtualFree(this->l_image, 0, MEM_RELEASE); // free local image

	if(this->m_image)
		VirtualFreeEx(memory::get_handle(), this->m_image, 0, MEM_RELEASE); // free mapped image

	if (this->pShellCode)
		VirtualFreeEx(memory::get_handle(), pShellCode, 0, MEM_RELEASE); // free mapped shellcode memory
}


bool Edmapper::dll_map::map_dll(const std::string_view proccess_name, const std::string_view dll_path, const std::string_view iat_functionName_to_hijack)
{
	// get process id

	if (!memory::GetProcessID(proccess_name))
	{
		std::cerr << "[-] couldn't obtain process id aborting." << '\n';
		return false;
	}
		
	this->process_id = memory::return_processid();

	// open handle to process

	if (!memory::OpenProcessHandle(this->process_id))
	{
		std::cerr << "[-] failed to open handle to process." << '\n';
		return false;
	}
		

	// open our dll file & get data
	if (!memory::GetRawDataFromFile(dll_path, this->rawDll_data, this->rawDll_dataSize))
	{
		std::cerr << "[-] failed to open file." << '\n';
		return false;
	}
		

	// validate image
	this->pnt_headers = portable_exe::IsValidImage(this->rawDll_data);

	if (this->pnt_headers == nullptr)
		return false;
	else
		std::printf("[+] image is valid.\n");
	

	// allocate local image 
	const auto image_size = this->pnt_headers->OptionalHeader.SizeOfImage;

	this->l_image = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!this->l_image)
	{
		std::cerr << "[-] failed allocate local image memory." << '\n';
		return false;
	}
		

	// copy all headers from our dll image.
	std::memcpy(l_image, rawDll_data, this->pnt_headers->OptionalHeader.SizeOfHeaders);


	// copy sections into local image.
	portable_exe::CopyImageSections(this->l_image, this->pnt_headers, this->rawDll_data);

	std::printf("[+] copied sections.\n");

	// fix imports

	if (!portable_exe::FixImageImports(this->l_image, this->pnt_headers, this->rawDll_data))
	{
		std::cerr << "[-] couldn't fix image imports." << '\n';	
		return false;
	}

	std::printf("[+] fixed imports.\n");

	// allocate image in target process

	const auto image_base = this->pnt_headers->OptionalHeader.ImageBase;

	// first try to allocate at prefered load address
	this->m_image = VirtualAllocEx(memory::get_handle(), reinterpret_cast<LPVOID>(image_base), image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!this->m_image)
	{
		// if we couldn't allocate at prefered address then just allocate memory on any random place in memory 
		// but we will need to fix relocation of image
		this->m_image = VirtualAllocEx(memory::get_handle(), nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!this->m_image)
		{
			std::cerr << "[-] couldn't allocate memory in target process." << '\n';
			return false;
		}

		// fix relocation
		portable_exe::FixImageRelocations(this->m_image, this->l_image, this->pnt_headers, this->rawDll_data);

		std::printf("[+] Fixed relocations!\n");
	}

	// no need to fix relocations since we loaded at prefered base address.

	// write content of our dll aka local image into the allocated memory in target process
	if (!memory::Write(reinterpret_cast<std::uintptr_t>(this->m_image), this->l_image, image_size))
	{
		std::cerr << "[-] couldn't copy image to target process." << '\n';
		return false;
	}

	std::printf("[+] Wrote image to target process.\n");


	// allocate memory for our shellcode inside target process
	this->pShellCode = VirtualAllocEx(memory::get_handle(), nullptr, sizeof(assembly::shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!this->pShellCode)
	{
		std::cerr << "[-] failed to allocate memory for shellcode in target process." << '\n';
		return false;
	}

	std::printf("[+] Allocated memory for shellcode at : %p \n", this->pShellCode);

	auto iat_func_ptr = get_ptr_to_iatfunc(memory::GetModuleBase(proccess_name.data()), iat_functionName_to_hijack.data());
	if (!iat_func_ptr)
		return false;

	auto entrypoint_jmp = reinterpret_cast<std::uintptr_t>(this->m_image) + 0x1020;

	std::uintptr_t iat_func_address = 0;
	if (!memory::Read(iat_func_ptr, &iat_func_address, sizeof(std::uintptr_t)))
		return false;


	// init shellcode 
	assembly::shellcode_insert_address<std::uintptr_t>(assembly::DLL_ENTRY_POINT, entrypoint_jmp);
	assembly::shellcode_insert_address<std::uintptr_t>(assembly::IAT_FUNCTION_PTR, iat_func_ptr);
	assembly::shellcode_insert_address<std::uintptr_t>(assembly::IAT_ORIGINAL_FUNCTION_ADDRESS, iat_func_address);

	// write our shellcode into memory
	if (!memory::Write((std::uintptr_t)this->pShellCode, assembly::shellcode, sizeof(assembly::shellcode)))
	{
		std::cerr << "[-] failed to write shellcode to memory" << '\n';
		return false;
	}

	if (!hook_iat_function(iat_func_ptr, this->pShellCode))
		return false;

	std::printf("[+] shellcode executed successfully.\n");	

	// free shellcode in our target process
	VirtualFreeEx(memory::get_handle(), this->pShellCode, 0, MEM_RELEASE);
	// free local image
	VirtualFree(this->l_image, 0, MEM_RELEASE);
	// free our raw dll data
	delete[] this->rawDll_data;

	return true;
}