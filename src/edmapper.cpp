#include "edmapper.hpp"

bool Edmapper::dll_map::map_dll(const std::string_view proccess_name, const std::string_view dll_path)
{
	// get process id

	if (!memory::GetProcessID(proccess_name))
		return false;

	this->process_id = memory::return_processid();

	// open handle to process

	if (!memory::OpenProcessHandle(this->process_id))
		return false;

	// open our dll file & get data
	if (!memory::GetRawDataFromFile(dll_path, this->rawDll_data, this->rawDll_dataSize))
		return false;

	// validate image
	this->pnt_headers = portable_exe::IsValidImage(this->rawDll_data);

	if (this->pnt_headers == nullptr)
	{
		delete[] this->rawDll_data;
		return false;
	}
	else
		std::printf("Valid image.\n");

	// allocate local image 
	const auto image_size = this->pnt_headers->OptionalHeader.SizeOfImage;

	this->l_image = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!this->l_image)
	{
		delete[] this->rawDll_data;
		return false;
	}

	// copy all headers from our dll image.
	std::memcpy(l_image, rawDll_data, this->pnt_headers->OptionalHeader.SizeOfHeaders);


	// copy sections into local image.
	portable_exe::CopyImageSections(this->l_image, this->pnt_headers, this->rawDll_data);

	std::printf("Sections copied.\n");

	// fix imports

	if (!portable_exe::FixImageImports(this->l_image, this->pnt_headers, this->rawDll_data))
	{
		// no need to delete this->rawDll_data since this function already does that.
		std::cerr << "[ERROR] couldn't fix image imports" << '\n';
		VirtualFree(this->l_image, 0, MEM_RELEASE);
		return false;
	}

	std::printf("Imports fixed.\n");

	// allocate image in target process

	const auto image_base = this->pnt_headers->OptionalHeader.ImageBase;

	// first try to allocate at prefered load address
	this->m_image = VirtualAllocEx(memory::get_handle(), reinterpret_cast<LPVOID>(image_base), image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!this->m_image)
	{
		// if we couldn't allocate at prefered address then just allocate memory on any random place in memory 
		// but we will need to fix relocation of image
		this->m_image = VirtualAllocEx(memory::get_handle(), nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		// if faild to allocate then cleanup & return
		if (!this->m_image)
		{
			delete[] this->rawDll_data;
			VirtualFree(this->l_image, 0, MEM_RELEASE);
			std::cerr << "[ERROR] couldn't allocate memory in target process." << '\n';
			return false;
		}

		// fix relocation
		portable_exe::FixImageRelocations(this->m_image, this->l_image, this->pnt_headers, this->rawDll_data);

		std::printf("Fixed relocations!\n");
	}

	// no need to fix relocations since we loaded at prefered base address.

	// write content of our dll aka local image into the allocated memory in target process
	if (!memory::Write(reinterpret_cast<std::uintptr_t>(this->m_image), this->l_image, image_size))
	{
		delete[] this->rawDll_data;
		VirtualFree(this->l_image, 0, MEM_RELEASE);
		VirtualFreeEx(memory::get_handle(), this->m_image, 0, MEM_RELEASE);
		std::cerr << "[ERROR] couldn't copy image to target process." << '\n';
		return false;
	}

	std::printf("Wrote image to target process.\n");

	// call shellcode

	// get entrypoint address for our dll
	// this->pnt_headers->OptionalHeader.AddressOfEntryPoint : is an RVA from base address
	const auto Entryaddress = reinterpret_cast<std::uintptr_t>(this->m_image) + this->pnt_headers->OptionalHeader.AddressOfEntryPoint;


	// hardcoded shellcode
	BYTE shellcode[] = {
		0x50, // push rax save old register so we don't corrupt it
		0x48, 0xB8, 0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, // mov rax,0xff00efbeadde00ff <- this value is just a place that will get replaced by our entrypoint pointer
		0x52, // push rdx save old register so we don't corrupt it
		0x48, 0x31, 0xD2, // xor rdx,rdx
		0x48, 0x83, 0xC2, 0x01, //  add rdx,byte +0x0 (add 1 bit to rdx)
		0x48, 0x83, 0xEC, 0x28, // sub rsp,0x28 (align the stack and shadow space allocation)
		0xFF, 0xD0, // call rax 
		0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
		0x58, // pop rax (restore rax)
		0x5A, // pop rdx (restore rdx)
		0xC3 // ret (return)
	};

	// note 0x1020 is an RVA to where the location that i want to jmp to. to get there we need to add image base + rva
	*(std::uintptr_t*)(shellcode + 3) = (std::uintptr_t)m_image + 0x1020; // Hardcoded offset

	/*
	TODO : use code cave for shellcode instead of allocating it to be extra stealth
	*/

	// allocate memory for our shellcode inside target process
	auto pShellCode = VirtualAllocEx(memory::get_handle(), nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellCode)
	{
		delete[] this->rawDll_data;
		VirtualFreeEx(memory::get_handle(), this->m_image, 0, MEM_RELEASE);
		VirtualFree(this->l_image, 0, MEM_RELEASE);
		std::cerr << "[ERROR] failed to allocate memory for shellcode in target process." << '\n';
		return false;
	}

	std::printf("[+]Allocated memory for shellcode at : %p \n", pShellCode);

	// write our shellcode into memory
	if (!memory::Write((std::uintptr_t)pShellCode, shellcode, sizeof(shellcode)))
	{
		delete[] this->rawDll_data;
		VirtualFreeEx(memory::get_handle(), this->m_image, 0, MEM_RELEASE);
		VirtualFreeEx(memory::get_handle(), pShellCode, 0, MEM_RELEASE);
		VirtualFree(this->l_image, 0, MEM_RELEASE);
		std::cerr << "[ERROR] failed to write shellcode to memory" << '\n';
		return false;
	}


	if (!hook_iat_function(memory::GetModuleBase(proccess_name.data()), "MessageBoxW", pShellCode))
	{
		delete[] this->rawDll_data;
		VirtualFreeEx(memory::get_handle(), this->m_image, 0, MEM_RELEASE);
		VirtualFreeEx(memory::get_handle(), pShellCode, 0, MEM_RELEASE);
		VirtualFree(this->l_image, 0, MEM_RELEASE);
		std::cerr << "[ERROR] failed to hook function pointer[IAT]." << '\n';
		return false;
	}

	// print msg here.

	/*
	// this will execute our shellcode inside the target process
	auto thread_h = CreateRemoteThread(memory::get_handle(), 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode), 0, 0, 0);
	if (!thread_h)
	{
		delete[] this->rawDll_data;
		VirtualFreeEx(memory::get_handle(), this->m_image, 0, MEM_RELEASE);
		VirtualFreeEx(memory::get_handle(), pShellCode, 0, MEM_RELEASE);
		VirtualFree(this->l_image, 0, MEM_RELEASE);
		std::cerr << "[ERROR] failed to create thread in target process." << '\n';
		return false;
	}

	// wait for the thread to finish executing shellcode.
	WaitForSingleObject(thread_h, INFINITE);

	// close thread handle.
	CloseHandle(thread_h); */
	// free shellcode in our target process
	VirtualFreeEx(memory::get_handle(), pShellCode, 0, MEM_RELEASE);
	// free local image
	VirtualFree(this->l_image, 0, MEM_RELEASE);
	// free our raw dll data
	delete[] this->rawDll_data;

	return true;
}