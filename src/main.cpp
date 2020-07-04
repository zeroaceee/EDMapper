#include "main_header.hpp"

int main()
{
	// get process id

	g_process_id = Edmapper::GetProcessID("notepad.exe");

	if (g_process_id == 0) {
		std::printf("[-]Couldn't get process ID\n");
		return -1;
	}


	// open handle to process

	gProc_handle = Edmapper::OpenProcessHandle(g_process_id);

	// add check for handle here.

	// read dll

	if (Edmapper::GetRawDataFromFile("C:\\Users\\User\\Desktop\\cpp-projects\\EDMapper\\x64\\Release\\test.dll") != false)
	{
		std::cout << "read dll." << '\n';
	}

	// validate image

	if (Edmapper::IsValidImage())
	{
		std::cout << "Image is valid." << '\n';
	}

	// allocate local image 
	const auto image_size = pOldnt_headers->OptionalHeader.SizeOfImage;
	const auto image_base = pOldnt_headers->OptionalHeader.ImageBase;
	void* l_image = nullptr;
	l_image = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	if (!l_image)
	{
		delete[] rawDll_data;
		return -1;
	}

	// copy all headers from our dll image.
	std::memcpy(l_image, rawDll_data,pOldnt_headers->OptionalHeader.SizeOfHeaders);


	// copy sections into local image.
	Edmapper::CopyImageSections(l_image,pOldnt_headers);


	// fix imports
	if (!Edmapper::FixImageImports(l_image, pOldnt_headers))
	{
		std::cerr << "[ERROR] couldn't fix image imports" << '\n';
		delete[] rawDll_data;
		return -1;
	}
		
	// fix relocation


	// TODO fix TLS callbacks


	// call shellcode

	std::printf("Everything worked.\n");
	VirtualFree(nullptr, 0, MEM_RELEASE);
	delete[] rawDll_data;

	std::cin.get();
}