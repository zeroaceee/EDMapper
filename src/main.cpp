#include "main_header.h"

int main()
{
	// get process id

	g_process_id = Edmapper::GetProcessID("notepad.exe");
	
	if (g_process_id == 0)
		return -1;

	// open handle to process

	gProc_handle =  Edmapper::OpenProcessHandle(g_process_id);

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
		
	// allocate memory in target process

	const auto image_size = pnt_headers->OptionalHeader.SizeOfImage;
	void* mapped_image = nullptr;
	
	mapped_image = VirtualAllocEx(gProc_handle.get(), nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (mapped_image == nullptr)
	{
		std::cerr << "Failed to allocate memory in target process." << '\n';
		return -1;
	}
	
	// create a local image to copy stuff to
	
	void* local_image = nullptr;
	local_image = VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (local_image == nullptr)
	{
		std::cerr << "Failed to allocate memory locally." << '\n';
		return -1;
	}

	// copy all headers from our dll image.
	std::memcpy(local_image,raw_data.data(),pnt_headers->OptionalHeader.SizeOfHeaders);

	// better make a struct to hold our local and dll headers so we can access them anytime.

	// copy sections into local image.
	Edmapper::CopyImageSections(local_image,pnt_headers);


	// fix relocations


	// fix imports


	// call shellcode

	std::printf("Everything worked.\n");

	VirtualFreeEx(gProc_handle.get(), mapped_image, 0, MEM_RELEASE);

	std::cin.get();
}