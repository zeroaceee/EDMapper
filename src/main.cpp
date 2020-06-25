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
		
	// allocate memory in target process so we can use it to copy our shit into it

	const auto image_size = pnt_headers->OptionalHeader.SizeOfImage;
	void* mapped_image = nullptr;
	Edmapper::AllocateMemoryInProcess(mapped_image, image_size);

	if (mapped_image == nullptr)
	{
		std::cerr << "Failed to allocate memory." << '\n';
		return -1;
	}
	
	// copy sections into mapped image.


	// fix relocations


	// fix imports


	// call shellcode

	std::printf("Everything worked.\n");

	Edmapper::FreeAllocatedMemoryInProcess(mapped_image);

	std::cin.get();
}