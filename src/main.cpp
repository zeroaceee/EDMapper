#include "main_header.h"

int main()
{
	g_process_id = Edmapper::GetProcessID("dummy.exe");
	
	if (g_process_id == 0)
		return -1;

	gProc_handle =  Edmapper::OpenProcessHandle(g_process_id);


	if (Edmapper::GetRawDataFromFile("C:\\Users\\User\\Desktop\\cpp-projects\\EDMapper\\x64\\Release\\test.dll") != false)
	{
		std::cout << "read dll." << '\n';
	}
		
	
	if (Edmapper::IsValidImage())
	{
		std::cout << "Image is valid." << '\n';
	}
		

	std::printf("Everything worked.\n");

	std::cin.get();
}