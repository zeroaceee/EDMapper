#include "main_header.h"

int main()
{
	if (Edmapper::GetRawDataFromFile("C:\\Users\\User\\Desktop\\cpp-projects\\EDMapper\\x64\\Release\\test.dll") != false)
	{
		std::wcout << "read dll." << '\n';
	}
		
	
	if (Edmapper::IsValidImage())
	{
		std::wcout << "Image is valid." << '\n';
	}
		


	std::printf("Everything worked.\n");

	std::cin.get();
}