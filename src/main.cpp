#include "main_header.h"

int main()
{
	if (Edmapper::GetRawDataFromFile("test.dll"))
	{
		// code here
	}


	delete[] raw_data;
	std::cin.get();
}