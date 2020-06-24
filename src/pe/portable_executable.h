#pragma once
#include <windows.h>
#include <vector>

namespace portable_exe{
	inline bool IsValidImage();
}



bool portable_exe::IsValidImage()
{
	PIMAGE_DOS_HEADER pdos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_data.data());

	if (pdos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::printf("[-]Invalid Image type.\n");
		return false;
	}
		
	PIMAGE_NT_HEADERS pnt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(raw_data.data() + pdos_header->e_lfanew);

	if (pnt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::printf("[-]Invalid nt_headers signature.\n");
		return false;
	}

	return true;
}