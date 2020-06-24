#pragma once
#include <windows.h>
#include <vector>

namespace portable_exe{
	inline bool IsValidImage();
	inline void MapImageSections(std::vector<std::uint8_t> & image, PIMAGE_NT_HEADERS pnt_headers);
}

// make this shit private
PIMAGE_DOS_HEADER pdos_header = nullptr;
PIMAGE_NT_HEADERS pnt_headers = nullptr;

bool portable_exe::IsValidImage()
{
	pdos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_data.data());

	if (pdos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::printf("[-]Invalid Image type.\n");
		return false;
	}
		
	pnt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(raw_data.data() + pdos_header->e_lfanew);

	if (pnt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::printf("[-]Invalid nt_headers signature.\n");
		return false;
	}
	
	return true;
}


void portable_exe::MapImageSections(std::vector<std::uint8_t>& image, PIMAGE_NT_HEADERS pnt_headers)
{
	for (int i = 0; i < pnt_headers->FileHeader.NumberOfSections; i++) {
		// write sections to our target application.
	}
}