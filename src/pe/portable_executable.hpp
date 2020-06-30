#pragma once
#include <windows.h>
#include <vector>

namespace portable_exe{
	inline bool IsValidImage();
	inline void CopyImageSections(void* image, PIMAGE_NT_HEADERS pnt_headers);
}

// make this shit private
PIMAGE_DOS_HEADER pOlddos_header = nullptr;
PIMAGE_NT_HEADERS pOldnt_headers = nullptr;

bool portable_exe::IsValidImage()
{
	pOlddos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(rawDll_data);

	if (pOlddos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::printf("[-]Invalid Image type.\n");
		delete[] rawDll_data;
		return false;
	}
		
	pOldnt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(rawDll_data + pOlddos_header->e_lfanew);

	if (pOldnt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::printf("[-]Invalid nt_headers signature.\n");
		delete[] rawDll_data;
		return false;
	}
	
	if (pOldnt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::printf("[-]Image is not 64 bit.\n");
		delete[] rawDll_data;
		return false;
	}

	return true;
}


void portable_exe::CopyImageSections(void* image, PIMAGE_NT_HEADERS pnt_headers)
{
	// Immediately following the PE header in memory is an array of IMAGE_SECTION_HEADERs. The number of elements in this array is given in the PE header (the IMAGE_NT_HEADER.FileHeader.NumberOfSections field).
	// basically this will return a pointer to an array 
	// then we probably need to index it to get to our structs.
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pnt_headers);

	for (size_t i = 0; i < pnt_headers->FileHeader.NumberOfSections; i++)
	{
		const auto copyfrom = rawDll_data + pSection->PointerToRawData;
		// if reserved memory differs from the allocated memory page then we need to relocate base address or else sections won't be copied correctly
		auto copyto = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(image) + pSection->VirtualAddress);
		const auto size = reinterpret_cast<std::size_t>(rawDll_data + pSection->SizeOfRawData);
		
		 std::memcpy(copyto,copyfrom,size);

		 pSection++; // this is totally wrong and its going in a wrong direction we can analyze this in memory.
	}

	std::printf("done\n");
}