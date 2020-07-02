#pragma once
#include <windows.h>
#include <vector>

namespace portable_exe{
	inline bool IsValidImage();
	inline void CopyImageSections(void* image, PIMAGE_NT_HEADERS pnt_headers);
	inline bool FixImageImports(void* image, PIMAGE_NT_HEADERS pnt_headers);
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
	// then we need to index it to get to our structs.
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pnt_headers);

	for (size_t i = 0; i < pnt_headers->FileHeader.NumberOfSections; i++, pSection++)
	{
		auto dest = reinterpret_cast<void*>((reinterpret_cast<std::uintptr_t>(image) + pSection->VirtualAddress));
		const auto src = rawDll_data + pSection->PointerToRawData;
		const auto size = pSection->SizeOfRawData;

		std::memcpy(dest,src , size);
	}

	std::printf("Sections copied.\n");
}


bool portable_exe::FixImageImports(void* image, PIMAGE_NT_HEADERS pnt_headers)
{

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;

	// we can use this offset to our .idata section because we have the same exact one that we copied from our 
	// dll so basically adding our image + our dll idata section is like doing it from our headers if we wanted to.
	pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<std::uintptr_t>(image) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	if (!pImportDesc)
	{
		delete[] rawDll_data;
		return false;
	}
		
	// https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/
	// https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN#pe-file-imports
	// https://blog.kowalczyk.info/articles/pefileformat.html
	

	return true;
}