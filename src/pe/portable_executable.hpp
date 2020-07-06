#pragma once
#include <windows.h>
#include <functional>

namespace portable_exe{
	inline bool IsValidImage();
	inline void CopyImageSections(void* image, PIMAGE_NT_HEADERS pnt_headers);
	inline bool FixImageImports(void* image, PIMAGE_NT_HEADERS pnt_headers);
	inline void FixImageRelocations(void* imageBase, PIMAGE_NT_HEADERS pnt_headers);

	// L l = L() basically because we are doing default params and we need to initialzie it to std::less<void*>
	// how we are not passing third param? to l(a,b) because its already in l == std::less<void*>
	template<class A, class B, class L = std::less<void*>>
	inline bool CheckHigher_addressInMem(const A a,const B b,L l = L()) {
		return l(a, b); // call std::less to do comparing for us
	}
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
	// links
	// https://stackoverflow.com/questions/42413937/why-pe-need-original-first-thunkoft
	// https://github.com/not-wlan/drvmap/blob/master/drvmap/drv_image.cpp
	// https://github.com/z175/kdmapper/blob/master/kdmapper/portable_executable.cpp
	// https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN#pe-file-imports
	// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
	// https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
	// https://stackoverflow.com/questions/7673754/pe-format-iat-questions
	// 

	// https://web.archive.org/web/20180103163005/https://blogs.msdn.microsoft.com/oldnewthing/20100318-00/?p=14563

	// use timestamp to compare and if its the same then just skip all of this bullshit
	// we can compare our own .DLL timestamp with the one like kernel32.dll (windows dll) and if they match
	// and if we loaded it at prefered address then we don't need to resolve function pointers.
	// i don't think we can do this since ASLR is ENABLED
	// https://en.wikipedia.org/wiki/Dynamic-link_library search for "bound" binding...

	// basically binding is when we use for example "kernel32.dll" from windows inside our "hack.dll"
	// "kernel32.dll" will have a timestamp (when it got compiled) and if we check the timestamp
	// from our dll (aka by getting them from our dll nt_headers same as line : [109]) and it matched the same current available one then there is no need 
	// to fix imports as they will have fixed address's (aka correct ones) and the loader will be happy!

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;

	// we can use this offset to our .idata section because we have the same exact one that we copied from our 
	// dll so basically adding our image + our dll idata section is like doing it from our (copied image) headers if we wanted to.
	// this will return a pointer to an array of structs
	pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<std::uintptr_t>(image) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// if we couldn't get the address of our .idata section then cleanup & return
	if (!pImportDesc)
	{
		delete[] rawDll_data;
		return false;
	}
		
	// loop through all imported dll's until we get to the last one
	while (pImportDesc->Name != NULL)
	{
		// get the imported dll name
		 const auto ModuleName = reinterpret_cast<char*>(
			reinterpret_cast<std::uintptr_t>(image) + pImportDesc->Name);

        // load the imported dll into our process to get the base address of it
		auto ModuleBase = LoadLibraryA(ModuleName);
		
		// if we couldn't obatin base of MODULE DLL return false
		if (!ModuleBase)
		{
			delete[] rawDll_data;
			return false;
		}
		
		
		PIMAGE_THUNK_DATA pFirst_thunkData = nullptr;
		PIMAGE_THUNK_DATA pOriginalFirst_thunkData = nullptr;
	

		// get address of FirstThunk pointer to PIMAGE_THUNK_DATA
		pFirst_thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(
			reinterpret_cast<std::uintptr_t>(image) + pImportDesc->FirstThunk);

		// get address of OriginalFirstThunk pointer to PIMAGE_THUNK_DATA
		pOriginalFirst_thunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(
			reinterpret_cast<std::uintptr_t>(image) + pImportDesc->OriginalFirstThunk);

		// if not found  cleanup resources & abort something is wrong
		if (!pFirst_thunkData && !pOriginalFirst_thunkData)
		{
			delete[] rawDll_data;
			return false;
		}
		

		// https://en.wikipedia.org/wiki/Bitwise_operation#AND
		// Check if this bit is set, then import by ordinal
		// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table

		std::uintptr_t Function_address = 0;

		// IMAGE_SNAP_BY_ORDINAL is a marco that checks if the highest bit is set or not in 
		// PIMAGE_THUNK_DATA which is (u1.Ordinal)


		// little note we can import using 2 ways 
		// 1 - [ordinal] number is just a number that the windows loader use to find an import function
		// 2 - by Function Name you can see how both works below

		
		// if set then import by ordinal otherwise import by name.
		if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirst_thunkData->u1.Ordinal))
		{
			// LOWORD marco gets the low-order word from the specified value
			// read about GetProcAddress to understand more on msdn.
			// then we cast it to a string to find our function address.
			Function_address = reinterpret_cast<std::uintptr_t>(GetProcAddress(ModuleBase, reinterpret_cast<LPCSTR>(LOWORD(pOriginalFirst_thunkData->u1.Ordinal))));
		}
		else
		{
			// pOriginalFirst_thunkData->u1.AddressOfData : is basically an rva to  PIMAGE_IMPORT_BY_NAME struct inside
			// union PIMAGE_THUNK_DATA
			// we can do the same thing using FirstThunk but i prefered to use OriginalFirstThunk cuz that's what its for (INT)
			// Import Name Table
			PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
				reinterpret_cast<std::uintptr_t>(image) + pOriginalFirst_thunkData->u1.AddressOfData);

			// get the current function address from current imported dll
			Function_address = reinterpret_cast<std::uintptr_t>(GetProcAddress(ModuleBase, pImport->Name));
		}		

		// if wasn't found then cleanup and return false since something should be wrong here
		if (!Function_address)
		{
			std::cerr << "[ERROR]Couldn't find address of function!" << " " << ":" << "Inside MODULE DLL :" << ModuleName << '\n';
			delete[] rawDll_data;
			return false;
		}

		
		// couldn't find any explanation about this but
		// pFirst_thunkData->u1.Function : is the address of the function that we are currently importing
		// if we tried to call it , it will crash so we need to add base address of MODULE DLL + Function offset
		// so it can get called normally.
		pFirst_thunkData->u1.Function = Function_address;

		// go to next imported dll in our array using pointer Arithmetic
		pImportDesc++;
	}

	

	return true;
}


void portable_exe::FixImageRelocations(void* imageBase, PIMAGE_NT_HEADERS pnt_headers)
{
	// get relocation directory pointer by adding imageBase + RVA
	auto pRelocation_dir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
		reinterpret_cast<std::uintptr_t>(imageBase) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	
	// same as above but we are getting the size here
	const auto relocation_size = static_cast<DWORD>(
		reinterpret_cast<std::uintptr_t>(imageBase) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	// if both of them are invalid then return and free resources
	if (!pRelocation_dir && !relocation_size)
	{
		delete[] rawDll_data;
		return;
	}

	// get end of .reloc section by adding the start of section + size of section
	const auto relocation_end = reinterpret_cast<unsigned long long>(pRelocation_dir) + relocation_size;

	// we can't compare address's using < or > operators since we will get undefined behavior
	// since both of them doesn't belong to each other or they are not pointing to the same object/array etc..
	// so we use std::less to compare 2 void pointers
	const auto isLess = 
		CheckHigher_addressInMem<void*, void*>(imageBase, reinterpret_cast<void*>(pnt_headers->OptionalHeader.ImageBase));
	
	// calculate delta
	// https://sciencing.com/calculate-delta-between-two-numbers-5893964.html

	ULONGLONG delta = 0;
	if (isLess)
	{
		// cast to ULONGLONG to perform calculations
		delta = pnt_headers->OptionalHeader.ImageBase - reinterpret_cast<ULONGLONG>(imageBase);
	}
	else
	{
		delta = reinterpret_cast<ULONGLONG>(imageBase) - pnt_headers->OptionalHeader.ImageBase;
	}

	

	
}