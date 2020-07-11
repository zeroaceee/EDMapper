#pragma once
#include <windows.h>
#include <functional>

namespace portable_exe{
	inline bool IsValidImage();
	inline void CopyImageSections(void* image, PIMAGE_NT_HEADERS pnt_headers);
	inline bool FixImageImports(void* image, PIMAGE_NT_HEADERS pnt_headers);
	inline void FixImageRelocations(void* mapped_image,void* local_image, PIMAGE_NT_HEADERS pnt_headers);

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

		// why storing result address in FirstThunk not OriginalFirstThunk since FirstThunk is the one that gets overwritten by windows loader
		// see https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
		pFirst_thunkData->u1.Function = Function_address;

		// go to next imported dll in our array using pointer Arithmetic
		pImportDesc++;
	}

	return true;
}


void portable_exe::FixImageRelocations(void* mapped_image, void* local_image, PIMAGE_NT_HEADERS pnt_headers)
{
	// get relocation directory pointer by adding imageBase + RVA (AKA the struct that has our .reloc info)
	auto pRelocation_dir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
		reinterpret_cast<std::uintptr_t>(local_image) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	

	
	if (!pRelocation_dir)
	{
		delete[] rawDll_data;
		return;
	}


	// we can't compare address's using < or > operators since we will get undefined behavior
	// since both of them doesn't belong to each other or they are not pointing to the same object/array etc..
	// so we use std::less to compare 2 void pointers
	const auto isLess = 
		CheckHigher_addressInMem<void*, void*>(mapped_image, reinterpret_cast<void*>(pnt_headers->OptionalHeader.ImageBase));
	
	// calculate delta
	// https://sciencing.com/calculate-delta-between-two-numbers-5893964.html

	ULONGLONG delta = 0;
	if (isLess)
	{
		// cast to ULONGLONG to perform calculations
		delta = pnt_headers->OptionalHeader.ImageBase - reinterpret_cast<ULONGLONG>(mapped_image);
	}
	else
	{
		delta = reinterpret_cast<ULONGLONG>(mapped_image) - pnt_headers->OptionalHeader.ImageBase;
	}


	// we will keep looping through pages until we encounter a null pointer which then means we are done and got to the end of it.
	while (pRelocation_dir->VirtualAddress)
	{
		 // get amount of entries basically
         // this represent a location 
         // (offset within the 4 KB page if 32bit or 8 KB page if on 64bit pointed out by the VirtualAddress member in the IMAGE_BASE_RELOCATION struct)
         // which needs to be fixed up

          // The .reloc section contains a serie of blocks
          // There is one block for each 4 KB page if 32bit or 8 KB page if on 64bit page that contains virtual addresses
          // The SizeOfBlock holds the size of the block in bytes (including the size of the IMAGE_BASE_RELOCATION struct)
         // so to get how many entries in our block we do this calculation 

          // sizeOfBlock has the size of our block + size of IMAGE_BASE_RELOCATION struct
         // so we need to subtract 8 bytes aka (size of IMAGE_BASE_RELOCATION) then divide by 2 which is size WORD 
        // since each entry is 2 bytes 

		// why we doing this inside our loop?
		// because we will be advancing to the second block and we need to get new block size of our second page in memory
		const auto amountof_entries = pRelocation_dir->SizeOfBlock - sizeof(PIMAGE_BASE_RELOCATION) / sizeof(WORD);

		//  Immediately following the IMAGE_BASE_RELOCATION structure is a variable number of WORD values
		// AKA an array of WORD values
		// we go 1 more byte after our relocation directory to get to it
		auto entry = reinterpret_cast<PWORD>(pRelocation_dir + 1);

		// loop through all entries (aka where we should apply our relocations) in our block of relocation
		for (size_t i = 0; i < amountof_entries; i++)
		{
			// we are doing a right-shift operation to get to the higher 4 bits inside our current WORD value
			// note that doing bitwise operations like this won't change the value of our WORD var unless we assign it with the assignment operator "="
			// we go 12 bits to the right to get the higher 4 bits in our WORD var
			// for IA-64 executables the relocation type is seem to be always type of IMAGE_REL_BASED_DIR64
			// which basically means write our (whole) delta value to where the relocation should be applied

			// note we can use both hex or dec with bitwise operators the result will be the same
			// 0x0C = 12(dec)
			// 0xFFF = 4095(dec)
			if (entry[i] >> 0x0C == IMAGE_REL_BASED_DIR64)
			{
				// get an offset pointer to the address that needs to be relocated
				// we need this to be a pointer to std::uintptr_t so we can modify its contents 

				// (entry[i] & 0xFFF) = lowest 12 bits which is an RVA to the address where we want to apply relocations
				// this might be confusing but i will explain it
				// when we want to extract specific bits from a variable
				// we can compare it with another value that has x amount of bits set and nothing more
				// so 0xFFF in binary is (1111 1111 1111) <- 12 bits
				// and when we do AND operation on it 
				// this is what happens ex

				/*
				USING THE (&) OPERATOR
				1111 1101 1001 0101 // lets say this is our WORD value in memory (16 bits)
				0000 1111 1111 1111 // and this is 0xFFF bitmask
				---- ---- ---- ----
				0000 1101 1001 0101 // <- see only the 8 bits are left and nothing more 

				by doing this too it won't change our WORD value only gets the lowest 12 bits
				// unless we assign it to it.

				why use & operator since the & operator won't change any data or won't result in any change 
				after the operation is done if a bit is 1 it will stay the same if 0 it will be 0 simple
				its literally grabbing values from our WORD variable
				*/
				// this is called bit-masking ^^

				auto offset_to_relocation = reinterpret_cast<std::uintptr_t*>(
					reinterpret_cast<std::uintptr_t>(local_image) + pRelocation_dir->VirtualAddress + (entry[i] & 0xFFF));

				// derf and add delta value
				*offset_to_relocation += delta;
			}
			// advance to the next WORD value
			entry++;
		}

		/*
		go to the next block of memory
		we add SizeOfBlock which contains the IMAGE_BASE_RELOCATION struct + entries to our original pointer to old block of relocation
		so we can advance to the second block of reloctaion.
		*/

		pRelocation_dir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<std::uintptr_t>(pRelocation_dir + pRelocation_dir->SizeOfBlock));
	}
}