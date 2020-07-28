#pragma once
#include <windows.h>
#include "../edmapper.hpp"


namespace portable_exe{
	inline PIMAGE_NT_HEADERS IsValidImage(std::uint8_t* &rawdll_image);
	inline void CopyImageSections(const void* image,const PIMAGE_NT_HEADERS pnt_headers, std::uint8_t* &rawdll_image);
	inline bool FixImageImports(const void* image, const PIMAGE_NT_HEADERS pnt_headers, std::uint8_t* &rawdll_image);
	inline void FixImageRelocations(void* mapped_image,void* local_image, const PIMAGE_NT_HEADERS pnt_headers, std::uint8_t* &rawdll_image);

	// L l = L() basically because we are doing default params and we need to initialzie it to std::less<void*>
	// how we are not passing third param? to l(a,b) because its already in l == std::less<void*>
	template<class A, class B, class L = std::less<void*>>
	inline bool CheckHigher_addressInMem(const A a,const B b,L l = L()) {
		return l(a, b); // call std::less to do comparing for us
	}
}


PIMAGE_NT_HEADERS portable_exe::IsValidImage(std::uint8_t* &rawdll_image)
{
	const auto p_dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(rawdll_image);

	// check the "MZ" chars to check if its a valid PE file.
	if (p_dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::printf("[-]Invalid Image type.\n");
		delete[] rawdll_image;
		return nullptr;
	}
		
	const auto p_ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(rawdll_image + p_dosHeader->e_lfanew);

	// check if our nt headers is valid or not by checking its signature
	if (p_ntHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		std::printf("[-]Invalid nt_headers signature.\n");
		delete[] rawdll_image;
		return nullptr;
	}
	
	// check if image is 64 bit
	if (p_ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		std::printf("[-]Image is not 64 bit.\n");
		delete[] rawdll_image;
		return nullptr;
	}

	return p_ntHeaders;
}


void portable_exe::CopyImageSections(const void* image, const PIMAGE_NT_HEADERS pnt_headers, std::uint8_t* &rawdll_image)
{
	// Immediately following the PE header in memory is an array of IMAGE_SECTION_HEADERs. The number of elements in this array is given in the PE header (the IMAGE_NT_HEADER.FileHeader.NumberOfSections field).
	// basically this will return a pointer to an array 
	// then we need to index it to get to our structs.
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pnt_headers);

	// loop through each section until we get to the last one
	for (size_t i = 0; i < pnt_headers->FileHeader.NumberOfSections; i++, pSection++)
	{
		// get pointer to where we want to copy the sections to which will be at location where our section offset start from.
		auto dest = reinterpret_cast<void*>((reinterpret_cast<std::uintptr_t>(image) + pSection->VirtualAddress));
		// get pointer to our section data
		const auto src = rawdll_image + pSection->PointerToRawData;
		// get the size of the section data
		const auto size = pSection->SizeOfRawData;
		// copy sections from our dll image to our local image 1 by 1
		std::memcpy(dest,src , size);
	}
}


bool portable_exe::FixImageImports(const void* image, const PIMAGE_NT_HEADERS pnt_headers, std::uint8_t* &rawdll_image)
{
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = nullptr;

	// we can use this offset to our .idata section because we have the same exact one that we copied from our 
	// dll so basically adding our image + our dll idata section is like doing it from our (copied image) headers if we wanted to.
	// this will return a pointer to an array of structs
	pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<std::uintptr_t>(image) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// if we couldn't get the address of our .idata section then cleanup & return
	if (!pImportDesc)
	{
		delete[] rawdll_image;
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
			delete[] rawdll_image;
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

		// ^^  these array's points to  structs each struct contains either an ordinal number for an imported function name.
		// difference is FirstThunk get overwritten by windows loader while OriginalFirstThunk does not and contains original information about imported functions.

		// if not found  cleanup resources & abort something is wrong
		if (!pFirst_thunkData && !pOriginalFirst_thunkData)
		{
			delete[] rawdll_image;
			return false;
		}
		
		std::uintptr_t Function_address = 0;

		// again we are using OriginalThunk data since its the one that guarantee us that we will have original information about this dll idata section.
		// each u1.AddressOfData will point to a struct in memory called PIMAGE_IMPORT_BY_NAME
		// each struct of type PIMAGE_IMPORT_BY_NAME contains an imported function name for example (MessageBoxA inside user32.dll)
		// if we did not loop through all imported functions we will only get the first one and other ones will be ignored which is not what we want.
		// so that's why we do this.
		while (pOriginalFirst_thunkData->u1.AddressOfData != NULL)
		{
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

			// couldn't find any explanation about this but
		    // pFirst_thunkData->u1.Function : is the address of the function that we are currently importing
		    // if we tried to call it , it will crash so we need to add base address of MODULE DLL + Function offset
		    // so it can get called normally.

			if (Function_address)
			{
				// why storing result address in FirstThunk not OriginalFirstThunk since FirstThunk is the one that gets overwritten by windows loader
				pFirst_thunkData->u1.Function = Function_address;
			}
			else
			{
				std::cerr << "[ERROR]Couldn't find address of function!" << " " << ":" << "Inside MODULE DLL :" << ModuleName << '\n';
				delete[] rawdll_image;
				return false;
			}

			// advance to second struct in our array to get imported function in current module.
			pOriginalFirst_thunkData++;
			pFirst_thunkData++;
		}

		// go to next imported dll in our array using pointer Arithmetic
		pImportDesc++;
	}

	return true;
}


void portable_exe::FixImageRelocations(void* mapped_image, void* local_image, const PIMAGE_NT_HEADERS pnt_headers, std::uint8_t* &rawdll_image)
{
	// get relocation directory pointer by adding imageBase + RVA (AKA the struct that has our .reloc info)
	auto pRelocation_dir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
		reinterpret_cast<std::uintptr_t>(local_image) + pnt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	

	
	if (!pRelocation_dir)
	{
		delete[] rawdll_image;
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