# Easy DLL Mapper
is a dll manual mapper the goal of this project is to make use of the modern
c++ language and to explain how does manual mapping works step by step.

## example usage
open cmd navigate to where the EDMapper.exe is located and type
`EDMapper.exe notepad.exe C:\\test.dll` 

## assembly ref
- https://defuse.ca/online-x86-assembler.htm#disassembly
- https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly
- https://forum.nasm.us/index.php?topic=2309.0

## general pe-format 
- https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN
- https://www.codeproject.com/Articles/36928/Parse-a-PE-EXE-DLL-OCX-Files-and-New-Dependency-Wa

## .idata section 
- https://stackoverflow.com/questions/7673754/pe-format-iat-questions
- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-idata-section
- https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN#pe-file-imports
- https://stackoverflow.com/questions/42413937/why-pe-need-original-first-thunkoft

## .reloc section 
- https://stackoverflow.com/questions/24821910/whats-the-meaning-of-highlow-in-a-disassembled-binary-file/24823931
- https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)?redirectedfrom=MSDN#pe-file-base-relocations
- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only
- https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2
- https://research32.blogspot.com/2015/01/base-relocation-table.html


## useful links for bitwise operators
- https://stackoverflow.com/questions/3270307/how-do-i-get-the-lower-8-bits-of-int
- https://en.wikipedia.org/wiki/Bitwise_operations_in_C#Bitwise_operators
- https://stackoverflow.com/questions/10493411/what-is-bit-masking


## few notes
when we try to manual map a dll that uses `MessageBoxA` for example the Target
process must have it in its (import table) `.idata` section or else we will crash. 


## Shellcode explanation
``` c++
	BYTE shellcode[] = {
		0x50, // push rax
		0x48, 0xB8, 0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, // mov rax,address
		0x52, // push rdx
		0x48, 0x31, 0xD2, // xor rdx,rdx
		0x48, 0x83, 0xC2, 0x01, //  add rdx,byte +0x0
		0x48, 0x83, 0xEC, 0x28, // sub rsp,0x28
		0xFF, 0xD0, // call rax 
		0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
		0x58, // pop rax
		0x5A, // pop rdx
		0xC3 // ret
	};


	// note 0x1020 is an RVA to where the location that i want to jmp to. to get there we need to add image base + rva
	*(std::uintptr_t*)(shellcode + 3) = (std::uintptr_t)m_image + 0x1020; // Hardcoded offset
```

first please see assembly ref and read on x64 shadow space before reading this so you have a better understanding about why we are reserving space in the stack

before i start talking about what does this shellcode does please note that you can use normal functions to achieve this exact way but am using assembly since it gives you more control on whats happening when executing it


now lets start with this shellcode first we need to put our offset in some place well we use the registery `rax` but before we use it we push it to the stack to save its old state then we can move our offset into it after that we push `rdx` to stack too. then we XOR rdx,rdx to zero out any garbage data that was in there before .then we add 1 bit to rdx .then we subtract some space for x64 shadowing and re-align the stack. then we `call rax` which will jmp to our address after finishing we clean up the stack by adding the same amount we subtracted before then we `pop rax` and `pop rdx` then we return from our shellcode to let the target process continue execution.

where did the hardcoded offset came from? shouldn't we call our dllEntry point.

- the answer is yes but for me there was a `cmp` instruction which compared edx with 1 and if edx wasn't `1` it will jmp and never execute my code. and to fix that problem i just hardcoded this shellcode + offset where the cmp instruction is so i can call my code you can see from the screenshot below :


<img src="https://i.imgur.com/2J7L7pY.jpg">