# Easy DLL Mapper
is a dll manual mapper the goal of this project is to make use of the modern
c++ language and to explain how does manual mapping works step by step.

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
