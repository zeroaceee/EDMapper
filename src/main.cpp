#include "main_header.h"

int main()
{
	g_process_id = Edmapper::GetProcessID(L"notepad.exe");
	gProc_handle = Edmapper::OpenProcessHandle(g_process_id);
	g_base = Edmapper::GetModuleBase(L"notepad.exe");

	std::printf("Base : 0x%p\n",(void*)g_base);

	std::cin.get();
}