#include "edmapper.hpp"


int main(int argc, char** argv)
{
	// check if file exists.
	if (!std::filesystem::exists(argv[2]))
	{
		std::cerr << "[-]file path is invalid" << '\n';
		return -1;
	}
	
	// check if its a dll file
	if (std::filesystem::path(argv[2]).extension().string().compare(".dll") == -1) {
		std::cerr << "[-]file is not a dll" << '\n';
		return -1;
	}
	
	std::unique_ptr<Edmapper::dll_map> dll = std::make_unique<Edmapper::dll_map>();

	dll->dll_map_init(argv[1], argv[2]);

	if (!dll->map_dll())
	{
		std::cerr << "[-]Failed to map dll." << '\n';
		return -1;
	}

    std::printf("DLL mapped!\n");

	std::cin.get();
}