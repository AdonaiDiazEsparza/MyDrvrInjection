#include <iostream>
#include <Windows.h>

int main()
{
    std::cout << "Testeando la DLL!\n";

    std::cout << "[.] Cargando la DLL\n";
    HINSTANCE hInstLibrary = LoadLibrary(L"edrHook.dll");

    if (hInstLibrary) {
        FreeLibrary(hInstLibrary);
        std::cout << "[+] REMOVIENDO DLL\n";
    }
    else
    {
        std::cout << "[-] DLL no cargada\n";
    }

    std::cout << "[+] Finish program\n";

    return 0;
}