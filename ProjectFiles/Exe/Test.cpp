/*
    App to get the DLL example named hola.dll
*/

#include <iostream>
#include <Windows.h>

typedef int (*func)(int, int); // prototype for the DLL

int main()
{
    std::cout << "This is the begining of something excited!\n";
    func _AddFunc = nullptr;

    std::cout << "[.] Loading the DLL\n";
    HINSTANCE hInstLibrary = LoadLibrary(L"hola.dll");

    if (hInstLibrary)
    {
        std::cout << "[+] DLL Loaded correctly\n";

        _AddFunc = (func)GetProcAddress(hInstLibrary, "suma");

        if (_AddFunc)
        {
            std::cout << "[+] Function loaded correctly\n\n";

            // ======================
            // LOOP INTERACTIVO
            // ======================

            int a, b;

            while (true)
            {
                std::cout << "Enter two numbers (0 0 to exit): ";
                std::cin >> a >> b;

                // Salida
                if (a == 0 && b == 0)
                {
                    std::cout << "Exiting...\n";
                    break;
                }

                int result = _AddFunc(a, b);

                std::cout << "Result: " << a << " + " << b
                    << " = " << result << "\n\n";
            }
        }
        else
        {
            std::cout << "[!] Error loading Add function\n";
        }
    }
    else
    {
        std::cout << "[!] Error loading DLL\n";
    }

    if (hInstLibrary)
    {
        FreeLibrary(hInstLibrary);
        std::cout << "[+] Removing DLL\n";
    }

    std::cout << "[+] Finish program\n";

    std::cin.get();
    return 0;
}