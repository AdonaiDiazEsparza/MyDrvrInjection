// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include <Windows.h>
#include "pch.h"
#include <stdio.h>
#include <time.h>
#include <winternl.h>
#include "detours.h"

/*
* La primera idea con este DLL es detectar cuando un proceso cargue alguna DLL correspondiente
* En este caso en conjunto con un driver detectaremos cuando se realice la carga de DLL.
*/

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Advapi32.lib")

/* Donde vamos a poner los logs */
const char* LogFilePath = "C:\\test\\log.txt";

/* Lo de siempre sera una suma, incluso puede ser una multiplicacion */
typedef int (WINAPI* anyfun_t)(int, int);

// Configuramos nuestra funcion como Nula
anyfun_t pSum = NULL;

// Added for the Sum
int WINAPI hookSuma(int a, int b) {
    return pSum(a, b) + 100;
}

/* Funcion para escribir logs en un archivo */
void WriteLogFile(char* Data) {

    FILE* f = NULL;
    fopen_s(&f, LogFilePath, "a");
    if (f) {
        fprintf(f, "%s", Data);
        fclose(f);
    }
}

/* Funcion para configurar detours */
void ConfigureDetours() {
    DWORD error = NO_ERROR; // Function for errors
    char EventData[512];

    // --- start initializing the detours ------

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        sprintf_s(EventData, "[!] Fallo el inicio de Detour transaction; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR)
    {
        sprintf_s(EventData, "[!] Fallo la obtencion de Hilo; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    // Find the specific function from a DLL
    pSum = (anyfun_t)DetourFindFunction("C:\\test\\hola.dll", "suma");

    error = DetourAttach((PVOID*)&pSum, hookSuma);

    if (error != NO_ERROR) {
        sprintf_s(EventData, "[!] Fallo en DetourAttach; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourTransactionCommit();

    if (error != NO_ERROR) {
        sprintf_s(EventData, "[!] Fallo en la finalizacion de accion de Detour; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    // On the HTB code here finishes all and didnt use a detach but I'll see whats going on.

    sprintf_s(EventData, "[+] Detour Adjuntado; Finalizado correctamente\n");
    WriteLogFile(EventData);
}

void detachDetours()
{
    DWORD error = NO_ERROR;
    char EventData[512];

    error = DetourTransactionBegin();
    if (error != NO_ERROR) {
        sprintf_s(EventData, "[!] Fallo en inicio de Operacion en DetourTransaction; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) {
        sprintf_s(EventData, "[!] Fallo en inicio de actualizacion de Hilo; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourDetach((PVOID*)&pSum, hookSuma);
    if (error != NO_ERROR)
    {
        sprintf_s(EventData, "[!] Fallo en DetourDetach; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    error = DetourTransactionCommit();
    if (error != NO_ERROR)
    {
        sprintf_s(EventData, "[!] Fallo en finalizacion de Operacion en DetourTransactionCommit; ERROR %d\n", error);
        WriteLogFile(EventData);
        return;
    }

    sprintf_s(EventData, "[+] Detour Desadjuntdo; Finalizado correctamente");
    WriteLogFile(EventData);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ConfigureDetours();
        break;
    case DLL_THREAD_ATTACH:
        // detachDetours();
        break;
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}