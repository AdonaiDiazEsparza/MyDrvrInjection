#pragma once

/**
 * Esta cabecera es creada solo para contener todo lo que se realizara en 
 */
#include "DrvrDefs.h"

#include <ntimage.h>

// Direcciones de las DLL a inyectar
#define DLL_PATH_NATIVE L"PATH"
#define DLL_PATH_WOW64 L""

// Funciones de las DLL a
#define NTDLL_NATIVE_PATH L"System32\\ntdll.dll"
#define NTDLL_WOW64_PATH L"SysWOW64\\ntdll.dll"

#define TAG_INJ "gat_jnI"

typedef struct _INJECTION_INFO
{
    /**
     * @brief este es usado para crear el nodo en la lista global
     */
    LIST_ENTRY entry; 

    /**
     * @brief variable que almacena el id del proceso
     */
    HANDLE ProcessId;

    /**
     * @brief esta variable es usada para indicar si la DLL ya fue inyectada
     */
    BOOL isInjected;

    /**
     * @brief esta variable indica si es un proceso de 32bit ejecutado en uno de 64bits
     */
    BOOL is32BitProcess;

    /**
     * @brief Direccion de la rutina de DLL que se va usar
     */
    POVID LdrLoadDllRoutineAddress

}INJECTION_INFO, *PINJECTION_INFO;

/**
 * @brief Funcion para inicializar la lista de ```g_list_entry```
 */
void InitilizeInfoList();
