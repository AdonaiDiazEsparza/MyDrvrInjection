#pragma once

/**
 * Esta cabecera es creada solo para contener todo lo que se realizara en 
 */
#include "DrvrDefs.h"

#include <ntimage.h>

// Direcciones de las DLL a inyectar, dll para un proceso nativo o para un proceso de 32bit en uno de 64
#define DLL_PATH_NATIVE L"PATH"
#define DLL_PATH_WOW64 L""

// Rutas de NTDLL en un proceso nativo o proceso de 32bit en uno de 64
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



/**
 * @brief Rutina para la captura de imagen
 * 
 * @param ImageName de la imagen o DLL cargada
 * 
 * @param ProcessId es un handle y contiene el id del proceso que carga la DLL
 * 
 * @param ImageInfo informacion de la DLL cargada
 */

void NotifyForAImageLoaded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);



/**
 * @brief Rutina para detectar cuando un proceso se crea o se destruye
 * 
 * @param ParentId Id del proceso padre
 * 
 * @param ProcessId Id del proceso creado o destruido
 * 
 * @param create Variable que indica si se crea o termina el proceso
 */
void NotifyForCreateAProcess(HANDLE ParentId, HANDLE ProcessId, BOOL create);