#pragma once

#include "DrvrDefs.h"

// Nombre de la DLL para filtrar
#define DLL_HOOKED_PATH L"\\hola.dll"

// Direcciones de las DLL a inyectar, dll para un proceso nativo o para un proceso de 32bit en uno de 64
#define DLL_PATH_NATIVE L"C:\\test\\edrHook.dll"
#define DLL_PATH_WOW64 L"C:\\testWOW\\edrHook.dll"

// Rutas de NTDLL en un proceso nativo o proceso de 32bit en uno de 64
#define NTDLL_NATIVE_PATH L"System32\\ntdll.dll"
#define NTDLL_WOW64_PATH L"SysWOW64\\ntdll.dll"


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
    BOOLEAN isInjected;

    /**
     * @brief esta variable indica si es un proceso de 32bit ejecutado en uno de 64bits
     */
    BOOLEAN is32BitProcess;

    /**
     * @brief Direccion de la rutina de DLL que se va usar
     */
    PVOID LdrLoadDllRoutineAddress;

}INJECTION_INFO, * PINJECTION_INFO;


namespace INJ_CODE {


    /**
     * @brief Funcion para inicializar la lista de ```g_list_entry```
     */
    void InitilizeInfoList();


    /**
     * @brief Funcion para crear la informacion de Process Id
     *
     * @param ProcessId El Pid del proceso
     */
    NTSTATUS CreateInfo(HANDLE ProcessId);


    /**
     * @brief Funcion para eliminar el espacio de memoria asignado para cierto proceso
     *
     * @param ProcessId Numero del proceso al que se eliminara el proceso
     */
    BOOLEAN RemoveInfoByProcess(HANDLE ProcessId);


    /**
     * @brief Funcion para obtener la informacion de la lista en la DLL segun el proceso que se le haya dado
     *
     * @param ProcessId Encontrar la informacion en este proceso
     */
    PINJECTION_INFO FindInfoElement(HANDLE ProcessId);


    /**
     * @brief Funcion para poder exportar la direccion de la
     *
     * @param DllBase La direccion de la DLL que se va tomar
     *
     * @param ExportName Nombre de la DLL
     */
    PVOID RtlxFindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName);


    /**
     * @brief Funcion para saber si la DLL puede ser inyectada en su momento o no
     *
     * @param info Informacion a Inyectar
     */
    BOOLEAN CanBeInjected(PINJECTION_INFO info);


    /*
    * @brief Funcion para eliminar todos los nodos de la lista cuando se detenga o se elimine el driver
    */
    VOID DestroyLists(void);


    /**
     * @brief InjQueueApc es una funcion para ejecutar las rutines de modo usuario y modo kernel en el APC
     *
     * @param ApcMode Modo de ejecucion de la rutina, puede ser en modo Usuario o modo Kernel
     *
     * @param NormalRoutine la rutina a ejecutar
     *
     * @param NormalContext Contexto que se le envia
     *
     * @param SystemArgumen1 Primer Argumento a enviar
     *
     * @param SystemArgumen1 Segundo Argumento a enviar
     */
    NTSTATUS InjQueueApc(KPROCESSOR_MODE ApcMode, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);


    /**
     * @brief Esta es simplemente una rutina para la inyeccion APC
     */
    void InjNormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);


    // =====================================================================================================================


    /**
     * @brief IsSuffixedUnicodeString es una funcion para encontrar un sufijo en alguna palabra de una variable tipo UNICODE_STRING
     *
     * @param FullName Variable completa
     *
     * @param ShortName El sufijo
     *
     * @param CaseInsensitive Si es CaseInsensitive
     */
    BOOLEAN IsSuffixedUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName, BOOLEAN CaseInsensitive);


    /**
     * @brief IsMappedByLdrLoadDll
     *
     * @param ShortName Dll a buscar
     */
    BOOLEAN IsMappedByLdrLoadDll(PCUNICODE_STRING ShortName);

}