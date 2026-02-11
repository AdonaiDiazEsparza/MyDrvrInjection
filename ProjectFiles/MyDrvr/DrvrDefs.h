#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <ntimage.h>

#define DRIVER_PREFIX "=> DRIVER_TEST: " // Prefix for the logs

// Direcciones de las DLL a inyectar, dll para un proceso nativo o para un proceso de 32bit en uno de 64
#define DLL_PATH_NATIVE L"PATH"
#define DLL_PATH_WOW64 L""

// Rutas de NTDLL en un proceso nativo o proceso de 32bit en uno de 64
#define NTDLL_NATIVE_PATH L"System32\\ntdll.dll"
#define NTDLL_WOW64_PATH L"SysWOW64\\ntdll.dll"

#define TAG_INJ 'jnI'

/* Macro for print with line jump */
#define PRINT(fmt, ...) \
    DbgPrint(DRIVER_PREFIX fmt "\n", ##__VA_ARGS__)

// otra manera de imprimir
#define print PRINT

// Flipea la TAG
#define TAG(t) ( ((((ULONG)t) & 0xFF) << (8 * 3)) | ((((ULONG)t) & 0xFF00) << (8 * 1)) | ((((ULONG)t) & 0xFF0000) >> (8 * 1)) | ((((ULONG)t) & 0xFF000000) >> (8 * 3)) )

// MACROS DE APOYO
#define STATIC_UNICODE_STRING(name, str) \
    static const UNICODE_STRING name = RTL_CONSTANT_STRING(str)

#define SET_UNICODE_STRING(name,str)\
    UNICODE_STRING name = RTL_CONSTANT_STRING(str)

#define STATIC_OBJECT_ATTRIBUTES(object_attributes, label_name, str_name)\
	STATIC_UNICODE_STRING(label_name, str_name);\
	static OBJECT_ATTRIBUTES object_attributes = { sizeof(object_attributes), 0, const_cast<PUNICODE_STRING>(&label_name), OBJ_CASE_INSENSITIVE }

#define GET_PEPROCESS(peproc, pid)\
	PEPROCESS peproc = NULL;\
	PsLookupProcessByProcessId(pid, &peproc)

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

// Funciones que se usaran para filtrar
BOOLEAN IsSuffixedUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName, BOOLEAN CaseInsensitive);
BOOLEAN IsMappedByLdrLoadDll(PCUNICODE_STRING ShortName);


/* Estas funciones siempre van a estar ahi asi que de una vez las definimos desde este punto */
enum KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
};

/**
 *
 * En este punto del codigo se definen las funciones que se incluyen externamente en el desarrollo de Kernel
 * Se ocupan para funciones APC y externas que se deben importar para el funcionamiento de este driver
 *
 */

 /* Definimos los tipos de dato a pasar a las rutinas de Ke */
typedef VOID(NTAPI* PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID KKERNEL_ROUTINE(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);
typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

/* Esto debe ser declarado en C*/
extern "C" {
    /*  Funciones de Kernel       */
    NTKERNELAPI void KeInitializeApc(
        PRKAPC Apc,
        PRKTHREAD Thread,
        KAPC_ENVIRONMENT Environment,
        PKKERNEL_ROUTINE KernelRoutine,
        PKRUNDOWN_ROUTINE RundownRoutine,
        PKNORMAL_ROUTINE NormalRoutine,
        KPROCESSOR_MODE ProcessorMode,
        PVOID NormalContext
    );


    NTKERNELAPI BOOLEAN KeInsertQueueApc(
        PRKAPC Apc,
        PVOID SystemArgument1,
        PVOID SystemArgument2,
        KPRIORITY Increment
    );

    NTKERNELAPI
        BOOLEAN
        KeTestAlertThread(
            KPROCESSOR_MODE AlertMode
        );

    /* Funciones para obtener Procesos */
    NTKERNELAPI PPEB __stdcall PsGetProcessPeb(_In_ PEPROCESS Process);
    NTKERNELAPI PVOID PsGetProcessWow64Process(__in PEPROCESS Process);
    NTKERNELAPI BOOLEAN __stdcall PsIsProtectedProcess(PEPROCESS Process);
    NTKERNELAPI PCHAR __stdcall PsGetProcessImageFileName(_In_ PEPROCESS Process);

    // Funcion para conseguir un directorio
    NTSYSAPI
        PVOID
        NTAPI
        RtlImageDirectoryEntryToData(
            _In_ PVOID BaseOfImage,
            _In_ BOOLEAN MappedAsImage,
            _In_ USHORT DirectoryEntry,
            _Out_ PULONG Size
        );

}