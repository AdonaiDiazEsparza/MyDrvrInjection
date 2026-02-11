#include "HeaderInjection.h"

/**
 *  En este archivo agregare las funciones para inyectar el codigo que se ocupa para inyectar la dll
 */

LIST_ENTRY g_list_entry; // Esta variable contiene todos los nodos


/**
 * DEFINITIONS FOR THE FUNCTIONS
 */

NTSTATUS CreateInfo( HANDLE ProcessId);

BOOL RemoveInfoByProcess( HANDLE ProcessId);

PINJECTION_INFO FindInfoElement(HANDLE ProcessId);


/**
 * @brief Funcion para inicializar la lista de ```g_list_entry```
 */
void InitilizeInfoList()
{
    InitializeListHead(&g_list_entry);

    PRINT("[+] LISTA INICIALIZADA");
}


/**
 * @brief Funcion para crear la informacion de Process Id
 *
 * @param ProcessId El Pid del proceso
 */
NTSTATUS CreateInfo(HANDLE ProcessId)
{
    PINJECTION_INFO InfoCreated = ExAllocatedPool2(POOL_FLAG_NON_PAGED, sizeof(INJECTION_INFO), TAG_INJ);

    if (!InfoCreated)
    {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    RtlZeroMemory(InfoCreated, sizeof(INJECTION_INFO));

    InfoCreated->ProcessId = ProcessId;

    /* Aun no se si funcione esta implementacion en esta parte */
    InfoCreated->is32BitProcess = IoIs32bitProcess(NULL);

    if(InfoCreated->is32BitProcess)
    {
        PRINT("[.] Es un proceso de 32Bit");
    }

    InsertTailList(&g_list_entry, &InfoCreated);

    return STATUS_SUCCESS;
}


/**
 * @brief Funcion para eliminar el espacio de memoria asignado para cierto proceso
 *
 * @param ProcessId Numero del proceso al que se eliminara el proceso
 */
BOOL RemoveInfoByProcess(HANDLE ProcessId)
{
    PINJECTION_INFO info = FindInfoElement(ProcessId);

    // Si retorna un puntero nulo
    if (!info)
    {
        PRINT("[-] Informacion no conseguida proceso no existente");
        return FALSE;
    }

    // Remove list entry
    RemoveEntrylist(&info->entry);

    // Liberar memoria
    ExFreePool(info);

    // Si no se libero la memoria
    if (info)
        return FALSE;

    return TRUE;
}

/**
 * @brief Funcion para obtener la informacion de la lista en la DLL
 *
 * @param ProcessId Encontrar la informacion en este proceso
 */
PINJECTION_INFO FindInfoElement(HANDLE ProcessId)
{
    PLIST_ENTRY NextEntry = g_list_entry.Flink;

    while (NextEntry != &g_list_entry)
    {
        PINJECTION_INFO info = CONTAINING_RECORD(NextEntry, INJECTION_INFO, entry);

        if (info->ProcessId == ProcessId)
        {
            return info;
        }
    }

    return NULL;
}


/**
 * @brief Funcion para saber si la DLL puede ser inyectada
 */
BOOL CanBeInjected(PINJECTION_INFO info)
{
    // Si el puntero es nulo, retorna un un falso
    if (!info)
    {
        return FALSE;
    }

    // Si el Proceso esta protegido no puede hacer la inyeccion
    if (PsIsProtectedProcess(PsGetCurrentProcess()))
    {
        PRINT("[-] Proceso Protegido: %d", info->ProcessId);
        return FALSE;
    }

    if(info->LdrLoadDllRoutineAddress){
        return FALSE;
    }

    return TRUE;
}


/**
 * @brief Funcion para poder exportar la direccion de la 
 */
PVOID RtlxFindExportedRoutineByName( PVOID DllBase, PANSI_STRING ExportName)
{

    PULONG NameTable;
    PUSHORT OrdinalTable;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    LONG Low = 0, Mid = 0, High, Ret;
    USHORT Ordinal;
    PVOID Function;
    ULONG ExportSize;
    PULONG ExportTable;

    ExportDirectory = RtlImageDirectoryEntryToData(DllBase,
                                                   TRUE,
                                                   IMAGE_DIRECTORY_ENTRY_EXPORT,
                                                   &ExportSize);

    if (!ExportDirectory)
    {
        return NULL;
    }

    NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
    OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

    High = ExportDirectory->NumberOfNames - 1;
    while (High >= Low)
    {
        Mid = (Low + High) >> 1;

        Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);
        if (Ret < 0)
        {
            High = Mid - 1;
        }
        else if (Ret > 0)
        {
            Low = Mid + 1;
        }
        else
        {
            break;
        }
    }

    if (High < Low)
    {
        return NULL;
    }

    Ordinal = OrdinalTable[Mid];

    if (Ordinal >= ExportDirectory->NumberOfFunctions)
    {
        return NULL;
    }

    ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
    Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

    NT_ASSERT(
        (Function < (PVOID)ExportDirectory) ||
        (Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize)));

    return Function;
}





