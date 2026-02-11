#include "HeaderInjection.h"

/**
 * @file InjFunctions 
 * 
 * @brief Aqui en este documento manejaremos todas las funciones que ocupamos obtener para realizar la inyeccion de la DLL
 * 
 */

LIST_ENTRY g_list_entry; // Esta variable contiene todos los nodos de informacion que se usaran para cada proceso

ANSI_STRING LdrLoadDLLRoutineName = RTL_CONSTANT_STRING("LdrLoadDll"); // Funcion que buscamos en NTDLL para poder inyectar nuestra DLL


// =====================================    FUNCIONES PRIVADAS ========================================================

/**
 * @brief Funcion para crear la informacion de Process Id
 *
 * @param ProcessId El Pid del proceso
 */
NTSTATUS CreateInfo( HANDLE ProcessId);

/**
 * @brief Funcion para eliminar el espacio de memoria asignado para cierto proceso
 *
 * @param ProcessId Numero del proceso al que se eliminara el proceso
 */
BOOL RemoveInfoByProcess( HANDLE ProcessId);

/**
 * @brief Funcion para obtener la informacion de la lista en la DLL segun el proceso que se le haya dado
 *
 * @param ProcessId Encontrar la informacion en este proceso
 */
PINJECTION_INFO FindInfoElement(HANDLE ProcessId);

// ==============================================================================================

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
        PRINT("[-] ERROR CRETING MEMORY: 0x%x", STATUS_MEMORY_NOT_ALLOCATED);
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
    if (info){
        PRINT("[-] Informacion no liberada")
        return FALSE;
    }

    return TRUE;
}


/**
 * @brief Funcion para obtener la informacion de la lista en la DLL segun el proceso que se le haya dado
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
 * 
 * @param info Informacion a Inyectar
 */
BOOL CanBeInjected(PINJECTION_INFO info)
{
    // Si el puntero es nulo, retorna un un falso
    if (!info)
    {
        return FALSE;
    }

    if(info->LdrLoadDllRoutineAddress){
        PRINT("[.] Direccion de Rutina de Load ya asignado");
        return FALSE;
    }

    return TRUE;
}


/**
 * @brief Funcion para poder exportar la direccion de la 
 * 
 * @param DllBase La direccion de la DLL que se va tomar
 * 
 * @param ExportName Nombre de la DLL
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


/**
 * @brief Rutina para la captura de imagen
 * 
 * @param ImageName Nombre de la imagen o DLL cargada
 * 
 * @param ProcessId Es un handle y contiene el id del proceso que carga la DLL
 * 
 * @param ImageInfo Informacion de la DLL cargada
 */
void NotifyForAImageLoaded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    if(!ImageName || !ImageName->Buffer)
        return;

    // Encontrar la informacion
    PINJECTION_INFO info = FindInfoElement(ProcessId);

    // Si retorna un NULL 
    if(info == NULL){
        PRINT("[!] Informacion no obtenida para este proceso")
        return;
    }

    // Obtienes el proceso
    GET_PEPROCESS(process, pid);

    // Revisa si el proceso esta protegido
    if(PsIsProtectedProcess(ProcessId) && info->is32BitProcess && ImageInfo->SystemModeImage) // Por el momento agregare el filtro si es un proceso de 32bit 
    {
        if(RemoveInfoByProcess(ProcessId)){
            PRINT("[.] Informacion removida de este proceso protegido %d", ProcessId);
        }
        return;
    }

    // Ahora toca buscar la DLL correspondiente
    if(CanBeInjected(info)){
        /* Aqui debo buscar la DLL entre las DLL que se carguen */
        if(IsSuffixedUnicodeString(ImageName, NTDLL_NATIVE_PATH,TRUE))
        {
            // Funcionara?
            PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDllRoutineName);

            // Si retorna un valor Nulo estaremos mal
            if(!LdrLoadDllRoutineAddress){
                
            }

            PRINT("[+] Direccion de la funcion LdrDLL obtenida");
            info->LdrLoadDllRoutineAddress = ;
        }

        return;
    }
}


/**
 * @brief Rutina para detectar cuando un proceso se crea o se destruye
 * 
 * @param ParentId Id del proceso padre
 * 
 * @param ProcessId Id del proceso creado o destruido
 * 
 * @param create Variable que indica si se crea o termina el proceso
 */
void NotifyForCreateAProcess(HANDLE ParentId, HANDLE ProcessId, BOOL create)
{
    UNREFERENCED_PARAMETER(ParentId);

    // Se crea un proceso
    if(create)
    {
        // Imprimir si el proceso fue creado
        PRINT("[+] Se crea un proceso con el pid: %d", ProcessId);

        /* Cuando se crea un proceso se debe crear la informacion que se inserta en la lista */
        if(NT_SUCESS(CreateInfo(ProcesId))){
            PRINT("[+] Informacion creada");
        }
    }
    else
    {
        if(RemoveInfoByProcess(ProcessId)){
            PRINT("Info removida correctamente");
        }
    }
}

