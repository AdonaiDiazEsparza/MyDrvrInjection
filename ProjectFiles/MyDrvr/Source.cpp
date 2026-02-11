/*
* Este es un archvio para el desarrollo de DLL y driver en conjunto
*
* Posiblemente me funcione este codigo como template para un futuro
*/

#include "DrvrDefs.h"

LIST_ENTRY g_list_entry; // Esta variable contiene todos los nodos de informacion que se usaran para cada proceso

ANSI_STRING LdrLoadDLLRoutineName = RTL_CONSTANT_STRING("LdrLoadDll"); // Funcion que buscamos en NTDLL para poder inyectar nuestra DLL

// =====================================================================================

void InitilizeInfoList();

NTSTATUS CreateInfo(HANDLE ProcessId);

BOOLEAN RemoveInfoByProcess(HANDLE ProcessId);

PINJECTION_INFO FindInfoElement(HANDLE ProcessId);

PVOID RtlxFindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName);

BOOLEAN CanBeInjected(PINJECTION_INFO info);

PVOID RtlxFindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName);

// =====================================================================================

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
    PINJECTION_INFO InfoCreated = (PINJECTION_INFO)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECTION_INFO), TAG_INJ);

    if (!InfoCreated)
    {
        PRINT("[-] ERROR CRETING MEMORY: 0x%x", STATUS_MEMORY_NOT_ALLOCATED);
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    RtlZeroMemory(InfoCreated, sizeof(INJECTION_INFO));

    InfoCreated->ProcessId = ProcessId;

    /* Aun no se si funcione esta implementacion en esta parte */
    InfoCreated->is32BitProcess = IoIs32bitProcess(NULL);

    if (InfoCreated->is32BitProcess)
    {
        PRINT("[.] Es un proceso de 32Bit");
    }

    InsertTailList(&g_list_entry, &InfoCreated->entry);

    return STATUS_SUCCESS;
}


/**
 * @brief Funcion para eliminar el espacio de memoria asignado para cierto proceso
 *
 * @param ProcessId Numero del proceso al que se eliminara el proceso
 */
BOOLEAN RemoveInfoByProcess(HANDLE ProcessId)
{
    PINJECTION_INFO info = FindInfoElement(ProcessId);

    // Si retorna un puntero nulo
    if (!info)
    {
        PRINT("[-] Informacion no conseguida del proceso no existente");
        return FALSE;
    }

    // Remove list entry
    RemoveEntryList(&info->entry);

    // Liberar memoria
    ExFreePoolWithTag(info, TAG_INJ);

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
BOOLEAN CanBeInjected(PINJECTION_INFO info)
{
    // Si el puntero es nulo, retorna un un falso
    if (!info)
    {
        return FALSE;
    }

    if (info->LdrLoadDllRoutineAddress) {
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
PVOID RtlxFindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName)
{

    PULONG NameTable;
    PUSHORT OrdinalTable;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    LONG Low = 0, Mid = 0, High, Ret;
    USHORT Ordinal;
    PVOID Function;
    ULONG ExportSize;
    PULONG ExportTable;

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(DllBase, TRUE,
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

/*
 * @brief Funcion para eliminar todos los nodos de la lista cuando se detenga o se elimine el driver
 */
VOID DestroyLists(void) 
{
    PLIST_ENTRY NextEntry = g_list_entry.Flink; // Apuntamos al primer elemento de la lista

    while (NextEntry != &g_list_entry)
    {
        PINJECTION_INFO info = CONTAINING_RECORD(NextEntry, INJECTION_INFO, entry); // Obtenermos el elemento 

        NextEntry = NextEntry->Blink; // Asignamos al siguiente elemento

        ExFreePoolWithTag(info, TAG_INJ); // Liberamos memoria
    }

    PRINT("[+] Listas de elementos eliminados");
}

// ========================================================================================================

// Funcion para comparar un nombre corto con el nombre completo de la llamada a funcion
BOOLEAN IsSuffixedUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName, BOOLEAN CaseInsensitive) {
    if (FullName &&
        ShortName &&
        ShortName->Length <= FullName->Length)
    {
        UNICODE_STRING ustr = {
            ShortName->Length,
            ustr.Length,
            (PWSTR)RtlOffsetToPointer(FullName->Buffer, FullName->Length - ustr.Length)
        };

        return RtlEqualUnicodeString(&ustr, ShortName, CaseInsensitive);
    }

    return FALSE;
}

// Funcion para mapear si la DLL fue cargada con la funcion LdrLoadDLL
BOOLEAN IsMappedByLdrLoadDll(PCUNICODE_STRING ShortName)
{
    //Check if this thread runs from within LdrLoadDll() function for the 'ShortName' module.
    //INFO: Otherwise the call could have come from someone invoking ZwMapViewOfSection with SEC_IMAGE
    //      Ex: smss.exe can map kernel32.dll during creation of \\KnownDlls (in that case ArbitraryUserPointer will be 0)
    //      ex: WOW64 processes map kernel32.dll several times (32 and 64-bit version) with WOW64_IMAGE_SECTION or NOT_AN_IMAGE
    //RETURN:
    //		- TRUE if yes
    UNICODE_STRING Name;

    __try
    {
        PNT_TIB Teb = (PNT_TIB)PsGetCurrentThreadTeb();
        if (!Teb ||
            !Teb->ArbitraryUserPointer)
        {
            //This is not it
            return FALSE;
        }

        Name.Buffer = (PWSTR)Teb->ArbitraryUserPointer;

        //Check that we have a valid user-mode address
        ProbeForRead(Name.Buffer, sizeof(WCHAR), __alignof(WCHAR));

        //Check buffer length
        Name.Length = (USHORT)wcsnlen(Name.Buffer, MAXSHORT);
        if (Name.Length == MAXSHORT)
        {
            //Name is too long
            return FALSE;
        }

        Name.Length *= sizeof(WCHAR);
        Name.MaximumLength = Name.Length;

        //See if it's our needed module
        return IsSuffixedUnicodeString(&Name, ShortName, TRUE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        //Something failed
        PRINT("#EXCEPTION: (0x%X) IsMappedByLdrLoadDll", GetExceptionCode());
    }

    return FALSE;
}

// ========================================================================================================

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
    if (!ImageName || !ImageName->Buffer)
        return;

    // Encontrar la informacion
    PINJECTION_INFO info = FindInfoElement(ProcessId);

    // Si retorna un NULL 
    if (info == NULL) {
        PRINT("[!] Informacion no obtenida para este proceso");
        return;
    }

    // Obtienes el proceso
    GET_PEPROCESS(process, ProcessId);

    // Revisa si el proceso esta protegido
    if (PsIsProtectedProcess(process) && info->is32BitProcess && ImageInfo->SystemModeImage) // Por el momento agregare el filtro si es un proceso de 32bit 
    {
        if (RemoveInfoByProcess(ProcessId)) {
            PRINT("[.] Informacion removida de este proceso protegido %d", ProcessId);
        }
        return;
    }

    // Imprimir Nombre de la imagen cargada 
    PRINT("[.] PID: %d NombreImagen: %wZ", ProcessId,ImageName);

    // Ahora toca buscar la DLL correspondiente
    if (CanBeInjected(info)) {

        SET_UNICODE_STRING(path_dll, NTDLL_NATIVE_PATH);

        /* Aqui debo buscar la DLL entre las DLL que se carguen */
        if (IsSuffixedUnicodeString(ImageName, &path_dll, TRUE))
        {
            // Funcionara?
            PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDLLRoutineName);

            // Si retorna un valor Nulo estaremos mal
            if (!LdrLoadDllRoutineAddress) {
                PRINT("[-] RUTINA NO OBTENIDA");
                PRINT("[.] Removiendo informacion de este proceso");
                if (RemoveInfoByProcess(ProcessId)) {
                    PRINT("[+] Informacion removida");
                }
                return;
            }

            PRINT("[+] Direccion de la funcion LdrDLL obtenida");
            PRINT("[+] Direccion:  0x%x", LdrLoadDllRoutineAddress);
            info->LdrLoadDllRoutineAddress = LdrLoadDllRoutineAddress;
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
void NotifyForCreateAProcess(HANDLE ParentId, HANDLE ProcessId, BOOLEAN create)
{
    UNREFERENCED_PARAMETER(ParentId);

    // Se crea un proceso
    if (create)
    {
        // Imprimir si el proceso fue creado
        PRINT("[+] Se crea un proceso con el pid: %d", ProcessId);

        /* Cuando se crea un proceso se debe crear la informacion que se inserta en la lista */
        if (NT_SUCCESS(CreateInfo(ProcessId))) {
            PRINT("[+] Informacion creada");
        }
    }
    else
    {

        PRINT("[.] Proceso terminado: %d", ProcessId);

        if (RemoveInfoByProcess(ProcessId)) {
            PRINT("[+] Info removida correctamente");
        }
    }
}


// =========================================================================================================

void Unload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    NTSTATUS status = PsRemoveLoadImageNotifyRoutine(NotifyForAImageLoaded);

    if (!NT_SUCCESS(status)) {
        PRINT("[-] ERROR REMOVIENDO RUTINA DE CARGA DE DLL: 0x%x", status);
    }

    status = PsSetCreateProcessNotifyRoutine(NotifyForCreateAProcess, TRUE);

    if (!NT_SUCCESS(status))
    {
        PRINT("[-] ERROR REMOVIENDO LA RUTINA DE CREACION DE PROCESOS: 0x%x", status);
    }

    DestroyLists(); // Destruimos todas las listas

    PRINT("[.] DRIVER UNLOADED");

}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

    // Print logs
    PRINT("CARGANDO DRIVER");

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    InitilizeInfoList();

    NTSTATUS status = PsSetLoadImageNotifyRoutine(NotifyForAImageLoaded);

    if (!NT_SUCCESS(status)) {
        PRINT("[-] ERROR 0x%x", status);
        return status;
    }

    status = PsSetCreateProcessNotifyRoutine(NotifyForCreateAProcess, FALSE);

    if (!NT_SUCCESS(status)) {
        PsRemoveLoadImageNotifyRoutine(NotifyForAImageLoaded);
        PRINT("[-] ERROR 0x%x", status);

        return status;
    }

    // Asignamos la funcion de Descarga del Driver
    DriverObject->DriverUnload = Unload;

    PRINT("[+] DRIVER CARGADO");

    return status;
}