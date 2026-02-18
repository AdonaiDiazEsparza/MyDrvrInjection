/*
 * Este es un archvio para el desarrollo de DLL y driver en conjunto
 *
 * Posiblemente me funcione este codigo como template para un futuro
 */

#include "DrvrDefs.h"

LIST_ENTRY g_list_entry; // Esta variable contiene todos los nodos de informacion que se usaran para cada proceso

ANSI_STRING LdrLoadDLLRoutineName = RTL_CONSTANT_STRING("LdrLoadDll"); // Funcion que buscamos en NTDLL para poder inyectar nuestra DLL

// Las constantes de las DLL que usaremos para inyectar
UNICODE_STRING NativeDLLToInject = RTL_CONSTANT_STRING(DLL_PATH_NATIVE);
UNICODE_STRING SysWOWDLLToInject = RTL_CONSTANT_STRING(DLL_PATH_WOW64);

// =====================================================================================

/**
 * Shellcodes
 */

UCHAR FunctionX86[] = {
	0x83, 0xec, 0x08,                   // sub    esp,0x8
	0x0f, 0xb7, 0x44, 0x24, 0x14,       // movzx  eax,[esp + 0x14]
	0x66, 0x89, 0x04, 0x24,             // mov    [esp],ax
	0x66, 0x89, 0x44, 0x24, 0x02,       // mov    [esp + 0x2],ax
	0x8b, 0x44, 0x24, 0x10,             // mov    eax,[esp + 0x10]
	0x89, 0x44, 0x24, 0x04,             // mov    [esp + 0x4],eax
	0x8d, 0x44, 0x24, 0x14,             // lea    eax,[esp + 0x14]
	0x50,                               // push   eax
	0x8d, 0x44, 0x24, 0x04,             // lea    eax,[esp + 0x4]
	0x50,                               // push   eax
	0x6a, 0x00,                         // push   0x0
	0x6a, 0x00,                         // push   0x0
	0xff, 0x54, 0x24, 0x1c,             // call   [esp + 0x1c]
	0x83, 0xc4, 0x08,                   // add    esp,0x8
	0xc2, 0x0c, 0x00,                   // ret    0xc
};

UCHAR FunctionX64[] = {
	0x48, 0x83, 0xec, 0x38, 				// sub    rsp,0x38
	0x48, 0x89, 0xc8, 						// mov    rax,rcx
	0x66, 0x44, 0x89, 0x44, 0x24, 0x20, 	// mov    [rsp+0x20],r8w
	0x66, 0x44, 0x89, 0x44, 0x24, 0x22, 	// mov    [rsp+0x22],r8w
	0x4c, 0x8d, 0x4c, 0x24, 0x40,	 		// lea    r9,[rsp+0x40]
	0x48, 0x89, 0x54, 0x24, 0x28, 			// mov    [rsp+0x28],rdx
	0x4c, 0x8d, 0x44, 0x24, 0x20, 			// lea    r8,[rsp+0x20]
	0x31, 0xd2, 							// xor    edx,edx
	0x31, 0xc9, 							// xor    ecx,ecx
	0xff, 0xd0, 							// call   rax
	0x48, 0x83, 0xc4, 0x38,			 		// add    rsp,0x38
	0xc2, 0x00, 0x00, 						// ret    0x0
};

SIZE_T Functionx64_lenght = sizeof(FunctionX64);
SIZE_T Functionx86_lenght = sizeof(FunctionX86);

// =====================================================================================

void InitilizeInfoList();

NTSTATUS CreateInfo(HANDLE ProcessId);

BOOLEAN RemoveInfoByProcess(HANDLE ProcessId);

PINJECTION_INFO FindInfoElement(HANDLE ProcessId);

PVOID RtlxFindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName);

BOOLEAN CanBeInjected(PINJECTION_INFO info);

PVOID RtlxFindExportedRoutineByName(PVOID DllBase, PANSI_STRING ExportName);

// =====================================================================================

NTSTATUS InjQueueApc(KPROCESSOR_MODE ApcMode, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

void InjNormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

void InjNormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);

NTSTATUS Injection(PINJECTION_INFO info);

NTSTATUS InjectOnSection(PINJECTION_INFO info, HANDLE SectionHandle, SIZE_T SectionSize);

void InjKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

// =======================================================================================

void NotifyForCreateAProcess(HANDLE ParentId, HANDLE ProcessId, BOOLEAN create);

void NotifyForAImageLoaded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

void CheckEveryDLLAdded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

// =======================================================================================

PLOAD_IMAGE_NOTIFY_ROUTINE RoutineImageLoad = (PLOAD_IMAGE_NOTIFY_ROUTINE)NotifyForAImageLoaded;

PCREATE_PROCESS_NOTIFY_ROUTINE RoutineProcessCreated = (PCREATE_PROCESS_NOTIFY_ROUTINE)NotifyForCreateAProcess;

// =======================================================================================

/**
 * @brief Es la funcion a ejecutar en modo kernel
 */
void InjKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	ExFreePoolWithTag(Apc, TAG_INJ);
}

// =====================================================================================

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
NTSTATUS InjQueueApc(KPROCESSOR_MODE ApcMode, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	PKAPC Apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), TAG_INJ);

	// Revisamos si se asigno un espacio de memoria
	if (!Apc)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	// Inicializamos el APC en el hilo actual
	KeInitializeApc(Apc, PsGetCurrentThread(), OriginalApcEnvironment, &InjKernelRoutine, NULL, NormalRoutine, ApcMode, NormalContext);

	// Revisamos si se inserta la rutina en el APC
	BOOLEAN Inserted = KeInsertQueueApc(Apc, SystemArgument1, SystemArgument2, 0);

	// Revisamos si se inserto
	if (!Inserted)
	{
		ExFreePoolWithTag(Apc, TAG_INJ);
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

// =======================================================================================

void InjNormalRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	PINJECTION_INFO info = (PINJECTION_INFO)NormalContext;

	UNREFERENCED_PARAMETER(info);

	// Aqui se realiza la otra funcion
	Injection(info);
}

NTSTATUS Injection(PINJECTION_INFO info)
{
	NTSTATUS status;

	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE SectionHandle;			// Seccion a asignar
	SIZE_T SectionSize = PAGE_SIZE; // Tamano de la seccion
	LARGE_INTEGER MaximumSize;		// Maximo tamano

	MaximumSize.QuadPart = SectionSize;

	status = ZwCreateSection(&SectionHandle, GENERIC_READ | GENERIC_WRITE, &ObjectAttributes, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// Mandamos a llamar la funcion de inyeccion en la seccion
	status = InjectOnSection(info, SectionHandle, SectionSize);

	ZwClose(SectionHandle);

	if (NT_SUCCESS(status))
	{
		KeTestAlertThread(UserMode);
	}

	return status;
}

NTSTATUS InjectOnSection(PINJECTION_INFO info, HANDLE SectionHandle, SIZE_T SectionSize)
{
	NTSTATUS status;

	PVOID SectionMemoryAddress = NULL;

	SIZE_T functionLength = 0;

	PUCHAR functionCode = NULL;

	UNICODE_STRING DllToInject;

	// Aqui obtenemos la seccion de memoria y la mapeamos, lo abrimos como read and write
	status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		SectionSize,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_READWRITE);

	// Revisar si fue exitoso
	if (!NT_SUCCESS(status))
	{
		// Aqui debemos retornar
		return status;
	}

	// Revisar que tipo de proceso es el nuestro, ya sea 32 o 64 bits
	if (!info->is32BitProcess) {

		// Si no es de 32 bit, entonces asignamos la shellcode de 64 bits y su longitud
		functionCode = FunctionX64;
		functionLength = Functionx64_lenght;
		DllToInject = NativeDLLToInject;
	}
	else {
		// Asignamos la shellcode de 32bit y su longitud
		functionCode = FunctionX86;
		functionLength = Functionx86_lenght;
		DllToInject = SysWOWDLLToInject;
	}

	// Asignamos la direccion de memoria donde haremos la inyeccion
	PVOID ApcRoutineAddress = SectionMemoryAddress;

	// Aqui copiamos la direccion de la rutina, en este caso es la shellcode para su inyeccion
	RtlCopyMemory(ApcRoutineAddress, functionCode, functionLength);

	// Obtenemos la direccion de la DLL
	PWCHAR DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + functionLength);

	// Copiamos la direccion de la DLL y su buffer
	RtlCopyMemory(DllPath, DllToInject.Buffer, DllToInject.Length);

	// Desmapeamos nuestra seccion
	ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);

	SectionMemoryAddress = NULL;

	status = ZwMapViewOfSection(SectionHandle,
		ZwCurrentProcess(),
		&SectionMemoryAddress,
		0,
		PAGE_SIZE,
		NULL,
		&SectionSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_READ);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	ApcRoutineAddress = SectionMemoryAddress;
	DllPath = (PWCHAR)((PUCHAR)SectionMemoryAddress + functionLength);
	PVOID ApcContext = (PVOID)info->LdrLoadDllRoutineAddress;
	PVOID ApcArgument1 = (PVOID)DllPath;
	PVOID ApcArgument2 = (PVOID)DllToInject.Length;

	// Se crea la rutina APC
	PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutineAddress;

	// Inyectamos el APC
	status = InjQueueApc(UserMode, ApcRoutine, ApcContext, ApcArgument1, ApcArgument2);

	if (!NT_SUCCESS(status))
	{
		ZwUnmapViewOfSection(ZwCurrentProcess(), SectionMemoryAddress);
	}

	return status;
}

// =======================================================================================

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

	if (info->LdrLoadDllRoutineAddress)
	{
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
BOOLEAN IsSuffixedUnicodeString(PCUNICODE_STRING FullName, PCUNICODE_STRING ShortName, BOOLEAN CaseInsensitive)
{
	if (FullName &&
		ShortName &&
		ShortName->Length <= FullName->Length)
	{
		UNICODE_STRING ustr = {
			ShortName->Length,
			ustr.Length,
			(PWSTR)RtlOffsetToPointer(FullName->Buffer, FullName->Length - ustr.Length) };

		return RtlEqualUnicodeString(&ustr, ShortName, CaseInsensitive);
	}

	return FALSE;
}

// Funcion para mapear si la DLL fue cargada con la funcion LdrLoadDLL
BOOLEAN IsMappedByLdrLoadDll(PCUNICODE_STRING ShortName)
{
	// Check if this thread runs from within LdrLoadDll() function for the 'ShortName' module.
	// INFO: Otherwise the call could have come from someone invoking ZwMapViewOfSection with SEC_IMAGE
	//       Ex: smss.exe can map kernel32.dll during creation of \\KnownDlls (in that case ArbitraryUserPointer will be 0)
	//       ex: WOW64 processes map kernel32.dll several times (32 and 64-bit version) with WOW64_IMAGE_SECTION or NOT_AN_IMAGE
	// RETURN:
	//		- TRUE if yes
	UNICODE_STRING Name;

	__try
	{
		PNT_TIB Teb = (PNT_TIB)PsGetCurrentThreadTeb();
		if (!Teb ||
			!Teb->ArbitraryUserPointer)
		{
			// This is not it
			return FALSE;
		}

		Name.Buffer = (PWSTR)Teb->ArbitraryUserPointer;

		// Check that we have a valid user-mode address
		ProbeForRead(Name.Buffer, sizeof(WCHAR), __alignof(WCHAR));

		// Check buffer length
		Name.Length = (USHORT)wcsnlen(Name.Buffer, MAXSHORT);
		if (Name.Length == MAXSHORT)
		{
			// Name is too long
			return FALSE;
		}

		Name.Length *= sizeof(WCHAR);
		Name.MaximumLength = Name.Length;

		// See if it's our needed module
		return IsSuffixedUnicodeString(&Name, ShortName, TRUE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		// Something failed
		PRINT("#EXCEPTION: (0x%X) IsMappedByLdrLoadDll", GetExceptionCode());
	}

	return FALSE;
}

UNICODE_STRING GetDLLForThePathResolution(BOOLEAN is32bit) {
	if (is32bit)
	{
		SET_UNICODE_STRING(path, NTDLL_WOW64_PATH);
		return path;
	}

	SET_UNICODE_STRING(path, NTDLL_NATIVE_PATH);

	return path;
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
	if (info == NULL)
	{
		PRINT("[!] Informacion no obtenida para este proceso");
		return;
	}

	// Obtienes el proceso
	GET_PEPROCESS(process, ProcessId);

	// Revisa si el proceso esta protegido
	if (PsIsProtectedProcess(process) && ImageInfo->SystemModeImage) // Por el momento agregare el filtro si es un proceso de 32bit
	{
		if (RemoveInfoByProcess(ProcessId))
		{
			PRINT("[.] Informacion removida de este proceso protegido %d", ProcessId);
		}
		return;
	}

	// Imprimir Nombre de la imagen cargada
	PRINT("[.] PID: %d NombreImagen: %wZ", ProcessId, ImageName);

	// Ahora toca buscar la DLL correspondiente
	if (CanBeInjected(info))
	{

		UNICODE_STRING path_dll = GetDLLForThePathResolution(info->is32BitProcess);

		/* Aqui debo buscar la DLL entre las DLL que se carguen */
		if (IsSuffixedUnicodeString(ImageName, &path_dll, TRUE))
		{
			// Funcionara?
			PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDLLRoutineName);

			// Si retorna un valor Nulo estaremos mal
			if (!LdrLoadDllRoutineAddress)
			{
				PRINT("[-] RUTINA NO OBTENIDA");
				PRINT("[.] Removiendo informacion de este proceso");
				if (RemoveInfoByProcess(ProcessId))
				{
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

	SET_UNICODE_STRING(dll_hooked, DLL_HOOKED_PATH);

	if (!info->isInjected && IsSuffixedUnicodeString(ImageName, &dll_hooked, TRUE) && info->LdrLoadDllRoutineAddress) {


		PRINT("[!] Intento de inyeccion a hola.dll");

		KAPC_STATE* apc_state = (KAPC_STATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC_STATE), 'gat');

		if (!apc_state) {
			PRINT("[-] APC STATE no asignado correctamente");
			RemoveInfoByProcess(ProcessId);
			return;
		}

		KeStackAttachProcess(process, apc_state);

		InjQueueApc(KernelMode, &InjNormalRoutine, info, NULL, NULL);

		KeUnstackDetachProcess(apc_state);

		info->isInjected = TRUE;
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
		if (NT_SUCCESS(CreateInfo(ProcessId)))
		{
			PRINT("[+] Informacion creada");
		}
	}
	else
	{

		PRINT("[.] Proceso terminado: %d", ProcessId);

		if (RemoveInfoByProcess(ProcessId))
		{
			PRINT("[+] Info removida correctamente");
		}
	}
}

// =========================================================================================================

/**
 * @brief Rutina para enseñar unicamente las DLLS que se iran cargando, esto me ayudara en el Debuggeo de 32bit
 *
 * @param ImageName Nombre de la imagen o DLL cargada
 *
 * @param ProcessId Es un handle y contiene el id del proceso que carga la DLL
 *
 * @param ImageInfo Informacion de la DLL cargada
 */
void CheckEveryDLLAdded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(ImageInfo);

	if (IoIs32bitProcess(NULL)) {
		PRINT("[.] x32 PID: %d IMG: %wZ", ProcessId, ImageName);
	}
	else {
		PRINT("[.] x64 PID: %d IMG: %wZ", ProcessId, ImageName);
	}

}

// =========================================================================================================

void Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = PsRemoveLoadImageNotifyRoutine(RoutineImageLoad);

	if (!NT_SUCCESS(status))
	{
		PRINT("[-] ERROR REMOVIENDO RUTINA DE CARGA DE DLL: 0x%x", status);
	}

#ifndef DEBUG_DLL

	status = PsSetCreateProcessNotifyRoutine(RoutineProcessCreated, TRUE);

	if (!NT_SUCCESS(status))
	{
		PRINT("[-] ERROR REMOVIENDO LA RUTINA DE CREACION DE PROCESOS: 0x%x", status);
	}

#endif

	DestroyLists(); // Destruimos todas las listas

	PRINT("[.] DRIVER UNLOADED");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

	// Print logs
	PRINT("CARGANDO DRIVER");

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	InitilizeInfoList();

#ifdef DEBUG_DLL
	RoutineImageLoad = (PLOAD_IMAGE_NOTIFY_ROUTINE)CheckEveryDLLAdded;
#endif

	NTSTATUS status = PsSetLoadImageNotifyRoutine(RoutineImageLoad);

	if (!NT_SUCCESS(status))
	{
		PRINT("[-] ERROR 0x%x", status);
		return status;
	}

#ifndef DEBUG_DLL

	status = PsSetCreateProcessNotifyRoutine(RoutineProcessCreated, FALSE);

	if (!NT_SUCCESS(status))
	{
		PsRemoveLoadImageNotifyRoutine(RoutineImageLoad);
		PRINT("[-] ERROR 0x%x", status);

		return status;
	}

#endif

	// Asignamos la funcion de Descarga del Driver
	DriverObject->DriverUnload = Unload;

	PRINT("[+] DRIVER CARGADO");

	return status;
}