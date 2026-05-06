/*
 * Este es un archvio para el desarrollo de DLL y driver en conjunto
 *
 * Posiblemente me funcione este codigo como template para un futuro
 */

#include "Injector.h"


using namespace INJ_CODE;

ANSI_STRING LdrLoadDLLRoutineName = RTL_CONSTANT_STRING("LdrLoadDll"); // Funcion que buscamos en NTDLL para poder inyectar nuestra DLL

/**
 * @brief Rutina para detectar cuando un proceso se crea o se destruye
 *
 * @param ParentId Id del proceso padre
 *
 * @param ProcessId Id del proceso creado o destruido
 *
 * @param create Variable que indica si se crea o termina el proceso
 */
void NotifyForCreateAProcess(HANDLE ParentId, HANDLE ProcessId, BOOLEAN create);


/**
 * @brief Rutina para la captura de imagen
 *
 * @param ImageName Nombre de la imagen o DLL cargada
 *
 * @param ProcessId Es un handle y contiene el id del proceso que carga la DLL
 *
 * @param ImageInfo Informacion de la DLL cargada
 */
void NotifyForAImageLoaded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);


/**
 * @brief Rutina para enseñar unicamente las DLLS que se iran cargando, esto me ayudara en el Debuggeo de 32bit
 *
 * @param ImageName Nombre de la imagen o DLL cargada
 *
 * @param ProcessId Es un handle y contiene el id del proceso que carga la DLL
 *
 * @param ImageInfo Informacion de la DLL cargada
 */
void CheckEveryDLLAdded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);

// =======================================================================================

PLOAD_IMAGE_NOTIFY_ROUTINE RoutineImageLoad = (PLOAD_IMAGE_NOTIFY_ROUTINE)NotifyForAImageLoaded;

PCREATE_PROCESS_NOTIFY_ROUTINE RoutineProcessCreated = (PCREATE_PROCESS_NOTIFY_ROUTINE)NotifyForCreateAProcess;

// ========================================================================================================

void NotifyForAImageLoaded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (!ImageName || !ImageName->Buffer)
		return;

	// Encontrar la informacion
	PINJECTION_INFO info = FindInfoElement(ProcessId);

	// Si retorna un NULL
	if (info == NULL)
	{
		return;
	}

	// Obtienes el proceso
	GET_PEPROCESS(process, ProcessId);

	// Revisa si el proceso esta protegido
	if (PsIsProtectedProcess(process) && ImageInfo->SystemModeImage) // Por el momento agregare el filtro si es un proceso de 32bit
	{
		if (!RemoveInfoByProcess(ProcessId))
		{
			PRINT("[-] Informacion no removida de este proceso protegido %d", ProcessId);
		}
		return;
	}

	// Imprimir Nombre de la imagen cargada
	PRINT("[.] PID: %d IMG: %wZ", ProcessId, ImageName);

	SET_UNICODE_STRING(path_filter, NTDLL_WOW64_PATH);

	// Filtramos si detecta \\SysWOW64\\ntdll.dll
	if (IsSuffixedUnicodeString(ImageName, &path_filter, TRUE)) {
		info->is32BitProcess = TRUE;
		info->LdrLoadDllRoutineAddress = NULL;
	}

	// Ahora toca buscar la DLL correspondiente
	if (CanBeInjected(info))
	{

		SET_UNICODE_STRING(path_dll, NTDLL_NATIVE_PATH);

		// Si detecta el hilo de 32 bit
		if (info->is32BitProcess) {
			path_dll = path_filter;
		}

		/* Aqui debo buscar la DLL entre las DLL que se carguen */
		if (IsSuffixedUnicodeString(ImageName, &path_dll, TRUE))
		{
			// Aqui veremos si funciona
			PRINT("[+] Obtenida de: %wZ", path_dll);

			PVOID LdrLoadDllRoutineAddress = RtlxFindExportedRoutineByName(ImageInfo->ImageBase, &LdrLoadDLLRoutineName);

			// Si retorna un valor Nulo estaremos mal
			if (!LdrLoadDllRoutineAddress)
			{
				PRINT("[-] RUTINA NO OBTENIDA Removiendo informacion de este proceso");
				if (RemoveInfoByProcess(ProcessId))
				{
					PRINT("[-] Informacion No removida");
				}
				return;
			}

			PRINT("[+] Direccion (LDR):  0x%x", LdrLoadDllRoutineAddress);
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