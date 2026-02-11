/*
* Este es un archvio para el desarrollo de DLL y driver en conjunto
* 
* Posiblemente me funcione este codigo como template para un futuro
*/

#include "HeaderInjection.h"

// Vamos a usar dos rutinas
// 1 para detectar cuando se realice la carga de DLL
// 2 Para ver que coincidan las cargas de memoria


// Funcion que se manda a llamar cada que una DLL se carga
// Routine to detect when a DLL is loaded
void LoadDLLNotify(PUNICODE_STRING imageName, HANDLE pid, PIMAGE_INFO imageInfo)
{
    UNREFERENCED_PARAMETER(imageInfo);
    UNREFERENCED_PARAMETER(imageName);
    UNREFERENCED_PARAMETER(pid);

    if (!imageName || !imageName->Buffer)
        return;

	GET_PEPROCESS(process, pid);

    /* Voy a agregar una funcion para no filtrar */

	PRINT("NAME PROCESS: %d IMAGE: %wZ", pid, imageName);

    if(PsIsProtectedProcess(process)){
        PRINT("[!] PROCESO PROTEGIDO");
    }


}

// Rutina para la creacion de procesos
void CreateNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create) {
	if (create) {
		PRINT("[!] PROCESS PARENT %d   AND CREATED: %d", ppid,pid);
	}
    else{
        PRINT("[!] PROCESS DESTROYED %d", pid);
    }
}


// Funcion de finalizado par el driver
void Unload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	NTSTATUS status = PsRemoveLoadImageNotifyRoutine(LoadDLLNotify);

	if (!NT_SUCCESS(status)) {
		PRINT("[-] ERROR REMOVIENDO RUTINA DE CARGA DE DLL: 0x%x",status);
	}

	status = PsSetCreateProcessNotifyRoutine(CreateNotifyRoutine, TRUE);

	if (!NT_SUCCESS(status))
	{
		PRINT("[-] ERROR REMOVIENDO LA RUTINA DE CREACION DE PROCESOS: 0x%x", status);
	}

	PRINT("[.] DRIVER UNLOADED");

}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;

	// Print logs
	PRINT("CARGANDO DRIVER");

	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	status = PsSetLoadImageNotifyRoutine(LoadDLLNotify);

	if (!NT_SUCCESS(status)) {
		PRINT("[-] ERROR 0x%x", status);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutine(CreateNotifyRoutine, FALSE);

	if (!NT_SUCCESS(status)) {
		PsRemoveLoadImageNotifyRoutine(LoadDLLNotify);
		PRINT("[-] ERROR 0x%x", status);

		return status;
	}

	// Asignamos la funcion de Descarga del Driver
	DriverObject->DriverUnload = Unload;

	PRINT("[+] DRIVER CARGADO");

	return status;
}