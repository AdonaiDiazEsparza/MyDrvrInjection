# EXPLICACIÓN DEL DRIVER
## Explicación de función de entrada
Cómo en toda programación existe una función o punto de entrada, por ejemplo en lenguaje C es común ver que existe la función ```main```, en el desarrollo de drivers en modo kernel, su punto de entrada es la función ```DriverEntry``` donde retorna un valor de tipo ```NT_STATUS``` y recibe dos parámetros, el objeto del driver (```PDRIVER_OBJECT```) y la dirección donde se registra el driver (```PUNICODE_STRING```). En el código no se realiza ninguna acción con estos dos parámetros, por lo que se usa una macro para evitar errores de variables sin referenciar (```UNREFERENCED_PARAMETER```).

```Cpp
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath){
    return STATUS_SUCCESS;
}
```

Es importante entender que esta función de entrada debe ser definida cómo una función de lenguaje C, por lo que en un archivo trabajado en lenguaje C++, se debe agregar las sentencia ```extern "C"```, esto para no tener problemas con la resolución de nombres de las funciones con el compilador.

## Configuración de rutina de finalización
Es importante crear una rutina de descarga o de finalización para el driver, ya que está nos da la oportunidad de quitar rutinas y funciones asignadas dentro del programa del driver, esto se realizará cada vez que se interrumpa el driver o se desinstale. 

> Su funcionalidad es de suma importancia para lograr la eliminación de asignaciones de memoria y rutinas. 

La asignación de la rutina de finalización se asigna de la siguiente manera. Dentro de la función de entrada ```DriverEntry``` se logra asignar con el parametro del objeto (```DriverObject```) donde le damos la rutina:

```Cpp
DriverObject->DriverUnload = Unload;
```

Donde nuestra rutina ```Unload``` debe ser una función definida cómo:

```Cpp
void Unload(PDRIVER_OBJECT DriverObject);
```

## Rutinas para la detección de Inicialización/Finalización de Procesos y de Cargas de DLL 
### Rutina para la detección de Procesos
En el código se usa una rutina que se llama cuando un proceso de windows se inicia o se finaliza, entrega parametros cómo el proceso padre que lo invoca y el PID del proceso, con el parametro de tipo booleano se indica si se crea o se elimina el proceso, esta función nos ayuda para la asignación y eliminación de elementos con estructuras de ```LIST_ENTRY``` en los procesos, esto se platicará más adelante. 
Esta rutina se puede asignar usando la función ```PsSetLoadImageNotifyRoutine``` donde pasamos nuestra función de tipo ```void``` con tres parametros:

```Cpp
void NotifyForCreateAProcess(HANDLE ParentId, HANDLE ProcessId, BOOLEAN create);
```

Esta función se asigna cómo rutina de la siguiente manera ```PsSetLoadImageNotifyRoutine(NotifyForCreateAProcess, FALSE)``` y se retira en la función de finalización del driver ```Unload``` cómo ```PsSetLoadImageNotifyRoutine(NotifyForCreateAProcess, TRUE)```, donde el valor booleano indica si se retira o se asigna.

### Rutina para la detección de Carga de DLL
Esta rutina se llama cada que una DLL se carga en algún proceso, entrega su nombre (la ruta completa de la DLL), el proceso que la carga y la información completa de la DLL. 
Esta rutina se puede asignar con usando la función ```PsSetLoadImageNotifyRoutine``` y podemos retirarla en con la función ```PsRemoveLoadImageNotifyRoutine```. Nuestra función puede ser la siguiente:

```Cpp
void NotifyForAImageLoaded(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
```

Esta puede ser asignada en la entrada del Driver de la siguiente manera: ```PsSetLoadImageNotifyRoutine(NotifyForAImageLoaded)``` y puede ser retirada con ```PsRemoveLoadImageNotifyRoutine(NotifyForAImageLoaded)```.

## Estructura LIST_ENTRY
La estructura ```LIST_ENTRY``` considero que forma una parte importante y fundamental en este driver (y creo es muy usado en el desarrollo de drivers y kernel de windows), lo considero crucial en el manejo de objetos asignados a procesos creados, incluso para la liberación de memorias asignadas en otras funciones.

Definiendo la estructura, es una lista de entrada que nos funciona para apuntar a sus elementos, ayudandonos a obtener elementos guardados en memoria. No reserva memoria, sino almacena punteros o referencias a un espacio de memoria asignado.

La estructura está definida:

```Cpp
typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY *Flink;
  struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;
```
Donde ```Flink``` apunta al siguiente elemento de la lista y ```Blink``` apunta al anterior elemento. Yo lo veo como un ringbuffer, pero este tiene un tamaño flexible donde se puede agregar o quitar más elemento (No es un ringbuffer, solo hago referencia a que se parecen).

### Uso de LIST_ENTRY en el driver
En el código definimos una variable global llamada ```g_list_entry```, esta variable es indispensable ya que su utilidad es almacenar referencias de estructuras ```LIST_ENTRY``` de varios objetos creados cada que se detecte una creación de algún proceso. Estas estructuras o variables de tipo ```LIST_ENTRY``` son obtenidas de una misma estructura que se define en el código, justo en el archivo [DrvrDefs.h](DrvrDefs.h).

## Estructura INJECTION_INFO
Al hablar de esta estructura puedo decir que empiezo a platicar del pivote de nuestro programa, las rutinas anteriormente mencionadas (detección de procesos y detecccion de carga de DLLs) y la estructura ```LIST_ENTRY``` son las bases para que todo el código, y en conjunto con esta estructura vamos manipulando el funcionamiento de nuestro driver.

La estructura está definida de la siguiente manera:
```Cpp
typedef struct _INJECTION_INFO
{
    LIST_ENTRY entry;

    HANDLE ProcessId;

    BOOLEAN isInjected;

    BOOLEAN is32BitProcess;

    PVOID LdrLoadDllRoutineAddress;

}INJECTION_INFO, * PINJECTION_INFO;

```

Cada elemento es usado para lo siguiente:
- ```entry``` nos ayuda a almacenar la referencia que se guarda en la variable global en ```g_list_entry``` con la intención de obtener la estructura en distintas partes del código.

- ```ProcessId``` guarda el ID del proceso que se creó, este nos ayuda a filtrar en diferentes funciones el proceso al que corresponde la estructura que se tiene que usar.

- ```isInjected``` Unicamente es una variable que nos indica si ya se inyectó la DLL.

- ```is32BitProcess``` Es una variable que nos ayuda a saber si el proceso es de 32bit en la arquitectura de Windows 64. 
>Este miembro únicamente se encuentra definido pero no hay acciones utilizadas para procesos de 32bit en windows 64 dentro del driver. Se espera en un futuro implementarlo.

- ```LdrLoadDllRoutineAddress``` Este es un elemento importante, aqui guardaremos el puntero a la dirección donde se encuentra la función de carga de DLL por parte de NTDLL.


## Funciones APC 
Las funciones APC (Asynchronous Procedure Calls) son rutinas que nos ayudan a realizar acciones en cierto proceso en el que estemos enfocados. Son importantes ya que nos brindan facilidad de ejecutar código en contexto de usuario o de kernel. 

Ciertas acciones cómo inyecciones de DLL no se puede hacer de manera nativa en un driver en modo kernel, estas son comúnmente realizadas en operaciones en modo usuario, cómo el siguiente código que es un fragmento de un programa de consola:

```C++
HINSTANCE hInstLibrary = LoadLibrary(L"hola.dll");
```

En un driver no existe una función para cargar una DLL en algún proceso por lo que tenemos que usar estas funciones APC que nos ayudarán.

### Resolución de inclusión de funciones APC
Algunas funciones no se incluyen simplemente usando ```Ntifs.h``` sino que se ocupa importarlas usando la sentencia ```NTKERNELAPI``` (es una macro que se extiende a ```__declspec(dllimport)```). Las funciones son las siguientes:

```C++
extern "C" {
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
}
```

A su vez debemos definir los prototipos y enumeración para que puedan trabajar las funciones y no marquen errores

``` C++
typedef VOID(NTAPI* PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID KKERNEL_ROUTINE(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);
typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);
typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);
```
