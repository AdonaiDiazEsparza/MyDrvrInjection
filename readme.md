# Inyeccion de DLL por Driver
Por el momento esta es un intento de implementación para lograr la inyección de una DLL en específico. Con la intención de agregar una DLL con carga de funciones o rutinas sobrepuestas haciendo uso de la libreria [Detours](https://github.com/microsoft/Detours) de Microsoft.

## Detours
La libreria detours te permite inyectar codigo entre funciones, usado principalmente para el monitoreo de llamadas de API de Windows.

## DEBUG VIEW
Para poder observar los logs, usaremos [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview), una herramienta que logra capturar los logs de eventos y programas que corren en kernel, así cada ves que usemos un ```print``` en nuestro driver en modo kernel, el programa lo capturara sin problemas.

## NOTA IMPORTANTE
Estas pruebas son hechas con la intención de aprendizaje y meramente uso educativo. Cualquier uso indebido que se le pueda dar a este repositorio, me deslindo de toda responsabilidad y cae bajo la persona u organización que haga uso de ello.

## Licencia
Licencia Bajo [MIT License](LICENSE).