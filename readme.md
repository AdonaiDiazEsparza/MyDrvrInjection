# Inyeccion de DLL por Driver
Por el momento esta es un intento de implementación para lograr la inyección de una DLL en específico. Con la intención de agregar una DLL con carga de funciones o rutinas sobrepuestas haciendo uso de la libreria [Detours](https://github.com/microsoft/Detours) de Microsoft. 

Es una prueba de concepto (PoC) dónde quiero demostrar cómo se puede realizar la inyección de una DLL en un proceso por medio de un driver que opera a nivel kernel. 

## Detours
La libreria detours te permite inyectar codigo entre funciones, usado principalmente para el monitoreo de llamadas de API de Windows.

## DEBUG VIEW
Para poder observar los logs, usaremos [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview), una herramienta que logra capturar los logs de eventos y programas que corren en kernel, así cada ves que usemos un ```print``` en nuestro driver en modo kernel, el programa lo capturará sin problemas.

## Código
Si deseas conocer más sobre el código, ve a la carpeta de ProjectFiles/MyDrvr y lee el [readme](ProjectFiles/MyDrvr/readme.md) que explica el funcionamiento del driver y que es lo que hace.

## Agradecimientos y Referencias
Todo esto ha sido posible gracias a diversos repositorios, cursos y páginas de Blog de diversos desarrolladores:

Al repositorio [INJECT](https://github.com/rbmm/INJECT) de [rbmm](https://github.com/rbmm), gracias al [tutorial](https://www.youtube.com/watch?v=_k3njkNkvmI&list=PLo7Gwt6RpLEdF1cdS7rJ3AFv_Qusbs9hD&pp=0gcJCbUEOCosWNin) de [Dennis A.Babkin](https://github.com/dennisbabkin) dónde entrega una técnica de cómo hacer la inyección de DLL ([Repositorio](https://github.com/dennisbabkin/InjectAll)).

Gracias al [repositorio injdrv](https://github.com/wbenny/injdrv) de [wbenny](https://github.com/wbenny), de donde me base para realizar la inyección ya que me llamó la atención de cómo consigue la dirección de memoria de la función ```LDRLoadDLL```.

Gracias a [Pavel Yosifovich](https://github.com/zodiacon) dónde aprendí el desarrollo de los drivers a nivel kernel, basandome en sus cursos y libros para el desarrollo de drivers a nivel kernel ([repositorio](https://github.com/zodiacon/windowskernelprogrammingbook2e)).

Agradecer a [hokmá](https://github.com/MrR0b0t19) por el apoyo en el aprendizaje de desarrollo de kernel en windows para la creación de este código. Sin el esta Prueba de Concepto, nunca se hubiera hecho.

## NOTA IMPORTANTE
Estas pruebas son hechas con la intención de aprendizaje y meramente uso educativo. Cualquier uso indebido que se le pueda dar a este repositorio, me deslindo de toda responsabilidad y cae bajo la persona u organización que haga uso de ello.

## Licencia
Licencia Bajo [MIT License](LICENSE).