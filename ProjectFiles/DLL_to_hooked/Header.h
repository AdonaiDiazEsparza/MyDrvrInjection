#pragma once

/* Header to get the functions */

#ifdef HELLO_EXPORTS
#define HELLO_API __declspec(dllexport)
#else
#define HELLO_API __declspec(dllimport)
#endif

extern "C" HELLO_API int suma(int a, int b);
