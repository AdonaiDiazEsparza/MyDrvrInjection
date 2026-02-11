#include "HeaderInjection.h"

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
