#include <Windows.h>
#include "pch.h"
__declspec(dllexport) DWORD WINAPI DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{

    if (dwReason == DLL_PROCESS_ATTACH)
    {

        MessageBoxW(NULL, L"Injected!", L"Module", MB_OK | MB_ICONINFORMATION);
    }

    return TRUE;
}
