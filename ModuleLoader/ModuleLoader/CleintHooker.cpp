#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <iostream>
#include <winternl.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

// define them its better
#define PROCESS_ALL_ACCESS 0x1F0FFF
#define TH32CS_SNAPPROCESS 0x00000002
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_READ 0x20
#define WH_GETMESSAGE 3
#define WM_NULL 0x0000

typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Parameter,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PVOID AttributeList
    );

NtCreateThreadEx_t NtCreateThreadEx = nullptr;

void Threadex() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");
    }
}

DWORD Cleint(const std::wstring& processName) {
    DWORD ret = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &entry)) {
            do {
                if (processName.compare(entry.szExeFile) == 0) {
                    ret = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return ret;
}

int main() {
    SetConsoleTitle(L"iusethis hecking tool");

    std::cout << "Waiting for Roblox process..." << std::endl;

    HWND windowHandle;
    while (true) {
        windowHandle = FindWindow(NULL, L"Roblox");
        if (IsWindowVisible(windowHandle))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    system("cls");

    DWORD CleintId = Cleint(L"RobloxPlayerBeta.exe");
    if (CleintId == 0) {
        std::cout << "Failed to find Roblox process." << std::endl;
        return -1;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CleintId);
    if (!processHandle) {
        std::cout << "Failed to open process." << std::endl;
        return -1;
    }

    HMODULE wintrustModule = LoadLibraryA("wintrust.dll");
    FARPROC _winVerifyTrust = GetProcAddress(wintrustModule, "WinVerifyTrust");

    BYTE payload[] = { 0x48, 0x31, 0xC0, 0x59, 0xFF, 0xE1 }; 

    DWORD oldProtect;
    if (!VirtualProtectEx(processHandle, _winVerifyTrust, sizeof(payload), PAGE_EXECUTE_READWRITE, &oldProtect))
        std::cout << "Failed to protect WinVerifyTrust." << std::endl;

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(processHandle, _winVerifyTrust, payload, sizeof(payload), &bytesWritten))
        std::cout << "Failed to patch WinVerifyTrust." << std::endl;

    VirtualProtectEx(processHandle, _winVerifyTrust, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect);


    Threadex();

    if (GetFileAttributesA("ModuleX012.dll") == INVALID_FILE_ATTRIBUTES) {
        std::cout << "DLL not found" << std::endl;
        return -1;
    }

    LPVOID allocatedMem = VirtualAllocEx(processHandle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocatedMem) {
        std::cout << "Failed to allocate memory in target process." << std::endl;
        return -1;
    }

    if (!WriteProcessMemory(processHandle, allocatedMem, "ModuleX012.dll", strlen("ModuleX012.dll") + 1, NULL)) {
        std::cout << "Failed to write DLL path to process memory." << std::endl;
        return -1;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cout << "Failed to get LoadLibraryA address" << std::endl;
        return -1;
    }

    if (NtCreateThreadEx) {
        HANDLE threadHandle = nullptr;
        NTSTATUS status = NtCreateThreadEx(
            &threadHandle,
            THREAD_ALL_ACCESS,
            NULL,  
            processHandle,
            (PVOID)loadLibraryAddr,
            allocatedMem,
            FALSE,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (status == 0) {
            std::cout << "Thread created " << std::endl;
        }
        else {
            std::cout << "Failed" << std::endl;
        }
    }

    std::cout << "Module Injected" << std::endl;

    CloseHandle(processHandle);

    std::this_thread::sleep_for(std::chrono::hours(999)); 

    return 0;
}
