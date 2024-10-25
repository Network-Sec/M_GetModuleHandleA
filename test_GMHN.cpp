#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <winternl.h>

#pragma comment(lib, "M_GetModuleHandleA.lib")

extern "C" {
    void __cdecl M_GetModuleHandleA(uint64_t* addr_array, int* idx, wchar_t** name_array);
}

int main() {
    uint64_t addr_array[50] = {0};   // Assuming a max of 256 DLLs
    wchar_t* name_array[260] = { 0 };
    int idx = 0;

    // Call the assembly function to populate both arrays
    M_GetModuleHandleA(addr_array, &idx, name_array);

    printf("Num of Entries received: %d\n", idx);

    printf("DLL Names...\n");
    for (int i = 0; i < idx; i++) {
        // Print each DLL name (wide character string)
        if (name_array[i] != NULL) { // Check if the pointer is not NULL
            printf("%p:", (PVOID*)addr_array[i]);
            wprintf(L"%ls\n", (wchar_t*)name_array[i]);
        }
        else {
            wprintf(L"NULL at index %zu\n", i); // Debug output for NULL pointers
        }
    }

    printf("DLL Addresses...\n");

    for (int i = 0; i < idx; i++) {
        // Print base address in hexadecimal format
        printf("%p\n", (PVOID*)addr_array[i]);
    }

    return 0;
}
