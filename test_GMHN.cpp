/* Note that this is a Demo for M_GetModuleHandleNames, the extended version that also prints DLL Names */

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

/* Output:
Num of Entries received: 8
DLL Names...
00007FF74AA60000:C:\Users\user\source\repos\M_GetModuleHandleA\x64\Release\M_GetModuleHandleA.exe
00007FFAF7C90000:C:\Windows\SYSTEM32\ntdll.dll
00007FFAF7A00000:C:\Windows\System32\KERNEL32.DLL
00007FFAF5350000:C:\Windows\System32\KERNELBASE.dll
00007FFAF5BD0000:C:\Windows\System32\ucrtbase.dll
00007FFAD2E10000:C:\Users\user\source\repos\M_GetModuleHandleA\x64\Release\M_GetModuleHandleA.dll
00007FFAD5F60000:C:\Windows\SYSTEM32\VCRUNTIME140.dll
0000000000000000:
DLL Addresses...
00007FF74AA60000
00007FFAF7C90000
00007FFAF7A00000
00007FFAF5350000
00007FFAF5BD0000
00007FFAD2E10000
00007FFAD5F60000
0000000000000000

There's still a small weirdness - we do pretty raw stuff here, so that can happen, especially when dealing with pointers in C afterwards and confusing types. 
But if you remove the second printf loop, the whole thing will stop working... whatever :D
*/
