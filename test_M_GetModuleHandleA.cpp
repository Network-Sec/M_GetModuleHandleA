// - Compile and link the assembly into a .dll and .lib 
// - Compile the .cpp into .obj
// - Link CPP .obj and DLL .lib
// - Turn off C++ optimizations, some other flags needed too

#include <stdio.h>
#include <windows.h>
#include <stdint.h> // Add this for uint64_t
#include <winternl.h>

#pragma comment(lib, "M_GetModuleHandleA.lib")

extern "C" {
    void __cdecl M_GetModuleHandleA(uint64_t* array, int* idx); // Forward declaration
}

int main() {
    uint64_t array[50] = { 0 };
    int idx = 0;

    // Directly call the statically linked function
    M_GetModuleHandleA(array, &idx);

    // Print the base addresses
    for (int i = 0; i < idx; i++) {
        if (array[i] == 0) {
            break;
        }
        printf("Base Address: %p\n", (void*)array[i]);
    }

    return 0;
}
