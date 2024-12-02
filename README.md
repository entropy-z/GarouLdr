# GarouLdr

shellcode Reflective DLL Injection (sRDI) with:
- compile time hashing
- stack spoofing for api calls
- avoid RWX parsing PE section and changing protections
- support to fowarded functions
- low dependencies ( NtAllocateVirtualMemory, NtProtectVirtualMemory, LdrLoadDll and NtFlushInstructionCash )
