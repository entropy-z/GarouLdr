#pragma once

#include <windows.h>
#include <native.h>
#include <common.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define DLL_QUERY_HMODULE 6

typedef struct _GAROU_API {
	D_API( LdrLoadDll );
	D_API( NtProtectVirtualMemory );
	D_API( NtFlushInstructionCache );
	D_API( NtAllocateVirtualMemory );
} GAROU_API, *PGAROU_API;

/*----------------------[ DllMain ]----------------------*/

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE, DWORD, LPVOID);

/*----------------------[ Dynamic Call ]----------------------*/

PVOID LdrLoadModule( _In_ UINT32 ModuleHash );
PVOID LdrLoadFunc( _In_ PVOID BaseModule, _In_ UINT32 FuncHash );
PVOID LdrLoadLib( _In_ PGAROU_API GarouApi, _In_ LPSTR ModuleName );