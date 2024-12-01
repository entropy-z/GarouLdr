#pragma once

#include <windows.h>
#include <native.h>

#define NtCurrentProcess() ((HANDLE)-1) 
#define NtCurrentThread()  ((HANDLE)-2) 

extern PVOID GarouStart();
extern PVOID GarouRipEnd();
#define DLLEXPORT extern __declspec(dllexport)

/*----------------------[ memory ]----------------------*/

PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
VOID  MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size);
PVOID MemSet(void* Destination, int Value, size_t Size);

/*----------------------[ strings ]----------------------*/

int    StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2);
SIZE_T StringLengthA( _In_ LPCSTR String );
SIZE_T StringLengthW(_In_ LPCWSTR String);
int    wCharCompare( _In_ const WCHAR *s1, _In_ const WCHAR *s2 );
SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed);
void   InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer);

/*----------------------[ defines ]----------------------*/

#define W_PTR( x )   ( ( PWCHAR    ) ( x ) )
#define A_PTR( x )   ( ( PCHAR     ) ( x ) )
#define B_PTR( x )   ( ( PBYTE     ) ( x ) )
#define C_PTR( x )   ( ( LPVOID    ) ( x ) )
#define U_PTR( x )   ( ( UINT_PTR  ) ( x ) )
#define D_SEC( x ) 	__attribute__(( section( ".text$" #x ) ))
#define D_API( x )	__typeof__( x ) * x

#define DEREF_64( x ) *(DWORD64 *) ( x )
#define DEREF_32( x ) *(DWORD *)   ( x )
#define DEREF_16( x ) *(WORD *)    ( x )
#define DEREF_8( x )  *(BYTE *)    ( x )

#ifdef  __cplusplus
#define CONSTEXPR         constexpr
#define TEMPLATE_TYPENAME template <typename T>
#define INLINE            inline
#else
#define CONSTEXPR
#define TEMPLATE_TYPENAME
#define INLINE
#endif

/*----------------------[ hashes ]----------------------*/

#define NtFlushInstructionCache_H 0x85BF2F9C
#define NtAllocateVirtualMemory_H 0xE0762FEB
#define NtProtectVirtualMemory_H  0x5C2D1A97
#define RtlAddFunctionTable_H     0x4C3CB59B
#define LoadLibraryA_H            0x3FC1BD8D
#define VirtualAlloc_H            0x09CE0D4A
#define VirtualProtect_H          0x10066F2F
#define ntdlldll_H                0x7808A3D2
#define KERNEL32DLL_H             0x330C7795
#define LdrLoadDll_H 0x183679F2