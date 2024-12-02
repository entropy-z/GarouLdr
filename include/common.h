#pragma once

#include <windows.h>
#include <native.h>

#define NtCurrentProcess() ((HANDLE)-1) 
#define NtCurrentThread()  ((HANDLE)-2) 

EXTERN_C PVOID GarouStart();
EXTERN_C PVOID GarouRipEnd();
EXTERN_C PVOID GarouLdr( LPVOID Parameter );

typedef  NTSTATUS (*fLdrLoadDll)(PWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID *DllHandle);
ULONG    HashString( _In_ PVOID String, _In_ SIZE_T Length );

/*----------------------[ memory ]----------------------*/

PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length);
VOID  MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size);
PVOID MemSet(void* Destination, int Value, size_t Size);

/*----------------------[ strings ]----------------------*/

void   toUpperCaseChar(char* str);
int    StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2);
int    StringCompareW( _In_ const WCHAR *s1, _In_ const WCHAR *s2 );
SIZE_T StringLengthA( _In_ LPCSTR String );
SIZE_T StringLengthW(_In_ LPCWSTR String);
SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed);
SIZE_T WCharStringToCharString(_Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed);
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
