#include <windows.h>

#include <constexpr.h>
#include <common.h>
#include <native.h>
#include <win32.h>

D_SEC( B ) PVOID LdrLoadModule( 
    _In_ UINT32 ModuleHash
) {
    PTEB                  Teb   = NtCurrentTeb();
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };
    CHAR                  cDllName[256] = { 0 };

    Head  = &Teb->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    if ( !ModuleHash ) {
        Data = C_PTR( Entry );
        return Data->DllBase;
    }

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );

        toUpperCaseChar( cDllName );
        WCharStringToCharString( cDllName, Data->BaseDllName.Buffer, Data->BaseDllName.MaximumLength );
        
        if ( HashString( cDllName, 0 ) == ModuleHash ){
            return C_PTR( Data->DllBase );
        }
    }

    return NULL;
}

D_SEC( B ) PVOID LdrLoadFunc( 
    _In_ PVOID  BaseModule, 
    _In_ UINT32 FuncHash 
) {
    PIMAGE_NT_HEADERS       pImgNt         = { 0 };
    PIMAGE_EXPORT_DIRECTORY pImgExportDir  = { 0 };
    DWORD                   ExpDirSz       = 0x00;
    PDWORD                  AddrOfFuncs    = NULL;
    PDWORD                  AddrOfNames    = NULL;
    PWORD                   AddrOfOrdinals = NULL;
    PVOID                   FuncAddr       = NULL;

    pImgNt          = C_PTR( BaseModule + ((PIMAGE_DOS_HEADER)BaseModule )->e_lfanew );
    pImgExportDir   = C_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );
    ExpDirSz        = U_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size );

    AddrOfNames     = C_PTR( BaseModule + pImgExportDir->AddressOfNames );
    AddrOfFuncs     = C_PTR( BaseModule + pImgExportDir->AddressOfFunctions );
    AddrOfOrdinals  = C_PTR( BaseModule + pImgExportDir->AddressOfNameOrdinals );

    for ( int i = 0 ; i < pImgExportDir->NumberOfNames ; i++ ) {
        PCHAR pFuncName         = (PCHAR)( BaseModule + AddrOfNames[i] );
        PVOID pFunctionAddress  = C_PTR( BaseModule + AddrOfFuncs[AddrOfOrdinals[i]] );

        if ( HashString( pFuncName, 0 ) == FuncHash ) {
            if (( U_PTR( pFunctionAddress ) >= U_PTR( pImgExportDir ) ) &&
                ( U_PTR( pFunctionAddress )  < U_PTR( pImgExportDir ) + ExpDirSz )) {

                CHAR  ForwarderName[MAX_PATH] = { 0 };
                DWORD dwOffset                = 0x00;
                PCHAR FuncMod                 = NULL;
                PCHAR nwFuncName              = NULL;

                MemCopy( ForwarderName, pFunctionAddress, StringLengthA( (PCHAR)pFunctionAddress ) );

                for ( int j = 0 ; j < StringLengthA( (PCHAR)ForwarderName ) ; j++ ) {
                    if (((PCHAR)ForwarderName)[j] == '.') {
                        dwOffset         = j;
                        ForwarderName[j] = '\0';
                        break;
                    }
                }

                FuncMod    = ForwarderName;
                nwFuncName = ForwarderName + dwOffset + 1;

                UNICODE_STRING  UnicodeString           = { 0 };
                WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
                DWORD           dwModuleNameSize        = StringLengthA( FuncMod );
                HMODULE         Module                  = NULL;

                CharStringToWCharString( ModuleNameW, FuncMod, dwModuleNameSize );

                if ( ModuleNameW ){
                    USHORT DestSize             = StringLengthW( ModuleNameW ) * sizeof( WCHAR );
                    UnicodeString.Length        = DestSize;
                    UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
                }

                UnicodeString.Buffer = ModuleNameW;

                fLdrLoadDll pLdrLoadDll      = LdrLoadFunc( LdrLoadModule( HASH_STR( "ntdll.dll" ) ), "LdrLoadDll" );
                HMODULE     hForwardedModule = NULL;

                pLdrLoadDll( NULL, 0, &UnicodeString, &hForwardedModule );
                if ( hForwardedModule ) {
                    if ( nwFuncName[0] == '#' ) {
                        int ordinal = (INT)( nwFuncName + 1 );
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( (LPCSTR)ordinal, 0 ) );
                    } else {
                        return (PVOID)LdrLoadFunc( hForwardedModule, HashString( nwFuncName, 0 ) );
                    }
                }
                return NULL;
            }

            return C_PTR( pFunctionAddress );
        }
    }

    return NULL;
}

D_SEC( B ) PVOID LdrLoadLib( 
    _In_ PGAROU_API GarouApi, 
    _In_ LPSTR      ModuleName 
) {

    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = StringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    CharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW ){
        USHORT DestSize             = StringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( GarouApi->LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;

}
