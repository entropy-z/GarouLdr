#include <windows.h>
#include <common.h>
 
D_SEC( B ) int StringCompareW( _In_ const WCHAR *s1, _In_ const WCHAR *s2 ) {
    while (*s1 && *s2 && *s1 == *s2) {
        ++s1;
        ++s2;
    }
    return *s1 - *s2;
}

D_SEC( B ) int StringCompareA( _In_ LPCSTR String1, _In_ LPCSTR String2 ){
	for (; *String1 == *String2; String1++, String2++){
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

D_SEC( B ) SIZE_T StringLengthA( _In_ LPCSTR String ){
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

D_SEC( B ) SIZE_T StringLengthW(_In_ LPCWSTR String){
	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

D_SEC( B ) SIZE_T CharStringToWCharString(_Inout_ PWCHAR Destination, _In_ PCHAR Source, SIZE_T _In_ MaximumAllowed){
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}

D_SEC( B ) void InitUnicodeString( _Out_ PUNICODE_STRING UsStruct, _In_opt_ PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = StringLengthW(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

D_SEC( B ) PVOID MemCopy( _Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length){
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

D_SEC( B ) VOID MemZero( _Inout_ PVOID Destination, _In_ SIZE_T Size){
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}

D_SEC( B ) PVOID MemSet(void* Destination, int Value, size_t Size){
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}