#include <windows.h>
#include <winnt.h>
#include <iostream>

#include "localpe.h"



// Reads File from disk and processes it into a buffer with the size of the file
bool ReadFile(LPCSTR filename, PBYTE* buffer, PDWORD size) {

    HANDLE hFile = INVALID_HANDLE_VALUE;
    PBYTE pBuffer = NULL;
    DWORD dwFileSize = 0,
    dwBytesRead = 0;

    hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return false;
    }
    std::cout << "File opened successfully: " << filename << std::endl;

    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        std::cerr << "Failed to get file size: " << filename << std::endl;
    }
    std::cout << "File size: " << dwFileSize << std::endl;

    pBuffer = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize));
    if (pBuffer == NULL) {
        std::cerr << "Failed to allocate memory: " << filename << std::endl;
        CloseHandle(hFile);
        return false;
    }
    std::cout << "Memory allocated successfully: " << pBuffer << std::endl;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL)) {
        std::cerr << "Failed to read file: " << filename << std::endl;
        HeapFree(GetProcessHeap(), 0, pBuffer);
    }

    *buffer = pBuffer;
    *size = dwFileSize;
    CloseHandle(hFile);
    return true;
}

// Parses the buffer into a PE_HEADERS structure representing the PE file
bool InitializePeHeaders(PPE_HEADERS pPeHeaders, PBYTE pBuffer, DWORD dwFileSize) {

    if (!pPeHeaders || !pBuffer || !dwFileSize)
        return false;

    pPeHeaders -> pFileBuffer = pBuffer;
    pPeHeaders -> dwFileSize = dwFileSize;
    pPeHeaders -> pImgNtHeaders = (PIMAGE_NT_HEADERS)(pBuffer + ((PIMAGE_DOS_HEADER)pBuffer) -> e_lfanew);

    if (pPeHeaders -> pImgNtHeaders -> Signature != IMAGE_NT_SIGNATURE)
        return false;
    pPeHeaders -> bIsDLLFile = (pPeHeaders -> pImgNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) ? true : false;
    pPeHeaders -> pImgSectionHeaders = IMAGE_FIRST_SECTION(pPeHeaders -> pImgNtHeaders);
    pPeHeaders -> pEntryImportDataDirectory = &pPeHeaders -> pImgNtHeaders -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pPeHeaders -> pEntryBaseRelocationDataDirectory = &pPeHeaders -> pImgNtHeaders -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    pPeHeaders -> pEntryTLSDataDirectory = &pPeHeaders -> pImgNtHeaders -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    pPeHeaders -> pEntryExceptionDataDirectory = &pPeHeaders -> pImgNtHeaders -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    pPeHeaders -> pEntryExportDataDirectory = &pPeHeaders -> pImgNtHeaders -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    return true;
}

bool PeFixReloc(PIMAGE_DATA_DIRECTORY pEntryBaseRelocDataDir, PBYTE pPeBaseAddress, ULONG_PTR pPreferableAddress) {

    PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pPeBaseAddress + pEntryBaseRelocDataDir->VirtualAddress);

    ULONG_PTR uDeltaOffset = pPeBaseAddress - pPeBaseAddress;

    PBASE_RELOCATION_ENTRY pBaseRelocEntry = NULL;

    while (pImgBaseReloc->VirtualAddress){
        pBaseRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgBaseReloc + 1);

         // Iterate through all the relocation entries in the current block.
        while ((PBYTE)pBaseRelocEntry != (PBYTE)pImgBaseReloc + pImgBaseReloc->SizeOfBlock) {
            // Process the relocation entry based on its type.
            switch (pBaseRelocEntry->type) {
	            case IMAGE_REL_BASED_DIR64:
	                // Adjust a 64-bit field by the delta offset.
	                *((ULONG_PTR*)(pPeBaseAddress + pImgBaseReloc->VirtualAddress + pBaseRelocEntry->offset)) += uDeltaOffset;
	                break;
	            case IMAGE_REL_BASED_HIGHLOW:
	                // Adjust a 32-bit field by the delta offset.
	                *((DWORD*)(pPeBaseAddress + pImgBaseReloc->VirtualAddress + pBaseRelocEntry->offset)) += (DWORD)uDeltaOffset;
	                break;
	            case IMAGE_REL_BASED_HIGH:
	                // Adjust the high 16 bits of a 32-bit field.
	                *((WORD*)(pPeBaseAddress + pImgBaseReloc->VirtualAddress + pBaseRelocEntry->offset)) += HIWORD(uDeltaOffset);
	                break;
	            case IMAGE_REL_BASED_LOW:
	                // Adjust the low 16 bits of a 32-bit field.
	                *((WORD*)(pPeBaseAddress + pImgBaseReloc->VirtualAddress + pBaseRelocEntry->offset)) += LOWORD(uDeltaOffset);
	                break;
	            case IMAGE_REL_BASED_ABSOLUTE:
	                // No relocation is required.
	                break;
	            default:
	                // Handle unknown relocation types.
	                printf("[!] Unknown relocation type: %d | Offset: 0x%08X \n", pBaseRelocEntry->type, pBaseRelocEntry->offset);
	                return FALSE;
            }
            // Move to the next relocation entry.
            pBaseRelocEntry++;
        }

        // Move to the next relocation block.
        pImgBaseReloc = (PIMAGE_BASE_RELOCATION)pBaseRelocEntry;
    }

    return TRUE;
}

bool FixImportAddressTable(PIMAGE_DATA_DIRECTORY pEntryImportDataDir, PBYTE pPeBaseAddress) {

	// Pointer to an import descriptor for a DLL
	PIMAGE_IMPORT_DESCRIPTOR	pImgDescriptor		= NULL;
 	// Iterate over the import descriptors
	for (SIZE_T i = 0; i < pEntryImportDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		// Get the current import descriptor
		pImgDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pPeBaseAddress + pEntryImportDataDir->VirtualAddress + i);
		// If both thunks are NULL, we've reached the end of the import descriptors list
		if (pImgDescriptor->OriginalFirstThunk == NULL && pImgDescriptor->FirstThunk == NULL)
			break;

		// Retrieve information from the current import descriptor
		LPSTR		cDllName                        = (LPSTR)(pPeBaseAddress + pImgDescriptor->Name);
		ULONG_PTR	uOriginalFirstThunkRVA          = pImgDescriptor->OriginalFirstThunk;
		ULONG_PTR	uFirstThunkRVA                  = pImgDescriptor->FirstThunk;
		SIZE_T		ImgThunkSize                    = 0x00;	// Used to move to the next function (iterating through the IAT and INT)
		HMODULE		hModule                         = NULL;

		// Try to load the DLL referenced by the current import descriptor
		if (!(hModule = LoadLibraryA(cDllName))) {
			std::cerr << "Failed to load library: " << cDllName << std::endl;
			return false;
		}

		// Iterate over the imported functions for the current DLL
		while (TRUE) {
			
			// Get pointers to the first thunk and original first thunk data
			PIMAGE_THUNK_DATA               pOriginalFirstThunk     = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uOriginalFirstThunkRVA + ImgThunkSize);
			PIMAGE_THUNK_DATA               pFirstThunk             = (PIMAGE_THUNK_DATA)(pPeBaseAddress + uFirstThunkRVA + ImgThunkSize);
			PIMAGE_IMPORT_BY_NAME           pImgImportByName        = NULL;
			ULONG_PTR                       pFuncAddress            = NULL;

			// At this point both 'pOriginalFirstThunk' & 'pFirstThunk' will have the same values
			// However, to populate the IAT (pFirstThunk), one should use the INT (pOriginalFirstThunk) to retrieve the 
			// functions addresses and patch the IAT (pFirstThunk->u1.Function) with the retrieved address.
			if (pOriginalFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
				break;
			}

			// If the ordinal flag is set, import the function by its ordinal number
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThunk->u1.Ordinal)) {
				if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, (LPCSTR)pOriginalFirstThunk->u1.Ordinal)) ) {
					printf("[!] Could Not Import !%s#%d \n", cDllName, (int)pOriginalFirstThunk->u1.Ordinal);
					return FALSE;
				}
			}
			// Import function by name
			else {
				pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pPeBaseAddress + pOriginalFirstThunk->u1.AddressOfData);
				if ( !(pFuncAddress = (ULONG_PTR)GetProcAddress(hModule, pImgImportByName->Name)) ) {
					printf("[!] Could Not Import !%s.%s \n", cDllName, pImgImportByName->Name);
					return FALSE;
				}
			}

			// Install the function address in the IAT
			pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;

			// Move to the next function in the IAT/INT array
			ImgThunkSize += sizeof(IMAGE_THUNK_DATA);
		}
	}

	return TRUE;
}


// Walk Section headers and apply correct memory permissions
bool FixMemPermissions(ULONG_PTR pPeBaseAddress, PIMAGE_NT_HEADERS pImgNtHeaders, PIMAGE_SECTION_HEADER pImgSectionHeaders){

    for (DWORD i=0; i< pImgNtHeaders->FileHeader.NumberOfSections; i++){
        DWORD dwProtection = 0x00,
              dwOldProtection = 0x00;
        if (!pImgSectionHeaders[i].SizeOfRawData || !pImgSectionHeaders[i].VirtualAddress)
            continue;

        if (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwProtection = PAGE_WRITECOPY;
        if (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ)
            dwProtection = PAGE_READONLY;
        if ((pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_READWRITE;
        if (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwProtection = PAGE_EXECUTE;
        if ((pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwProtection = PAGE_EXECUTE_WRITECOPY;
        if ((pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtection = PAGE_EXECUTE_READ;
        if ((pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_READ) && (pImgSectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwProtection = PAGE_EXECUTE_READWRITE;

        if (!VirtualProtect((PVOID)(pPeBaseAddress + pImgSectionHeaders[i].VirtualAddress), pImgSectionHeaders[i].SizeOfRawData, dwProtection, &dwOldProtection)){
            std::cerr << "Failed to change memory protection" << std::endl;
            return false;
        }
    }

}

VOID HandleCmdLineArgs(int argc, char* argv[], char** ppe_arg, char** pfptr_arg, char** pparm_arg) {

	char*	pe_arg					= NULL;
	char*	fptr_arg				= NULL;
	char*	parm_arg				= NULL;
	char	parm_buffer[1024 * 2]	= { 0 };

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-pe") == 0 && i + 1 < argc) {
			pe_arg = argv[++i];
		}
		else if (strcmp(argv[i], "-fptr") == 0 && i + 1 < argc) {
			fptr_arg = argv[++i];
		}
		else if (strcmp(argv[i], "-parm") == 0 && i + 1 < argc) {
			parm_arg = parm_buffer;
			strcpy(parm_arg, argv[++i]);
			while (i + 1 < argc && argv[i + 1][0] != '-') {
				strcat(parm_arg, " ");
				strcat(parm_arg, argv[++i]);
			}
		}
	}

	*ppe_arg	= pe_arg;
	*pfptr_arg	= fptr_arg;
	*pparm_arg	= parm_arg;
}

bool PeExec(PPE_HEADERS pPeHeaders) {

    if (!pPeHeaders)
        return false;

    PBYTE  pPeBaseAddress = NULL;
    PVOID pEntryPoint = NULL;

    if ((pPeBaseAddress = static_cast<PBYTE>(VirtualAlloc(NULL, pPeHeaders ->pImgNtHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) == NULL){
        std::cerr << "Failed to allocate memory" << std::endl;
        return false;
    }
    std::cout << "[*] Memory allocated at: " << pPeBaseAddress << std::endl;

    for (int i=0; i< pPeHeaders->pImgNtHeaders->FileHeader.NumberOfSections; i++){
        memcpy(
            (PVOID)(pPeBaseAddress + pPeHeaders->pImgSectionHeaders[i].VirtualAddress), // Destination 
            (PVOID)(pPeHeaders->pFileBuffer + pPeHeaders->pImgSectionHeaders[i].PointerToRawData), // Source 
            pPeHeaders->pImgSectionHeaders[i].SizeOfRawData

        );
    }

    if (!PeFixReloc(pPeHeaders->pEntryBaseRelocationDataDirectory, pPeBaseAddress, pPeHeaders->pImgNtHeaders->OptionalHeader.ImageBase)){
        std::cerr << "Failed to fix relocations" << std::endl;
        return false;
    }

    if (!FixImportAddressTable(pPeHeaders->pEntryImportDataDirectory, pPeBaseAddress)){
        std::cerr << "Failed to fix import address table" << std::endl;
        return false;
    }

    if (!FixMemPermissions(reinterpret_cast<ULONG_PTR>(pPeBaseAddress), pPeHeaders->pImgNtHeaders, pPeHeaders->pImgSectionHeaders)){
        std::cerr << "Failed to fix memory permissions" << std::endl;
        return false;
    }

    pEntryPoint = (PVOID)(pPeBaseAddress + pPeHeaders->pImgNtHeaders->OptionalHeader.AddressOfEntryPoint);
    if (pPeHeaders->bIsDLLFile){
        DLLMAIN pDllMain = (DLLMAIN)pEntryPoint;
        HANDLE hThread = NULL;

        pDllMain((HINSTANCE)pPeBaseAddress, DLL_PROCESS_ATTACH, NULL);
        if (hThread)
            WaitForSingleObject(hThread, INFINITE);
    }
    else {
        MAIN pMain = (MAIN)pEntryPoint;
        return pMain();
    }


    return true;
}


int main() {

    PBYTE pBuffer = NULL;
    DWORD dwFileSize = 0;
    PE_HEADERS peHeaders = { 0 };

    if (!ReadFile("C:\\MDev\\personal\\ref_injection\\dll.exe", &pBuffer, &dwFileSize)){
        std::cerr << "Failed to read file: " << "C:\\MDev\\personal\\ref_injection\\dll.exe" << std::endl;
        return 1;
    }

    if (!InitializePeHeaders(&peHeaders, pBuffer, dwFileSize)){
        std::cerr << "Failed to initialize PE headers" << std::endl;
        return 1;
    }

    if (!PeExec(&peHeaders)){
        std::cerr << "Failed to execute PE file" << std::endl;
        return 1;
    }

    return 0;

}