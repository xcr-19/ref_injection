#pragma once

#include <windows.h>

typedef struct _PE_HEADERS {
    PBYTE pFileBuffer;
    DWORD dwFileSize;

    PIMAGE_NT_HEADERS pImgNtHeaders;
    PIMAGE_SECTION_HEADER pImgSectionHeaders;

    PIMAGE_DATA_DIRECTORY pEntryImportDataDirectory;
    PIMAGE_DATA_DIRECTORY pEntryBaseRelocationDataDirectory;
    PIMAGE_DATA_DIRECTORY pEntryTLSDataDirectory;
    PIMAGE_DATA_DIRECTORY pEntryExceptionDataDirectory;
    PIMAGE_DATA_DIRECTORY pEntryExportDataDirectory;

    bool bIsDLLFile;

} PE_HEADERS, *PPE_HEADERS;

typedef struct _BASE_RELOCATION_ENTRY {
    WORD offset : 12;
    WORD type: 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

typedef BOOL(WINAPI* MAIN)();

typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);