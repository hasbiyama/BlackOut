#pragma once
#pragma warning(disable : 4966)

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <shlwapi.h>
#include <string.h>
#include <stdlib.h>
#include <psapi.h>
#include <tlhelp32.h>

#define DEVICE_NAME "\\\\.\\GlobalRoot\\Device\\BlackOut"

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PROTECTION_VALUES {
    ULONG pid;
    UCHAR Signer;
    UCHAR Type;
} PROTECTION_VALUES, * PPROTECTION_VALUES;

typedef struct _DSE_MODE {
    BOOLEAN EnableDSE;
} DSE_MODE, * PDSE_MODE;

CHAR fullPath[MAX_PATH];
CHAR parentDir[MAX_PATH];
CHAR folderName[MAX_PATH];
CHAR deviceName[MAX_PATH];
HANDLE hDevice;