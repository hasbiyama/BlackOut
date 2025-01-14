#pragma once
#pragma warning(disable : 4201)
#pragma warning(disable : 4459)

#include <ntifs.h>
#include <ntimage.h>
#include <fltKernel.h>

typedef enum {
    CoFileDirectoryInformation = 1,
    CoFileFullDirectoryInformation = 2,
    CoFileBothDirectoryInformation = 3,
    CoFileNamesInformation = 12,
    CoFileIdBothDirectoryInformation = 37,
    CoFileIdFullDirectoryInformation = 38,
    CoFileIdExtdBothDirectoryInformation = 63,
    CoFileIdExtdDirectoryInformation = 60
} CTM_FILE_INFORMATION_CLASS;

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _PROTECTION_VALUES {
    ULONG pid;
    UCHAR Signer;
    UCHAR Type;
} PROTECTION_VALUES, * PPROTECTION_VALUES;

typedef struct _DSE_MODE {
    BOOLEAN EnableDSE;
} DSE_MODE, * PDSE_MODE;

PVOID g_CiDllBase = NULL;
BOOLEAN g_EnableDSE = FALSE;

// Global variables to store original values
static BOOLEAN originalProtectionSaved = FALSE;
static UCHAR originalSigner;
static UCHAR originalType;

PFLT_FILTER gFilterHandle;
UNICODE_STRING gTargetFolders[10] = { 0 };
UNICODE_STRING gTargetFiles[10] = { 0 };
ULONG gTargetFolderCount = 0;
ULONG gTargetFileCount = 0;
PDEVICE_OBJECT gDeviceObject = NULL;
UNICODE_STRING gDeviceName = RTL_CONSTANT_STRING(L"\\Device\\BlackOut");
UNICODE_STRING gSymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\BlackOut");
BOOLEAN gBlockAccess = FALSE;