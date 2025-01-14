#include "dHelpers.h"

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("FilterUnload called.\n");
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
    }
    IoDeleteSymbolicLink(&gSymLinkName);
    if (gDeviceObject) {
        IoDeleteDevice(gDeviceObject);
    }
    DbgPrint("Filter Driver Unloaded.\n");
    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS PreOperationCreateCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (gBlockAccess) {
        if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        PFLT_FILE_NAME_INFORMATION fileNameInfo;
        NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);

        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to get FileNameInformation: 0x%08X\n", status);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        status = FltParseFileNameInformation(fileNameInfo);
        if (NT_SUCCESS(status)) {
            for (ULONG i = 0; i < gTargetFolderCount; i++) {
                if (RtlPrefixUnicodeString(&gTargetFolders[i], &fileNameInfo->Name, TRUE)) {
                    for (ULONG j = 0; j < gTargetFileCount; j++) {
                        if (RtlCompareUnicodeString(&fileNameInfo->FinalComponent, &gTargetFiles[j], TRUE) == 0) {
                            DbgPrint("Blocking access to %wZ\n", &fileNameInfo->FinalComponent);
                            FltReleaseFileNameInformation(fileNameInfo);
                            Data->IoStatus.Status = STATUS_NOT_FOUND;
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                }
            }
        }
        FltReleaseFileNameInformation(fileNameInfo);
    }
    else {
        if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        PFLT_FILE_NAME_INFORMATION fileNameInfo;
        NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);

        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to get FileNameInformation: 0x%08X\n", status);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        status = FltParseFileNameInformation(fileNameInfo);
        if (NT_SUCCESS(status)) {
            for (ULONG i = 0; i < gTargetFolderCount; i++) {
                if (RtlPrefixUnicodeString(&gTargetFolders[i], &fileNameInfo->Name, TRUE)) {
                    for (ULONG j = 0; j < gTargetFileCount; j++) {
                        if (RtlCompareUnicodeString(&fileNameInfo->FinalComponent, &gTargetFiles[j], TRUE) == 0) {
                            //DbgPrint("File being accessed %wZ\n", &fileNameInfo->FinalComponent);
                            FltReleaseFileNameInformation(fileNameInfo);
                            Data->IoStatus.Status = STATUS_SUCCESS;
                            return FLT_PREOP_SUCCESS_NO_CALLBACK;
                        }
                    }
                }
            }
        }
        FltReleaseFileNameInformation(fileNameInfo);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS PreOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->MajorFunction != IRP_MJ_DIRECTORY_CONTROL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG fileInformationClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
    PFLT_FILE_NAME_INFORMATION fileNameInfo;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInfo);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to get FileNameInformation: 0x%08X\n", status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(fileNameInfo);
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < gTargetFolderCount; i++) {
            if (RtlPrefixUnicodeString(&gTargetFolders[i], &fileNameInfo->Name, TRUE)) {
                switch (fileInformationClass) {
                case CoFileDirectoryInformation:
                case CoFileFullDirectoryInformation:
                case CoFileBothDirectoryInformation:
                case CoFileNamesInformation:
                case CoFileIdBothDirectoryInformation:
                case CoFileIdFullDirectoryInformation:
                case CoFileIdExtdBothDirectoryInformation:
                case CoFileIdExtdDirectoryInformation:
                    *CompletionContext = (PVOID)1; // Indicate that we need post-operation callback
                    FltReleaseFileNameInformation(fileNameInfo);
                    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
                default:
                    break;
                }
            }
        }
    }

    FltReleaseFileNameInformation(fileNameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostOperationCallback(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (CompletionContext) {
        PVOID prevDirInfo = NULL;
        UNICODE_STRING fileName;

        __try {
            switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass) {
            case CoFileDirectoryInformation:
            {
                PFILE_DIRECTORY_INFORMATION dirInfo = (PFILE_DIRECTORY_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_DIRECTORY_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_DIRECTORY_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileFullDirectoryInformation:
            {
                PFILE_FULL_DIR_INFORMATION dirInfo = (PFILE_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    if ((PUCHAR)dirInfo + sizeof(FILE_FULL_DIR_INFORMATION) > (PUCHAR)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer + Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length) {
                        DbgPrint("DirectoryBuffer is out of bounds. Denying request.\n");
                        Data->IoStatus.Status = STATUS_NOT_FOUND;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }

                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_FULL_DIR_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_FULL_DIR_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    fileName.Length = 0;
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileBothDirectoryInformation:
            {
                PFILE_BOTH_DIR_INFORMATION dirInfo = (PFILE_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_BOTH_DIR_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_BOTH_DIR_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileNamesInformation:
            {
                PFILE_NAMES_INFORMATION dirInfo = (PFILE_NAMES_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_NAMES_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_NAMES_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileIdBothDirectoryInformation:
            {
                PFILE_ID_BOTH_DIR_INFORMATION dirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_ID_BOTH_DIR_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_ID_BOTH_DIR_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileIdFullDirectoryInformation:
            {
                PFILE_ID_FULL_DIR_INFORMATION dirInfo = (PFILE_ID_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_ID_FULL_DIR_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_ID_FULL_DIR_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileIdExtdBothDirectoryInformation:
            {
                PFILE_ID_EXTD_BOTH_DIR_INFORMATION dirInfo = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_ID_EXTD_BOTH_DIR_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_ID_EXTD_BOTH_DIR_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_ID_EXTD_BOTH_DIR_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            case CoFileIdExtdDirectoryInformation:
            {
                PFILE_ID_EXTD_DIR_INFORMATION dirInfo = (PFILE_ID_EXTD_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
                while (dirInfo != NULL) {
                    fileName.Length = (USHORT)dirInfo->FileNameLength;
                    fileName.MaximumLength = (USHORT)dirInfo->FileNameLength;
                    fileName.Buffer = (PWCH)dirInfo->FileName;

                    for (ULONG i = 0; i < gTargetFileCount; i++) {
                        if (RtlEqualUnicodeString(&fileName, &gTargetFiles[i], TRUE)) {
                            if (prevDirInfo) {
                                if (dirInfo->NextEntryOffset == 0) {
                                    ((PFILE_ID_EXTD_DIR_INFORMATION)prevDirInfo)->NextEntryOffset = 0;
                                }
                                else {
                                    ((PFILE_ID_EXTD_DIR_INFORMATION)prevDirInfo)->NextEntryOffset += dirInfo->NextEntryOffset;
                                }
                            }
                            else {
                                if (dirInfo->NextEntryOffset == 0) {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NULL;
                                }
                                else {
                                    Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = (PVOID)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                                }
                            }
                            break;
                        }
                    }

                    prevDirInfo = dirInfo;

                    if (dirInfo->NextEntryOffset == 0) {
                        break;
                    }
                    dirInfo = (PFILE_ID_EXTD_DIR_INFORMATION)((PUCHAR)dirInfo + dirInfo->NextEntryOffset);
                }
                break;
            }
            default:
                break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            NTSTATUS exceptionCode = GetExceptionCode();
            ULONG fileInformationClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
            DbgPrint("Exception occurred in PostOperationCallback. Exception Code: 0x%08X, FileInformationClass: %u\n", exceptionCode, fileInformationClass);
        }
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}


const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreOperationCreateCallback, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_OPERATION_END }
};

const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};