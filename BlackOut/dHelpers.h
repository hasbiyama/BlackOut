#include "dGlobalDef.h"

/* ===========================================

                 Minifilter 

============================================== */

void PrintCurrentHiddenTargets()
{
    DbgPrint("Current hidden folders:\n");
    for (ULONG i = 0; i < gTargetFolderCount; i++) {
        DbgPrint("  %wZ\n", &gTargetFolders[i]);
    }

    DbgPrint("Current hidden files:\n");
    for (ULONG i = 0; i < gTargetFileCount; i++) {
        DbgPrint("  %wZ\n", &gTargetFiles[i]);
    }
}

void UnhideAllFiles()
{
    for (ULONG i = 0; i < gTargetFileCount; i++) {
        if (gTargetFiles[i].Buffer != NULL) {
            RtlFreeUnicodeString(&gTargetFiles[i]);
        }
    }
    gTargetFileCount = 0;
    DbgPrint("All files have been unhidden.\n");

    for (ULONG i = 0; i < gTargetFolderCount; i++) {
        if (gTargetFolders[i].Buffer != NULL) {
            RtlFreeUnicodeString(&gTargetFolders[i]);
        }
    }
    gTargetFolderCount = 0;
    DbgPrint("All folders have been unhidden.\n");
}