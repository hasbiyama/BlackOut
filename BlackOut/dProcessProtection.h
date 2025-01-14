#include "dGlobalDef.h"

VOID SaveOriginalProtection(PPS_PROTECTION pProtection, UCHAR* originalSigner, UCHAR* originalType) {
    *originalSigner = pProtection->Signer;
    *originalType = pProtection->Type;
}

VOID RevertProtection(PEPROCESS pEProcess) {
    if (originalProtectionSaved && pEProcess != NULL) { // Check if pEProcess is not NULL
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
        PVOID pPsIsProtectedProcess = MmGetSystemRoutineAddress(&routineName);

        if (pPsIsProtectedProcess) {
            UCHAR* pBytes = (UCHAR*)pPsIsProtectedProcess;
            USHORT offset = (pBytes[3] << 8) | pBytes[2];
            PUCHAR process = (PUCHAR)pEProcess;
            PPS_PROTECTION pProtection = (PPS_PROTECTION)(process + offset);

            if (MmIsAddressValid(pProtection)) {
                DbgPrint("Reverting PS_PROTECTION - Original Signer: %d, Original Type: %d\n", originalSigner, originalType);
                pProtection->Signer = originalSigner;
                pProtection->Type = originalType;
                DbgPrint("Reverted PS_PROTECTION - Level: 0x%02X, Type: %d, Audit: %d, Signer: %d\n", pProtection->Level, pProtection->Type, pProtection->Audit, pProtection->Signer);
            }
            else {
                DbgPrint("PS_PROTECTION address is not valid.\n");
            }
        }
        else {
            DbgPrint("Failed to get the address of PsIsProtectedProcess.\n");
        }
    }
    else {
        DbgPrint("Original protection values not saved or pEProcess is NULL.\n");
    }
}

VOID PrintPSProtectionAddress(PEPROCESS pEProcess, UCHAR Signer, UCHAR Type) {
    __try {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsIsProtectedProcess");
        PVOID pPsIsProtectedProcess = MmGetSystemRoutineAddress(&routineName);

        if (pPsIsProtectedProcess) {
            DbgPrint("Address of PsIsProtectedProcess: %p\n", pPsIsProtectedProcess);

            UCHAR* pBytes = (UCHAR*)pPsIsProtectedProcess;
            USHORT offset = (pBytes[3] << 8) | pBytes[2];
            DbgPrint("2nd and 3rd bytes in little endian: %04X\n", offset);

            PUCHAR process = (PUCHAR)pEProcess;
            PPS_PROTECTION pProtection = (PPS_PROTECTION)(process + offset);

            if (MmIsAddressValid(pProtection)) {
                DbgPrint("PS_PROTECTION Address: %p\n", pProtection);
                DbgPrint("Level: 0x%02X, Type: %d, Audit: %d, Signer: %d\n", pProtection->Level, pProtection->Type, pProtection->Audit, pProtection->Signer);

                // Save original values only once
                if (!originalProtectionSaved) {
                    SaveOriginalProtection(pProtection, &originalSigner, &originalType);
                    originalProtectionSaved = TRUE;
                }

                // Update values
                pProtection->Signer = Signer;
                pProtection->Type = Type;

                DbgPrint("Updated PS_PROTECTION - Level: 0x%02X, Type: %d, Audit: %d, Signer: %d\n", pProtection->Level, pProtection->Type, pProtection->Audit, pProtection->Signer);
            }
            else {
                DbgPrint("PS_PROTECTION address is not valid.\n");
            }
        }
        else {
            DbgPrint("Failed to get the address of PsIsProtectedProcess.\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Exception occurred in PrintPSProtectionAddress.\n");
    }
}