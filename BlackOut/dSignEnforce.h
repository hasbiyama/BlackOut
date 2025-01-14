#include "dGlobalDef.h"

void FindAndPrintCiInitializeSymbol(PVOID pImageBase) {
    __try {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)pImageBase + pDosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pImageBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        PULONG pNameTable = (PULONG)((PUCHAR)pImageBase + pExportDirectory->AddressOfNames);
        PULONG pAddressTable = (PULONG)((PUCHAR)pImageBase + pExportDirectory->AddressOfFunctions);
        PUSHORT pOrdinalTable = (PUSHORT)((PUCHAR)pImageBase + pExportDirectory->AddressOfNameOrdinals);

        for (ULONG i = 0; i < pExportDirectory->NumberOfNames; i++) {
            PCHAR pName = (PCHAR)((PUCHAR)pImageBase + pNameTable[i]);
            if (strcmp(pName, "CiInitialize") == 0) {
                ULONG_PTR address = (ULONG_PTR)((PUCHAR)pImageBase + pAddressTable[pOrdinalTable[i]]);
                //DbgPrint("Symbol: %s, Address: %p\n", pName, (PVOID)address);

                PUCHAR code = (PUCHAR)address;
                ULONG_PTR movEbpEcxAddress = 0;
                ULONG_PTR movRbxQwordAddr = 0;

                for (int j = 0; j < 100; j++) { // Search within the next 100 bytes
                    if (RtlCompareMemory(&code[j], "\x4C\x8B\xCB\x4C\x8B\xC7\x48\x8B\xD6\x8B\xCD", 11) == 11) {
                        movEbpEcxAddress = (ULONG_PTR)(code + j);
                        //DbgPrint("Found 'mov ecx, ebp' instruction at: %p\n", (PVOID)movEbpEcxAddress);
                        break;
                    }
                }

                if (movEbpEcxAddress != 0) {
                    for (int j = 0; j < 100; j++) { // Search within the next 100 bytes
                        if (RtlCompareMemory(&code[j], "\x48\x8B\x5C\x24\x30\x48\x8B\x6C\x24\x38", 10) == 10) {
                            movRbxQwordAddr = (ULONG_PTR)(code + j);
                            //DbgPrint("Found 'mov rbx, qword ptr [addr]' instruction at: %p\n", (PVOID)movRbxQwordAddr);
                            break;
                        }
                    }
                }

                if (movEbpEcxAddress != 0 && movRbxQwordAddr != 0) {
                    for (ULONG_PTR k = movEbpEcxAddress; k < movRbxQwordAddr; k++) {
                        if (*(PUCHAR)k == 0xE8) { // Opcode for call instruction
                            LONG relOffset = *(PLONG)(k + 1);
                            ULONG_PTR callAddress = k;
                            ULONG_PTR targetAddress = callAddress + relOffset + 5;
                            //DbgPrint("Call instruction address: %p, Target address: %p\n", (PVOID)callAddress, (PVOID)targetAddress);

                            PUCHAR targetCode = (PUCHAR)targetAddress;
                            for (int j = 0; j < 100; j++) { // Search within the next 100 bytes
                                if (targetCode[j] == 0x89 && targetCode[j + 1] == 0x0D) {
                                    ULONG_PTR movAddress = *(PLONG)(targetCode + j + 2) + (ULONG_PTR)targetCode + j + 6;
                                    //DbgPrint("Found 'mov ptr [address], ecx' instruction at: %p, Target address: %p\n", (PVOID)(targetCode + j), (PVOID)movAddress);

                                    PULONG_PTR valueAddress = (PULONG_PTR)movAddress;
                                    DbgPrint("Value at address %p: %p\n", (PVOID)valueAddress, (PVOID)*valueAddress);

                                    __try {
                                        *valueAddress = g_EnableDSE ? 0x6 : 0x0;
                                        DbgPrint("Changed value at address %p to: %p\n", (PVOID)valueAddress, (PVOID)(g_EnableDSE ? 0x6 : 0x0));
                                    }
                                    __except (EXCEPTION_EXECUTE_HANDLER) {
                                        DbgPrint("Exception occurred while changing value at address %p\n", (PVOID)valueAddress);
                                    }
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
                return;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("Exception occurred while accessing memory\n");
    }

    DbgPrint("Symbol 'CiInitialize' not found\n");
}