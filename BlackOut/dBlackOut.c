#include "IoControl.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    DbgPrint("DriverEntry called. Registry Path: %wZ\n", RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (NT_SUCCESS(status)) {
        DbgPrint("Filter registered successfully.\n");
        status = FltStartFiltering(gFilterHandle);
        if (!NT_SUCCESS(status)) {
            DbgPrint("Failed to start filter: 0x%08X\n", status);
            FltUnregisterFilter(gFilterHandle);
        }
    }
    else {
        DbgPrint("Failed to register filter: 0x%08X\n", status);
    }

    if (NT_SUCCESS(status)) {
        status = IoCreateDevice(DriverObject, 0, &gDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &gDeviceObject);
        if (NT_SUCCESS(status)) {
            status = IoCreateSymbolicLink(&gSymLinkName, &gDeviceName);
            if (NT_SUCCESS(status)) {
                DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
                DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
                DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;
                DriverObject->DriverUnload = DriverUnload;
                DbgPrint("Device and symbolic link created successfully.\n");
            }
            else {
                IoDeleteDevice(gDeviceObject);
                gDeviceObject = NULL;
                DbgPrint("Failed to create symbolic link: 0x%08X\n", status);
            }
        }
        else {
            DbgPrint("Failed to create device: 0x%08X\n", status);
        }
    }

    return status;
}