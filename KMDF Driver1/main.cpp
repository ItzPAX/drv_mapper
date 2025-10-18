#include <ntifs.h>
#include <ntddk.h>
#include "ntos.h"

NTSTATUS get_process_id(PCWSTR executable_name, PHANDLE pOutHandle)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    BOOLEAN found = FALSE;
    PSYSTEM_PROCESS_INFORMATION spi = NULL;
    UNICODE_STRING targetName;

    *pOutHandle = nullptr;

    RtlInitUnicodeString(&targetName, executable_name);

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;

    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'proc');
    if (!buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, 'proc');
        return status;
    }

    spi = (PSYSTEM_PROCESS_INFORMATION) buffer;
    while (TRUE) {
        if (spi->UniqueProcessId && spi->ImageName.Buffer) {
            UNICODE_STRING currentName;
            RtlInitUnicodeString(&currentName, spi->ImageName.Buffer);

            if (RtlCompareUnicodeString(&currentName, &targetName, FALSE) == 0) {
                *pOutHandle = spi->UniqueProcessId;
                found = TRUE;
                break;
            }
        }

        if (spi->NextEntryOffset == 0)
            break;

        spi = (PSYSTEM_PROCESS_INFORMATION) ((PUCHAR) spi + spi->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, 'proc');

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

void th_Routine()
{
    DbgPrint("Hi from thread\n");
}

NTSTATUS CustomDriverEntry(
	_In_ PDRIVER_OBJECT  kdmapperParam1,
	_In_ PUNICODE_STRING kdmapperParam2,
	_In_ VOID* ntoskrnl
)
{
	UNREFERENCED_PARAMETER(ntoskrnl);
	UNREFERENCED_PARAMETER(kdmapperParam2);

	DbgPrintEx(0, 0, "> Hello world! from 0x%llx\n", kdmapperParam1);

    HANDLE procId = NULL;
    get_process_id(L"kdmapper_Release.exe", &procId);

    DbgPrint("PID: %d\n", procId);
    PEPROCESS process = NULL;
    PsLookupProcessByProcessId(procId, &process);
    DbgPrint("Eproc: %llx", process);

    HANDLE hProc;
    ObOpenObjectByPointer(process, 0, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc);

    HANDLE thread = NULL;
    PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, hProc, NULL, (PKSTART_ROUTINE) th_Routine, NULL);

	return 0;
}