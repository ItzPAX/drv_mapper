#include <ntddk.h>

NTSTATUS CustomDriverEntry(
	_In_ PDRIVER_OBJECT  kdmapperParam1,
	_In_ PUNICODE_STRING kdmapperParam2,
	_In_ VOID* ntoskrnl
)
{
	UNREFERENCED_PARAMETER(ntoskrnl);
	UNREFERENCED_PARAMETER(kdmapperParam2);

	DbgPrintEx(0, 0, "> Hello world! from 0x%llx\n", kdmapperParam1);

	return 0;
}