#include <wdm.h>
#include <tchar.h>
#include <initguid.h>
#include <mountmgr.h>
#include <mountdev.h>
#include <ntddvol.h>

#include "NtDriver.h"

static NTSTATUS MBRReadWriteDevice(BOOL write, PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatusBlock;
	PIRP irp;
	KEVENT completionEvent;

	ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	KeInitializeEvent(&completionEvent, NotificationEvent, FALSE);
	irp = IoBuildSynchronousFsdRequest(write ? IRP_MJ_WRITE : IRP_MJ_READ, deviceObject, buffer, length, &offset, &completionEvent, &ioStatusBlock);
	if (!irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	ObReferenceObject(deviceObject);
	status = IoCallDriver(deviceObject, irp);

	if (status == STATUS_PENDING)
	{
		status = KeWaitForSingleObject(&completionEvent, Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS(status))
			status = ioStatusBlock.Status;
	}

	ObDereferenceObject(deviceObject);
	return status;
}

NTSTATUS MBRReadDevice(PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	return MBRReadWriteDevice(FALSE, deviceObject, buffer, offset, length);
}


NTSTATUS MBRWriteDevice(PDEVICE_OBJECT deviceObject, PVOID buffer, LARGE_INTEGER offset, ULONG length)
{
	return MBRReadWriteDevice(TRUE, deviceObject, buffer, offset, length);
}
