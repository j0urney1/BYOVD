#include "struct.h"
UCHAR PTRN_W10_1709_Process[] = { 0x48, 0x8d, 0x0c, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xc0, 0x49, 0x03, 0xcd, 0x48, 0x8b/*, 0xd6, 0xe8*/ };


void InitProcessNotify(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.Pattern = PTRN_W10_1709_Process;
		pInfor->Notify.dwPattern = sizeof(PTRN_W10_1709_Process);
		pInfor->Notify.startFunc = "PsSetCreateProcessNotifyRoutine";
		pInfor->Notify.endFunc = "IoCreateDriver";
		pInfor->Notify.ModuleName = "ntoskrnl.exe";
		pInfor->Notify.offset = -4;
		break;
	default:
		break;
	}
}
/*void DeleteProcessCallBack(PINFORMATION pInfor, PWSTR Copyright)
{
	NTSTATUS status;
	ULONG_PTR ProcessNotifyArray;
	ULONG_PTR eachCallBack;
	ULONG_PTR NotifyFuncAddress;

	InitProcessNotify(pInfor);
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

	if (GetGlobalAddress(pInfor->NotifyEnableMask.ModuleName, pInfor->NotifyEnableMask.startFunc, pInfor->NotifyEnableMask.endFunc, pInfor->NotifyEnableMask.Pattern, pInfor->NotifyEnableMask.dwPattern, pInfor->NotifyEnableMask.offset, &ProcessNotifyArray))
	{
		wprintf(L"[*] PspCreateProcessNotifyRoutine @ %I64X\n", ProcessNotifyArray); 
		for (USHORT i = 0; i < 64; i++)
		{
			if (UtilReadKernelMemory(pInfor->hDevice, ProcessNotifyArray + (i * sizeof(PVOID)), &eachCallBack))
			{

				if (!eachCallBack)
					continue;
				eachCallBack &= ~7;

				if (UtilReadKernelMemory(pInfor->hDevice, eachCallBack, &NotifyFuncAddress))
				{
					checkDriver(pInfor->hDevice, ProcessNotifyArray + (i * sizeof(PVOID)), NotifyFuncAddress, Copyright, L"PspCreateProcessNotify");
				}
			}
			else break;
		}
	}
}*/