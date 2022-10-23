#include "struct.h"

UCHAR PTRN_W10_Thread[] = { 0x48, 0x8b, 0xcd, 0xe8 };

void InitThreadNotiry(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.Pattern = PTRN_W10_Thread;
		pInfor->Notify.dwPattern = sizeof(PTRN_W10_Thread);
		pInfor->Notify.startFunc = "PsRemoveCreateThreadNotifyRoutine";
		pInfor->Notify.endFunc = "PsRemoveLoadImageNotifyRoutine";
		pInfor->Notify.ModuleName = "ntoskrnl.exe";
		pInfor->Notify.offset = -8;
		break;
	default:
		break;
	}
}

/*void DeleteThreadCallBack(PINFORMATION pInfor, PWSTR Copyright)
{
	NTSTATUS status;
	ULONG_PTR ThreadNotifyArray, eachCallBack, NotifyFuncAddress;

	InitThreadNotiry(pInfor);
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

	if (GetGlobalAddress(pInfor->NotifyEnableMask.ModuleName, pInfor->NotifyEnableMask.startFunc, pInfor->NotifyEnableMask.endFunc, pInfor->NotifyEnableMask.Pattern, pInfor->NotifyEnableMask.dwPattern, pInfor->NotifyEnableMask.offset, &ThreadNotifyArray))
	{
		wprintf(L"[*] PspCreateThreadNotifyRoutine @ %I64X\n", ThreadNotifyArray);
		for (USHORT i = 0; i < 64; i++)
		{
			if (UtilReadKernelMemory(pInfor->hDevice, ThreadNotifyArray + (i * sizeof(PVOID)), &eachCallBack))
			{
				if (!eachCallBack)
					continue;
				eachCallBack &= ~7;
				if (UtilReadKernelMemory(pInfor->hDevice, eachCallBack, &NotifyFuncAddress))
				{
					checkDriver(pInfor->hDevice, ThreadNotifyArray + (i * sizeof(PVOID)), NotifyFuncAddress, Copyright, L"PspCreateThreadNotify");
				}
			}
			else break;
		}
	}
}*/