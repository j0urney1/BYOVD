#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <stdio.h>
#include <NTSecAPI.h>
#include <shlwapi.h>
#include <winver.h>


#pragma comment(lib,"ntdll")
#pragma comment(lib,"shlwapi")
#pragma comment(lib,"Version")
#pragma comment(lib,"user32")

#define NT_SUCCESS(status) ((NTSTATUS)status >= 0)
#define PRINT_ERROR(...) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " __VA_ARGS__))
#define FILE_OPEN								0x00000001
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }





typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemProcessInformation = 5,
	SystemModuleInformation = 11,
	SystemHandleInformation = 16,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;
typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation
} OBJECT_INFORMATION_CLASS;
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef LONG KPRIORITY;
typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;
typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;
typedef enum _KWAIT_REASON {
	Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	WrKeyedEvent,
	WrTerminated,
	WrProcessInSwap,
	WrCpuRateControl,
	WrCalloutStack,
	WrKernel,
	WrResource,
	WrPushLock,
	WrMutex,
	WrQuantumEnd,
	WrDispatchInt,
	WrPreempted,
	WrYieldExecution,
	WrFastMutex,
	WrGuardedMutex,
	WrRundown,
	MaximumWaitReason
} KWAIT_REASON;
typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
typedef struct _SYSTEM_THREAD {
#if !defined(_M_X64) || !defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER KernelTime;
#endif
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG State;
	KWAIT_REASON WaitReason;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
	LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, * PSYSTEM_THREAD;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE ParentProcessId;
	ULONG HandleCount;
	LPCWSTR Reserved2[2];
	ULONG PrivatePageCount;
	VM_COUNTERS VirtualMemoryCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
}RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG 	NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION 	Modules[ANYSIZE_ARRAY];
}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _PREVIOUSMODE
{
	USHORT PreviousModeOffset;
}PREVIOUSMODE;
typedef struct _NOTIFY
{
	PSTR ModuleName;
	PSTR startFunc;
	PSTR endFunc;
	PUCHAR Pattern;
	USHORT dwPattern;
	LONG offset;
	
}NOTIFY, * PNOTIFY;
typedef struct _MINIFILTER
{
	USHORT MiniFilterGlobalOffset;
	USHORT InstanceListOffset;
	USHORT rListOffset;
	USHORT rCountOffset;
	USHORT portOffset;
	USHORT InstanceOffset;
	ULONG CallbackOffset;
	ULONG CallbackPreOffset;
	ULONG CallbackPostOffset;
}MINIFILTER, * PMINIFILTER;
typedef struct _INFORMATION
{
	HANDLE hDevice;
	BOOL isInit;
	PREVIOUSMODE PreviousMode;
	NOTIFY Notify;
	DWORD Build;
	USHORT CallbackListOffset;
	MINIFILTER MiniFilter;

}INFORMATION, * PINFORMATION;

typedef struct _ARBITRARY_READ_PRIMITIVE
{
	ULONGLONG unk0;
	ULONG_PTR address;
	ULONGLONG zero;
	ULONG_PTR value;
} ARBITRARY_READ_PRIMITIVE, * PARBITRARY_READ_PRIMITIVE;

typedef struct _ARBITRARY_WRITE_PRIMITIVE
{
	ULONGLONG padding1;
	ULONG_PTR address;
	ULONGLONG padding2;
	ULONG_PTR value_to_write;
} ARBITRARY_WRITE_PRIMITIVE, * PARBITRARY_WRITE_PRIMITIVE;

typedef struct _RTCORE64_MEMORY_READ {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD ReadSize;
	DWORD Value;
	BYTE Pad3[16];
}RTCORE64_MEMORY_READ, * PRTCORE64_MEMORY_READ;


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	/// ...
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModulevector;
	LIST_ENTRY InMemoryOrderModulevector;
	LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	struct BitField {
		BYTE ImageUsesLargePages : 1;
		BYTE SpareBits : 7;
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	/// ...
} PEB, * PPEB;
typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29,
	ProcessProtectionInformation = 61,
}PROCESSINFOCLASS, * PPROCESSINFOCLASS;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;
typedef struct _RTL_BUFFER
{
	PUCHAR Buffer;
	PUCHAR StaticBuffer;
	SIZE_T Size;
	SIZE_T StaticSize;
	SIZE_T ReservedForAllocatedSize;
	PVOID ReservedForIMalloc;
} RTL_BUFFER, * PRTL_BUFFER;
typedef struct _RTL_UNICODE_STRING_BUFFER
{
	UNICODE_STRING String;
	RTL_BUFFER ByteBuffer;
	UCHAR MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
} RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;

EXTERN_C NTSYSAPI NTSTATUS NTAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS 	SystemInfoClass, OUT PVOID 	SystemInfoBuffer, IN ULONG 	SystemInfoBufferSize, OUT PULONG BytesReturned 	OPTIONAL);
EXTERN_C NTSYSAPI NTSTATUS ZwQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
EXTERN_C NTSYSAPI VOID RtlInitUnicodeString(PUNICODE_STRING         DestinationString, PCWSTR SourceString);
EXTERN_C NTSYSAPI BOOLEAN RtlEqualUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN          CaseInSensitive);
EXTERN_C NTSYSAPI VOID RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PULONG);
EXTERN_C NTSTATUS NtReadVirtualMemory(IN  HANDLE ProcessHandle, IN  PVOID BaseAddress, OUT PVOID Buffer, IN  ULONG BufferSize, OUT PULONG NumberOfBytesRead OPTIONAL);
EXTERN_C NTSTATUS NTAPI NtAllocateVirtualMemory(IN HANDLE 	ProcessHandle, IN OUT PVOID* UBaseAddress, IN ULONG_PTR 	ZeroBits, IN OUT PSIZE_T 	URegionSize, IN ULONG 	AllocationType, IN ULONG 	Protect);
EXTERN_C NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(IN HANDLE               ProcessHandle,IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,IN BOOLEAN              CreateSuspended,IN ULONG                StackZeroBits,IN OUT PULONG           StackReserved,IN OUT PULONG           StackCommit,IN PVOID                StartAddress,IN PVOID                StartParameter OPTIONAL,OUT PHANDLE             ThreadHandle,OUT LPVOID          ClientID);
EXTERN_C NTSTATUS NTAPI ZwWriteVirtualMemory(_In_ HANDLE 	ProcessHandle, PVOID 	BaseAddress, PVOID 	Buffer, SIZE_T 	NumberOfBytesToWrite, PSIZE_T 	NumberOfBytesWritten);
EXTERN_C NTSTATUS NTAPI NtClose(HANDLE);
EXTERN_C NTSTATUS WINAPI NtQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, OUT ULONG ProcessInformationLength, OUT OPTIONAL PULONG ReturnLength);
EXTERN_C NTSTATUS NTAPI NtOpenThread(OUT PHANDLE 	ThreadHandle,IN ACCESS_MASK 	DesiredAccess,IN POBJECT_ATTRIBUTES 	ObjectAttributes,IN PCLIENT_ID ClientId 	OPTIONAL);
EXTERN_C NTSTATUS NTAPI NtOpenProcess(OUT PHANDLE 	ProcessHandle, IN ACCESS_MASK 	DesiredAccess, IN POBJECT_ATTRIBUTES 	ObjectAttributes, IN PCLIENT_ID 	ClientId);
EXTERN_C NTSTATUS NtDeviceIoControlFile(HANDLE           FileHandle, HANDLE           Event, PVOID  ApcRoutine, PVOID            ApcContext, PVOID IoStatusBlock, ULONG            IoControlCode, PVOID            InputBuffer, ULONG            InputBufferLength, PVOID            OutputBuffer, ULONG            OutputBufferLength);
EXTERN_C BOOLEAN  RtlDosPathNameToNtPathName_U(_In_opt_z_ PCWSTR 	DosPathName, _Out_ PUNICODE_STRING 	NtPathName, _Out_opt_ PCWSTR* NtFileNamePart, _Out_opt_ PVOID 	DirectoryInfo);
EXTERN_C NTSTATUS NtCreateFile(PHANDLE            FileHandle, ACCESS_MASK        DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER     AllocationSize, ULONG              FileAttributes, ULONG              ShareAccess, ULONG              CreateDisposition, ULONG              CreateOptions, PVOID              EaBuffer, ULONG              EaLength);
EXTERN_C NTSTATUS NTAPI RtlGetNtVersionNumbers(DWORD*, DWORD*, DWORD*);
EXTERN_C NTSTATUS WINAPI RtlNtPathNameToDosPathName(ULONG Flags, PRTL_UNICODE_STRING_BUFFER Path, PULONG Type, PULONG Unknown4);
EXTERN_C NTSYSAPI NTSTATUS ZwTerminateProcess( HANDLE   ProcessHandle,NTSTATUS ExitStatus);

void PreviousMode(PINFORMATION);
void PspNotifyEnableMask(PINFORMATION pInfor);
BOOL GetHandleTypeIndex(PSYSTEM_HANDLE_INFORMATION buffer, PUCHAR HandleTypeIndex, PWSTR wStr, DWORD cId);
NTSTATUS GetGlobalHandleTable(PVOID* handletable);
BOOL GetTargetObjectAddress(PSYSTEM_HANDLE_INFORMATION buffer, DWORD UniqueProcess, HANDLE handleValue, PVOID object, UCHAR typeIndex);
NTSTATUS GetGlobalProcessInformation(PVOID buffer);
BOOL GetProcessID(PSYSTEM_PROCESS_INFORMATION buffer, PWSTR processName, DWORD* processId);
BOOL RtReadKernelMemory(HANDLE hDevice, ULONG_PTR address, DWORD size, DWORD* out);
BOOL RtReadKernelMemoryDWORD64(HANDLE hDevice, ULONG_PTR address, ULONG_PTR* out);
BOOL RtWriteKernelMemory(HANDLE hDevice, DWORD size, ULONG_PTR address, DWORD value);
BOOL RtWriteKernelMemoryDWORD64(HANDLE hDevice, ULONG_PTR address, ULONG_PTR value);
BOOL UtilReadKernelMemory(HANDLE hDevice, ULONG_PTR in, ULONG_PTR* out);
BOOL UtilWriteKernelMemory(HANDLE hDevice, ULONG_PTR in, ULONG_PTR value);
NTSTATUS enumDriver();
void SortDevice();
BOOL GetGlobalAddress(PSTR ModuleName, PSTR StartFunction, PSTR endFunction, PUCHAR pattern, DWORD dwPattern, LONG callback, ULONG_PTR* globalAddress);
BOOL checkDriver(HANDLE hDevice, ULONG_PTR routeAddress, ULONG_PTR funcAddress, PWSTR LegalCopyrightName, PWSTR, BOOL);
void DeleteRegCallBackList(PINFORMATION pInfor, PWSTR Copyright);
void DeleteObCallBackList(void(*callback)(void* info), PINFORMATION pInfor, PWSTR Copyright, PWSTR);
void minifilter(PINFORMATION pInfor, PWSTR Copyright);

void InitProcessNotify(PINFORMATION pInfor);
void InitThreadNotiry(PINFORMATION pInfor);
void InitLoadImage(PINFORMATION pInfor);
void InitProcessObject(PINFORMATION pInfor);
void InitThreadObject(PINFORMATION pInfor);
void DeleteRegistryCallBack(void(*callback)(void* info), PINFORMATION pInfor, PWSTR Copyright, PWSTR Routine, PWSTR Notify);

EXTERN_C PRTL_PROCESS_MODULES moduleInfos;
EXTERN_C BOOL needSort;



