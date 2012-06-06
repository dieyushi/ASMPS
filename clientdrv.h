/*++
Author: zzscu@live.com
Module Name:clientdrv.c
Last Modified Time:2011-1-4
--*/
#include <ntddk.h>
#include <windef.h>
#define DEVICE_NAME L"\\Device\\clientdrv"    
#define LINK_NAME L"\\DosDevices\\clientdrv"  

//#pragma pack(1)
//typedef struct ServiceDescriptorEntry {
//	unsigned int *ServiceTableBase;
//	unsigned int *ServiceCounterTableBase;
//	unsigned int NumberOfServices;
//	unsigned char *ParamTableBase;
//} SSDT_Entry;
//#pragma pack()
//
//__declspec(dllimport) SSDT_Entry KeServiceDescriptorTable;
//
//#define SYSCALL(_func) KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_func+1)]
//#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
//#define SYSTEMSERVICE(ID)  KeServiceDescriptorTable.ServiceTableBase[ID]
//
//#define ZwSuspendProcessWinXP 0xFD
//#define ZwSuspendProcessWin7 0x16E
//#define ZwResumeProcessWinXP 0xCD
//#define ZwResumeProcessWin7 0x119

#define IOCTL_BASE	0x800
#define	FILE_DEVICE_COMM_DRIVER		 0x00008810

#define NEITHER_CTL_CODE(i)    CTL_CODE(FILE_DEVICE_NULL, IOCTL_BASE+i, METHOD_NEITHER, FILE_ANY_ACCESS)
#define BUFF_CTL_CODE(i)       CTL_CODE(FILE_DEVICE_NULL, IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define  IOCTL_SEND_EVENT BUFF_CTL_CODE(1)   //获取应用层创建的事件句柄进程启动
#define  IOCTL_GET_NEWPATH   BUFF_CTL_CODE(2)    //获取新建进程路径
#define  IOCTL_GET_NEWPID	BUFF_CTL_CODE(3) //获取新的进程pid
#define  IOCTL_PROTECT_PROC     BUFF_CTL_CODE(4) //保护进程
#define  IOCTL_TERMINATE_THREAD BUFF_CTL_CODE(5) //终结线程
#define  IOCTL_TERMINATE_PROCESS BUFF_CTL_CODE(6) //终结进程
#define  IOCTL_GET_REMOTETID  BUFF_CTL_CODE(7)  //获取新的远程线程id
#define  IOCTL_SEND_EVENT2  BUFF_CTL_CODE(8)  //获取应用层创建的事件句柄进程退出
#define  IOCTL_SEND_EVENT3 BUFF_CTL_CODE(9)  //获取应用层创建的事件句柄远程线程出现
#define  IOCTL_GET_ENDPATH BUFF_CTL_CODE(10) //获取结束进程路径

ULONG g_pidnew;
ULONG g_pidend;
ULONG g_remotepid;
ULONG g_remotetid;
PRKEVENT gpEventObject = NULL;	      //new process
PRKEVENT gpEventObject2 = NULL;       //end process
PRKEVENT gpEventObject3 = NULL;	      //remote thread
CHAR  g_ProcName[256] = "";
CHAR  z_ProcName[256] = "";

ULONG osver = 0;
BOOLEAN g_bMainThread = FALSE;

typedef struct _EVENTHANDLES
{
	HANDLE event1;
	HANDLE event2;
}EventHandles, *PEventHandles;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef NTSTATUS (*PSPTERMINATETHREADBYPOINTER)(PETHREAD PET, NTSTATUS Status);
typedef VOID (*PSPEXITTHREAD)(NTSTATUS status);
PSPTERMINATETHREADBYPOINTER PspTerminateThreadByPointer;
PSPEXITTHREAD PspExitThread;
typedef NTSTATUS (*NTSUSPENDPROCESS) (IN HANDLE ProcessHandle);
typedef NTSTATUS (*NTRESUMEPROCESS) (IN HANDLE ProcessHandle);
//typedef PETHREAD (*PSGETNEXTPROCESSTHREAD)(IN PEPROCESS Process,IN PETHREAD Thread OPTIONAL);
//PSGETNEXTPROCESSTHREAD PsGetNextProcessThread;
VOID OnUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath);
VOID ProcCreateCallback(IN HANDLE  ParentId,IN HANDLE  ProcessId,IN BOOLEAN  Create);
VOID ThreadCreateCallback(IN HANDLE  ProcessId,IN HANDLE  ThreadId,IN BOOLEAN  Create);
NTSTATUS NtNameToDosName( IN PUNICODE_STRING NtName, OUT PUNICODE_STRING DosName);
BOOLEAN GetProcPath(IN HANDLE PID,OUT PUNICODE_STRING imageName);
NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId,OUT PEPROCESS *Process);
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(IN HANDLE ProcessHandle,IN PROCESSINFOCLASS ProcessInformationClass,OUT PVOID ProcessInformation,IN ULONG ProcessInformationLength,OUT PULONG ReturnLength OPTIONAL); 
DWORD ZZSearchUndocumentFunction_PspTerminateThreadByPointer();
PETHREAD NTAPI PsGetNextProcessThread(IN PEPROCESS Process,IN PETHREAD Thread OPTIONAL);
NTSTATUS AntiTerminate(HANDLE PID);
ULONG GetCrossFlagOffSet();
ULONG GetOsVersion();
NTSTATUS PsLookupThreadByThreadId(IN HANDLE ThreadId,OUT PETHREAD *Thread);
DWORD ZZSearchUndocumentFunction_PspExitThread();
BOOLEAN TerminateThread(PETHREAD ethread);
VOID TerminateThisThread(PKAPC Apc,PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,PVOID *SystemArgument1,PVOID *SystemArgument2);
VOID KeInitializeApc (PKAPC Apc,PETHREAD Thread,KAPC_ENVIRONMENT Environment,PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,PKNORMAL_ROUTINE NormalRoutine,KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext);
BOOLEAN KeInsertQueueApc(PKAPC Apc,PVOID SystemArg1,PVOID SystemArg2,KPRIORITY Increment);
NTSTATUS TerminateProcess(HANDLE PID);
