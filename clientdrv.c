/*++
Author: zzscu@live.com
Module Name:clientdrv.c
Last Modified Time:2011-1-4
--*/
#include "clientdrv.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, OnUnload)
#pragma alloc_text(PAGE, DispatchClose)
#pragma alloc_text(PAGE, DispatchCreate)
#pragma alloc_text(PAGE, DispatchIoctl)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ProcCreateCallback)
#pragma alloc_text(PAGE, ThreadCreateCallback)
#pragma alloc_text(PAGE, NtNameToDosName)
#pragma alloc_text(PAGE, GetProcPath)
#pragma alloc_text(PAGE, PsGetNextProcessThread)
#pragma alloc_text(PAGE, AntiTerminate)
#pragma alloc_text(PAGE, GetOsVersion)
#pragma alloc_text(PAGE, TerminateThisThread)
#pragma alloc_text(PAGE, TerminateProcess)
#endif

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)  
{  
    UNICODE_STRING strLink;
    RtlInitUnicodeString(&strLink, LINK_NAME);

    IoDeleteSymbolicLink(&strLink);         
    IoDeleteDevice(DriverObject->DeviceObject);           

    PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ProcCreateCallback,TRUE);
    PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)ThreadCreateCallback);

    KdPrint (("[Clientdrv]DriverUnload\n"));
} 

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    KdPrint(("[Clientdrv]IRP_MJ_CREATE\n"));
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    KdPrint(("[Clientdrv]IRP_MJ_CLOSE\n"));
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    NTSTATUS IoCtlNtstus;
    PIO_STACK_LOCATION pIRPStack;
    ULONG uIoControlCode;
    PVOID pIoBuffer;
    ULONG uInSize;
    ULONG uOutSize ;

    HANDLE	hEvent;
    HANDLE  hEvent2;
    HANDLE  hEvent3;
    OBJECT_HANDLE_INFORMATION	objHandleInfo;
    OBJECT_HANDLE_INFORMATION       objHandleInfo2;
    OBJECT_HANDLE_INFORMATION	objHandleInfo3;
    KIRQL irql;
    //assume unsuccessful
    IoCtlNtstus = STATUS_INVALID_DEVICE_REQUEST;

    //IRP stack
    pIRPStack = IoGetCurrentIrpStackLocation(pIrp);

    //iocontrolcode
    uIoControlCode = pIRPStack->Parameters.DeviceIoControl.IoControlCode;
    uInSize = pIRPStack->Parameters.DeviceIoControl.InputBufferLength;
    uOutSize = pIRPStack->Parameters.DeviceIoControl.OutputBufferLength;
    //use systembuffer
    pIoBuffer= pIrp-> AssociatedIrp.SystemBuffer;

    switch(uIoControlCode)
    {
    case IOCTL_SEND_EVENT:
        {
            if(pIoBuffer == NULL || uInSize < sizeof(HANDLE))
            {
                KdPrint(("[Clientdrv]Set Event Error\n"));
                IoCtlNtstus = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            hEvent = *(HANDLE*)pIoBuffer;

            irql = KeGetCurrentIrql();
            if(irql > PASSIVE_LEVEL)
            {
                IoCtlNtstus = STATUS_UNSUCCESSFUL;
                break;
            }

            IoCtlNtstus = ObReferenceObjectByHandle(hEvent,
                GENERIC_ALL,
                NULL,
                KernelMode,
                (PVOID *)&gpEventObject,
                &objHandleInfo); 
            if (!NT_SUCCESS(IoCtlNtstus))
            {
                KdPrint(("[Clientdrv]Event Resume Failed!\n"));
                break;
            }
        }
        break;

    case IOCTL_GET_NEWPATH:
        {
            if(pIoBuffer && z_ProcName)
            {
                RtlCopyMemory(pIoBuffer,z_ProcName,strlen(z_ProcName)+1);
                KdPrint(("[Clientdrv]give new process PATH\n"));
            }
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    case IOCTL_GET_NEWPID:
        {
            RtlCopyMemory(pIoBuffer,&g_pidnew,sizeof(ULONG));
            KdPrint(("[Clientdrv]give new process PID\n"));
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    case IOCTL_PROTECT_PROC:
        {
            HANDLE PID;
            RtlCopyMemory(&PID,pIoBuffer,sizeof(HANDLE));
            AntiTerminate(PID);
            KdPrint(("[Clientdrv]Antiterminate OK. PID=%d\n",(ULONG)PID));
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    case  IOCTL_TERMINATE_THREAD:
        {
            HANDLE ThreadId;
            HANDLE PID;
            PETHREAD ethread = NULL;
            PEPROCESS eprocess = NULL;
            EventHandles EH = {0};

            RtlCopyMemory(&EH,pIoBuffer,sizeof(EventHandles));
            PID = EH.event1;
            ThreadId = EH.event2;
            if(osver > 5)
            {
                PsLookupThreadByThreadId(ThreadId,&ethread);
                if(!ethread)
                {
                    IoCtlNtstus = STATUS_UNSUCCESSFUL;
                    break;
                }
                ObDereferenceObject(ethread);
                if(!TerminateThread(ethread))
                {
                    PspTerminateThreadByPointer(ethread,STATUS_ACCESS_DENIED);
                }
                KdPrint(("[Clientdrv]RemoteThread %d has been killed\n",ThreadId));
            }
            else
            {
                PsLookupProcessByProcessId(PID,&eprocess);
                if(!eprocess)
                {
                    IoCtlNtstus = STATUS_INVALID_PARAMETER;
                    break;
                }
                ObDereferenceObject(eprocess);
                ethread = PsGetNextProcessThread(eprocess,NULL);
                if(ethread)
                {
                    do 
                    {
                        if(((PCLIENT_ID)((ULONG)ethread + 0x1EC))->UniqueThread == ThreadId)
                        {
                            if(!TerminateThread(ethread))
                            {
                                PspTerminateThreadByPointer(ethread,STATUS_ACCESS_DENIED);
                            }
                            KdPrint(("[Clientdrv]RemoteThread %d has been killed\n",ThreadId));
                        }
                    } while (ethread = PsGetNextProcessThread(eprocess,ethread));
                }
            }

            KdPrint(("[Clientdrv]Terminate RemoteThread.ThreadId=%d\n",(ULONG)ThreadId));
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    case IOCTL_TERMINATE_PROCESS:
        {
            HANDLE PID;

            RtlCopyMemory(&PID,pIoBuffer,sizeof(HANDLE));
            IoCtlNtstus = TerminateProcess(PID);
            if(NT_SUCCESS(IoCtlNtstus))
            {
                KdPrint(("[Clientdrv]Terminate Process. PID=%d\n",(ULONG)PID));
            }
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    case IOCTL_GET_REMOTETID:
        {
            EventHandles EH = {0};
            EH.event1 = (HANDLE)g_remotepid;
            EH.event2 = (HANDLE)g_remotetid;

            RtlCopyMemory(pIoBuffer,&EH,sizeof(EventHandles));
            KdPrint(("[Clientdrv]give RemoteThread Infomation\n"));
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    case IOCTL_SEND_EVENT2:
        {
            if(pIoBuffer == NULL || uInSize < sizeof(HANDLE))
            {
                KdPrint(("[Clientdrv]Set Event2 Error\n"));
                IoCtlNtstus = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            hEvent2 = *(HANDLE*)pIoBuffer;

            irql = KeGetCurrentIrql();
            if(irql > PASSIVE_LEVEL)
            {
                IoCtlNtstus = STATUS_UNSUCCESSFUL;
                break;
            }

            IoCtlNtstus = ObReferenceObjectByHandle(hEvent2,
                GENERIC_ALL,
                NULL,
                KernelMode,
                (PVOID *)&gpEventObject2,
                &objHandleInfo2); 
            if (!NT_SUCCESS(IoCtlNtstus))
            {
                KdPrint(("[Clientdrv]Event2 Resume Failed!\n"));
                break;
            }
        }
        break;

    case IOCTL_SEND_EVENT3:
        {
            if(pIoBuffer == NULL || uInSize < sizeof(HANDLE))
            {
                KdPrint(("[Clientdrv]Set Event3 Error\n"));
                IoCtlNtstus = STATUS_INVALID_BUFFER_SIZE;
                break;
            }

            hEvent3 = *(HANDLE*)pIoBuffer;

            irql = KeGetCurrentIrql();
            if(irql > PASSIVE_LEVEL)
            {
                IoCtlNtstus = STATUS_UNSUCCESSFUL;
                break;
            }

            IoCtlNtstus = ObReferenceObjectByHandle(hEvent3,
                GENERIC_ALL,
                NULL,
                KernelMode,
                (PVOID *)&gpEventObject3,
                &objHandleInfo3); 
            if (!NT_SUCCESS(IoCtlNtstus))
            {
                KdPrint(("[Clientdrv]Event3 Resume Failed!\n"));
                break;
            }
        }
        break;

    case  IOCTL_GET_ENDPATH:
        {
            RtlCopyMemory(pIoBuffer,g_ProcName,strlen(g_ProcName)+1);
            KdPrint(("[Clientdrv]Give exited process PATH\n"));
            IoCtlNtstus = STATUS_SUCCESS;
        }
        break;

    default:
        break;
    }

    if(IoCtlNtstus == STATUS_SUCCESS)
        pIrp->IoStatus.Information = uOutSize;
    else
        pIrp->IoStatus.Information =0;

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)  
{
    NTSTATUS status;
    UNICODE_STRING ustrLinkName;
    UNICODE_STRING ustrDevName;    
    PDEVICE_OBJECT pDevObj;

    KdPrint (("[Clientdrv]DriverEntry\n"));
    RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);

    status = IoCreateDevice(DriverObject, 
        0,
        &ustrDevName, 
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &pDevObj);

    if(!NT_SUCCESS(status))
    {
        KdPrint(("[Clientdrv]IoCreateDevice = 0x%x\n", status));
        return status;
    }

    RtlInitUnicodeString(&ustrLinkName, LINK_NAME);

    status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);  
    if(!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDevObj);  
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->DriverUnload = OnUnload;  
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=DispatchIoctl;

    PsSetCreateProcessNotifyRoutine(( PCREATE_PROCESS_NOTIFY_ROUTINE)ProcCreateCallback,FALSE);
    PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)ThreadCreateCallback);

    PspTerminateThreadByPointer = (PSPTERMINATETHREADBYPOINTER)ZZSearchUndocumentFunction_PspTerminateThreadByPointer();
    PspExitThread = (PSPEXITTHREAD)ZZSearchUndocumentFunction_PspExitThread();

    osver = GetOsVersion();
    return STATUS_SUCCESS;  
}

VOID ProcCreateCallback(IN HANDLE  ParentId,IN HANDLE  ProcessId,IN BOOLEAN  Create)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    UNICODE_STRING uImageName = {0}; 
    UNICODE_STRING dosImageName = {0}; 
    ANSI_STRING dosName = {0}; 
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if(irql > PASSIVE_LEVEL)
    {
        return;
    }
    PsLookupProcessByProcessId(ProcessId,&process);
    if(!process)
    {
        return;
    }
    ObDereferenceObject(process);
    if(!GetProcPath(ProcessId,&uImageName))
    {
        return;
    }
    status = NtNameToDosName(&uImageName,&dosImageName);
    if(!NT_SUCCESS(status))
    {
        return;
    }
    status = RtlUnicodeStringToAnsiString(&dosName,&dosImageName,TRUE);
    if(!NT_SUCCESS(status))
    {
        return;
    }

    if(Create)
    {                   
        //KdPrint(("[Clientdrv]%s Create\n",dosName.Buffer));
        g_pidnew = (ULONG)ProcessId;
        if(z_ProcName && dosName.Buffer)
        {
            RtlCopyMemory(z_ProcName,dosName.Buffer,dosName.MaximumLength);
            KdPrint(("[Clientdrv]%s Create\n",z_ProcName));
            if(gpEventObject)
                KeSetEvent(gpEventObject,0,FALSE);
        }
        g_bMainThread = TRUE;
        //TerminateProcess(ProcessId);
        //AntiTerminate(ProcessId);
    }
    else
    {
        //KdPrint(("[Clientdrv]%s End\n",dosName.Buffer));
        g_pidend = (ULONG)ProcessId;
        if(g_ProcName && dosName.Buffer)
        {
            RtlCopyMemory(g_ProcName,dosName.Buffer,dosName.MaximumLength);
            KdPrint(("[Clientdrv]%s End\n",g_ProcName));
            if(gpEventObject2)
                KeSetEvent(gpEventObject2,0,FALSE);
        }
    }
    if(dosName.Buffer)
        RtlFreeAnsiString(&dosName);
    if(uImageName.Buffer)
        RtlFreeUnicodeString(&uImageName);
    if(dosImageName.Buffer)
        RtlFreeUnicodeString(&dosImageName);
}

VOID ThreadCreateCallback(IN HANDLE  ProcessId,IN HANDLE  ThreadId,IN BOOLEAN  Create)
{
    ULONG CurrentPid = 0;
    PEPROCESS eprocess = NULL;
    PETHREAD ethread = NULL;
    UNICODE_STRING createprocntpath = {0};
    UNICODE_STRING procntpath = {0};
    UNICODE_STRING createprocdospath = {0};
    UNICODE_STRING procdospath = {0};
    KIRQL irql;

#if DBG
    ANSI_STRING patha = {0};
    ANSI_STRING pathb = {0};
#endif // _DEBUG

    irql = KeGetCurrentIrql();
    if(irql > PASSIVE_LEVEL)
    {
        return;
    }

    if(Create)
    {
        if(4 != (ULONG)ProcessId && 0 != (ULONG)ProcessId)
        {
            CurrentPid = (ULONG)PsGetCurrentProcessId();	//remotethread creater	 
            if(CurrentPid == (ULONG)ProcessId)
            {
                g_bMainThread = FALSE;
                return;
            }

            if(g_bMainThread)
            {
                g_bMainThread = FALSE;
                //KdPrint (("[Clientdrv]MainThread Created\n"));
                return;
            }

            else
            {
                PsLookupProcessByProcessId((HANDLE)ProcessId,&eprocess);
                ObDereferenceObject(eprocess);
#if DBG		
                if(GetProcPath((HANDLE)CurrentPid,&createprocntpath) && 
                    GetProcPath((HANDLE)ProcessId,&procntpath))
                {
                    if(NT_SUCCESS(NtNameToDosName(&createprocntpath,&createprocdospath)) &&
                        NT_SUCCESS(NtNameToDosName(&procntpath,&procdospath)))
                    {
                        RtlUnicodeStringToAnsiString(&patha,&createprocdospath,TRUE);
                        RtlUnicodeStringToAnsiString(&pathb,&procdospath,TRUE);
                    }
                }				
#endif
                g_remotetid = (ULONG)ThreadId;
                g_remotepid = (ULONG)ProcessId;

                //We cannot use PsLookupThreadByThreadId in a create thread notify because lThread->GrantedAccess initials 
                //after notify.It valuse Zero Before Thread notify.This Bug exists until Vista initials GrantedAccess correctly.
                if(osver > 5)
                {
                    PsLookupThreadByThreadId(ThreadId,&ethread);
                    ObDereferenceObject(ethread);
                    //PspTerminateThreadByPointer(ethread,STATUS_ACCESS_DENIED);
                    KdPrint(("[Clientdrv]RemoteThread ThreadID=%d\n[Clientdrv]Creator:%Z\n[Clientdrv]Victim:%Z\n",ThreadId,&patha,&pathb));

                    /*if(TerminateThread(ethread))
                    {
                        KdPrint(("RemoteThread %d has been killed\n",ThreadId));
                    }*/
                }
                else
                {
                    ethread = PsGetNextProcessThread(eprocess,NULL);
                    if(ethread)
                    {
                        do 
                        {
                            if(((PCLIENT_ID)((ULONG)ethread + 0x1EC))->UniqueThread == ThreadId)
                            {
                                //PspTerminateThreadByPointer(ethread,STATUS_ACCESS_DENIED);
                                KdPrint(("[Clientdrv]RemoteThread ThreadID=%d\n[Clientdrv]Creator:%Z\n[Clientdrv]Victim:%Z\n",ThreadId,&patha,&pathb));
                            }
                        } while (ethread = PsGetNextProcessThread(eprocess,ethread));
                    }
                }

#if DBG
                if(patha.Buffer)
                    RtlFreeAnsiString(&patha);
                if(pathb.Buffer)
                    RtlFreeAnsiString(&pathb);

                if(createprocntpath.Buffer)
                    RtlFreeUnicodeString(&createprocntpath);
                if(procntpath.Buffer)
                    RtlFreeUnicodeString(&procntpath);
                if(createprocdospath.Buffer)
                    RtlFreeUnicodeString(&createprocdospath);
                if(procdospath.Buffer)
                    RtlFreeUnicodeString(&procdospath);
#endif
                if(gpEventObject3)
                    KeSetEvent(gpEventObject3,0,FALSE);

                g_bMainThread = FALSE;
                return;
            }
        }
    }
}

NTSTATUS NtNameToDosName( IN PUNICODE_STRING NtName, OUT PUNICODE_STRING DosName)
{ 
    OBJECT_ATTRIBUTES attributes = {0};
    UNICODE_STRING driveLetterName ={0};
    UNICODE_STRING linkTarget = {0};
    HANDLE linkHandle = 0;
    WCHAR c = L'\0';
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > PASSIVE_LEVEL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    linkTarget.Length = 0;
    linkTarget.MaximumLength = 256;
    linkTarget.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, linkTarget.MaximumLength,0);

    //RtlInitUnicodeString(&driveLetterName, L"\\??\\C:");
    driveLetterName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool,256,0);
    driveLetterName.Buffer[0] =L'\\';
    driveLetterName.Buffer[1] =L'?';
    driveLetterName.Buffer[2] =L'?';
    driveLetterName.Buffer[3] =L'\\';
    driveLetterName.Buffer[4] =L'C';
    driveLetterName.Buffer[5] =L':';
    driveLetterName.Buffer[6] =L'\0';
    driveLetterName.Length = 12;

    driveLetterName.MaximumLength = 256;
    for (c = L'A'; c <= L'Z'; c++) 
    {
        driveLetterName.Buffer[4] = c;
        InitializeObjectAttributes(&attributes, &driveLetterName, OBJ_CASE_INSENSITIVE, 0, NULL);

        if (!NT_SUCCESS(ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &attributes))) continue;
        if (!NT_SUCCESS(ZwQuerySymbolicLinkObject(linkHandle, &linkTarget, NULL))) continue;

        //KdPrint(("%wZ->%wZ\n", &driveLetterName, &linkTarget));

        if (_wcsnicmp(NtName->Buffer, linkTarget.Buffer, linkTarget.Length>>1) == 0)
        {
            DosName->Length = 4 + NtName->Length - linkTarget.Length;
            DosName->MaximumLength = DosName->Length + 2; 
            DosName->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, DosName->MaximumLength,0);
            if (!DosName->Buffer) return STATUS_INSUFFICIENT_RESOURCES;

            memcpy((PBYTE)DosName->Buffer + 4, (PBYTE)NtName->Buffer + linkTarget.Length, NtName->Length - linkTarget.Length);

            DosName->Buffer[0] = c; 
            DosName->Buffer[1] = L':'; 
            DosName->Buffer[DosName->Length>>1] = L'\0';

            RtlFreeUnicodeString(&driveLetterName);
            RtlFreeUnicodeString(&linkTarget);
            return STATUS_SUCCESS; 
        }
    } 

    RtlFreeUnicodeString(&driveLetterName);
    RtlFreeUnicodeString(&linkTarget);
    return STATUS_NOT_FOUND; 
}

BOOLEAN GetProcPath(IN HANDLE PID,OUT PUNICODE_STRING pImageName)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcess=NULL;
    CLIENT_ID clientid = {0};
    OBJECT_ATTRIBUTES ObjectAttributes = {0};
    ULONG returnedLength = 0; 
    ULONG bufferLength = 0;    
    PVOID buffer = NULL;
    PUNICODE_STRING imageName = NULL;
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > PASSIVE_LEVEL)
    {
        return FALSE;
    }
    InitializeObjectAttributes(&ObjectAttributes,0,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,0,0);
    clientid.UniqueProcess=PID;
    clientid.UniqueThread=0;
    //get handle var pid
    status = ZwOpenProcess(&hProcess,PROCESS_ALL_ACCESS,&ObjectAttributes,&clientid);

    if(!NT_SUCCESS(status))
    {
        KdPrint(("[Clientdrv]OpenProcess Failed.Status = %x, PID =%x\n",status,PID));
        return FALSE;
    }
    //get length
    status = ZwQueryInformationProcess(hProcess, 
        ProcessImageFileName,
        NULL, // buffer
        0, // buffer size
        &returnedLength);

    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        ZwClose(hProcess);
        return FALSE;
    }

    buffer=ExAllocatePoolWithTag(NonPagedPool,returnedLength,0);

    if (buffer==NULL)
    {
        ZwClose(hProcess);
        return FALSE;        
    }

    //Requirements 	Windows 2000 Professional and later versions of Windows. 
    status=ZwQueryInformationProcess(hProcess,ProcessImageFileName,buffer,
        returnedLength,&returnedLength);

    if (NT_SUCCESS(status)) 
    {
        imageName=(PUNICODE_STRING)buffer;	
        pImageName->Length = imageName->Length;
        pImageName->MaximumLength = imageName->MaximumLength;
        pImageName->Buffer = ExAllocatePoolWithTag(NonPagedPool,pImageName->Length,0);
        RtlCopyMemory(pImageName->Buffer,imageName->Buffer,imageName->Length);/*imageName->Buffer;*/
        //RtlCopyUnicodeString(pImageName, imageName); 
    }

    ZwClose(hProcess);
    ExFreePoolWithTag(buffer,0);
    return TRUE;
}

DWORD ZZSearchUndocumentFunction_PspTerminateThreadByPointer()
{
    DWORD PsTerminateSystemThreadAddr = 0;
    int    iLen;
    PCHAR pAddr = NULL;
    static DWORD result= 0;

    if (result !=0)
    {
        return result;
    }

    PsTerminateSystemThreadAddr = (DWORD)PsTerminateSystemThread;
    KdPrint(("[Clientdrv]PsTerminateSystemThreadAddr: 0x%08X\n",PsTerminateSystemThreadAddr));

    pAddr = (PCHAR)PsTerminateSystemThreadAddr;
    for (iLen = 0;iLen<0xff;iLen++)
    {

        if ( *pAddr == (char)0xE8 )
        {
            result = (DWORD)(pAddr) + *(DWORD *)(pAddr+1) + 5;
            KdPrint(("[Clientdrv]PspTerminateThreadByPointer Addr: 0x%08X\n",result));
            return result;
        }
        pAddr++;
    }
    KdPrint(("[Clientdrv]PspTerminateThreadByPointer not found\n"));
    return 0;
}

PETHREAD NTAPI PsGetNextProcessThread (IN PEPROCESS Process, IN PETHREAD Thread) 
{
    PLIST_ENTRY ListEntry = NULL;
    PETHREAD NewThread = NULL;
    ULONG ThreadListHeadOffset = 0;
    ULONG ThreadListEntryOffset = 0;
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if(irql > APC_LEVEL)
    {
        return NULL;
    }

    if(osver == 5)
    {
        ThreadListHeadOffset = 0x190;
        ThreadListEntryOffset = 0x22c;
    }
    else
    {
        ThreadListHeadOffset = 0x188;
        ThreadListEntryOffset = 0x268;
    }

    KeEnterCriticalRegion();
    if (Thread == NULL)
        ListEntry = ((PLIST_ENTRY)((ULONG)Process + ThreadListHeadOffset))->Flink;
    else
        ListEntry = ((PLIST_ENTRY)((ULONG)Thread + ThreadListEntryOffset))->Flink;

    while(1)
    {
        if (ListEntry != (PLIST_ENTRY)((ULONG)Process + ThreadListHeadOffset))
        {
            NewThread = (PETHREAD)((ULONG)ListEntry - ThreadListEntryOffset);
            if (NewThread)
            {
                if(ObReferenceObject(NewThread))
                {
                    break;
                }
            } 
        }
        else
        {
            NewThread = NULL;
            break;
        }
        ListEntry = ListEntry->Flink;
    }
    KeLeaveCriticalRegion();
    if (Thread)
    {
        ObDereferenceObject (Thread);
    }
    return NewThread;
}

NTSTATUS AntiTerminate(HANDLE PID)
{
    PEPROCESS PEP = NULL;
    PETHREAD  Thread = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if(irql > APC_LEVEL)
    {
        status = STATUS_UNSUCCESSFUL;
        return status;
    }

    PsLookupProcessByProcessId(PID,&PEP);
    if(!PEP)
    {
        status = STATUS_UNSUCCESSFUL;
        return status;
    }
    ObDereferenceObject(PEP);

    Thread = PsGetNextProcessThread(PEP,NULL);
    if (Thread)
    {
        do 
        {
            PULONG Flags = (PULONG)((PUCHAR)Thread + GetCrossFlagOffSet());
            KdPrint(("[Clientdrv]CrossFlags == 0x%08X\n",*Flags));
            *Flags |= 0x000000010UL;
            KdPrint(("[Clientdrv]CrossFlags Modified to: 0x%08X\n", *Flags));

        } while ((Thread = PsGetNextProcessThread(PEP, Thread)));
    }

    return status;
}

ULONG GetCrossFlagOffSet()
{
    static ULONG Offset = 0;
    if (Offset == 0)
    {
        PUCHAR pProc  = (PUCHAR) PsTerminateSystemThread;
        while (*pProc != 0xF6 || *(pProc + 1 ) != 0x80)
        {
            pProc ++;
        }

        Offset =*(PULONG)(pProc + 2);
        KdPrint(("[Clientdrv]CrossFlagOffSet == 0x%08X\n",Offset));
    }
    return Offset;
}

ULONG GetOsVersion()
{
    RTL_OSVERSIONINFOEXW osverinfo = { sizeof(osverinfo) }; 
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if(irql > PASSIVE_LEVEL)
    {
        return 7;
    }
    //Available in Windows 2000 and later versions of Windows. 
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osverinfo);
    if( osverinfo.dwMajorVersion == 5 )
    {
        KdPrint(("[Clientdrv]Runing On Windows XP\n"));
        return 5;
    }
    if( osverinfo.dwMajorVersion == 6 && osverinfo.dwMinorVersion == 0)
    {
        KdPrint(("[Clientdrv]Runing On Windows Vista\n"));
        return 6;
    }
    if( osverinfo.dwMajorVersion ==6 && osverinfo.dwMinorVersion == 1)
    {
        KdPrint(("[Clientdrv]Runing On Windows 7\n"));
        return 7;
    }
    return 7;
}

DWORD ZZSearchUndocumentFunction_PspExitThread()
{
    int    iLen = 0;
    PCHAR pAddr = NULL;
    static DWORD result= 0;

    if(result != 0)
    {
        return result; 
    }

    pAddr = (PCHAR)ZZSearchUndocumentFunction_PspTerminateThreadByPointer();

    for (iLen = 0;iLen<0xff;iLen++)
    {

        if ( *pAddr == (char)0xFF && *(pAddr + 1 ) == (char)0x75 
            && *(pAddr+2) == (char)0x0C )
        {
            pAddr += 3;
            result = (DWORD)(pAddr) + *(DWORD *)(pAddr+1) + 5;
            KdPrint(("[Clientdrv]PspExitThread Addr: 0x%08X\n",result));
            return result;
        }
        pAddr++;
    }

    KdPrint(("[Clientdrv]PspExitThread not found\n"));
    return 0;
}

BOOLEAN TerminateThread(PETHREAD ethread)
{
    PKAPC apc = NULL;
    BOOLEAN status = TRUE;
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if(irql > DISPATCH_LEVEL)
    {
        return FALSE;
    }
    if(!ethread)
    {
        return FALSE;
    }

    if(!ZZSearchUndocumentFunction_PspExitThread())
    {
        return FALSE;
    }

    apc = ExAllocatePoolWithTag(NonPagedPool,sizeof(KAPC),0);
    KeInitializeApc(apc,
        ethread,
        OriginalApcEnvironment,
        TerminateThisThread,
        NULL,
        NULL,
        KernelMode,
        0);

    status = KeInsertQueueApc(apc,apc,NULL,2); //requires irql <= DISPATCH_LEVEL
    if(status)
    {
        KdPrint(("[Clientdrv]KeInsertQueueApc success\n"));  
    }
    else
    {
        KdPrint(("[Clientdrv]KeInsertQueueApc failed\n"));
    }

    return status;
}

VOID TerminateThisThread(PKAPC Apc,PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,PVOID *SystemArgument1,PVOID *SystemArgument2)
{
    KIRQL irql;

    irql = KeGetCurrentIrql();  //wrk writes it needs APC_LEVEL
    if(irql != APC_LEVEL)
    {
        return;
    }
    ExFreePool(Apc);
    PspExitThread(STATUS_SUCCESS);
}

NTSTATUS TerminateProcess(HANDLE PID)
{
    PEPROCESS eprocess = NULL;
    PETHREAD ethread = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;

    irql = KeGetCurrentIrql();
    if (irql > APC_LEVEL)
    {
        status = STATUS_UNSUCCESSFUL;
        return status;
    }

    status = PsLookupProcessByProcessId(PID,&eprocess);
    if(!eprocess )
    {
        status = STATUS_UNSUCCESSFUL;
        return status;
    }
    ObDereferenceObject(eprocess);
    ethread = PsGetNextProcessThread(eprocess,NULL);
    if(ethread)
    {
        do 
        {
            if( !TerminateThread(ethread))
            {
                PspTerminateThreadByPointer(ethread,STATUS_ACCESS_DENIED);
            }
        } while (ethread = PsGetNextProcessThread(eprocess,ethread));
    }
    status = STATUS_SUCCESS;
    return status;
}