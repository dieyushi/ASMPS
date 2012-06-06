#include <stdio.h>
#include <Windows.h>

#define IOCTL_BASE	0x800
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

typedef struct _EVENTHANDLES
{
	HANDLE event1;
	HANDLE event2;
}EventHandles, *PEventHandles;

#ifndef LIB_H_ZZ_
#define LIB_H_ZZ_
extern "C"  __declspec(dllexport)void drvdll();
extern "C"  __declspec(dllexport)char* getnewprocpath();
extern "C"  __declspec(dllexport)ULONG getnewpid();
extern "C"  __declspec(dllexport)char* getendprocpath();
extern "C"  __declspec(dllexport)EventHandles getremotethread();
extern "C"  __declspec(dllexport)void terminatethread(EventHandles EH);
extern "C"  __declspec(dllexport)void terminateprocess(HANDLE PID);
extern "C"  __declspec(dllexport)void protectprocess(HANDLE PID);
#endif

HANDLE hDevice;
HANDLE m_hEvent;
HANDLE m_hEvent2;
HANDLE m_hEvent3;
DWORD dwOutput;
DWORD dwOutput2;
DWORD dwOutput3;
char OutputBuffer[256];
char OutputBuffer2[256];
EventHandles output2;
ULONG output = 0;
void drvdll()
{
	printf("DLL Called!\n");
	hDevice = CreateFileA("\\\\.\\clientdrv",
		GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0,
		NULL);

	m_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL); // 创建事件
	m_hEvent2 = CreateEvent(NULL, FALSE, FALSE, NULL);
	m_hEvent3 = CreateEvent(NULL, FALSE, FALSE, NULL);

	DeviceIoControl(hDevice, IOCTL_SEND_EVENT, &m_hEvent, sizeof(HANDLE),
		NULL, 0, &dwOutput, NULL); // 发事件给ring0
	DeviceIoControl(hDevice, IOCTL_SEND_EVENT2, &m_hEvent2, sizeof(HANDLE),
		NULL, 0, &dwOutput2, NULL);
	DeviceIoControl(hDevice, IOCTL_SEND_EVENT3, &m_hEvent3, sizeof(HANDLE),
		NULL, 0, &dwOutput3, NULL);

	/*while (true) {
		getcreatepid();
	}*/
}


char* getnewprocpath()
{
	WaitForSingleObject(m_hEvent,INFINITE);  //等待ring0事件通知

	DeviceIoControl(hDevice,IOCTL_GET_NEWPATH,NULL,0,OutputBuffer,256,&dwOutput,NULL);  //获取数据
	
	//printf("%s\n",OutputBuffer);
	return OutputBuffer;
}

ULONG getnewpid()
{
	DeviceIoControl(hDevice,IOCTL_GET_NEWPID,NULL,0,&output,sizeof(ULONG),&dwOutput,NULL);
	ResetEvent(m_hEvent);  //重置事件
	return output;
}

char* getendprocpath()
{
	WaitForSingleObject(m_hEvent2,INFINITE);
	DeviceIoControl(hDevice,IOCTL_GET_ENDPATH,NULL,0,OutputBuffer2,256,&dwOutput2,NULL);  //获取数据
	ResetEvent(m_hEvent2);
	return OutputBuffer2;
}

EventHandles getremotethread()
{
	WaitForSingleObject(m_hEvent3,INFINITE);
	DeviceIoControl(hDevice,IOCTL_GET_REMOTETID,NULL,0,&output2,sizeof(EventHandles),&dwOutput3,NULL);
	ResetEvent(m_hEvent3);
	return output2;
}

void terminatethread(EventHandles EH)
{
	DeviceIoControl(hDevice,IOCTL_TERMINATE_THREAD,&EH,sizeof(EH),NULL,0,&dwOutput,NULL);
}

void terminateprocess(HANDLE PID)
{
	DeviceIoControl(hDevice,IOCTL_TERMINATE_PROCESS,&PID,sizeof(HANDLE),NULL,0,&dwOutput,NULL);
}

void protectprocess(HANDLE PID)
{
	DeviceIoControl(hDevice,IOCTL_PROTECT_PROC,&PID,sizeof(HANDLE),NULL,0,&dwOutput,NULL);
}