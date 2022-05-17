/*
  Build upon the MSJDrvr.C by James M. Finnegan - Microsoft Systems Journal (1998)  
*/
#include <stdio.h>
#include "FHMFunc.h"
#include "rootkit.h"
#include "processlist.h"
#include "memscan.h"
#include "threads.h"
#include "newkernel.h"

#include "define.h"
#include "struct.h"


void MSJUnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS MSJDispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS MSJDispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS MSJDispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

//-----NtUserSetWindowsHookEx----- //prevent global hooks
typedef ULONG (NTUSERSETWINDOWSHOOKEX)(
    IN HANDLE hmod,
    IN PUNICODE_STRING pstrLib OPTIONAL,
    IN DWORD idThread,
    IN int nFilterType,
    IN PVOID pfnFilterProc,
    IN DWORD dwFlags
);
//------------------------------------------------------------------------
NTUSERSETWINDOWSHOOKEX OldNtUserSetWindowsHookEx;
ULONG NtUserSetWindowsHookEx_callnumber;
//HHOOK NewNtUserSetWindowsHookEx(IN HANDLE hmod,IN PUNICODE_STRING pstrLib OPTIONAL,IN DWORD idThread,IN int nFilterType, IN PROC pfnFilterProc,IN DWORD dwFlags);

typedef NTSTATUS (*ZWSUSPENDPROCESS) ( IN ULONG ProcessHandle );	// Handle to the process
ZWSUSPENDPROCESS ZwSuspendProcess;

//PVOID GetApiEntry(ULONG FunctionNumber);
void Unhook(void);

NTSTATUS ZwCreateThread(
	OUT PHANDLE  ThreadHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN HANDLE  ProcessHandle,
	OUT PCLIENT_ID  ClientId,
	IN PCONTEXT  ThreadContext,
	IN PVOID  UserStack,
	IN BOOLEAN  CreateSuspended
);

PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTableShadow = NULL;
PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable = NULL;

UNICODE_STRING  uszDeviceString;

#define SYSTEMSERVICE(_function)		KeServiceDescriptorTable->ServiceTable[ *(PULONG)((PUCHAR)_function+1)]
#define SYSTEMSERVICELINK(_function)	KeServiceDescriptorTable->ServiceTable[*((PUCHAR)(*(PULONG)*((PULONG)((PUCHAR)_function+2)))+1)]

typedef struct _MODULE_ENTRY {
	LIST_ENTRY le_mod;
	DWORD  unknown[4];
	DWORD  base;
	DWORD  driver_start;
	DWORD  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
} MODULE_ENTRY, *PMODULE_ENTRY;

void hideme(PDRIVER_OBJECT DriverObject) {
	PMODULE_ENTRY pm_current				= *((PMODULE_ENTRY*)((DWORD)DriverObject + 0x14)); //eeeeew
	*((PDWORD)pm_current->le_mod.Blink)		= (DWORD) pm_current->le_mod.Flink;
	pm_current->le_mod.Flink->Blink			= pm_current->le_mod.Blink;
	HiddenDriver							= TRUE;
}

void mykapc2(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	ExFreePool(Apc);
	DbgPrint("My second kernelmode apc!!!!\n");
	DbgPrint("SystemArgument1=%x\n", *(PULONG)SystemArgument1 );
}

void nothing(PVOID arg1, PVOID arg2, PVOID arg3) {
	return;
}

void mykapc(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
	//kernelmode apc, always gets executed
	LARGE_INTEGER Timeout;
	PKAPC kApc = ExAllocatePool(NonPagedPool, sizeof(KAPC));
	ExFreePool(Apc);

	DbgPrint("My kernelmode apc!!!!\n");
	DbgPrint("NormalRoutine=%x\n",*(PULONG)NormalRoutine);
	DbgPrint("NormalContext=%x\n",*(PULONG)NormalContext);
	DbgPrint("SystemArgument1=%x\n",*(PULONG)SystemArgument1);
	DbgPrint("SystemArgument1=%x\n",*(PULONG)SystemArgument2);
	
	KeInitializeApc(kApc, (PKTHREAD)PsGetCurrentThread(), 0, (PKKERNEL_ROUTINE)mykapc2, NULL, (PKNORMAL_ROUTINE)*(PULONG)SystemArgument1, UserMode, (PVOID)*(PULONG)NormalContext);
	KeInsertQueueApc(kApc, (PVOID)*(PULONG)SystemArgument1, (PVOID)*(PULONG)SystemArgument2, 0);
	//wait in usermode (to interruptable by a usermode apc)
	Timeout.QuadPart = 0;
	KeDelayExecutionThread(UserMode, TRUE, &Timeout);
	return;
}

void CreateRemoteAPC(ULONG threadid,PVOID addresstoexecute) {
	PKTHREAD kThread = (PKTHREAD)getPEThread(threadid);
	PKAPC kApc = ExAllocatePool(NonPagedPool, sizeof(KAPC));
	DbgPrint("(PVOID)KThread=%p\n",kThread);
	KeInitializeApc(kApc, kThread, 0, (PKKERNEL_ROUTINE)mykapc, NULL, (PKNORMAL_ROUTINE)nothing, KernelMode, 0);
	KeInsertQueueApc (kApc, addresstoexecute, addresstoexecute, 0);
}
/*
int testfunction(int p1,int p2) {
	DbgPrint("Hello\nParam1=%d\nParam2=%d\n",p1,p2);
	return 0x666;
}
*/
void* functionlist[1];
char  paramsizes[1];
int registered = 0;
/*
void AddSystemServices(void) {

}
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    NTSTATUS			ntStatus;
    
	UNICODE_STRING		uszDriverString;
    
	PDEVICE_OBJECT		pDeviceObject;
	int					i = 0;
	ULONG				cr4reg = 0;

	OBJECT_ATTRIBUTES	oa;

	UNICODE_STRING		temp; 
	//DbgPrint("%S",oa.ObjectName.Buffer);  
	WORD this_cs, this_ss, this_ds, this_es, this_fs, this_gs;
	__asm
	{
		mov ax,cs
		mov [this_cs],ax

		mov ax,ss
		mov [this_ss],ax

		mov ax,ds
		mov [this_ds],ax

		mov ax,es
		mov [this_es],ax

		mov ax,fs
		mov [this_fs],ax

		mov ax,gs
		mov [this_gs],ax
	}
	DbgPrint("cs=%x ss=%x ds=%x es=%x fs=%x gs=%x\n",this_cs, this_ss, this_ds, this_es, this_fs, this_gs);
	//lame antiviruses and more lamer users that keep crying rootkit virus....
	RtlInitUnicodeString(&temp, L"KeServiceDescriptorTable"); 
	KeServiceDescriptorTable=MmGetSystemRoutineAddress(&temp);         
	DbgPrint("Loading driver\n");
	
	RtlInitUnicodeString(&uszDriverString, L"\\Device\\FHMDRIVER54");
	RtlInitUnicodeString(&uszDeviceString, L"\\DosDevices\\FHMDRIVER54");
	// Point uszDriverString at the driver name
	
	// Create and initialize device object
	DbgPrint("start IoCreateDevice");
    ntStatus = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &uszDriverString, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	DbgPrint("end IoCreateDevice");
    if(ntStatus != STATUS_SUCCESS) {
		DbgPrint("IoCreateDevice failed.\n");
        return ntStatus;
	}
    // Point uszDeviceString at the device name
    // Create symbolic link to the user-visible name
	DbgPrint("start IoCreateSymbolicLink");
    ntStatus = IoCreateSymbolicLink(&uszDeviceString, &uszDriverString);
	DbgPrint("end IoCreateSymbolicLink");
    if(ntStatus != STATUS_SUCCESS) {
        // Delete device object if not successful
		DbgPrint("IoCreateSymbolicLink failed.\n");
        IoDeleteDevice(pDeviceObject);
        return ntStatus;
    }
    // Load structure to point to IRP handlers...
    
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = MSJDispatchCreate;
	DbgPrint("end MSJDispatchCreate");
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = MSJDispatchClose;
	DbgPrint("end MSJDispatchClose");
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MSJDispatchIoctl;
	DbgPrint("end MSJDispatchIoctl");
	DriverObject->DriverUnload                         = MSJUnloadDriver;
	DbgPrint("end MSJUnloadDriver");

	/*
	DebuggedProcessID = 0;
	
	ProtectOn = FALSE;
	ImageNotifyRoutineLoaded = FALSE;
	LastForegroundWindow = 0;
	ProtectedProcessID = 0;
	ModuleList = NULL;
	ModuleListSize = 0;
	KernelCopy = 0;

	globaldebug = 0;

	newthreaddatafiller = IoAllocateWorkItem(pDeviceObject);
	//Processlist init
	ProcessEventCount = 0;
	KeInitializeSpinLock(&ProcesslistSL);
	CreateProcessNotifyRoutineEnabled = FALSE;
	//threadlist init
	ThreadEventCount=0;
	for ( i = 0 ; i < 32 ; i++ ) {
		IDTAddresses[i]=0; //init. I dont know for sure if it gets set to NULL by default so let's be sure
	}
	RtlZeroMemory(&DebugEvents[0], 50*sizeof(DebugEvent));
	
	BufferSize = 0;
	processlist = NULL;
	OriginalInt1.wHighOffset = 0;
	OriginalInt3.wHighOffset = 0;
	ChangeRegistersOnBP = FALSE;
	for ( i = 0 ; i < 4 ; i++ ) {
		ChangeRegs[i].Active = FALSE;
	}
    //determine if PAE is used
	cr4reg = getCR4();
	if ( ( cr4reg & 0x20 ) == 0x20 ) {
		PTESize = 8; //pae
		PAGE_SIZE_LARGE = 0x200000;
		MAX_PDE_POS = 0xC0604000;
	}
	else {
		PTESize = 4;
		PAGE_SIZE_LARGE = 0x400000;
		MAX_PDE_POS = 0xC0301000;
	}
	UsesAlternateMethod = FALSE;
	*/
	pDeviceObject->Flags |= DO_BUFFERED_IO;
	DbgPrint("start hideme()");
    hideme(DriverObject); //ok, for those that see this, enabling this WILL fuck up try except routines, even in usermode you'll get a blue sreen
	DbgPrint("end hideme()");
	// Return success (don't do the devicestring, I need it for unload)
		
    return ntStatus;
}

NTSTATUS MSJDispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	DbgPrint("MSJDispatchCreate");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return(STATUS_SUCCESS);
}

NTSTATUS MSJDispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	DbgPrint("MSJDispatchClose");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information=0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return(STATUS_SUCCESS);
}

NTSTATUS MSJDispatchIoctl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
    NTSTATUS ntStatus;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	DbgPrint("MSJDispatchIoctl %d %d", irpStack->Parameters.DeviceIoControl.IoControlCode, IOCTL_CE_GETVERSION);
    switch(irpStack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_CE_OPENPROCESS:
			{					
				PEPROCESS selectedprocess;
				PHANDLE pid = Irp->AssociatedIrp.SystemBuffer;
				HANDLE ProcessHandle = 0;
				ntStatus = STATUS_SUCCESS;
				__try
				{
					ProcessHandle = 0;
					if (PsLookupProcessByProcessId((PVOID)(*pid),&selectedprocess)==STATUS_SUCCESS) {		
						DbgPrint("Calling ObOpenObjectByPointer\n");
						ntStatus = ObOpenObjectByPointer ( 
									selectedprocess,
									0,
									NULL,
									PROCESS_ALL_ACCESS,
									NULL,
									KernelMode, //UserMode,
									&ProcessHandle);
						DbgPrint("ntStatus=%x",ntStatus);
					}
				}
				__except(1) {
					ntStatus = STATUS_UNSUCCESSFUL;
				}			
				*pid = ProcessHandle;
				break;
			}
		case IOCTL_CE_OPENTHREAD:
			{
				HANDLE ThreadHandle;
				PHANDLE tid;
				CLIENT_ID ClientID;
				OBJECT_ATTRIBUTES ObjectAttributes;
	
				RtlZeroMemory(&ObjectAttributes,sizeof(OBJECT_ATTRIBUTES));

				ntStatus = STATUS_SUCCESS;
				tid = Irp->AssociatedIrp.SystemBuffer;

				ClientID.UniqueProcess = 0;
				ClientID.UniqueThread = *tid;
				ThreadHandle = 0;
				__try {
					ThreadHandle = 0;
					ntStatus = ZwOpenThread(&ThreadHandle,PROCESS_ALL_ACCESS,&ObjectAttributes,&ClientID);									
				}
				__except(1) {
					ntStatus = STATUS_UNSUCCESSFUL;
				}
				*tid = ThreadHandle;
				break;
			}
		case IOCTL_CE_PROTECTME:
			{
				struct input
				{
					HANDLE ProcessID; 
					ULONG DenyList;
					ULONG GlobalDenyList; //ignored if it is a includelist
					ULONG ListSize;
				} *pinp;

				UINT_PTR NextProcess;
				UINT_PTR PreviousProcess;

				pinp = Irp->AssociatedIrp.SystemBuffer;
				
				if (ModuleList != NULL) {
					MmFreeNonCachedMemory(ModuleList,ModuleListSize);
				}
				ModuleList=NULL;
				ModuleListSize=0;

				if (pinp->ListSize > 0) {
					ModuleList=MmAllocateNonCachedMemory(pinp->ListSize);
					if (ModuleList != NULL) {
						__try {
							
                            RtlCopyMemory(ModuleList,(PVOID)((UINT_PTR)(&(pinp->ListSize))+sizeof(pinp->ListSize)),pinp->ListSize);
							ModuleListSize=pinp->ListSize;
						}
						__except(1) {

						}
					}
				}
				DenyList=pinp->DenyList==1;
				GlobalDenyList=pinp->GlobalDenyList==1;

				ProtectedProcessID=pinp->ProcessID;
				PsLookupProcessByProcessId((PVOID)(pinp->ProcessID),&ProtectedPEProcess);			

				if (ActiveLinkOffset != 0) {
					NextProcess = *(PUINT_PTR)((UINT_PTR)ProtectedPEProcess+ActiveLinkOffset)-ActiveLinkOffset;
					PreviousProcess = *(PUINT_PTR)((UINT_PTR)ProtectedPEProcess+ActiveLinkOffset+4)-ActiveLinkOffset;
	
					*(PUINT_PTR)(PreviousProcess+ActiveLinkOffset) = *(PULONG)((UINT_PTR)ProtectedPEProcess+ActiveLinkOffset); //the previous process points to me next process
					*(PUINT_PTR)(NextProcess+ActiveLinkOffset+4) = *(PULONG)((UINT_PTR)ProtectedPEProcess+ActiveLinkOffset+4); //the next process points to the previous process

					*(PUINT_PTR)((UINT_PTR)ProtectedPEProcess+ActiveLinkOffset) = (UINT_PTR)ProtectedPEProcess+ActiveLinkOffset;
					*(PUINT_PTR)((UINT_PTR)ProtectedPEProcess+ActiveLinkOffset+4) = (UINT_PTR)ProtectedPEProcess+ActiveLinkOffset;			
				}

				if (!ProtectOn) {
					//unlink this process from the activeprocess list
					if (!ImageNotifyRoutineLoaded) {
						ImageNotifyRoutineLoaded = (PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine)==STATUS_SUCCESS);
					}
					//Hook
					OldZwOpenProcess = (ZWOPENPROCESS)SYSTEMSERVICE(ZwOpenProcess);
					OldZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)SYSTEMSERVICE(ZwQuerySystemInformation);

					if ((KeServiceDescriptorTableShadow != NULL) && (NtUserBuildHwndList_callnumber != 0) && (NtUserBuildHwndList_callnumber != 0) && (NtUserFindWindowEx_callnumber != 0) && (NtUserGetForegroundWindow_callnumber != 0)) {
						OldNtUserQueryWindow = (NTUSERQUERYWINDOW)KeServiceDescriptorTableShadow->ServiceTable[NtUserQueryWindow_callnumber];						
						OldNtUserBuildHwndList = (NTUSERBUILDHWNDLIST)KeServiceDescriptorTableShadow->ServiceTable[NtUserBuildHwndList_callnumber];
						OldNtUserFindWindowEx = (NTUSERFINDWINDOWEX)KeServiceDescriptorTableShadow->ServiceTable[NtUserFindWindowEx_callnumber];
                        OldNtUserGetForegroundWindow = (NTUSERGETFOREGROUNDWINDOW)KeServiceDescriptorTableShadow->ServiceTable[NtUserGetForegroundWindow_callnumber];

						//now a extra check before I screw up the system
						if (((UCHAR)KeServiceDescriptorTableShadow->ServiceTable[NtUserBuildHwndList_callnumber] != 0x1c) || 
						    ((UCHAR)KeServiceDescriptorTableShadow->ServiceTable[NtUserQueryWindow_callnumber] != 0x08)  ||
							((UCHAR)KeServiceDescriptorTableShadow->ServiceTable[NtUserFindWindowEx_callnumber] != 0x14) ||
							((UCHAR)KeServiceDescriptorTableShadow->ServiceTable[NtUserGetForegroundWindow_callnumber] != 0x0)
						) {
							//NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO!
							KeServiceDescriptorTableShadow=NULL; //disable it
							NtUserBuildHwndList_callnumber=0;
							NtUserQueryWindow_callnumber=0;
							NtUserFindWindowEx_callnumber=0;
							NtUserGetForegroundWindow_callnumber=0;							
						}	
					}
					else {
						KeServiceDescriptorTableShadow = NULL; //do not enable hooking. All have to work, else none
					}
					ProtectOn=TRUE;
				}
				__asm
				{
					cli 
					mov eax,CR0
					and eax,not 0x10000
					mov CR0,eax
				}
				(ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess)) = NewZwOpenProcess;
				(ZWQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation)) = NewZwQuerySystemInformation;

				if ((NtUserQueryWindow_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
				  (NTUSERQUERYWINDOW)(KeServiceDescriptorTableShadow->ServiceTable[NtUserQueryWindow_callnumber]) = NewNtUserQueryWindow;
				}
				if ((NtUserFindWindowEx_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
				  (NTUSERFINDWINDOWEX)(KeServiceDescriptorTableShadow->ServiceTable[NtUserFindWindowEx_callnumber]) = NewNtUserFindWindowEx;
				}
				if ((NtUserGetForegroundWindow_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
				  (NTUSERGETFOREGROUNDWINDOW)(KeServiceDescriptorTableShadow->ServiceTable[NtUserGetForegroundWindow_callnumber]) = NewNtUserGetForegroundWindow;
				}
				if ((NtUserBuildHwndList_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
                  (NTUSERBUILDHWNDLIST)(KeServiceDescriptorTableShadow->ServiceTable[NtUserBuildHwndList_callnumber]) = NewNtUserBuildHwndList;
				}
				__asm
				{
					mov eax,CR0
					xor eax,0x10000
					mov CR0,eax
					sti
				}						
				ntStatus = STATUS_SUCCESS;
				break;
			}
		case IOCTL_CE_DONTPROTECTME:
			{
				//Unhook();
				if (ProtectOn) {
					ntStatus = STATUS_UNSUCCESSFUL;
				}
				else {
					ntStatus = STATUS_SUCCESS;
				}
				//ProtectOn=FALSE;
				break;
			}
		case IOCTL_CE_HOOKINTS:
			{
				IDT idt;
				BYTE Processor;
				GetIDT(&idt);

				DbgPrint("IOCTL_CE_HOOKINTS\n");
				Processor=*(PCHAR)Irp->AssociatedIrp.SystemBuffer;
				ntStatus=STATUS_SUCCESS;

				if ( IDTAddresses[Processor] == 0 ) {					
					DbgPrint("Stored the IDT of this cpu\n");
					IDTAddresses[Processor]=(UINT_PTR)idt.vector;
				}
				DbgPrint("Calling HookInt1()\n");
				if (HookInt1() /*&& HookInt3()*/) {
					ntStatus = STATUS_SUCCESS;
					DbgPrint("HookSuccess");
				}
				else {
				    ntStatus=STATUS_UNSUCCESSFUL;
					DbgPrint("HookFailed");
				}
				break;
			}
		case IOCTL_CE_SETGLOBALDEBUGSTATE:
			{
				struct intput
				{
					ULONG newstate;
				} *pinp;
				pinp = Irp->AssociatedIrp.SystemBuffer;
				globaldebug=pinp->newstate;
			}
		case IOCTL_CE_STOPDEBUGGING:
			{
				StopDebugging();
				ntStatus = STATUS_SUCCESS;
				break;
			}
		case IOCTL_CE_STOP_DEBUGPROCESS_CHANGEREG:
			{
				struct input
				{
					int debugreg;					
				} *pinp;
				pinp = Irp->AssociatedIrp.SystemBuffer;
				StopChangeRegOnBP(pinp->debugreg);
				break;
			}
		case IOCTL_CE_DEBUGPROCESS_CHANGEREG:
			{
				struct input
				{
					DWORD ProcessID;
					int debugreg;
					ChangeReg CR;
				} *pinp;
				pinp = Irp->AssociatedIrp.SystemBuffer;
				DbgPrint("Start HBP");
				ChangeRegOnBP(pinp->ProcessID, pinp->debugreg, &(pinp->CR));
				DbgPrint("End HBP");
				ntStatus = STATUS_SUCCESS; //always succeeds, else the memory was unwritable and thus a blue screen of death
				break;
			}
		case IOCTL_CE_DEBUGPROCESS:
			{
				struct input
				{					
					DWORD	ProcessID;
					DWORD	Address;
					BYTE	Length;
					BYTE	RWE;
				} *pinp;
				pinp = Irp->AssociatedIrp.SystemBuffer;
				if (DebugProcess(pinp->ProcessID, pinp->Address, pinp->Length,pinp->RWE)) {
					ntStatus = STATUS_SUCCESS;
				}
				else {
					ntStatus = STATUS_UNSUCCESSFUL;
				}
				break;
			}
		case IOCTL_CE_RETRIEVEDEBUGDATA:
			{
				*(PUCHAR)Irp->AssociatedIrp.SystemBuffer = BufferSize;	
				RtlCopyMemory((PVOID)((UINT_PTR)Irp->AssociatedIrp.SystemBuffer+1),&DebugEvents[0],BufferSize*sizeof(DebugEvent));
				BufferSize = 0; //there's room for new events
				ntStatus = STATUS_SUCCESS;
				break;
			}
		case IOCTL_CE_GETPROCESSEVENTS:
			{
				KIRQL OldIrql;
				KeAcquireSpinLock(&ProcesslistSL,&OldIrql);
				*(PUCHAR)Irp->AssociatedIrp.SystemBuffer = ProcessEventCount;	
				RtlCopyMemory((PVOID)((UINT_PTR)Irp->AssociatedIrp.SystemBuffer+1),&ProcessEventdata[0],ProcessEventCount*sizeof(ProcessEventdta));
				ProcessEventCount = 0; //there's room for new events
				KeReleaseSpinLock(&ProcesslistSL,OldIrql);
				ntStatus = STATUS_SUCCESS;
				break;
			}
		case IOCTL_CE_GETTHREADEVENTS:
			{
				KIRQL OldIrql;
				KeAcquireSpinLock(&ProcesslistSL,&OldIrql);
				*(PUCHAR)Irp->AssociatedIrp.SystemBuffer = ThreadEventCount;	
				RtlCopyMemory((PVOID)((UINT_PTR)Irp->AssociatedIrp.SystemBuffer+1),&ThreadEventData[0],ThreadEventCount*sizeof(ThreadEventDta));
				ThreadEventCount = 0; //there's room for new events
				KeReleaseSpinLock(&ProcesslistSL,OldIrql);
				ntStatus = STATUS_SUCCESS;
				break;
			}
		case IOCTL_CE_GETVERSION:
			{
				*(PULONG)Irp->AssociatedIrp.SystemBuffer=FHMVERSION;	
				ntStatus=STATUS_SUCCESS;
				break;
			}
		case IOCTL_CE_INITIALIZE:
			{
				//find the KeServiceDescriptorTableShadow 
				struct input
				{
					ULONG AddressOfWin32K;
					ULONG SizeOfWin32K;
					ULONG NtUserBuildHwndList_callnumber;
					ULONG NtUserQueryWindow_callnumber;
					ULONG NtUserFindWindowEx_callnumber;
					ULONG NtUserGetForegroundWindow_callnumber;
					ULONG ActiveLinkOffset;
					ULONG ProcessNameOffset;
					ULONG DebugportOffset;	
					ULONG ProcessEvent;
					ULONG ThreadEvent;
  				} *pinp;

				int i;

				PSERVICE_DESCRIPTOR_TABLE PossibleKeServiceDescriptorTableShow; //long name's are FUN!!!!
				PossibleKeServiceDescriptorTableShow = KeServiceDescriptorTable;

				ntStatus = STATUS_UNSUCCESSFUL;
				pinp = Irp->AssociatedIrp.SystemBuffer;
				NtUserBuildHwndList_callnumber = pinp->NtUserBuildHwndList_callnumber;
				NtUserQueryWindow_callnumber = pinp->NtUserQueryWindow_callnumber;
				NtUserFindWindowEx_callnumber = pinp->NtUserFindWindowEx_callnumber;
				NtUserGetForegroundWindow_callnumber = pinp->NtUserGetForegroundWindow_callnumber;

				ActiveLinkOffset = pinp->ActiveLinkOffset;
				ProcessNameOffset = pinp->ProcessNameOffset;
				DebugportOffset = pinp->DebugportOffset;
				//referencing event handles to objects
				ObReferenceObjectByHandle((HANDLE)pinp->ProcessEvent, EVENT_ALL_ACCESS, NULL,KernelMode, &ProcessEvent, NULL); 
				ObReferenceObjectByHandle((HANDLE)pinp->ThreadEvent, EVENT_ALL_ACCESS, NULL,KernelMode, &ThreadEvent, NULL); 
				//in win2k sp4 the distance is even bigger than -6, at least 21 entries down to find it
				i =- 25;//takes some longer to load now....
				while ( i < 25 ) {
					if (IsAddressSafe((UINT_PTR)&PossibleKeServiceDescriptorTableShow[i])) { //dont want to crash for a page pault now do we?
						/*
						look for a entry that looks like:
						unsigned int *ServiceTable=Region of Win32K.sys
						unsigned int *ServiceCounterTableBase=00000000 but lets be safe and dont check it in case of a checked build
						unsigned int NumberOfServices=smaller than 0xffff;
						unsigned char *ParamTableBase=Region of Win32K.sys;
						*/
						if (((UINT_PTR)PossibleKeServiceDescriptorTableShow[i].ServiceTable >= pinp->AddressOfWin32K) &&
							((UINT_PTR)PossibleKeServiceDescriptorTableShow[i].ServiceTable < (pinp->AddressOfWin32K+pinp->SizeOfWin32K)) &&
							((UINT_PTR)PossibleKeServiceDescriptorTableShow[i].ArgumentTable >= pinp->AddressOfWin32K) &&
							((UINT_PTR)PossibleKeServiceDescriptorTableShow[i].ArgumentTable < (pinp->AddressOfWin32K+pinp->SizeOfWin32K)) &&
							(PossibleKeServiceDescriptorTableShow[i].TableSize<0xffff)
						) {
							//found it!!!!!!
							KeServiceDescriptorTableShadow = &PossibleKeServiceDescriptorTableShow[i];
							ntStatus = STATUS_SUCCESS;
                            *(UINT_PTR*)Irp->AssociatedIrp.SystemBuffer = (UINT_PTR)KeServiceDescriptorTableShadow;
							DbgPrint("KeServiceDescriptorTableShadow[0]=%p",&KeServiceDescriptorTableShadow[0]);
							DbgPrint("KeServiceDescriptorTableShadow[1]=%p",&KeServiceDescriptorTableShadow[1]);
							DbgPrint("KeServiceDescriptorTableShadow[2]=%p",&KeServiceDescriptorTableShadow[2]);
							DbgPrint("KeServiceDescriptorTableShadow[3]=%p",&KeServiceDescriptorTableShadow[3]);
							//AddSystemServices();
							break;
						}
					}
					i++;
				}				                
				break;
			}
        default:
			DbgPrint("MSJDispatchIoctl default");
            break;
    }
    Irp->IoStatus.Status = ntStatus;
    // Set # of bytes to copy back to user-mode...
    if ( ntStatus == STATUS_SUCCESS ) {
        Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	}
    else {
        Irp->IoStatus.Information = 0;
	}
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}

typedef NTSTATUS (*PSRCTNR)(__in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
PSRCTNR PsRemoveCreateThreadNotifyRoutine2;

typedef NTSTATUS (*PSRLINR)(__in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
PSRLINR PsRemoveLoadImageNotifyRoutine2;

void MSJUnloadDriver(PDRIVER_OBJECT DriverObject) {
	DbgPrint("MSJUnloadDriver");
	if (ProtectOn) {
		return;
	}
	if ( KeServiceDescriptorTableShadow && registered ) {	//I can't unload without a shadotw table (system service registered)
		//1 since my routine finds the address of the 2nd element
		KeServiceDescriptorTableShadow[1].ArgumentTable = NULL;
		KeServiceDescriptorTableShadow[1].CounterTable = NULL;
		KeServiceDescriptorTableShadow[1].ServiceTable = NULL;
		KeServiceDescriptorTableShadow[1].TableSize = 0;

		KeServiceDescriptorTable[2].ArgumentTable = NULL;
		KeServiceDescriptorTable[2].CounterTable = NULL;
		KeServiceDescriptorTable[2].ServiceTable = NULL;
		KeServiceDescriptorTable[2].TableSize = 0;
	}
	if ( OriginalInt1.wHighOffset != 0 ) {	//hidden feature: unloading WILL be able to stop the hook so it can be enabled a second time (e.g something overwrote my hook)
		int	i;		
		for (i=0;i<32;i++) {
			if ( IDTAddresses[i] != 0 ) {							
				((PINT_VECTOR)(IDTAddresses[i]))[1] = OriginalInt1;
				//((PINT_VECTOR)(IDTAddresses[i]))[3]=OriginalInt3;
			};
		};
	}
	if ((CreateProcessNotifyRoutineEnabled) || (ImageNotifyRoutineLoaded)) {
		PVOID x;
		RtlInitUnicodeString(&uszDeviceString, L"PsRemoveCreateThreadNotifyRoutine");
		PsRemoveCreateThreadNotifyRoutine2 = MmGetSystemRoutineAddress(&uszDeviceString);

		RtlInitUnicodeString(&uszDeviceString, L"PsRemoveCreateThreadNotifyRoutine");
		PsRemoveLoadImageNotifyRoutine2 = MmGetSystemRoutineAddress(&uszDeviceString);

		RtlInitUnicodeString(&uszDeviceString, L"ObOpenObjectByName");
		x = MmGetSystemRoutineAddress(&uszDeviceString);
		DbgPrint("ObOpenObjectByName=%p\n",x);
		if ((PsRemoveCreateThreadNotifyRoutine2) && (PsRemoveLoadImageNotifyRoutine2)) {
			DbgPrint("Stopping processwatch\n");
			if (CreateProcessNotifyRoutineEnabled) {
				PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine,TRUE);
				PsRemoveCreateThreadNotifyRoutine2(CreateThreadNotifyRoutine);
			}
			if (ImageNotifyRoutineLoaded) {
				PsRemoveLoadImageNotifyRoutine2(LoadImageNotifyRoutine);
			}
		}
		else {
			return;  //leave now!!!!!
		}
	}
	//Unhook();
    IoDeleteDevice(DriverObject->DeviceObject);
	//ZwClose(ProcessEventHandle);

#ifndef CETC_RELEASE
	IoDeleteSymbolicLink(&uszDeviceString);
#endif

}

void Unhook(void) {
	DbgPrint("Unhook");
    if (ProtectOn) {
        __asm
		{
			cli 
			mov eax,CR0
			and eax,not 0x10000 //disable bit
			mov CR0,eax
		}
		(ZWOPENPROCESS)(SYSTEMSERVICE(ZwOpenProcess)) = OldZwOpenProcess;
		(ZWQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation)) = OldZwQuerySystemInformation;

        if ((NtUserBuildHwndList_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
          (NTUSERBUILDHWNDLIST)(KeServiceDescriptorTableShadow->ServiceTable[NtUserBuildHwndList_callnumber]) = OldNtUserBuildHwndList;
		}
        if ((NtUserQueryWindow_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
          (NTUSERQUERYWINDOW)(KeServiceDescriptorTableShadow->ServiceTable[NtUserQueryWindow_callnumber]) = OldNtUserQueryWindow;
		}
        if ((NtUserFindWindowEx_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
          (NTUSERFINDWINDOWEX)(KeServiceDescriptorTableShadow->ServiceTable[NtUserFindWindowEx_callnumber]) = OldNtUserFindWindowEx;
		}
        if ((NtUserGetForegroundWindow_callnumber != 0) && (KeServiceDescriptorTableShadow != NULL)) {
		  (NTUSERGETFOREGROUNDWINDOW)(KeServiceDescriptorTableShadow->ServiceTable[NtUserGetForegroundWindow_callnumber]) = OldNtUserGetForegroundWindow;
		}
		__asm
		{
			mov eax,CR0
			or  eax,0x10000 //re-enable this bit
			mov CR0,eax
			sti
		}
		ProtectOn = FALSE;
	}
}
