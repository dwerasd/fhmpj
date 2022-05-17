typedef VOID (__stdcall *IsValidHandle_PROC)( HANDLE , BOOL );
typedef VOID (__stdcall *OpenProcess_PROC)( DWORD , BOOL, DWORD );
typedef VOID (__stdcall *OpenThread_PROC)( DWORD , BOOL, DWORD );
typedef VOID (__stdcall *ReadProcessMemory_PROC)(HANDLE , LPCVOID , LPVOID , DWORD , LPDWORD );
typedef VOID (__stdcall *WriteProcessMemory_PROC)(HANDLE , LPVOID , LPVOID , DWORD , LPDWORD );
typedef VOID (__stdcall *VirtualQueryEx_PROC)(HANDLE , LPCVOID , PMEMORY_BASIC_INFORMATION , DWORD );
typedef VOID (__stdcall *NtOpenProcess_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *NtOpenThread_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *VirtualAllocEx_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *CreateRemoteAPC_PROC)(HANDLE , BOOL );
/*
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
typedef VOID (__stdcall *IsValidHandle_PROC)(HANDLE , BOOL );
*/
/*
Function {OpenProcess}OP(dwDesiredAccess:DWORD;bInheritHandle:BOOL;dwProcessId:DWORD):THANDLE; stdcall;
Function {OpenThread}OT(dwDesiredAccess:DWORD;bInheritHandle:BOOL;dwThreadId:DWORD):THANDLE; stdcall;
function {ReadProcessMemory}RPM(hProcess:THANDLE;lpBaseAddress:pointer;lpBuffer:pointer;nSize:DWORD;var NumberOfBytesRead:DWORD):BOOL; stdcall;
function {WriteProcessMemory}WPM(hProcess:THANDLE;lpBaseAddress:pointer;lpBuffer:pointer;nSize:DWORD;var NumberOfBytesWritten:DWORD):BOOL; stdcall;
function {VirtualQueryEx}VQE(hProcess: THandle; address: pointer; var mbi: _MEMORY_BASIC_INFORMATION; bufsize: DWORD):dword; stdcall;
Function {NtOpenProcess}NOP(var Handle: THandle; AccessMask: dword; objectattributes: pointer; clientid: PClient_ID):DWORD; stdcall;
Function {NtOpenThread}NtOT(var Handle: THandle; AccessMask: dword; objectattributes: pointer; clientid: PClient_ID):DWORD; stdcall;
Function {VirtualAllocEx}VAE(hProcess: THandle; lpAddress: Pointer; dwSize, flAllocationType: DWORD; flProtect: DWORD): Pointer; stdcall;
Function CreateRemoteAPC(threadid: dword; lpStartAddress: TFNAPCProc): THandle; stdcall;


Function GetPEProcess(ProcessID: dword):dword; stdcall;
Function GetPEThread(Threadid: dword):dword; stdcall;
function GetDebugportOffset: DWORD; stdcall;
function GetProcessnameOffset: dword; stdcall;
function GetThreadsProcessOffset: dword; stdcall;
function GetThreadListEntryOffset: dword; stdcall;

function ReadPhysicalMemory(hProcess:THANDLE;lpBaseAddress:pointer;lpBuffer:pointer;nSize:DWORD;var NumberOfBytesRead:DWORD):BOOL; stdcall;
function WritePhysicalMemory(hProcess:THANDLE;lpBaseAddress:pointer;lpBuffer:pointer;nSize:DWORD;var NumberOfBytesWritten:DWORD):BOOL; stdcall;
function GetPhysicalAddress(hProcess:THandle;lpBaseAddress:pointer;var Address:int64): BOOL; stdcall;

function ProtectMe(ProtectedProcessID: dword; denylist,globaldenylist:BOOL;list:pchar; listsize:dword):BOOL; stdcall; //or should I give it a array of processid's?
function UnprotectMe:bool; stdcall;
function MakeKernelCopy(Base: dword; size: dword): bool; stdcall;

function GetCR4:DWORD; stdcall;
function GetCR3(hProcess:THANDLE;var CR3:DWORD):BOOL; stdcall;
function SetCR3(hProcess:THANDLE;CR3: DWORD):BOOL; stdcall;
function GetCR0:DWORD; stdcall;
function GetSDT:DWORD; stdcall;
function GetSDTShadow:DWORD; stdcall;
function setAlternateDebugMethod(var int1apihook:dword; var OriginalInt1handler:dword):BOOL; stdcall;
function getAlternateDebugMethod:BOOL; stdcall;
function DebugProcess(processid:dword;address:DWORD;size: byte;debugtype:byte):BOOL; stdcall;
function SetGlobalDebugState(state: boolean): BOOL; stdcall;
function StopDebugging:BOOL; stdcall;
function StopRegisterChange(regnr:integer):BOOL; stdcall;
function RetrieveDebugData(Buffer: pointer):integer; stdcall;
function ChangeRegOnBP(Processid:dword; address: dword; debugreg: integer; changeEAX,changeEBX,changeECX,changeEDX,changeESI,changeEDI,changeEBP,changeESP,changeEIP,changeCF,changePF,changeAF,changeZF,changeSF,changeOF:BOOLEAN; newEAX,newEBX,newECX,newEDX,newESI,newEDI,newEBP,newESP,newEIP:DWORD; newCF,newPF,newAF,newZF,newSF,newOF:BOOLEAN):BOOLEAN; stdcall;
function StartProcessWatch:BOOL;stdcall;
function WaitForProcessListData(processpointer:pointer;threadpointer:pointer;timeout:dword):dword; stdcall;
function GetProcessNameFromPEProcess(peprocess:dword; buffer:pchar;buffersize:dword):integer; stdcall;
function GetProcessNameFromID(processid:dword; buffer:pointer;buffersize:dword):integer; stdcall;
function MakeWritable(Address,Size:dword;copyonwrite:boolean): boolean; stdcall;
function RewriteKernel32:boolean; stdcall;
function RestoreKernel32:boolean; stdcall;

function InitializeDriver(Address,size:dword):BOOL; stdcall;
function GetWin32KAddress(var address:DWORD;var size:dworD):boolean;
function GetDriverVersion: dword;

function GetIDTCurrentThread:dword; stdcall;
function GetIDTs(idtstore: pointer; maxidts: integer):integer; stdcall;

function GetLoadedState: BOOLEAN; stdcall;

function test: boolean; stdcall;
procedure useIOCTL(use: boolean); stdcall;

function FHMSuspendThread(ThreadID:dword):boolean; stdcall;
function FHMResumeThread(ThreadID:dword):boolean; stdcall;
function FHMSuspendProcess(ProcessID:dword):boolean; stdcall;
function FHMResumeProcess(ProcessID:dword):boolean; stdcall;

function KernelAlloc(size: dword):pointer; stdcall;
function GetKProcAddress(s: pwidechar):pointer; stdcall;

function GetSDTEntry(nr: integer; address: PDWORD; paramcount: PBYTE):boolean; stdcall;
function SetSDTEntry(nr: integer; address: DWORD; paramcount: BYTE):boolean; stdcall;
function GetSSDTEntry(nr: integer; address: PDWORD; paramcount: PBYTE):boolean; stdcall;
function SetSSDTEntry(nr: integer; address: DWORD; paramcount: BYTE):boolean; stdcall;

function GetGDT(limit: pword):dword; stdcall;


exp|ts VQE//VirtualQueryEx
exp|ts OP//OpenProcess
exp|ts OT//OpenThread
exp|ts NOP//NtOpenProcess
exp|ts RPM//ReadProcessMemORY
exp|ts WPM//WriteProcessMemORY
exp|ts VAE //VirtualAllocEx
exp|ts CreateRemoteAPC
exp|ts ReadPhysicalMemORY
exp|ts WritePhysicalMemORY
exp|ts GetPhysicalAddress
exp|ts GetPEProcess
exp|ts GetPEThread
exp|ts ProtectMe
exp|ts UnprotectMe
exp|ts IsValidHandle
exp|ts GetCR4
exp|ts GetCR3
exp|ts SetCR3
exp|ts GetCR0
exp|ts GetSDT
exp|ts GetSDTShadow
exp|ts setAlternateDebugMethod
exp|ts getAlternateDebugMethod
exp|ts DebugProcess
exp|ts StopDebugging
exp|ts StopRegisterChange
exp|ts RetrieveDebugData
exp|ts GetThreadsProcessOffset
exp|ts GetThreadListEntryOffset
exp|ts GetDebugp|tOffset
exp|ts GetProcessnameOffset
exp|ts StartProcessWatch
exp|ts WaitF|ProcessListData
exp|ts GetProcessNameFromID
exp|ts GetProcessNameFromPEProcess
exp|ts GetIDTCurrentThread
exp|ts GetIDTs
exp|ts MakeWritable
exp|ts GetLoadedState
exp|ts ChangeRegOnBP
exp|ts SetGlobalDebugState

exp|ts FHMSuspendThread
exp|ts FHMResumeThread
exp|ts FHMSuspendProcess
exp|ts FHMResumeProcess

exp|ts KernelAlloc
exp|ts GetKProcAddress

exp|ts GetSDTEntry
exp|ts SetSDTEntry
exp|ts GetSSDTEntry
exp|ts SetSSDTEntry

exp|ts GetGDT

exp|ts test
exp|ts useIOCTL
exp|ts MakeKernelCopy
randomize
*/