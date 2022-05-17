#include <windows.h>
#include <winioctl.h>
#include "define.h"
#include "struct.h"
#include "Tracef.h"

#include "psapi.h"
#pragma comment(lib,"psapi.lib")

BOOL bHookIDT = FALSE;
HANDLE hSCManager = NULL;
HANDLE hService = NULL;
HANDLE hDevice = NULL;
CHANGEREG tempregEDIt = {0};
HANDLE hProcess = NULL;
/*
BOOL StartDebuggerIfNeeded(BOOL ask) {
	BOOL bResult = FALSE;
	CHAR mes[1024] = {0};
	BOOL res = FALSE;
	DWORD i = 0;

	if ( hProcess == 0 ) {
		return FALSE;
	}
	ntsuspendprocess = NULL; //lets use the debugger for this
	//start the debugger on the current process
	//check for a debugger
	Debuggerthread = TDebugger.MyCreate2(GetCurrentProcessId());
	while (debuggerthread != NULL) && DebuggerThread.attaching do sleep(10);  //give him some time
	if ( !debuggerthread.attached ) {
		debuggerthread.Free;
		debuggerthread = NULL;
	}

	return bResult;
}
*/
/*
function startdebuggerifneeded(ask:boolean): boolean; overload;
var mes: string;
reS:boolean;
i: integer;
   begin
result:=false;
   if processhandle=0 then raise exception.create('You must first open a process');
   
   {$ifndef netserver}
   if debuggerthread2<>nil then
	   begin
	   if messagedlg('The kerneldebugger is currently active. Enabling the default windows debugger will cause the kernel debugger to terminate itself. Continue?',mtwarning,[mbyes,mbno],0)=mrno then exit;
	   freeandnil(debuggerthread2);
	   end;
	   {$endif}
	   
	   if (debuggerthread=nil) or (not debuggerthread.attached) then
		   begin
		   if @DebugActiveProcessStop=@DebugActiveProcessStopProstitute then
mes:='This will attach the debugger of Cheat Engine to the current process. If you close Cheat Engine while the game is running, the game will close too. Are you sure you want to do this?'
    else
mes:='This will attach the debugger of Cheat Engine to the current process. Continue?';
		   
		   {$ifndef net}
		   if ask then
res:=Messagedlg(mes,mtConfirmation,[mbYes, mbNo],0)=mrYes
    else
res:=true;
		   
		   if res then
		   {$endif}
		   begin
		   {$ifndef net}
		   if not advancedoptions.Pausebutton.Down then
			   @ntsuspendprocess:=nil; //lets use the debugger for this
		   {$endif}
		   
		   //start the debugger on the current process
		   //check for a debugger
Debuggerthread:=TDebugger.MyCreate2(processid);
			   while (debuggerthread<>nil) and DebuggerThread.attaching do sleep(10);  //give him some time
			   if not debuggerthread.attached then
				   begin
				   debuggerthread.Free;
debuggerthread:=nil;
			   raise exception.Create('I couldn''t attach the debugger to this process! You could try to open the process using the processpicker and try that! If that also doesn''t work check if you have debugging rights.');
			   end;
			   
			   {$ifndef netserver}
			   //Enable the debugger screen for the memorybrowser
			   memorybrowser.splitter1.Visible:=true;
			   memorybrowser.panel1.Visible:=true;
			   
			   memorybrowser.view1.Visible:=true;
			   memorybrowser.Debug1.Visible:=true;
			   memorybrowser.Splitter2.Visible:=true;
			   memorybrowser.RegisterView.Visible:=true;
			   
			   Memorybrowser.UpdateRegisterview;
			   {$endif}
			   
result:=true;
	   exit;
	   end
	   {$ifndef net}
	   else
		   begin
result:=false;
	   exit;
	   end;
	   {$endif}
	   end;
result:=true;
end;
*/
BOOL __stdcall HookIDTThread() {
	BOOL bResult = FALSE;
	do {
		if ( bHookIDT ) {
			TRACEF("이미 훅 됨");
			bResult = bHookIDT;
			break;
		}
		BYTE cpunr;
		DWORD br, cc = IOCTL_CE_HOOKINTS;
		if ( DeviceIoControl(hDevice, cc, &cpunr, 1, &cpunr, 0, &br, NULL) ) {
			TRACEF("IDT 훅 성공");
			bHookIDT = TRUE;
			bResult = TRUE;
		}
		else {
			TRACEF("IDT 훅 실패");
		}
	} while ( FALSE );
	return bResult;
}

/*
		  SetProcessAffinityMask(getcurrentprocess,PA); //multi processors are so fun. It'd be a waste not to use it
		  outputdebugstring('going to start the hooker');
hooker:=thookidtconstantly.Create(false);
	   
result:=true;
	   end;
end;
*/
#if defined(IOCTL_CE_DEBUGPROCESS_CHANGEREG)
BOOL __stdcall ChangeRegOnBP/*(DWORD ProcessID, DWORD Address, DWORD debugreg, 
				   DWORD changeEAX, DWORD changeEBX, DWORD changeECX, DWORD changeEDX, DWORD changeESI, DWORD changeEDI, DWORD changeEBP, DWORD changeESP, DWORD changeEIP,
				   BOOL changeCF, BOOL changePF, BOOL changeAF, BOOL changeZF, BOOL changeSF, BOOL changeOF,
				   DWORD newEAX, BOOL newEBX, BOOL newECX, BOOL newEDX, BOOL newESI, BOOL newEDI, BOOL newEBP, BOOL newESP, BOOL newEIP,
				   BOOL newCF, BOOL newPF, BOOL newAF, BOOL newZF, BOOL newSF, BOOL newOF
				   )
				   */
				   (DWORD ProcessID, DWORD Address, DWORD debugreg, CHANGEREG *inreg)
{
	DWORD			dwBytesReturned = 0;
	BOOL			bResult		= FALSE;
	SENDDRVBUF		buf = {0};

	if ( hDevice ) {
		bResult = HookIDTThread();
		if ( !bResult ) {
			return FALSE;
		}
		buf.ProcessID = ProcessID;
		buf.debugreg = debugreg;
		buf.ChangeReg.address = Address;
		TRACEF("buf.ChangeReg.address: %x", buf.ChangeReg.address);
		buf.ChangeReg.changeEAX = inreg->changeEAX;
		buf.ChangeReg.changeEBX = inreg->changeEBX;
		buf.ChangeReg.changeECX = inreg->changeECX;
		buf.ChangeReg.changeEDX = inreg->changeEDX;
		buf.ChangeReg.changeESI = inreg->changeESI;
		buf.ChangeReg.changeEDI = inreg->changeEDI;
		buf.ChangeReg.changeEBP = inreg->changeEBP;
		buf.ChangeReg.changeESP = inreg->changeESP;
		buf.ChangeReg.changeEIP = inreg->changeEIP;
		buf.ChangeReg.changeCF = inreg->changeCF;
		buf.ChangeReg.changePF = inreg->changePF;
		buf.ChangeReg.changeAF = inreg->changeAF;
		buf.ChangeReg.changeZF = inreg->changeZF;
		buf.ChangeReg.changeSF = inreg->changeSF;
		buf.ChangeReg.changeOF = inreg->changeOF;
		
		buf.ChangeReg.newEAX = inreg->newEAX;
		buf.ChangeReg.newEBX = inreg->newEBX;
		buf.ChangeReg.newECX = inreg->newECX;
		buf.ChangeReg.newEDX = inreg->newEDX;
		buf.ChangeReg.newESI = inreg->newESI;
		buf.ChangeReg.newEDI = inreg->newEDI;
		buf.ChangeReg.newEBP = inreg->newEBP;
		buf.ChangeReg.newESP = inreg->newESP;
		buf.ChangeReg.newEIP = inreg->newEIP;
		buf.ChangeReg.newCF = inreg->newCF;
		buf.ChangeReg.newPF = inreg->newPF;
		buf.ChangeReg.newAF = inreg->newAF;
		buf.ChangeReg.newZF = inreg->newZF;
		buf.ChangeReg.newSF = inreg->newSF;
		buf.ChangeReg.newOF = inreg->newOF;
		
		DWORD cc = IOCTL_CE_DEBUGPROCESS_CHANGEREG, x = 0;
		//result=result and deviceiocontrol(hdevice,cc,@buf,sizeof(buf),@buf,0,x,nil);
		bResult = DeviceIoControl(hDevice,cc,&buf, sizeof(SENDDRVBUF), &buf, 0, &x, NULL);
	}
	return bResult;
}
#endif
#if defined(IOCTL_CE_STOP_DEBUGPROCESS_CHANGEREG)
BOOL __stdcall StopRegisterChange(DWORD regnr) {
	BOOL bResult = FALSE;
	if ( hDevice ) {
		DWORD cc = IOCTL_CE_STOP_DEBUGPROCESS_CHANGEREG, x = 0;
		bResult = DeviceIoControl(hDevice,cc,&regnr, sizeof(DWORD), NULL, 0, &x, NULL);
	}
	return bResult;
}
#endif

#if defined(IOCTL_CE_GETVERSION)
DWORD GetDriverVersion() {
	DWORD x, res, cc, cc2, cc3, dwResult = 0;
	if ( hDevice != INVALID_HANDLE_VALUE ) {
		TRACEF("hDevice: %x", hDevice);
		cc = IOCTL_CE_GETVERSION;
		if ( cc != cc2 ) {
			TRACEF("cc2 cc3: %d %d", cc2, cc3);
			if ( cc != cc3) {
				TRACEF("start DeviceIoControl");
				if ( DeviceIoControl(hDevice,cc,&res, sizeof(DWORD), &res, sizeof(DWORD), &x, NULL) ) {
					TRACEF("end DeviceIoControl: %x", res);
					dwResult = res;
				}
			}
		}
	}
	return dwResult;
}
#endif

BOOL InitializeDriver() {
	BOOL bResult = FALSE;

	return bResult;
}
bool fileExists(const char filename[]) {
	WIN32_FIND_DATA finddata;
	HANDLE handle = FindFirstFile(filename,&finddata);
	return (handle!=INVALID_HANDLE_VALUE);
} 

#if defined(FHMVERSION)
BOOL LoadDriver() {
	BOOL bResult = FALSE;
	CHAR tmpbuf[256] = {0};
	
	hSCManager = OpenSCManager(NULL, NULL, GENERIC_READ | GENERIC_WRITE);
	TRACEF("hSCManager: %x", hSCManager);
	CHAR servicename[64] = {"FHMDRIVER54"};
	CHAR processeventname[64] = {"FHMProcList54"};
	CHAR threadeventname[64] = {"FHMThreadList54"};
	CHAR sySFile[64] = {"fhm32.sys"};
	CHAR DriverPath[1024] = {0};
	GetCurrentDirectory(1024, DriverPath);
	strcat(DriverPath, "\\");
	strcat(DriverPath, sySFile);
	
	if ( !fileExists(DriverPath) ) {
		return FALSE;
	}
	if ( hSCManager != 0 ) {
		hService = OpenService(hSCManager, servicename, SERVICE_ALL_ACCESS);
		if ( !hService ) {
			hService = CreateService(hSCManager, servicename, servicename, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DriverPath, NULL, NULL, NULL, NULL, NULL);
			TRACEF("서비스 오픈 실패라서 크리에잇함: %x", hService);
		}
		else {	//make sure the service points to the right file
			TRACEF("서비스 오픈 성공이네, 체인지함: %x", hService);
			ChangeServiceConfig(hService, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DriverPath, NULL, NULL, NULL, NULL, NULL, servicename);
		}
	}
	if ( hService ) {	//setup the configuration parameters before starting the driver
		CHAR sav = 0;
		TRACEF("일단 서비스 오픈 성공");
		// 레지스트리 키는 HKEY_LOCAL_MACHINE 오픈
		/*
		레지스트리클래스 a = 레지스트리클래스.Create;
		if ( !OpenKey("\\SYSTEM\\CurrentControlSet\\Services\\"+servicename) {
		TRACEF("드라이버 설정 실패");
		return FALSE;
		}
		a.WriteString("A","\\Device\\"+servicename);
		a.WriteString("B","\\DosDevice\\"+servicename);
		a.WriteString("C","\\BaseNamedObjects\\"+processeventname);
		a.WriteString("D","\\BaseNamedObjects\\"+threadeventname);
		*/
		if ( !StartService(hService, 0, NULL) ) {
			if ( GetLastError() == 577 ) {
			TRACEF("윈7이라 F8에서 Allow unsigned drivers 를 선택해야함");
			}
			CloseServiceHandle(hService);
		}
	}
	else {
		TRACEF("서비스 오픈에 실패함. 서비스 생성됐는지랑 관리자 권한인지 확인해봐");
		return FALSE;
	}
	CLEAR(tmpbuf);
	wsprintf(tmpbuf, "\\\\.\\%s", servicename);
	TRACEF("CreateFile: %s", tmpbuf);
	//hDevice = CreateFile(tmpbuf, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);	// 오리지날
	hDevice = CreateFile(tmpbuf, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);	// 이건 치엔방식
	if ( hDevice == INVALID_HANDLE_VALUE ) {
		TRACEF("드라이버 오픈 실패여 로드가 안됐을테니 재부팅해봐");
	}
	else {
		if ( GetDriverVersion() != FHMVERSION ) {
			TRACEF("드라이버 버전이 틀려 %d : %d", GetDriverVersion(), FHMVERSION);
			CloseHandle(hDevice);
			hDevice = INVALID_HANDLE_VALUE;
		}
		else {
			/*
			if GetWin32KAddress(win32kAddress,win32size) )
				begin
				if not InitializeDriver(win32kAddress,win32size) )
					begin
					messagebox(0,'The driver failed to succesSFully initialize. Some functions may not completly work','fhm32.dll',MB_ICONERROR or MB_OK);
					end;
				end
			else
				messagebox(0,'There was an error while trying to find the win32k.sys device driver. This means that some functions will not work','fhm32.dll',MB_ICONERROR or MB_OK);
				
			
			if ( !InitializeDriver(win32kAddress,win32size) ) {
				TRACEF("드라이버 초기화 실패");
			}
			*/
			TRACEF("드라이버 버전 확인함");
			HookIDTThread();
			bResult = TRUE;
		}
	}
	/*
	//succesSFully initialized, say goodbye to the init params
    reg.DeleteValue('A');
    reg.DeleteValue('B');
    reg.DeleteValue('C');
    reg.DeleteValue('D');
	
	*/
	CloseServiceHandle(hSCManager);
	return bResult;
}
#endif

CHAR szDllPath[1024] = {0};
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved) {
	if(dwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);
		GetModuleFileName(hModule, szDllPath, 1024);
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		if ( LoadDriver() ) {
			TRACEF("뭐 되긴 된거 같은디 브포 걸어볼까");
#if defined(IOCTL_CE_DEBUGPROCESS_CHANGEREG)
			INT drnr = -1, i = 0;
			CLEAR(&tempregEDIt);

			tempregEDIt.changeEAX = FALSE;
			tempregEDIt.changeEBX = FALSE;
			tempregEDIt.changeECX = FALSE;
			tempregEDIt.changeEDX = FALSE;
			tempregEDIt.changeESI = FALSE;
			tempregEDIt.changeEDI = FALSE;
			tempregEDIt.changeEBP = FALSE;
			tempregEDIt.changeESP = FALSE;
			tempregEDIt.changeEIP = TRUE;
			tempregEDIt.changeCF = FALSE;
			tempregEDIt.changePF = FALSE;
			tempregEDIt.changeAF = FALSE;
			tempregEDIt.changeZF = FALSE;
			tempregEDIt.changeSF = FALSE;
			tempregEDIt.changeOF = FALSE;
			
			if ( tempregEDIt.changeEAX ) tempregEDIt.newEAX = 0;
			if ( tempregEDIt.changeEBX ) tempregEDIt.newEBX = 0;
			if ( tempregEDIt.changeECX ) tempregEDIt.newECX = 0;
			if ( tempregEDIt.changeEDX ) tempregEDIt.newEDX = 0;
			if ( tempregEDIt.changeESI ) tempregEDIt.newESI = 0;
			if ( tempregEDIt.changeEDI ) tempregEDIt.newEDI = 0;
			if ( tempregEDIt.changeEBP ) tempregEDIt.newEBP = 0;
			if ( tempregEDIt.changeESP ) tempregEDIt.newESP = 0;
			if ( tempregEDIt.changeEIP ) {
				tempregEDIt.newEIP = 0x40103d;//atoi(EDIt9.text);
				TRACEF("tempregEDIt.newEIP: %x", tempregEDIt.newEIP);
			}
			if ( tempregEDIt.changeCF ) tempregEDIt.newCF = FALSE;
			if ( tempregEDIt.changePF ) tempregEDIt.newPF = FALSE;
			if ( tempregEDIt.changeAF ) tempregEDIt.newAF = FALSE;
			if ( tempregEDIt.changeZF ) tempregEDIt.newZF = FALSE;
			if ( tempregEDIt.changeSF ) tempregEDIt.newSF = FALSE;
			if ( tempregEDIt.changeOF ) tempregEDIt.newOF = FALSE;


			//ChangeRegOnBP(GetCurrentProcessId(), 0x40107c, i, 0, 0, 0, 0, 0, 0, 0, 0, 0x4010e6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

			if ( ChangeRegOnBP(GetCurrentProcessId(), 0x401026, i, &tempregEDIt) ) {
				TRACEF("하드브포 성공 반환함");
			}
			//debuggerthread2.breakpointchanges[i] = tempregEDIt;  // 이건 뭐지
			//debuggerthread2.setbreakpoints; // setbreakpoints 를 또 호출하는거 같다
			drnr = i;
#endif
		}
		return TRUE;
	}
	else if(dwReason == DLL_PROCESS_DETACH) {
		
	}
    return FALSE;
}