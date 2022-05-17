//type TDeviceIoControl=function(hDevice: THandle; dwIoControlCode: DWORD; lpInBuffer: Pointer; nInBufferSize: DWORD; lpOutBuffer: Pointer; nOutBufferSize: DWORD; var lpBytesReturned: DWORD; lpOverlapped: POverlapped): BOOL; stdcall;

typedef struct _HANDLELIST
{
	HANDLE processhandle;
	DWORD processid;
	BOOL validhandle;
} HANDLELIST ;
			 
typedef struct _CLIENT_ID
{
	HANDLE processid;
	DWORD threadid;
	BOOL validhandle;
} CLIENT_ID ;

CLIENT_ID PClient_ID;

typedef struct _CHANGEREG
{
	DWORD address;
	
	BOOL changeEAX;
	BOOL changeEBX;
	BOOL changeECX;
	BOOL changeEDX;
	BOOL changeESI;
	BOOL changeEDI;
	BOOL changeEBP;
	BOOL changeESP;
	BOOL changeEIP;
	BOOL changeCF;
	BOOL changePF;
	BOOL changeAF;
	BOOL changeZF;
	BOOL changeSF;
	BOOL changeOF;

	DWORD newEAX;
	DWORD newEBX;
	DWORD newECX;
	DWORD newEDX;
	DWORD newESI;
	DWORD newEDI;
	DWORD newEBP;
	DWORD newESP;
	DWORD newEIP;
	BOOL newCF;
	BOOL newPF;
	BOOL newAF;
	BOOL newZF;
	BOOL newSF;
	BOOL newOF;
	
	BOOL Active;
} CHANGEREG;

typedef struct _SENDDRVBUF
{
	DWORD ProcessID;
	DWORD debugreg;
	CHANGEREG ChangeReg;
} SENDDRVBUF;


class _HOOKIDTTHREAD
{
public:
	BYTE cpunr;
	BOOL done;
	BOOL succeeded;

};


/*
		  type THookIDTThread=class(tthread)
			  public
cpunr: byte;
done: boolean;
succeeded: boolean;
		   procedure execute; override;
		   end;
		   
class _HOOKIDTTHREAD
{
public:
	BYTE cpunr;
	BOOL done;
	BOOL succeeded;
};
		   type THookIDTConstantly=class(tthread)
			   public
			   procedure execute; override;
end;
*/