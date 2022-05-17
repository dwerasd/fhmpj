#include "ntifs.h"
#include <windef.h>
#include "memscan.h"
#include "FHMFunc.h"
#include "rootkit.h"

BOOLEAN IsAddressSafe(UINT_PTR StartAddress) {
/*	MDL x;

	
	MmProbeAndLockPages(&x,KernelMode,IoModifyAccess);


	MmUnlockPages(&x);
	*/
	ULONG kernelbase = 0x7ffe0000;
	if ((!HiddenDriver) && (StartAddress<kernelbase)) {
		return TRUE;
	}
    {	// 변수를 선언하기 위해 괄호로 묶어준다
		UINT_PTR PTE,PDE;
		struct PTEStruct *x;
		/*
		PHYSICAL_ADDRESS physical;
		physical=MmGetPhysicalAddress((PVOID)StartAddress);
		return (physical.QuadPart!=0);*/
		PTE = (UINT_PTR)StartAddress;
		PTE = PTE / 0x1000 * PTESize + 0xc0000000;
    	//now check if the address in PTE is valid by checking the page table directory at 0xc0300000 (same location as CR3 btw)
	    PDE = PTE / 0x1000 * PTESize + 0xc0000000; //same formula
		x = (PVOID)PDE;
		if ( (x->P==0) && (x->A2==0) ) {
			//Not present or paged, and since paging in this area isn't such a smart thing to do just skip it
			//perhaps this is only for the 4 mb pages, but those should never be paged out, so it should be 1
			//bah, I've got no idea what this is used for
			return FALSE;
		}
		if (x->PS==1) {
			//This is a 4 MB page (no pte list)
			//so, (startaddress/0x400000*0x400000) till ((startaddress/0x400000*0x400000)+(0x400000-1) ) ) is specified by this page
		}
		else {	//if it's not a 4 MB page then check the PTE
				//still here so the page table directory agreed that it is a usable page table entry
			x = (PVOID)PTE;
			if ( (x->P==0) && (x->A2==0) ) {
				return FALSE; //see for explenation the part of the PDE
			}
		}
		return TRUE;
	} 
}

ULONG getPEThread(ULONG threadid) {	
    //UINT_PTR *threadid;
	PETHREAD selectedthread;
	ULONG result = 0;
	if (PsLookupThreadByThreadId((PVOID)threadid,&selectedthread) == STATUS_SUCCESS) {
		result = (ULONG)selectedthread;
		ObDereferenceObject(selectedthread);
	}
	return result;
}

BOOLEAN WriteProcessMemory(DWORD PID,PEPROCESS PEProcess,PVOID Address,DWORD Size, PVOID Buffer) {
	PEPROCESS selectedprocess = PEProcess;
	KAPC_STATE apc_state;
	NTSTATUS ntStatus = STATUS_SUCCESS;

	if (selectedprocess == NULL) {
		DbgPrint("WriteProcessMemory:Getting PEPROCESS\n");
        if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID,&selectedprocess))) {
		   return FALSE; //couldn't get the PID
		}
		DbgPrint("Retrieved peprocess");  
	}
	//selectedprocess now holds a valid peprocess value
	__try {
		unsigned int temp = (unsigned int)Address;
		RtlZeroMemory(&apc_state,sizeof(apc_state));					
    	KeAttachProcess((PEPROCESS)selectedprocess);				
        __try {
			char* target;
			char* source;
			unsigned int i;	
			DbgPrint("Checking safety of memory\n");
			if ((!IsAddressSafe((ULONG)Address)) || (!IsAddressSafe((ULONG)Address+Size-1))) {
				return FALSE; //if the first or last byte of this region is not safe then exit; //I know I should also check the regions inbetween, but since my own dll doesn't request more than 512 bytes it wont overlap
			}
    		//still here, then I gues it's safe to read. (But I can't be 100% sure though, it's still the users problem if he accesses memory that doesn't exist)
			DbgPrint("Copying memory to target\n");
			target = Address;
			source = Buffer;
			for ( i = 0 ; i < Size ; i++ ) {
               target[i] = source[i];
			}
			ntStatus = STATUS_SUCCESS;							
		}
		__finally {
			KeDetachProcess();
		}
	}			
	__except(1) {
		DbgPrint("Error while writing\n");
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	if ( PEProcess == NULL ) { //no valid peprocess was given so I made a reference, so lets also dereference
		ObDereferenceObject(selectedprocess);
	}
	return NT_SUCCESS(ntStatus);
}

BOOLEAN ReadProcessMemory(DWORD PID,PEPROCESS PEProcess,PVOID Address,DWORD Size, PVOID Buffer) {
	PEPROCESS selectedprocess = PEProcess;
	//KAPC_STATE apc_state;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	if ( PEProcess == NULL ) {
		//DbgPrint("ReadProcessMemory:Getting PEPROCESS\n");
        if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID,&selectedprocess))) {
		   return FALSE; //couldn't get the PID
		}
		//DbgPrint("Retrieved peprocess");  
	}
	//DbgPrint("a");
	//selectedprocess now holds a valid peprocess value
	__try {
		unsigned int temp = (unsigned int)Address;
		ULONG currentcr3;
    	KeAttachProcess((PEPROCESS)selectedprocess);

        __try {
			char* target;
			char* source;
			unsigned int i;	
			//DbgPrint("Checking safety of memory\n");
			if ((!IsAddressSafe((ULONG)Address)) || (!IsAddressSafe((ULONG)Address+Size-1))) {
				return FALSE; //if the first or last byte of this region is not safe then exit;
			}
    		//still here, then I gues it's safe to read. (But I can't be 100% sure though, it's still the users problem if he accesses memory that doesn't exist)
			//DbgPrint("Copying memory to target\n");
			target = Buffer;
			source = Address;
			RtlCopyMemory(target, source, Size);
			ntStatus = STATUS_SUCCESS;
		}
		__finally {
			//DbgPrint("%d: Before going back: PEProcess=%x ProcessID=%x CR3=%x (real=%x)\n",cpunr(), (ULONG)PsGetCurrentProcess(), PsGetCurrentProcessId(), currentcr3, vmx_getRealCR3());
			KeDetachProcess();
		}
	}			
	__except(1)	{
		DbgPrint("Error while reading\n");
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	
	if (PEProcess == NULL) { //no valid peprocess was given so I made a reference, so lets also dereference
		ObDereferenceObject(selectedprocess);
	}
	return NT_SUCCESS(ntStatus);
}

NTSTATUS ReadPhysicalMemory(char *startaddress, UINT_PTR bytestoread, void *output) {
	HANDLE			physmem;
	UNICODE_STRING	physmemString;
	OBJECT_ATTRIBUTES attributes;
	WCHAR			physmemName[] = L"\\device\\physicalmemory";
	UCHAR*			memoryview;
	NTSTATUS		ntStatus = STATUS_UNSUCCESSFUL;

	__try {
		RtlInitUnicodeString( &physmemString, physmemName );	

		InitializeObjectAttributes( &attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL );	
		ntStatus = ZwOpenSection( &physmem, SECTION_MAP_READ, &attributes );
		if (ntStatus == STATUS_SUCCESS) {
			//hey look, it didn't kill it
			UINT_PTR length;
			PHYSICAL_ADDRESS	viewBase;
			UINT_PTR offset;
			UINT_PTR toread;

			viewBase.QuadPart = (ULONGLONG)(startaddress);					
			length = 0x2000;//pinp->bytestoread; //in case of a overlapping region
			toread = bytestoread;
			memoryview = NULL;
			ntStatus = ZwMapViewOfSection(
				physmem,  //sectionhandle
				NtCurrentProcess(), //processhandle (should be -1)
				&memoryview, //BaseAddress
				0L, //ZeroBits
				length, //CommitSize
				&viewBase, //SectionOffset
				&length, //ViewSize
				ViewShare,
				0,
				PAGE_READWRITE
			);
			if ( ntStatus == STATUS_SUCCESS ) {
				offset = (UINT_PTR)(startaddress) - (UINT_PTR)viewBase.QuadPart;
				RtlCopyMemory(output,&memoryview[offset],toread);
				ZwUnmapViewOfSection( NtCurrentProcess(), memoryview);
			};
			ZwClose(physmem);
		};
	}
	__except(1) {
		DbgPrint("Error while reading physical memory\n");
	}
	return ntStatus;
}

BOOLEAN GetMemoryRegionData(DWORD PID,PEPROCESS PEProcess, PVOID mempointer,ULONG *regiontype, DWORD *memorysize,DWORD *baseaddress) {
	UINT_PTR StartAddress;
	KAPC_STATE apc_state;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	struct PTEStruct *PPTE,*PPDE;
	PEPROCESS selectedprocess = PEProcess;

	if ( PEProcess == NULL ) {
		DbgPrint("GetMemoryRegionData:Getting PEPROCESS\n");
        if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID,&selectedprocess))) {
		   return FALSE; //couldn't get the PID
		}
		DbgPrint("Retrieved peprocess");  
	}
	StartAddress = (UINT_PTR)mempointer;
	*baseaddress = ((StartAddress) /0x1000) *0x1000;
	//switch context to the target process
	RtlZeroMemory(&apc_state,sizeof(apc_state));
	__try {
		KeAttachProcess((PEPROCESS)selectedprocess);
		__try {
			//do my stuff here
			(UINT_PTR)PPTE = *baseaddress / 0x1000 *PTESize + 0xc0000000;
			(UINT_PTR)PPDE = ((UINT_PTR)PPTE) / 0x1000 *PTESize + 0xc0000000;
			//DbgPrint("PPTE=%p\nPPDE=%p\n",PPTE,PPDE);
			if ( (PPDE->P == 0) && (PPDE->A2 == 0) ) {
				//Not paged
    			//thats 4KB of PTE, wich is 1024 PTE's wich is 4096*1024 bytes wich is 4MB non-paged memory(in case of PAE obnlt 512 PTE's wich is 4096*512=2MB)
				UINT_PTR BaseAddressOfPDE = (((UINT_PTR)PPDE)-0xc0000000)/PTESize * 0x1000 ; //=address of pte (if it had one)
				BaseAddressOfPDE = ((BaseAddressOfPDE)-0xc0000000)/PTESize * 0x1000 ; //=*baseaddress that this PDE points too . (Actually, just looking at the last 3 hex digits and filling the rest with 0's should also have worked)

				*memorysize = PAGE_SIZE_LARGE - (*baseaddress - BaseAddressOfPDE);
				*regiontype = PAGE_NOACCESS;
				(UINT_PTR)PPDE = (UINT_PTR)PPDE+PTESize;  //perhaps PPDE++ also works but at least I'm sure this works
				(UINT_PTR)PPTE = ((UINT_PTR)(PPDE) - 0xc0000000) / PTESize * 0x1000; //point to the first PTE of the new PDE
			}
			else {
				if (PPDE->PS) {	//it's a 4mb page meaning the PTE is invalid
					UINT_PTR BaseAddressOfPDE = (((UINT_PTR)PPDE)-0xc0000000)/PTESize * 0x1000 ; //=address of pte (if it had one)
					BaseAddressOfPDE = ((BaseAddressOfPDE) - 0xc0000000) / PTESize * 0x1000 ; //=*baseaddress that this PDE points too . (Actually, just looking at the last 3 hex digits and filling the rest with 0's should also have worked)
					//find the *baseaddress in this 4 MB page
					*memorysize = PAGE_SIZE_LARGE - (*baseaddress - BaseAddressOfPDE);

					if ( (PPDE->P) == 0 ) {
						if ( PPDE->A2 == 1 ) {
							*regiontype = PAGE_EXECUTE_READ;
						}
						else {
							*regiontype = PAGE_NOACCESS;
						}
					}
					else {								
						if (PPDE->RW) {
							*regiontype = PAGE_EXECUTE_READWRITE;
						}
						else {
							*regiontype = PAGE_EXECUTE_READ;
						}
					}
					//next PDE
					(UINT_PTR)PPDE = (UINT_PTR)PPDE + PTESize;  //perhaps PPDE++ also works but at least I'm sure this works
					(UINT_PTR)PPTE = ((UINT_PTR)(PPDE) - 0xc0000000) / PTESize * 0x1000; //point to the first PTE of the new PDE
				}
				else {
					//4 KB
					*memorysize = 0x1000;
					//the PTE is readable
					if ( (PPTE->P == 0) && (PPTE->A2 == 0) ) {
						*regiontype=PAGE_NOACCESS;
					}
					else {						
						if (PPTE->P == 1) {
							if (PPTE->RW == 1) {
								*regiontype = PAGE_EXECUTE_READWRITE;
							}
							else {
								*regiontype = PAGE_EXECUTE_READ;
							}
						}
						else {
							//not present, but paged
							//and since I don''t know if it's writable or not lets make it readonly
							*regiontype = PAGE_EXECUTE_READ;
						}
					}
					(UINT_PTR)PPTE = (UINT_PTR)PPTE + PTESize; //next PTE in the list
    				(UINT_PTR)PPDE = ((UINT_PTR)PPTE) / 0x1000 *PTESize + 0xc0000000;
				}
			}
			//now the location of the PDE and PTE are set as they should and I can scan the rest of the memory
			//DbgPrint("after first check: PPTE=%p\nPPDE=%p\n",PPTE,PPDE);
			while ((UINT_PTR)PPDE<MAX_PDE_POS) {
				//DbgPrint("PPTE=%p(%x)\nPPDE=%p(%x)\n",PPTE,(UINT_PTR)PPTE,PPDE,(UINT_PTR)PPDE);
				if ( !((PPDE->P == 0) && (PPDE->A2 == 0)) ) {
					//this is a valid PDE
					if (PPDE->PS == 1) {
                        //it's a 4 MB PDE (so no PTE)								
						//now check the protection, if it is the same as *regiontype add 4 MB to the size
						//else break out of the loop
						if (*regiontype == PAGE_EXECUTE_READ) {
							if ( (PPDE->RW == 0) || ((PPDE->P == 0) && (PPDE->A2==1)) ) {	//paged to disk, I gues it's read-only
								*memorysize+=PAGE_SIZE_LARGE;
							}
							else {
								break; //not the same protection so let's quit
							}
						}
						if (*regiontype == PAGE_EXECUTE_READWRITE) {
							if ( (PPDE->RW == 1) && (PPDE->P == 1) ) {	//only if it's present in memory.
								*memorysize+=PAGE_SIZE_LARGE;
							}
							else {
								break;
							}
						}
						if (*regiontype == PAGE_NOACCESS) {
							if ( (PPDE->P == 0) && (PPDE->A2 == 0) ) {
								*memorysize+=PAGE_SIZE_LARGE; 
							}
							else {
								break;
							}
						}
					}
					else {
						//the 4MB bit wasn't set										
						//this means that we'll have to look through the PTEa PTE follows
						BOOLEAN EverythingOK = TRUE;
						while ((UINT_PTR)PPTE < ((((UINT_PTR)(PPDE)+PTESize)-0xc0000000)/PTESize*0x1000)) {	//while the current PTE isn't in the memorylocation of the next PDE check the memory
							if (*regiontype == PAGE_NOACCESS) {									
								if ( (PPTE->P == 0) && (PPTE->A2 == 0) ) {	//not readable so
									*memorysize+=0x1000;
								}
								else {
									EverythingOK = FALSE;
									break; //the memory I found IS accessible																										
								}
							}
							if (*regiontype == PAGE_EXECUTE_READWRITE) {
								if ( (PPTE->RW == 1) || ((PPTE->P == 1) || (PPTE->A2 == 1) ) ) {
									*memorysize+=0x1000; //writable or paged
								}
								else {
									EverythingOK = FALSE;
									break;
								}										
							}
							if (*regiontype == PAGE_EXECUTE_READ) {
								if ((PPTE->RW == 0) || ((PPTE->P == 0) && (PPTE->A2 == 1) ) ) {	//read only or paged to disk (lets assume that the protection follows (just a gues)
									*memorysize+=0x1000;
								}
								else {
									//if it's writable
									//or if it's not paged and the global bit is on
									//then it isn't read-only
									EverythingOK = FALSE;
									break;
								}
							}
							(UINT_PTR)PPTE = (UINT_PTR)PPTE + PTESize;
						}
						if (!EverythingOK) {
							break;
						}
					}
				}
				else {
					//4MB of non paged memory
					if (*regiontype == PAGE_NOACCESS) {
						*memorysize+=PAGE_SIZE_LARGE; //increase the size of page_noaccess memory with 4 MB
					}
					else {
						break; //no, the previous wasn't PAGE_NOACCESS so break with the current length
					}
				}
				(UINT_PTR)PPDE = (UINT_PTR)PPDE+PTESize;
				(UINT_PTR)PPTE = ((UINT_PTR)(PPDE)-0xc0000000)/PTESize*0x1000; //point to the first PTE of the new PDE
			}
			if ((UINT_PTR)PPDE >= MAX_PDE_POS) {
                ntStatus=STATUS_UNSUCCESSFUL;
			}
		}
		__finally {
			KeDetachProcess();
		}
	}
	__except(1) {
		DbgPrint("Exception in GetMemoryRegionData\n");
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	if (PEProcess == NULL) { //no valid peprocess was given so I made a reference, so lets also dereference
		ObDereferenceObject(selectedprocess);
	}
	return NT_SUCCESS(ntStatus);
}