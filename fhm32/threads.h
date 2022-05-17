#include "ntifs.h"
#include <windef.h>

void Ignore(PKAPC Apc, PKNORMAL_ROUTINE NormalRoutine, PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
void SuspendThreadAPCRoutine(PVOID arg1, PVOID arg2, PVOID arg3);

void FHMSuspendThread(ULONG ThreadID);
void FHMResumeThread(ULONG ThreadID);

void FHMResumeProcess(ULONG ProcessID);
void FHMSuspendProcess(ULONG ProcessID);
