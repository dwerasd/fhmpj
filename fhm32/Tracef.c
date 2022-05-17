
#include <windef.h>
#include <tchar.h>
#include <stdio.h>
#include "Tracef.h"

#define TRACE_BUFFER_SIZE	1024

void TraceFormat(LPCTSTR lpszFormat, ...) {	// TRACEF, Format Trace
	TCHAR szBuffer[TRACE_BUFFER_SIZE] = {0};
	
	va_list fmtList;
	va_start(fmtList, lpszFormat);
	_vsnprintf(szBuffer, TRACE_BUFFER_SIZE - 1, TRACE_BUFFER_SIZE - 1, lpszFormat, fmtList);
	va_end(fmtList);
	
	szBuffer[TRACE_BUFFER_SIZE - 1] = 0;
	DbgPrint(szBuffer);
}
