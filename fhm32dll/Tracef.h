#pragma once

#ifndef __TRACEF_H__
#define __TRACEF_H__

#include "define.h"

#if !defined(__RELEASE)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#include <stdio.h>

// Marco
#define TRACEF                   CTrace::TraceFormat
/// Implement ///
#define TRACE_BUFFER_SIZE     sizeof(DWORD)*8192

class CTrace
{
private:	// No copies
	CTrace(const CTrace &rhs);
	CTrace &operator=(const CTrace &rhs);
public:
	CTrace() { }
	~CTrace() { }
	static void TraceFormat(LPCTSTR lpszFormat, ...) {	// TRACEF, Format Trace
		TCHAR szBuffer[TRACE_BUFFER_SIZE] = {0};
		
		va_list fmtList;
		va_start(fmtList, lpszFormat);
		_vsnprintf(szBuffer, TRACE_BUFFER_SIZE - 1, lpszFormat, fmtList);
		va_end(fmtList);
		
		szBuffer[TRACE_BUFFER_SIZE - 1] = 0;
		OutputDebugString(szBuffer);
	}
};

#else // !defined(__RELEASE)
#define TRACEF
#endif // !defined(__RELEASE)

#endif // __TRACEF_H__
