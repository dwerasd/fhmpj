#ifndef __TRACEF_H__
#define __TRACEF_H__

void TraceFormat(LPCTSTR lpszFormat, ...);

#if !defined(__RELEASE)


// Marco
#define TRACEF				TraceFormat
/// Implement ///
#else // !defined(__RELEASE)
#define TRACEF
#endif // !defined(__RELEASE)

#endif // __TRACEF_H__