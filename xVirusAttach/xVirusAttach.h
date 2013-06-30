#if !defined(__XVIRUSATTACH_H__)
#define __XVIRUSATTACH_H__

#include "Common.h"


#if defined(__cplusplus)
extern "C"
{
#endif

/*
 * º¯ÊýÖ¸Õë
 */
typedef __integer (__API__ *FPxVirusInsertPlugin)(__tchar *pPluginPath);
typedef __bool (__API__ *FPxVirusInfect2Dll)(__tchar *pTargetPath);
typedef __bool (__API__ *FPxVirusInfect2Exe)(__tchar *pTargetPath, __tchar *pIconPath);

#if defined(__cplusplus)
}
#endif

#endif
