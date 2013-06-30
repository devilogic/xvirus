#if !defined(__EVILPLUGIN_H__)
#define __EVILPLUGIN_H__

#include "Common.h"


#if defined(__cplusplus)
extern "C"
{
#endif

// 插件初始化
typedef __bool (__API__ *FPEvilPluginInit)();
// 插件运行
typedef __bool (__API__ *FPEvilPluginRun)();

#if defined(__cplusplus)
}
#endif

#endif
