#if !defined(__EVILKERNEL_H__)
#define __EVILKERNEL_H__

#include "Common.h"


#if defined(__cplusplus)
extern "C"
{
#endif

// 如果是要调试插件则设置此宏
#define __DEBUG_EVIL_PLUGIN__				1

/*
 * 配置结构
 */
#define __MAX_EVIL_PLUGIN_COUNT__			128	//邪恶插件的总数
#define __EVIL_PLUGIN_NAME_LENGTH__			256 //邪恶插件的名的长度
typedef struct _EVILKERNEL_CONFIGURE {
	__bool bIsDll;//是否是DLL
	__integer iTargetFileSize;//目标文件长度
	__integer iPluginTotalCount;//插件数量
	__integer PluginSizeArray[__MAX_EVIL_PLUGIN_COUNT__];//插件的大小队列
#if defined(__DEBUG_EVIL_PLUGIN__)
	/*
	 * 在调试邪恶插件时才开启
	 */
	__char PluginNameArray[__MAX_EVIL_PLUGIN_COUNT__][__EVIL_PLUGIN_NAME_LENGTH__];
#endif
} EVILKERNEL_CONFIGURE, *PEVILKERNEL_CONFIGURE;

/*
 * 如果是DLL,定义的参数结构
 * 这个区域只有xVirusDll使用
 * 没有eax,丫不用保存
 */
typedef struct _XVIRUSDLL_ARG {
	__dword dwOrigEsp;
	__dword dwOrigEbp;
	__dword dwOrigEsi;
	__dword dwOrigEdi;
	__dword dwOrigEbx;
	__dword dwOrigEdx;
	__dword dwOrigEcx;
	__address addrOrigImageBase;//原始的映射地址,提供给EvilKernel中获取原始映射
} XVIRUSDLL_ARG, *PXVIRUSDLL_ARG;

#if defined(__cplusplus)
}
#endif

#endif
