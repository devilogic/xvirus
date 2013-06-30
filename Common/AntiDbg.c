__bool __INTERNAL_FUNC__ AntiVM0(__address addrImageBase) {
	__bool bRet = FALSE;
	__memory pImageBase = NULL;
	__dword dwImageBase = 0;
	if (addrImageBase == 0)
		pImageBase = (__memory)GetModuleHandle(NULL);
	else
		pImageBase = (__memory)addrImageBase;
	dwImageBase = __GetNtHeader__(pImageBase)->OptionalHeader.ImageBase;
	__asm
	{
		push eax
		call _delta
_delta:
		pop eax
		and eax, 0xFFF00000
		cmp eax, dwImageBase
		jz _is_not_in_vm
		mov bRet, TRUE
		jmp _end
_is_not_in_vm:
		mov bRet, FALSE
_end:
		pop eax
	}

	return bRet;
}

__dword __INTERNAL_FUNC__ GetExtcode()
{
	static HDC dc=NULL;
	if(dc==NULL)dc=GetDC(NULL);

	MoveToEx(dc,0,5,NULL);
	Sleep(100);
	LineTo(dc,100,5);

	if(GetPixel(dc,120,5)==0)return 1;

	return GetPixel(dc,55,5);
}

__void __INTERNAL_FUNC__ AntiVM1() {
	__dword i;
	for (i = 0; i < 10; i++) {
		if (GetExtcode() ==0)
			break;
	}
}
