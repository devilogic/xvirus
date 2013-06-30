__dword __API__ crc32(__memory data, __dword length) {
	__dword r = 0xFFFFFFFFUL;
	__dword i, b;

	for (i = 0; i < length; ++i) {
		r ^= data[i];
		for (b = 0; b < 8; ++b) {
			if ((__byte) r & 1)
				r = (r >> 1) ^ 0xEDB88320UL;
			else
				r >>= 1;
		}
	}

	return r ^ 0xFFFFFFFFUL;
}

__INLINE__ __dword __INTERNAL_FUNC__ PolyXorKey(__dword dwKey) {
	__integer i = 0, j = 0, n = 0;
	__memory pKey = (__memory)&dwKey;
	__byte bVal = 0, bTmp = 0, bTmp2 = 0;
	dwKey ^= 0x5DEECE66DL + 2531011;
	for (i = 0; i < sizeof(__dword); i++, pKey++) {
		bVal = *pKey;
		/*
		* 第一位与第二位异或放到第一位,依次类推
		* 到达第八位,与第一位异或放到第八位
		* 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01
		*/
		for (j = 0x80, n = 7; j > 0x01; j /= 2, n--) {
			bTmp = (bVal & j) >> n;
			bTmp2 = (bVal & j / 2) >> (n - 1);
			bTmp ^= bTmp2;
			bTmp <<= n;
			bVal |= bTmp;
		}
		bTmp = bVal & 0x01;
		bTmp2 = bVal & 0x80 >> 7;
		bTmp ^= bTmp2;

		*pKey = bVal;
	}/* end for */
	return dwKey;
}

__void __API__ XorArray(__dword dwKey, __memory pPoint, __memory pOut, __integer iLength) {
	__dword dwNextKey = dwKey;
	__memory pKey = (__memory)&dwNextKey;
	__integer i = 0, j = 0;
	for (i = 0; i < iLength; i++) {
		pOut[i] = pPoint[i] ^ pKey[j];
		if (j == 3) {
			// 变换Key
			dwNextKey = PolyXorKey(dwNextKey);
			j = 0;
		} else j++;
	}
}
