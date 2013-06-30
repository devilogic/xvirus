#include "Common.h"
#include <Windows.h>
//#include <Wincrypt.h>

/*
 * 生成一个证书
 */
#define __DEF_CERT_SERIALNUM__					"\x5D\x06\x88\xF9\x04\x0A\xD5\x22\x87\xFC\x32\xAD\xEC\xEB\x85\xB0"
#define __DEF_CERT_SERIALNUM_LENGTH__			16
__dword __API__ xVirusMakeCert(__byte *pSerialNum, \
							   __char *pSignatureAlgorithm, __memory pSignatureAlgorithmParameter, __integer iSignatureAlgorithmParameterLength, \
							   __char *pCertIssuerName, __char *pCertSubjectName, \
							   __tchar *pX509CertPath, __tchar *pPKCS7CertPath) {
	HCRYPTPROV hProv;   
	HCRYPTKEY hKey;
	__bool bCret;
	CERT_RDN_ATTR rgNameAttr = {0};
	CERT_RDN rgRDN = {0};
	CERT_NAME_INFO CertName = {0};
	__dword dwIssuerNameLength = 0;
	__byte *pIssuerName = NULL;
	__dword dwCertSubNameLength = 0;
	__memory pCertSubName = NULL;

	bCret = CryptAcquireContext(&hProv, _T("LogicContainer"), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);   
	if (!bCret) {
		bCret = CryptAcquireContext(&hProv, _T("LogicContainer"), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		bCret = CryptAcquireContext(&hProv, _T("LogicContainer"), MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
		if (!bCret)   
			return GetLastError();   
	}
   
	bCret = CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey) ;  //|CRYPT_USER_PROTECTED    
	if(!bCret)   
		return GetLastError();

	// 生成证书
	{
		CERT_INFO Cert = {0};
		PCERT_PUBLIC_KEY_INFO PubKeyBuf = NULL;
		__byte *pCertOut = NULL;

		__logic_memset__((__memory)&Cert, 0, sizeof(CERT_INFO));

		// 1.设置版本
		Cert.dwVersion = CERT_V3;   
   
		// 2.序列号
		if (pSerialNum)
			Cert.SerialNumber.pbData = pSerialNum;
		else
			Cert.SerialNumber.pbData = __DEF_CERT_SERIALNUM__;
		Cert.SerialNumber.cbData = 16;

		// 3.算法
		if (pSignatureAlgorithm)
			Cert.SignatureAlgorithm.pszObjId = pSignatureAlgorithm;
		else
			Cert.SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
		if ((pSignatureAlgorithmParameter) && (iSignatureAlgorithmParameterLength)) {
			Cert.SignatureAlgorithm.Parameters.cbData = iSignatureAlgorithmParameterLength;
			Cert.SignatureAlgorithm.Parameters.pbData = pSignatureAlgorithmParameter;
		} else {
			Cert.SignatureAlgorithm.Parameters.cbData = 0;
			Cert.SignatureAlgorithm.Parameters.pbData = NULL;
		}
   
		// 4.发布商,编码发布商名称使用ASN.1
		rgNameAttr.pszObjId = szOID_COMMON_NAME;
		rgNameAttr.dwValueType = CERT_RDN_PRINTABLE_STRING;
		rgNameAttr.Value.cbData = __logic_strlen__(pCertIssuerName)+1;
		rgNameAttr.Value.pbData = (__byte *)pCertIssuerName;
		rgRDN.cRDNAttr = 1;
		rgRDN.rgRDNAttr = &rgNameAttr; 
		CertName.cRDN = 1;
		CertName.rgRDN = &rgRDN;  

		// 第一次调用获取长度
		bCret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &CertName, 0, NULL, NULL, &dwIssuerNameLength);
		if (!bCret)
			return GetLastError();

		pIssuerName = (__byte*)__logic_new_size__(dwIssuerNameLength);   
		if (!pIssuerName)
			return GetLastError();

		bCret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &CertName, 0, NULL, pIssuerName, &dwIssuerNameLength);   
		if (!bCret) {
			__logic_delete__(pIssuerName);
			return GetLastError();
		}

		Cert.Issuer.cbData = dwIssuerNameLength;
		Cert.Issuer.pbData = pIssuerName;
   
		// 5.证书时间
		{
			SYSTEMTIME SysTime;   
			GetSystemTime(&SysTime);   
			SystemTimeToFileTime(&SysTime , &Cert.NotBefore);   

			SysTime.wYear += 10;
			SystemTimeToFileTime(&SysTime , &Cert.NotAfter);
		}
   
		// 6.证书子名称	   
		rgNameAttr.pszObjId = szOID_COMMON_NAME;   
		rgNameAttr.dwValueType = CERT_RDN_PRINTABLE_STRING;   
		rgNameAttr.Value.cbData = __logic_strlen__(pCertSubjectName) +1;   
		rgNameAttr.Value.pbData = (__byte *)pCertSubjectName;   
		
		// 第一次调用获取长度
		bCret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &CertName, 0, NULL, NULL, &dwCertSubNameLength);   
		if (!bCret) {
			__logic_delete__(pIssuerName);
			__logic_delete__(pCertSubName);
			return GetLastError();
		}
   
		pCertSubName = (__byte *)__logic_new_size__(dwCertSubNameLength);   
		if (!pCertSubName) {
			__logic_delete__(pIssuerName);
			__logic_delete__(pCertSubName);
			return GetLastError();
		}
   
		bCret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME, &CertName, 0, NULL, pCertSubName, &dwCertSubNameLength);   
		if (!bCret) {
			__logic_delete__(pIssuerName);
			__logic_delete__(pCertSubName);
			return GetLastError();
		}
   
		Cert.Subject.cbData = dwCertSubNameLength;   
		Cert.Subject.pbData = pCertSubName;
   
		// 7.公钥
		{   
			__dword PubKeyLen;

			// 第一调用获取长度
			bCret = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING ,NULL, &PubKeyLen);   
			if(!bCret) {
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				return GetLastError();
			}

			PubKeyBuf = (PCERT_PUBLIC_KEY_INFO)__logic_new_size__(PubKeyLen);   
			if (!PubKeyBuf) {
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				return GetLastError();
			}

			bCret = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, PubKeyBuf, &PubKeyLen);
			if (!bCret) {
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}

			__logic_memcpy__(&(Cert.SubjectPublicKeyInfo), PubKeyBuf, sizeof(CERT_PUBLIC_KEY_INFO));
		}
	   
		// 扩展    
		Cert.cExtension = 0;   
		Cert.rgExtension = NULL;   
		Cert.IssuerUniqueId.cbData = 0 ;   
		Cert.SubjectUniqueId.cbData = 0;   
	   
		// 生成证书
		{
			CRYPT_ALGORITHM_IDENTIFIER algId;   
			__byte paraData[16];   
			paraData[0] = 0x05; paraData[1] = 0x00;   

			algId.pszObjId = szOID_RSA_SHA1RSA;   
			algId.Parameters.cbData = 2;   
			algId.Parameters.pbData = paraData;

			/*
			 * CryptSignAndEncodeCertificate  
			 * The CryptSignAndEncodeCertificate function encodes and signs a certificate, CRL, CTL or certificate request.   
			 * This function performs the following operations:  
			 * 1-> Calls CryptEncodeObject using lpszStructType to encode the "to be signed" information.   
			 * 2-> Calls CryptSignCertificate to sign this encoded information.   
			 * 3-> Calls CryptEncodeObject again, with lpszStructType set to X509_CERT,   
		     * to further encode the resulting signed, encoded information.   
			 */
			// 导出X.509证书
			{
				__dword CertLen = 0;

				// 第一次调用计算证书大小
				bCret = CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE, X509_ASN_ENCODING, \
													  X509_CERT_TO_BE_SIGNED, (__void *)&Cert, &algId, \
													  NULL, NULL, &CertLen);
				if (!bCret) {
					__logic_delete__(pIssuerName);
					__logic_delete__(pCertSubName);
					__logic_delete__(PubKeyBuf);
					return GetLastError();
				}

				pCertOut = (__byte *)__logic_new_size__(CertLen);
				if (!pCertOut) {
					__logic_delete__(pIssuerName);
					__logic_delete__(pCertSubName);
					__logic_delete__(PubKeyBuf);
					return GetLastError();
				}

				bCret = CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE, X509_ASN_ENCODING, \
													  X509_CERT_TO_BE_SIGNED, (__void *)&Cert, &algId,   
													  NULL, pCertOut, &CertLen);
				if (!bCret) {
					__logic_delete__(pCertOut);
					__logic_delete__(pIssuerName);
					__logic_delete__(pCertSubName);
					__logic_delete__(PubKeyBuf);
					return GetLastError();
				}

				// 写入文件
				{
					__dword dwNumberOfWritten = 0;
					HANDLE hX509File = NULL;

					hX509File = CreateFile((LPCTSTR)pX509CertPath ,GENERIC_READ |GENERIC_WRITE, \
											FILE_SHARE_READ| FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, \
											NULL, NULL);
					if (!hX509File) {
						__logic_delete__(pCertOut);
						__logic_delete__(pIssuerName);
						__logic_delete__(pCertSubName);
						__logic_delete__(PubKeyBuf);
						return GetLastError();
					}

					bCret = WriteFile(hX509File, pCertOut, CertLen, &dwNumberOfWritten, NULL);   
					if (!bCret) {
						__logic_delete__(pCertOut);
						__logic_delete__(pIssuerName);
						__logic_delete__(pCertSubName);
						__logic_delete__(PubKeyBuf);
						return GetLastError();
					}

					bCret = CloseHandle(hX509File);
					if (!bCret) {
						__logic_delete__(pCertOut);
						__logic_delete__(pIssuerName);
						__logic_delete__(pCertSubName);
						__logic_delete__(PubKeyBuf);
						return GetLastError();
					}
				} 
			}
		}/* 导出X.509证书完毕 */
   
		// 导出PKCS#7证书
		{
			__dword dwNumberOfWritten = 0;
			HANDLE hPKCS7File = NULL;
			HCERTSTORE hStore = NULL;
			__void *pvData = NULL;   
			__dword cbData = 0; 

			hPKCS7File = CreateFile((LPCTSTR)pPKCS7CertPath ,GENERIC_READ |GENERIC_WRITE, FILE_SHARE_READ| FILE_SHARE_WRITE, \
									NULL, CREATE_ALWAYS, NULL, NULL);   
			if (!hPKCS7File)  {
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}

			hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, PKCS_7_ASN_ENCODING, hProv, CERT_STORE_OPEN_EXISTING_FLAG, NULL);   
			if (!hStore) {
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}

			// 第一调用取得证书长度
			bCret = CertGetStoreProperty(hStore, CERT_STORE_LOCALIZED_NAME_PROP_ID, NULL, &cbData);   
			if (!bCret) {
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();// 如果没有找到 CRYPT_E_NOT_FOUND
			}

			pvData = __logic_new_size__(cbData);   
			if (!pvData) {
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}

			bCret = CertGetStoreProperty(hStore, CERT_STORE_LOCALIZED_NAME_PROP_ID, pvData, &cbData);  
			if (!bCret) {
				__logic_delete__(pvData);
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();// 如果没有找到 CRYPT_E_NOT_FOUND
			}

			bCret = CertSaveStore(hStore, X509_ASN_ENCODING, CERT_STORE_SAVE_AS_PKCS7, CERT_STORE_SAVE_TO_FILE, hPKCS7File, 0);   
			if (!bCret) {
				__logic_delete__(pvData);
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}

			bCret = CloseHandle(hPKCS7File);   
			if (!bCret) {
				__logic_delete__(pvData);
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}
 
			// 释放容器
			bCret = CryptReleaseContext(hProv, 0);
			if (!bCret) {
				__logic_delete__(pvData);
				__logic_delete__(pCertOut);
				__logic_delete__(pIssuerName);
				__logic_delete__(pCertSubName);
				__logic_delete__(PubKeyBuf);
				return GetLastError();
			}

			// 释放证书
			__logic_delete__(pvData);
		}/*  导出PKCS#7证书完毕 */

		// 释放内存
		__logic_delete__(pCertOut);
		__logic_delete__(pIssuerName);
		__logic_delete__(pCertSubName);
		__logic_delete__(PubKeyBuf);
	}
	return 0;
}   
