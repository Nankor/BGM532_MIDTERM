#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Strsafe.h>
#include <time.h>
#include "../MyDll/mydll.h"
#include "../MyApp/MainApp.h"

//#define FILENAME _T("KriptoAnahtar.exe")
//#define SIZE 1024
//#define MD5LEN  16
//#define XORENCODING _T("-t1")

//#define LIBNAME TEXT("mylib.dll")
//#define PROCNAME "myFunc"
//#define USERNAME TEXT("osman")
#define NEWEXENAME TEXT("PrivateVize.exe")

CHAR szLibname[] = "MYLIBNAME.DLL"; // dosya ismi random olabilir herhalde
CHAR szFuncName[] = "myFuncName"; // bu random olabilir mi? denemek lazým sanki
//TCHAR szUserName[] = TEXT("osman");
CHAR szTablo[29] = "mYuGn.oLp_45qTmLp_45q_.YuGn";
TCHAR szSubkey[] = TEXT("SOFTWARE\\Odev2Notes");
CHAR szKeyValue[] = KEYVALUE;
CHAR szMyMutex[] = MYMUTEX;
CHAR szRandStr[20]; // yeterince büyük olmasý lazým

PSTR szKatarListesi[] = {
	szLibname,
	szFuncName,
	szKeyValue,
	szMyMutex
};

//#define SRCFILE TEXT("mydll.dll")
//#define DSTFILE TEXT("MainApp.exe")

PBYTE DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize);
BOOL DosyaYaz(PTSTR szFileName, LPVOID lpData, DWORD dwSize);
void XorEncode(LPBYTE lpbVeri, DWORD dwSize, BYTE bByte);
BOOL ChangeStr(PBYTE pbVeri, DWORD dwSize, PCHAR szOld, PCHAR szNew);
BOOL ChangeByteSeq(PBYTE pbVeri, DWORD dwVeriSize, PBYTE bOld, PBYTE bNew, DWORD dwLen);
void GetRandomCharSeq(PCHAR szData, DWORD dwSize);

void _tmain(int argc, TCHAR* argv[]) {
	BYTE bXorByte = 0;
	PBYTE pbLibVeri = NULL, pbEXEVeri = NULL;
	HANDLE hRsrc = NULL;
	//Kullaným sekli kontrolü
	if (argc < 3) {
		_tprintf(_T("Kullanim Sekli:\n\t %s KaynakDosyaIsmi HedefPEDosyaIsmi\n"), argv[0]);
		return;
	}

	//kaynak dosyayý oku
	DWORD dwLibSize = 0;
	pbLibVeri = DosyaOku(argv[1], &dwLibSize);
	if (dwLibSize == 0) {
		_tprintf(_T("Kaynak dosyadan veri okuma basarisiz oldu: %s.\n"), argv[1]);
		goto temizle;
	}

	//Hedef dosyayý oku
	DWORD dwEXESize = 0;
	pbEXEVeri = DosyaOku(argv[2], &dwEXESize);
	if (dwEXESize == 0) {
		_tprintf(_T("Hedef dosyadan veri okuma basarisiz oldu: %s.\n"), argv[2]);
		goto temizle;
	}

	//_tprintf(_T("Kaynak dosyadan veri okundu.\n"));	
	srand((unsigned)time(NULL));//sadece bir kere çalýþtýrmak lazým

	// stringleri deðiþtir:
	for each (PSTR szKatar in szKatarListesi) {
		// random string üret
		// exe de bul ve yaz
		GetRandomCharSeq(szRandStr, strlen(szKatar));
		BOOL boolLib = ChangeStr(pbLibVeri, dwLibSize, szKatar, szRandStr);
		BOOL boolExe = ChangeStr(pbEXEVeri, dwEXESize, szKatar, szRandStr);
		memcpy_s(szKatar, strlen(szKatar), szRandStr, strlen(szKatar));
		//EncodeStr((PBYTE)pVeri1, dwSize1, (PBYTE)szKatar, strlen(szKatar), (PBYTE)szID, SIFRE_SIZE);
	}

	// þifreleme için gerekli byte i random olarak seç
	//	srand((unsigned)time(NULL));
	bXorByte = (byte)(rand() * 255 + 1);

	// paraloyý da set et
	GetRandomCharSeq(szRandStr, PASSLEN);
	szRandStr[PASSLEN] = 0; //rahat ekrana yazabilmek için 
	printf("%s ", szRandStr);
	XorEncode((LPBYTE)szRandStr, PASSLEN, bXorByte);
	ChangeByteSeq(pbEXEVeri, dwEXESize, bPassword, (PBYTE)szRandStr, PASSLEN);

	//çalýþtýrýldýðý PATH i bulma
	TCHAR szPath[MAX_PATH];
	GetModuleFileName(NULL, szPath, MAX_PATH);
	PTCHAR szProcessName = wcsrchr(szPath, L'\\') + 1;
	*szProcessName = 0; //dosya ismini ayýrmak için

	//hedef dosyalarýn FULL path ini bul
	TCHAR szDscExename[MAX_PATH] = TEXT("");
	StringCbCopy(szDscExename, MAX_PATH, szPath);
	StringCbCat(szDscExename, MAX_PATH, NEWEXENAME);

	if (!DosyaYaz(szDscExename, pbEXEVeri, dwEXESize)) {
		_tprintf(_T("Hedef exe dosya (%s) yazma basarisiz oldu.\n"), NEWEXENAME);
		goto temizle;
	}

	//_tprintf(_T("BeginUpdateResource %s basarili.\n"), DSTFILE);
	//Yeni hedef dosyada update iþlemini baþlat
	hRsrc = BeginUpdateResource(szDscExename, TRUE);

	if (hRsrc == NULL) {
		_tprintf(_T("BeginUpdateResource %s hata: %x \n"), szDscExename, GetLastError());
		goto temizle;
	}

	// lib verisini þifrele
	XorEncode(pbLibVeri, dwLibSize, bXorByte);

	//_tprintf(_T("SifirAtlamaliTekByte XOR Encoding uygulandi.\n"));

	//LPCTSTR szRsrcName = _T("denmee");
	//CHAR * veri = "Merhaba millet";

	// ilk kaynak olarak kaynak dosyanýn þifreli halini hedef dosyaya ekle
	WORD index = 0;
	if (!UpdateResource(hRsrc, RT_RCDATA, MAKEINTRESOURCE(index++), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), pbLibVeri, dwLibSize)) {
		_tprintf(_T("UpdateResource hata: %x \n"), GetLastError());
		goto temizle;
	}

	/*TCHAR szLibname[] = TEXT("mylib.dll");
	CHAR szFuncName[] = "myFunc";
	TCHAR szUserName[] = TEXT("osman");
	CHAR szTablo[28] = "mYuGn.oLp_45qTmLp_45q_.YuGn";
	TCHAR szSubkey[] = TEXT("SOFTWARE\\Odev2Notes");*/

	BYTE bMaxSize = 200;
	BYTE lpVeri2[200];

	// buf temizle 
	ZeroMemory(lpVeri2, bMaxSize);
	DWORD dwSize2 = 0;

	// ilk byte olarak XOR þifresini koy
	lpVeri2[dwSize2++] = bXorByte;

	// lib name i buff a koy, sonuna .dll ekleme
	szLibname[strlen(szLibname) - 4] = 0;
	PCHAR szNewLibName = lstrcatA(szLibname, ".dll");
	lpVeri2[dwSize2++] = strlen(szNewLibName);
	memcpy_s(lpVeri2 + dwSize2, bMaxSize - dwSize2, szNewLibName, lpVeri2[dwSize2 - 1]);
	dwSize2 += lpVeri2[dwSize2 - 1];

	// lib funksiyon ismini buff a koy
	lpVeri2[dwSize2++] = strlen(szFuncName);
	memcpy_s(lpVeri2 + dwSize2, bMaxSize - dwSize2, szFuncName, lpVeri2[dwSize2 - 1]);
	dwSize2 += lpVeri2[dwSize2 - 1];

	/*lpVeri2[dwSize2++] = lstrlen(szUserName) * 2;
	memcpy_s(lpVeri2 + dwSize2, bMaxSize - dwSize2, szUserName, lpVeri2[dwSize2 - 1]);
	dwSize2 += lpVeri2[dwSize2 - 1];*/

	// rasgele tablomuzu üret 28 byte
	GetRandomCharSeq(szTablo, 28);

	// bu tabloyu buff a ekle
	lpVeri2[dwSize2++] = strlen(szTablo);
	memcpy_s(lpVeri2 + dwSize2, bMaxSize - dwSize2, szTablo, lpVeri2[dwSize2 - 1]);
	dwSize2 += lpVeri2[dwSize2 - 1];

	// reg kaydýný buff a ekle
	lpVeri2[dwSize2++] = lstrlen(szSubkey) * 2;
	memcpy_s(lpVeri2 + dwSize2, bMaxSize - dwSize2, szSubkey, lpVeri2[dwSize2 - 1]);
	dwSize2 += lpVeri2[dwSize2 - 1];

	// buff ý þifrele (XOR)
	XorEncode((LPBYTE)(lpVeri2 + 1), dwSize2 - 1, bXorByte);

	// buff i ikinci kaynak olarak hedef EXE ye ekle
	if (!UpdateResourceW(hRsrc, RT_RCDATA, MAKEINTRESOURCE(index++), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), lpVeri2, dwSize2)) {
		_tprintf(_T("UpdateResource hata: %x \n"), GetLastError());
		goto temizle;
	}

	// Write changes to target EXE and then close it.
	if (!EndUpdateResource(hRsrc, FALSE)) {
		_tprintf(TEXT("Could not write changes to file."));
		goto temizle;
	}

	// username ý random olarak deðiþtir


	//_tprintf(_T("KaynakDosya ekleme islemi basarili oldu.\n"));
	//bXorByte //szTablo
	printf("%x %s", bXorByte, szTablo);
	for each (PSTR szKatar in szKatarListesi) {
		// random string üret
		// exe de bul ve yaz
		printf(" %s ", szKatar);
	}

temizle:
	if (pbLibVeri != NULL) free(pbLibVeri);
	if (pbEXEVeri != NULL) free(pbEXEVeri);
	return;
}

PBYTE DosyaOku(PTSTR szFileName, PDWORD pdwFizeSize) {
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HANDLE hFile = NULL;
	DWORD cbRead = 0;
	LARGE_INTEGER fileSize;
	PBYTE pbVeri = NULL;

	hFile = CreateFile(szFileName,
	                   GENERIC_READ,
	                   FILE_SHARE_READ,
	                   NULL,
	                   OPEN_EXISTING,
	                   FILE_FLAG_SEQUENTIAL_SCAN,
	                   NULL);

	if (INVALID_HANDLE_VALUE == hFile) {
		dwStatus = GetLastError();
		_tprintf(_T("Error opening file %s\nError: %d\n"), szFileName,
		         dwStatus);
		goto Temizle;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		dwStatus = GetLastError();
		_tprintf(_T("Error GetFileSizeEx %s\nError: %d\n"), szFileName, dwStatus);
		goto Temizle;
	}

	*pdwFizeSize = fileSize.LowPart;
	pbVeri = (PBYTE)malloc(fileSize.LowPart);


	if (!ReadFile(hFile, pbVeri, fileSize.LowPart, &cbRead, NULL)) {
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		goto Temizle;
	}

Temizle:
	if (hFile != NULL)
		CloseHandle(hFile);

	return pbVeri;
}

BOOL DosyaYaz(PTSTR szFileName, LPVOID lpData, DWORD dwSize) {
	HANDLE hLibFile = NULL;
	BOOL bSuccess = FALSE;
	//DWORD err = 0;

	//yeni dosyayý oluþtur //FILE_ATTRIBUTE_SYSTEM biraz daha saklý olmasý için
	hLibFile = CreateFile(szFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hLibFile == INVALID_HANDLE_VALUE) {
		//err = GetLastError();
		return FALSE;
	}

	DWORD dwWritten = 0;
	if (!WriteFile(hLibFile, lpData, dwSize, &dwWritten, NULL) || dwSize != dwWritten) {
		//err = GetLastError();
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	if (hLibFile) CloseHandle(hLibFile);

	return bSuccess;
}

void XorEncode(LPBYTE lpbVeri, DWORD dwSize, BYTE bByte) {
	for (DWORD i = 0; i < dwSize; i++)
		if (lpbVeri[i] != 0 && lpbVeri[i] != bByte) lpbVeri[i] = lpbVeri[i] ^ bByte;
}

void GetRandomCharSeq(PCHAR szData, DWORD dwSize) {
	const char myBasis_64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
	/* initialize random seed: */
	//srand((unsigned)time(NULL));
	DWORD dwLen = strlen(myBasis_64);

	for (DWORD i = 0; i < dwSize; i++) {
		szData[i] = myBasis_64[rand() % dwLen];
	}

	return;
} // End of main.

BOOL ChangeStr(PBYTE pbVeri, DWORD dwSize, PCHAR szOld, PCHAR szNew) {
	PCHAR szTempName = NULL;//strstr(PCHAR(pbVeri), szOld);
	//BOOL bFound = FALSE;
	DWORD dwLen = strlen(szOld);

	/*	if (dwLen > strlen(szNew)){
	printf("ChangeStr HATA!: Eski katar yeni katardan daha uzun.\n");
	return FALSE;
	}*/

	for (DWORD i = 0; i < dwSize; i++) {
		//bFound = FALSE;
		for (DWORD m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != szOld[m]) break;
			else if (m == dwLen - 1) {
				//bFound = TRUE;
				szTempName = (PCHAR)(pbVeri + i);
				goto found;
			}
		}
	}

	//printf("ChangeStr HATA!: Eski katar bulunamadi: %s.\n", szOld);
	return FALSE;

found:

	/*if (szTempName == NULL){
	_tprintf(_T("Ýlk kaynak dosya için wcsstr basarisiz oldu.\n"));
	return FALSE;
	}*/

	//DWORD szTempSize = strlen(szOld);
	memcpy_s(szTempName, dwLen + 1, szNew, dwLen);

	return TRUE;
}

BOOL ChangeByteSeq(PBYTE pbVeri, DWORD dwVeriSize, PBYTE bOld, PBYTE bNew, DWORD dwLen) {
	PBYTE pTempAdr = NULL;
	DWORD m, i;

	for (i = 0; i < dwVeriSize; i++) {
		for (m = 0; m < dwLen; m++) {
			if (*(pbVeri + i + m) != bOld[m]) break;
		}

		if (m == dwLen) {
			pTempAdr = pbVeri + i;
			break;
		}
	}

	if (pTempAdr == NULL) {
		printf("ChangeStr HATA!: Eski katar bulunamadi!\n");
		return FALSE;
	}

	memcpy_s(pTempAdr, dwLen, bNew, dwLen);

	return TRUE;
}
