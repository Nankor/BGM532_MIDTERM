#include <windows.h>
#include <strsafe.h>
#define EXPORTING_DLL
#include "mydll.h"

//PTSTR szFileName = L"sifre";
//CHAR szTablo[] = "mYuGn.oLp_45qTmLp_45q_.YuGn";
//BYTE bMod = 11;

PCHAR DosyaOku(PSTR szFileName, PDWORD pdwFileSize);
BOOL RegGetVal(LPBYTE lpData, LPDWORD pcbData, PTSTR szSubkey);
void ShowAlert(PTSTR szAlert);

void myFuncName(PTSTR szSubkey) {
	//ilk önce mutex kontrolü
	//sonra dosya kontrolü
	//sonra dosyanýn içindeki verinin kontrolü

	//CHAR szMutexName[10];
	//StringCchCopyA(szMutexName, 10, szTablo + 10);
	PCHAR szVeri = NULL; //okunacak dosya verisi
	HANDLE hMutex = NULL;

	// mutex hazýr oluþturulmuþ olmasý lazým
	hMutex = OpenMutexA(MUTEX_ALL_ACCESS, FALSE, MYMUTEX);
	if (hMutex == NULL) {
		// DWORD err = GetLastError();
		goto temizle;
	}

	// mutex bize verilene kadar bekle
	WaitForSingleObject(hMutex, INFINITE);

	// keyýt defterinden veriyi oku
	DWORD cbData = 40;
	CHAR szTablo[40];
	if (!RegGetVal((LPBYTE)szTablo, &cbData, szSubkey)) {
		goto temizle;
	}

	CHAR szFileName[10];
	// dosya ismini hesapla 
	StringCchCopyA(szFileName, 10, szTablo);
	DWORD dwFileSize = 0;
	// dosyayý oku
	szVeri = DosyaOku(szFileName, &dwFileSize);
	// dosya okunamadýysa veya içinde veri istenilen sayýda deðilse çýk
	if (dwFileSize == 0) {
		ShowAlert(TEXT("Ýstenilen dosyayý okumada sorun var"));
		goto temizle;
	}
	// yerel zamaný al
	SYSTEMTIME lt;
	GetLocalTime(&lt);
	// yerel zamaný dosya içinde veri ile kontrol et, istenilen formatta deðilse çýk
	if (dwFileSize < 3 || dwFileSize > 20 || strncmp(szVeri + 3, szTablo + 5, 10)) {
		ShowAlert(TEXT("Dosyayýnýn içeriði istenilen formatta deðil"));
		goto temizle;
	}

	//if (szTablo[lt.wDay % dwFileSize] != szVeri[4] || szTablo[lt.wHour % dwFileSize] != szVeri[9])
	//	goto temizle;

	// istenilen formattaysa MessageBox oluþtur
	CHAR szMsg[128];
	sprintf_s(szMsg, "Yerel Tarih: %02d.%02d.%04d %02d:%02d\n%s", lt.wDay, lt.wMonth, lt.wYear, lt.wHour, lt.wMinute, szTablo);
	MessageBoxA(
		NULL,
		szMsg,
		(LPCSTR)"Vizeyi çözme islemi tamamlandi",
		MB_ICONINFORMATION | MB_OK
	);

temizle:
	if (hMutex != NULL)
		CloseHandle(hMutex);
	if (szVeri != NULL)
		free(szVeri);
}

void ShowAlert(PTSTR szAlert) {
	MessageBox(NULL, szAlert, TEXT("Uyarý"), MB_OK | MB_ICONERROR);
}

PCHAR DosyaOku(PSTR szFileName, PDWORD pdwFileSize) {
	DWORD dwStatus = 0;
	HANDLE hFile = NULL;
	DWORD cbRead = 0;
	LARGE_INTEGER fileSize;
	PCHAR veri = NULL;

	hFile = CreateFileA(szFileName,
	                    GENERIC_READ,
	                    FILE_SHARE_READ,
	                    NULL,
	                    OPEN_EXISTING,
	                    FILE_FLAG_SEQUENTIAL_SCAN,
	                    NULL);

	if (INVALID_HANDLE_VALUE == hFile) {
		dwStatus = GetLastError();
		//printf("Error opening file %s\nError: %d\n", szFileName, dwStatus);
		goto Temizle;
	}

	if (!GetFileSizeEx(hFile, &fileSize)) {
		dwStatus = GetLastError();
		//printf("Error GetFileSizeEx %s\nError: %d\n", szFileName, dwStatus);
		goto Temizle;
	}

	*pdwFileSize = fileSize.LowPart;
	veri = (PCHAR)malloc(*pdwFileSize + 1);
	ZeroMemory(veri, *pdwFileSize + 1);

	if (!ReadFile(hFile, veri, fileSize.LowPart, &cbRead, NULL)) {
		dwStatus = GetLastError();
		*pdwFileSize = 0;
		//printf("ReadFile failed: %d\n", dwStatus);
		goto Temizle;
	}

Temizle:
	if (hFile != NULL)
		CloseHandle(hFile);

	return veri;
}

BOOL RegGetVal(LPBYTE lpData, LPDWORD pcbData, PTSTR szSubkey) {
	HKEY hKey;
	BOOL bSuccess = FALSE;
	DWORD err = 0;

	if (err = RegOpenKeyEx(SVCHKEY, szSubkey, 0, KEY_QUERY_VALUE, &hKey)) {
		goto Cleanup;
	}

	//64 bit te düzügn çalýþmýyor mu?
	if (err = RegQueryValueExA(hKey, KEYVALUE, NULL, NULL, lpData, pcbData)) {
		goto Cleanup;
	}

	bSuccess = TRUE;

Cleanup:
	RegCloseKey(hKey);

	return bSuccess;
}
