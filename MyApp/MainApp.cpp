#include "MainApp.h"
#include <strsafe.h>
#include "../MyDll/mydll.h"

//#pragma comment(lib, "mydll.lib")

//#define LIBNAME TEXT("mylib.dll")
//#define PROCNAME "myFunc"
#define USERNAME "BGM532Ogrencisi" // bu sabit olsun mu? 

CHAR szLibname[20];// = TEXT("mylib.dll");
CHAR szFuncName[20];// = "myFunc";
//TCHAR szUserName[20];// = TEXT("osman");
CHAR szTablo[29];// = "mYuGn.oLp_45qTmLp_45q_.YuGn";
TCHAR szSubkey[50];// = TEXT("SOFTWARE\\Odev2Notes");

BYTE bTheByte = 0;

typedef void (* MyFuncType)(
	_In_      PTSTR szSubkey
);

BOOL DosyaYaz(PSTR szFileName, LPVOID lpData, DWORD dwSize);
LPVOID KaynakGetir(PTSTR szKaynakIsmi, LPDWORD lpdwBoyut);
void XorEncode(LPBYTE lpbVeri, DWORD dwSize, BYTE bByte);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	//mutex icin	
	HANDLE hMutex = NULL;
	//thread icin
	HANDLE hThread = NULL;
	//resource isleri icin
	LPVOID lpResLock = NULL; // pointer to resource data
	DWORD dwSizeOfRes = 0; //size of resource
	//lib yükleme icin
	HMODULE hMyLib = NULL;
	//lib yazma için
	LPBYTE bLibFile = NULL;

	// ilk kontrol kullanýcý ismi kontrolü
	CHAR lpBuffer[40];
	DWORD cbBuffer = 40;
	if (!GetUserNameA(lpBuffer, &cbBuffer))
		goto temizle;
	// eðer beklenen isim deðilse çýk
	if (strcmp(lpBuffer, USERNAME))
		goto temizle;

	// konfigürasyon ayarlarýný resource dan getir
	lpResLock = KaynakGetir(MAKEINTRESOURCE(1), &dwSizeOfRes);
	if (lpResLock == NULL || dwSizeOfRes == 0) {
		goto temizle;
	}

	//ayarlarý çöz
	BYTE bMaxSize = 200;
	BYTE lpVeri[200];
	DWORD dwSize = 0;

	memcpy_s(lpVeri, bMaxSize, lpResLock, dwSizeOfRes);
	lpResLock = NULL;
	// XOR u çözmek için gerekli BYTE
	bTheByte = (BYTE)lpVeri[dwSize++];

	// girilen parolayý kontrol et
	BYTE bPassDen[PASSLEN];
	memcpy_s(bPassDen, PASSLEN, lpCmdLine, PASSLEN);
	XorEncode(bPassDen, PASSLEN, bTheByte);

	for (int i = 0; i < PASSLEN; i++) {
		if (bPassDen[i] != bPassword[i]) {
			MessageBox(NULL, TEXT("Yanlýþ Parola"), TEXT("Uyarý"), MB_OK | MB_ICONERROR);
			goto temizle;
		}
	}

	// MessageBoxA(NULL, lpCmdLine, "Caption", MB_ICONINFORMATION | MB_OK);

	// ilk byte dýþýndaki verileri XOR ile çöz
	XorEncode(lpVeri + 1, bMaxSize - 1, bTheByte);

	/*TCHAR szLibname[20];// = TEXT("mylib.dll");
	CHAR szFuncName[20];// = "myFunc";	
	CHAR szTablo[29];// = "mYuGn.oLp_45qTmLp_45q_.YuGn";
	TCHAR szSubkey[50];// = TEXT("SOFTWARE\\Odev2Notes");*/

	// lib dosya ismini al
	ZeroMemory(szLibname, 20);
	memcpy_s(szLibname, 20, lpVeri + dwSize + 1, lpVeri[dwSize]);
	dwSize += lpVeri[dwSize] + 1;
	//szLibname = lstrcatA(szLibname, ".dll");

	// lib teki function ismini al
	ZeroMemory(szFuncName, 20);
	memcpy_s(szFuncName, 20, lpVeri + dwSize + 1, lpVeri[dwSize]);
	dwSize += lpVeri[dwSize] + 1;

	// random car seq olarak üretilmiþ olan Tablo yu al
	ZeroMemory(szTablo, 29);
	memcpy_s(szTablo, 28, lpVeri + dwSize + 1, lpVeri[dwSize]);
	dwSize += lpVeri[dwSize] + 1;

	// kayýt defteri ismini al
	ZeroMemory(szSubkey, 50 * 2);
	memcpy_s(szSubkey, 50 * 2, lpVeri + dwSize + 1, lpVeri[dwSize]);

	//lib dosyasýný oku
	lpResLock = KaynakGetir(MAKEINTRESOURCE(0), &dwSizeOfRes);
	if (lpResLock == NULL || dwSizeOfRes == 0) {
		goto temizle;
	}

	// decode et	
	bLibFile = (LPBYTE)malloc(dwSizeOfRes);
	memcpy_s(bLibFile, dwSizeOfRes, lpResLock, dwSizeOfRes);
	XorEncode(bLibFile, dwSizeOfRes, bTheByte);

	// yeni dosyaya eldeki verileri (lib dosyasýnýn çözülmüþ hali) yaz
	if (!DosyaYaz(szLibname, bLibFile, dwSizeOfRes)) {
		goto temizle;
	}

	// lib i yükle ve ilgili func i bul
	hMyLib = LoadLibraryA(szLibname);
	if (hMyLib == NULL) {
		//DWORD error = GetLastError();
		//printf("%i\n", error);
		goto temizle;
	}
	// ilgili func ismini bul
	MyFuncType lpMyFunc = (MyFuncType)GetProcAddress(hMyLib, szFuncName);
	if (lpMyFunc == NULL) {
		goto temizle;
	}

	//****************************
	// Mutex olustur
	hMutex = CreateMutexA(NULL, TRUE, MYMUTEX);
	if (hMutex == NULL)
		goto temizle;

	//****************************
	// threadi çalýþtýr
	DWORD dwThreadId = 0;

	hThread = CreateThread(
		NULL, // default security attributes
		0, // use default stack size  
		(LPTHREAD_START_ROUTINE)lpMyFunc, // thread function name
		szSubkey, // argument to thread function //burada reg adresi olacak
		0, // use default creation flags 
		&dwThreadId); // returns the thread identifier 

	//myFunc();
	Sleep(1000);

	//****************************
	HKEY hk;
	DWORD dwDisp;

	//counter registry deðerinin oluþturma iþlemi	
	if (RegCreateKeyEx(SVCHKEY, szSubkey,
	                   0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, &dwDisp))
		goto temizle;

	//ilk deðeri atayalým
	if (RegSetValueExA(hk, // subkey handle 
	                   KEYVALUE, // value name 
	                   0, // must be zero 
	                   REG_SZ, // value type 
	                   (LPBYTE)szTablo, // pointer to value data 
	                   strlen(szTablo) + 1)) // data size
	{
		RegCloseKey(hk);
		goto temizle;
	}

	//reg set islemi bitti
	RegCloseKey(hk);
	//write reg value
	ReleaseMutex(hMutex);
	//thread in de isi bitsin
	WaitForSingleObject(hThread, INFINITE);
	//temizlik islemleri

temizle:
	//lib dosyasýný sil
	if (hMyLib != NULL) {
		FreeLibrary(hMyLib);
		if (!DeleteFileA(szLibname)) {
			//silme iþlemi baþarýsýz
			// DWORD err = GetLastError();
			goto temizle;
		}
	}

	if (bLibFile != NULL)
		free(bLibFile);
	if (hThread != NULL)
		CloseHandle(hThread);
	if (hMutex != NULL)
		CloseHandle(hMutex);
	return 0;
}

BOOL DosyaYaz(PSTR szFileName, LPVOID lpData, DWORD dwSize) {
	HANDLE hLibFile = NULL;
	BOOL bSuccess = FALSE;

	//yeni dosyayý oluþtur
	hLibFile = CreateFileA(szFileName, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_SYSTEM, NULL);
	if (hLibFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD dwWritten = 0;
	if (!WriteFile(hLibFile, lpData, dwSize, &dwWritten, NULL) || dwSize != dwWritten) {
		//DWORD err = GetLastError();
		goto temizle;
	}

	bSuccess = TRUE;

temizle:
	CloseHandle(hLibFile);

	return bSuccess;
}

LPVOID KaynakGetir(PTSTR szKaynakIsmi, LPDWORD pdwBoyut) {
	HGLOBAL hResLoad; // handle to loaded resource	
	HRSRC hRes; // handle/ptr. to res. info. in hExe
	LPVOID lpResLock = NULL; // pointer to resource data

	// Locate the dialog box resource in the .EXE file.
	hRes = FindResource(NULL, szKaynakIsmi, RT_RCDATA);
	if (hRes == NULL) {
		//ErrorHandler(TEXT("Could not locate dialog box."));
		goto temizle;
	}

	// Load the dialog box into global memory.
	hResLoad = LoadResource(NULL, hRes);
	if (hResLoad == NULL) {
		//ErrorHandler(TEXT("Could not load dialog box."));
		goto temizle;
	}

	// Lock the dialog box into global memory.
	lpResLock = LockResource(hResLoad);
	if (lpResLock == NULL) {
		//ErrorHandler(TEXT("Could not lock dialog box."));
		goto temizle;
	}

	//boyutu ogren
	*pdwBoyut = SizeofResource(NULL, hRes);
	if (*pdwBoyut == 0) {
		goto temizle;
	}

temizle:
	return lpResLock;
}

void XorEncode(LPBYTE lpbVeri, DWORD dwSize, BYTE bByte) {
	for (int i = 0; i < dwSize; i++)
		if (lpbVeri[i] != 0 && lpbVeri[i] != bByte) lpbVeri[i] = lpbVeri[i] ^ bByte;
}
