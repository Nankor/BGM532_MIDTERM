#pragma once

#ifdef EXPORTING_DLL
extern "C" __declspec(dllexport) void myFuncName(PTSTR szSubkey);
//#else
//extern __declspec(dllimport) void myFunc(PTSTR szSubkey);
#endif

#define	KEYVALUE	"KEYNOTE" // bununda random olmas� laz�m
#define SVCHKEY		HKEY_CURRENT_USER
#define MYMUTEX		"MYMUTEX" // bununda random olmas� laz�m