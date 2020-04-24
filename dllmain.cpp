// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include "psapi.h"

#include <vector>
#include <fstream>



#define STR_MODULE_NAME					    "GlobalHooking.dll"
// #define STR_MODULE_NAME					    "myhack.dll"
#define STR_HIDE_PROCESS_NAME			    "notepad.exe"
#define STR_LOG_FILE_PATH				    "I:\\07-ReversingWork\\logs\\client.log"
#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;


using namespace std;

void send_log(const char *msg);
std::string to_string(int x);
void init_readfile_filter_list();

HINSTANCE g_hInstance = NULL;
HHOOK g_hMouseHook = NULL;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	BYTE Reserved1[52];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI *PFZWQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef BOOL(WINAPI *PFCREATEPROCESSA)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI *PFCREATEPROCESSW)(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

typedef BOOL(WINAPI* PFREADFILE)(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
	);

typedef BOOL(WINAPI* PFREADFILEEX)(
	HANDLE                          hFile,
	LPVOID                          lpBuffer,
	DWORD                           nNumberOfBytesToRead,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);

BYTE g_pOrgCPA[5] = { 0, };
BYTE g_pOrgCPW[5] = { 0, };
BYTE g_pOrgZwQSI[5] = { 0, };

std::vector<std::string> g_filter_list;

BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
	PBYTE pByte;

	// 후킹대상 API 주소를 구한다
	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;

	// 만약 이미 후킹되어 있다면 return FALSE
	if (pByte[0] == 0xE9)
		return FALSE;

	// 5 byte 패치를 위하여 메모리에 WRITE 속성 추가
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// 기존코드 (5 byte) 백업
	memcpy(pOrgBytes, pFunc, 5);

	// JMP 주소계산 (E9 XXXX)
	// => XXXX = pfnNew - pfnOrg - 5
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	// Hook - 5 byte 패치(JMP XXXX)
	memcpy(pFunc, pBuf, 5);

	// 메모리 속성 복귀
	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if (pByte[0] != 0xE9)
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,             // lookup privilege on local system
		lpszPrivilege,    // privilege to lookup 
		&luid))          // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

BOOL InjectDll2(HANDLE hProcess, LPCSTR szDllName)
{

	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = strlen(szDllName) + 1;
	FARPROC pThreadProc;
	char NAME_BUFFER[MAX_PATH];
	char MSG_STR[255];


	memset(NAME_BUFFER, 0, 255);
	GetModuleFileNameExA(hProcess, 0, NAME_BUFFER, MAX_PATH);

	memset(MSG_STR, 0, 255);
	sprintf_s(MSG_STR, "ModuleName : %s", NAME_BUFFER);
	MessageBoxA(NULL, MSG_STR, "Status", 0);

	send_log(MSG_STR);
	return TRUE;
	
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
		MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
		return FALSE;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName,
		dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"),
		"LoadLibraryA");
	hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pThreadProc,
		pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}

NTSTATUS WINAPI NewZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
	char szProcName[MAX_PATH] = { 0, };

	unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", g_pOrgZwQSI);

	pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"),
		"ZwQuerySystemInformation");
	status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
		(SystemInformationClass, SystemInformation,
			SystemInformationLength, ReturnLength);

	if (status != STATUS_SUCCESS)
		goto __NTQUERYSYSTEMINFORMATION_END;

	if (SystemInformationClass == SystemProcessInformation)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		pPrev = pCur;

		while (TRUE)
		{
			WideCharToMultiByte(CP_ACP, 0, (PWSTR)pCur->Reserved2[1], -1,
				szProcName, MAX_PATH, NULL, NULL);

			if (!_strcmpi(szProcName, STR_HIDE_PROCESS_NAME))
			{
				if (pCur->NextEntryOffset == 0)
					pPrev->NextEntryOffset = 0;
				else
					pPrev->NextEntryOffset += pCur->NextEntryOffset;
			}
			else
				pPrev = pCur;	// 盔窍绰 橇肺技胶甫 给 茫篮 版快父 pPrev 技泼

			if (pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
		}
	}

__NTQUERYSYSTEMINFORMATION_END:

	hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
		(PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);

	return status;
}

BOOL WINAPI MyReadFile(
	HANDLE		hFile,
	LPVOID		lpBuffer,
	DWORD		nNumberOfBytesToRead,
	LPDWORD		lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped
) {
	BOOL bRet;
	FARPROC pFunc;
	DWORD dwRet;
	char NAME_BUFFER[MAX_PATH];
	


	// unhook.
	unhook_by_code("kernel32.dll", "ReadFile", g_pOrgCPA);
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFile");
	bRet = ((PFREADFILE)pFunc)(
		hFile,
		lpBuffer,
		nNumberOfBytesToRead,
		lpNumberOfBytesRead,
		lpOverlapped);

	if (bRet)
	{
		

		dwRet = GetFinalPathNameByHandleA(hFile, NAME_BUFFER, MAX_PATH, VOLUME_NAME_NT);
		if (dwRet < MAX_PATH)
		{
			

			std::string name_string(NAME_BUFFER);

			BOOLEAN bExist = FALSE;
			for (int idx = 0; idx < g_filter_list.size(); idx++)
			{
				if (name_string.find(g_filter_list[idx]) != std::string::npos)
				{
					bExist = TRUE;
					break;
				}
			}

			if (bExist == FALSE)
			{
				send_log("ReadFile Hook working...");
				send_log(NAME_BUFFER);
			}
		}
	}

	// hook
	hook_by_code("kernel32.dll", "ReadFile",
		(PROC)MyReadFile, g_pOrgCPA);

	return bRet;

}

BOOL WINAPI MyReadFileEx(
	HANDLE                          hFile,
	LPVOID                          lpBuffer,
	DWORD                           nNumberOfBytesToRead,
	LPOVERLAPPED                    lpOverlapped,
	LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
	BOOL bRet;
	FARPROC pFunc;
	char NAME_BUFFER[MAX_PATH];

	// unhook.
	unhook_by_code("kernel32.dll", "ReadFileEx", g_pOrgCPA);
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ReadFileEx");
	bRet = ((PFREADFILEEX)pFunc)(
		hFile,
		lpBuffer,
		nNumberOfBytesToRead,
		lpOverlapped,
		lpCompletionRoutine);

	if (bRet)
	{
		send_log("ReadFileEx Hook working...");
	}

	// hook
	hook_by_code("kernel32.dll", "ReadFileEx",
		(PROC)MyReadFileEx, g_pOrgCPA);

	return bRet;
}

BOOL WINAPI NewCreateProcessA(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;
	char NAME_BUFFER[MAX_PATH];

	// unhook
	unhook_by_code("kernel32.dll", "CreateProcessA", g_pOrgCPA);

	// original API 龋免
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
	bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	if (bRet)
	{

		InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);
	}
		

	// hook
	hook_by_code("kernel32.dll", "CreateProcessA",
		(PROC)NewCreateProcessA, g_pOrgCPA);

	return bRet;
}

BOOL WINAPI NewCreateProcessW(
	LPCTSTR lpApplicationName,
	LPTSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCTSTR lpCurrentDirectory,
	LPSTARTUPINFO lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
)
{
	BOOL bRet;
	FARPROC pFunc;
	char NAME_BUFFER[255];

	// unhook
	unhook_by_code("kernel32.dll", "CreateProcessW", g_pOrgCPW);

	// original API 龋免
	pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
	bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation);

	if (bRet)
	{
		//memset(NAME_BUFFER, 0, 255);
		//GetModuleFileNameExA(lpProcessInformation->hProcess, 0, NAME_BUFFER, MAX_PATH);

		//string module_path(NAME_BUFFER);
		//std:size_t pos = module_path.find("DNF.exe");
		//if (pos != std::string::npos)
		//{
		//	InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);
		//}

	}
		

	// hook
	hook_by_code("kernel32.dll", "CreateProcessW",
		(PROC)NewCreateProcessW, g_pOrgCPW);

	return bRet;
}



LRESULT CALLBACK MouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {

	

	if (nCode >= 0 && wParam == WM_MOUSEMOVE) {
		MSLLHOOKSTRUCT* mh = (MSLLHOOKSTRUCT*)lParam;

		std::string log_str = "Mouse Event ======> X : " + to_string(mh->pt.x) + "\tY : " + to_string(mh->pt.y);
		send_log(log_str.c_str());

	}
	// return CallNextHookEx(NULL, nCode, wParam, lParam);
	return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

void ProcMouseHookModule()
{

	SYSTEMTIME systime;
	char day[32];
	char date_string[255];

	GetLocalTime(&systime);
	memset(day, 0, 32);
	memset(date_string, 0, 255);

	switch (systime.wDayOfWeek)
	{
	case 0:
		strcpy_s(day, "Sunday");
		break;
	case 1:
		strcpy_s(day, "Monday");
		break;
	case 2:
		strcpy_s(day, "Tuesday");
		break;
	case 3:
		strcpy_s(day, "Wednesday");
		break;
	case 4:
		strcpy_s(day, "Thursday");
		break;
	case 5:
		strcpy_s(day, "Friday");
		break;
	case 6:
		strcpy_s(day, "Saturday");
		break;
	}
	sprintf_s(date_string, "Analyze log started....\t%s %u/%u/%u  %u:%u\n", day,
		systime.wYear, systime.wMonth, systime.wDay,
		systime.wHour, systime.wMinute);
	send_log(date_string);
	
	if (!(g_hMouseHook = SetWindowsHookExA(WH_MOUSE_LL, MouseHookProc, g_hInstance, NULL)))
	{
		send_log("Failed to install mouse hook!");
	}
	else
		send_log("Success to install mouse hook!");
	

}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	char            szCurProc[MAX_PATH] = { 0, };
	char            *p = NULL;

	// change privilege
	SetPrivilege(SE_DEBUG_NAME, TRUE);

	init_readfile_filter_list();

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:

		hook_by_code("kernel32.dll", "ReadFile",
			(PROC)MyReadFile, g_pOrgCPA);
		//hook_by_code("kernel32.dll", "ReadFileEx",
		//	(PROC)MyReadFileEx, g_pOrgCPA);
		//hook_by_code("kernel32.dll", "CreateProcessA",
		//	(PROC)NewCreateProcessA, g_pOrgCPA);
		//hook_by_code("kernel32.dll", "CreateProcessW",
		//	(PROC)NewCreateProcessW, g_pOrgCPW);
		//hook_by_code("ntdll.dll", "ZwQuerySystemInformation",
		//	(PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);
		g_hInstance = hinstDLL;
		break;

	case DLL_PROCESS_DETACH:
		// unhook

		unhook_by_code("kernel32.dll", "ReadFile",
			g_pOrgCPA);
		//unhook_by_code("kernel32.dll", "ReadFileEx",
		//	g_pOrgCPA);
		//unhook_by_code("kernel32.dll", "CreateProcessA",
		//	g_pOrgCPA);
		//unhook_by_code("kernel32.dll", "CreateProcessW",
		//	g_pOrgCPW);
		//unhook_by_code("ntdll.dll", "ZwQuerySystemInformation",
		//	g_pOrgZwQSI);
		break;
	}

	return TRUE;
}

void init_readfile_filter_list() {
	g_filter_list.push_back(".png");
}

void send_log(const char *msg)
{
	fstream log_file;
	log_file.open(STR_LOG_FILE_PATH, std::fstream::app);
	log_file << msg << endl;
	log_file.close();
}


std::string to_string(int x) {
	int length = snprintf(NULL, 0, "%d", x);
	char* buf = new char[length + 1];
	snprintf(buf, length + 1, "%d", x);
	std::string str(buf);
	delete[] buf;
	return str;
}



