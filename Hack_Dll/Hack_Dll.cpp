// Hack_Dll.cpp : Defines the initialization routines for the DLL.
//

#include "stdafx.h"
#include "Hack_Dll.h"
#include "Logger.h"

#include <algorithm>
#include <iostream>
#include <PROCESS.H>
#include <psapi.h>

#include <string>
#include <vector>
#include <windows.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

using namespace std;
//
//	Note!
//
//		If this DLL is dynamically linked against the MFC
//		DLLs, any functions exported from this DLL which
//		call into MFC must have the AFX_MANAGE_STATE macro
//		added at the very beginning of the function.
//
//		For example:
//
//		extern "C" BOOL PASCAL EXPORT ExportedFunction()
//		{
//			AFX_MANAGE_STATE(AfxGetStaticModuleState());
//			// normal function body here
//		}
//
//		It is very important that this macro appear in each
//		function, prior to any calls into MFC.  This means that
//		it must appear as the first statement within the 
//		function, even before any object variable declarations
//		as their constructors may generate calls into the MFC
//		DLL.
//
//		Please see MFC Technical Notes 33 and 58 for additional
//		details.
//

/////////////////////////////////////////////////////////////////////////////
// CHack_DllApp

BEGIN_MESSAGE_MAP(CHack_DllApp, CWinApp)
//{{AFX_MSG_MAP(CHack_DllApp)
// NOTE - the ClassWizard will add and remove mapping macros here.
//    DO NOT EDIT what you see in these blocks of generated code!
//}}AFX_MSG_MAP
END_MESSAGE_MAP()

//Get all module related info, this will include the base DLL. 
//and the size of the module
MODULEINFO GetModuleInfo( char *szModule )
{
	MODULEINFO modinfo = {0};
	HMODULE hModule = GetModuleHandle(szModule);
	if(hModule == 0) 
		return modinfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
	return modinfo;
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

void readProcessMemory_1()
{
	try
	{
		/*
		log_inform(L"Timer Log");
		CString strHeaders = _T("Content-Type: application/x-www-form-urlencoded");
		LPCTSTR pstrServer = _T("192.168.2.27");
		INTERNET_PORT nPort = 80;
		CInternetSession session(_T("MySession"));
		CString strFormData = _T("command=save_inject_data&IP_Address=192.168.2.27&HWID=1231231231231231231&Pattern=1123412341234");
		
		CHttpConnection *pConnection = session.GetHttpConnection(pstrServer, nPort, NULL, NULL);
		
		CHttpFile *pFile = pConnection->OpenRequest(CHttpConnection::HTTP_VERB_POST, _T("/Dll_Inject_Server/api/index.php"));
		pFile->AddRequestHeaders(strHeaders);
		BOOL result = pFile->SendRequest(strHeaders, (LPVOID) (LPCTSTR) strFormData, strFormData.GetLength());
		
		DWORD dwRet;
		pFile->QueryInfoStatusCode(dwRet);
		char szBuff[1024];
		CString out;
		if (dwRet == HTTP_STATUS_OK)
		{
			UINT nRead = pFile->Read(szBuff, 1023);
			while (nRead > 0)
			{
				//read file...
				out = CString(szBuff);
				break;
			}
		}
		
		session.Close();
		*/
		
		HANDLE hProcess = GetCurrentProcess();
		if (!hProcess) {
			log_error(L"Invalid process handle");
			return;
		}

		HMODULE hModule = ::GetModuleHandle("notepad.exe");
		if (!hModule) {
			log_error(L"Didn't find Base Address!");
			return;
		}

		MODULEINFO minfo;
		
		if (!::GetModuleInformation( hProcess, hModule, (LPMODULEINFO)(&minfo), sizeof( minfo ) )) {
			log_error(L"GetModuleInformation Failed");
			return;
		}

		DWORD image_size = minfo.SizeOfImage;
		LPVOID base_address = minfo.lpBaseOfDll;
		log_inform(L"BaseAddress: 0X%x, SizeOfImage: %d", base_address, image_size);

/*			offset += 255;
		char *cur_p = static_cast<char*>(minfo.lpBaseOfDll) + offset;
		log_inform(L"address 0x%x", (LPVOID)cur_p);
		nRead += 255;
		continue;
*/
		// Read all process memory
		log_inform(L"Process memory begin..........");

		image_size = 4096;
		char* buf = new char[image_size];
		char* msg = new char[image_size];
		DWORD nRead = 0;

		if (!ReadProcessMemory(hProcess, base_address, buf, image_size, &nRead)) {
			log_error(L"ReadProcessMemory Failed");
		} else {
			for (DWORD i = 0; i < nRead; i++)
			{
				sprintf(msg, "%s 0X%x", msg, buf[i]);
			}
		}
		
		delete[] msg;
		delete[] buf;

		string m_msg(msg);
		wstring w_msg = string2wstring(m_msg);

		log_inform(L"%s", w_msg.c_str());
		log_inform(L"Process memory end..........");
	}
	catch (CMemoryException*)
	{
		log_error(L"MemoryException");
	}
	catch (CFileException*)
	{
		log_error(L"FileException");
	}
	catch (CException*)
	{
		log_error(L"UnknownException");
	}
}

void readProcessMemory_2()
{
	//FARPROC pFunc;
	DWORD dwOldProtect;
	
	try
	{
		log_inform(L"Starting dump module.....\n");
		DWORD pid = GetCurrentProcessId();
		log_inform(L"Open process.....\n");
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
		if (!hProcess) {
			log_error(L"Invalid process handle");
			return;
		}

		log_inform(L"Get module handle.....\n");
		HMODULE hModule = GetModuleHandle(NULL);
		if (!hModule) {
			log_error(L"Didn't find Base Address!");
			return;
		}

		log_inform(L"Get module information.....\n");
		// Get all module related information
		MODULEINFO mInfo = GetModuleInfo("notepad.exe");
		
		DWORD image_size = mInfo.SizeOfImage;
		LPVOID base_address = mInfo.lpBaseOfDll/*(LPVOID)hModule*/;
		log_inform(L"BaseAddress: 0X%x, SizeOfImage: %d", base_address, image_size);
		
		DWORD offset = 0;				
		
		FILE* fd = fopen("C:\\procdump.txt", "w");
		if (fd != NULL) {
			while (offset < image_size) {
				// Read all process memory
				log_inform(L"Process memory reading..........\n");
				
				DWORD buf_size = min(1024, image_size - offset);
				if (buf_size <= 0) {
					break;
				}
				
				log_inform(L"Handling memory offset 0X%x buffer size %d", offset, buf_size);
				
				char* buf = new char[buf_size];
				memset(buf, 0, buf_size);
				
				log_inform(L"Set virtual protect settings..........\n");
				// Add memory write attribute 
				VirtualProtect((LPVOID)((char*)base_address + offset), buf_size, PAGE_EXECUTE_READ, &dwOldProtect);
				
				log_inform(L"Dump memory.....\n");
				memcpy(buf, (LPVOID)((char*)base_address + offset), buf_size);
				
				log_inform(L"Restore virtual protect settings..........\n");
				// Restore memory attribute
				VirtualProtect((LPVOID)((char*)base_address + offset), buf_size, dwOldProtect, &dwOldProtect);
				
				log_inform(L"Writing into file.....\n");
				fwrite(buf, sizeof(char), buf_size, fd);
				delete[] buf;
				offset += buf_size;
			}				
			fclose(fd);
		}
		
		CloseHandle(hProcess);
		log_inform(L"dump module finished.....\n");
	}
	catch (CMemoryException*)
	{
		log_error(L"MemoryException");
	}
	catch (CFileException*)
	{
		log_error(L"FileException");
	}
	catch (CException*)
	{
		log_error(L"UnknownException");
	}
}

/////////////////////////////////////////////////////////////////////////////
// CHack_DllApp construction
void Thread_Proc(void *param){
	while (TRUE)
	{
		//readProcessMemory_1();
		readProcessMemory_2();
		
		Sleep(10000);
	}
}

CHack_DllApp::CHack_DllApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
	log_inform(L"Hack_Dll Injection Success!");
	// change privilege
	SetPrivilege(SE_DEBUG_NAME, TRUE);
	_beginthread(Thread_Proc, 0, NULL);
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CHack_DllApp object

CHack_DllApp theApp;
