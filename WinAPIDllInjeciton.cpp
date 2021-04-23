// Copyright 2020 Kaizen Cyber Ops LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#define CREATE_PROC_FUNC_NAME "_HookCreateProcessA@40"
#define WRITE_MEM_FUNC_NAME "_HookedWriteProcessMemory@20"

#define ALLTHREADS 0

//easy method to unhook from winapi when done

BOOL unhook(HHOOK h)
{
	printf("hooked globally.  All new process will be injected. press enter to stop");
	getchar();
	return UnhookWindowsHookEx(h);

}

/*
	https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa

	HHOOK SetWindowsHookExA(
	int       idHook,
	HOOKPROC  lpfn,
	HINSTANCE hmod,
	DWORD     dwThreadId
	);

	We will use these constants:
		int idHook = WH_CALLWNDPROC;  // WH_CALLWNDPROC=0x4

*/
int main()
{
	char* pPath = new char[MAX_PATH];
	char fname[] = "Dll-Inject.dll";     // You dll to inject goes here
	GetModuleFileNameA(0, pPath, MAX_PATH);
	pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
	lstrcatA(pPath, fname);


	HMODULE dll = LoadLibrary(pPath);  //load the dll we will be injecting into running processes
	if (dll == NULL)
	{
		printf("failed locating the dll");
		return EXIT_FAILURE;
	}


	HOOKPROC addr2 = (HOOKPROC)GetProcAddress(dll, CREATE_PROC_FUNC_NAME);  //get the address of the function to be injected from the dll
	if (addr2 == NULL)
	{
		printf("The function was not found");
		return EXIT_FAILURE;
	}


	HOOKPROC addr = (HOOKPROC)GetProcAddress(dll, WRITE_MEM_FUNC_NAME);	//get address of the rewritten writeprocessmemory
	if (addr == NULL)
	{
		printf("The function was not found");
		return EXIT_FAILURE;
	}

	HHOOK handle = SetWindowsHookEx(WH_CALLWNDPROC, addr, dll, ALLTHREADS);	//hook writeprocessmemory
	if (handle == NULL)
	{
		printf("Unable to hook.  (RUNAS admin?)");
		return EXIT_FAILURE;
	}
	HHOOK handle2 = SetWindowsHookEx(WH_CALLWNDPROC, addr2, dll, ALLTHREADS);//hook createprocess
	if (handle2 == NULL)
	{
		printf("Unable to hook.  (RUNAS admin?)");
		return EXIT_FAILURE;
	}


	//comment out this next line if you want the program to hook and quit, with no option to unhook.
	unhook(handle);

	printf("shutting down");
	return EXIT_SUCCESS;

}
