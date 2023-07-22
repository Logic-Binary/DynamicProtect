#include"pch.h"
#include"Dll2.h"
#include<Windows.h>
#include<iostream>

//堆中存放代码段的缓冲区
LPVOID tempAdd = NULL;
//区段首地址
LPVOID sectionAdd = NULL;
//缓冲区大小
DWORD size = NULL;

LONG NTAPI VEH_Handler(_EXCEPTION_POINTERS* ExceptionInfo)
{
	//不是CC断点
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
		
	printf("正在处理异常,EIP:%p\n异常原因是:%08X\n",ExceptionInfo->ContextRecord->Eip,ExceptionInfo->ExceptionRecord->ExceptionCode);
	//测试阶段,先将所有代码段全部还原,
	//memcpy(sectionAdd, tempAdd, *(PDWORD)size);
	//二次测试,将代码段分为三段，每次解密一段，根据EIP来判断现在是在哪段
	DWORD EIP = ExceptionInfo->ContextRecord->Eip;
	
	//手动找到了三个区段 
	//第一个区段 0x411000-0x413000	2000字节
	//第二个区段 0x413000-0x415000	2000字节
	//第三个区段 0x415000-0x416fff	1FFF字节
	DWORD section1 = (DWORD)sectionAdd;
	DWORD section2 = section1 + 0x2000;
	DWORD section3 = section2 + 0x2000;
	//调试信息
	//printf("%p\n", section1);
	//printf("%p\n", section2);
	//printf("%p\n", section3);
	//printf("新码段地址%p\n", tempAdd);
	//system("pause");

	//将原本的整个代码段划分为三个段
	LPVOID test1 = new char[0x2000] {0};
	LPVOID test2 = new char[0x2000] {0};
	LPVOID test3 = new char[0x2000] {0};
	DWORD dwSectionAddress1 = (DWORD)tempAdd;
	memcpy(test1, (LPVOID)dwSectionAddress1, 0x2000);
	DWORD dwSectionAddress2 = dwSectionAddress1 + 0x2000;
	memcpy(test2, (LPVOID)dwSectionAddress2, 0x2000);
	DWORD dwSectionAddress3 = dwSectionAddress2 + 0x2000;
	memcpy(test3, (LPVOID)dwSectionAddress3, 0x1FFF);
	//判断EIP在哪个区段
	if (EIP >= section1 && EIP < section2) {
		//在第一个区段
		//将第一个区段的值给写上，并将其他两个区段写为0xCC
		printf("修复第一个区段\n");
		memcpy((LPVOID)section1, test1, 0x2000);
		memset((LPVOID)section2, 0xCC, 0x2000);
		memset((LPVOID)section3, 0xCC, 0x1FFF);
	}
	else if (EIP >= section2 && EIP < section3) {
		//在第二个区段
		printf("修复第二个区段\n");
		memset((LPVOID)section1, 0xCC, 0x2000);
		memcpy((LPVOID)section2, test2, 0x2000);
		memset((LPVOID)section3, 0xCC, 0x2000);
	}
	else if (EIP >= section3 && EIP < section3 + 0x1FFF) {
		//在第三个区段
		printf("修复第三个区段\n");
		memset((LPVOID)section1, 0xCC, 0x2000);
		memset((LPVOID)section2, 0xCC, 0x2000);
		memcpy((LPVOID)section3, test3, 0x1FFE);
	}
	else {
		//产生错误
		printf("发生了意料之外的错误");
		system("pause");
		ExitProcess(0);
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

void fun() {
	//调试信息
	//MessageBox(0, L"DLL加载成功", L"信息", 0);
	HMODULE hModule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(hModule);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)hModule);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	section_header += file_header->NumberOfSections - 1;
	//新代码段位置
	tempAdd = LPVOID(section_header->VirtualAddress + (DWORD)hModule + 0x1000);
	//代码段大小
	size = section_header->SizeOfRawData;
	//原来代码段的位置
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	sectionAdd = (LPVOID)((section_header + 1)->VirtualAddress + (DWORD)hModule);

	//注册VEH
	AddVectoredExceptionHandler(1, VEH_Handler);
}

void fun1() {
	//仅提供导出意义
	MessageBox(0, L"123", 0, 0);
}