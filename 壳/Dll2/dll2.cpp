#include"pch.h"
#include"Dll2.h"
#include<Windows.h>
#include<iostream>

//���д�Ŵ���εĻ�����
LPVOID tempAdd = NULL;
//�����׵�ַ
LPVOID sectionAdd = NULL;
//��������С
DWORD size = NULL;

LONG NTAPI VEH_Handler(_EXCEPTION_POINTERS* ExceptionInfo)
{
	//����CC�ϵ�
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
		
	printf("���ڴ����쳣,EIP:%p\n�쳣ԭ����:%08X\n",ExceptionInfo->ContextRecord->Eip,ExceptionInfo->ExceptionRecord->ExceptionCode);
	//���Խ׶�,�Ƚ����д����ȫ����ԭ,
	//memcpy(sectionAdd, tempAdd, *(PDWORD)size);
	//���β���,������η�Ϊ���Σ�ÿ�ν���һ�Σ�����EIP���ж����������Ķ�
	DWORD EIP = ExceptionInfo->ContextRecord->Eip;
	
	//�ֶ��ҵ����������� 
	//��һ������ 0x411000-0x413000	2000�ֽ�
	//�ڶ������� 0x413000-0x415000	2000�ֽ�
	//���������� 0x415000-0x416fff	1FFF�ֽ�
	DWORD section1 = (DWORD)sectionAdd;
	DWORD section2 = section1 + 0x2000;
	DWORD section3 = section2 + 0x2000;
	//������Ϣ
	//printf("%p\n", section1);
	//printf("%p\n", section2);
	//printf("%p\n", section3);
	//printf("����ε�ַ%p\n", tempAdd);
	//system("pause");

	//��ԭ������������λ���Ϊ������
	LPVOID test1 = new char[0x2000] {0};
	LPVOID test2 = new char[0x2000] {0};
	LPVOID test3 = new char[0x2000] {0};
	DWORD dwSectionAddress1 = (DWORD)tempAdd;
	memcpy(test1, (LPVOID)dwSectionAddress1, 0x2000);
	DWORD dwSectionAddress2 = dwSectionAddress1 + 0x2000;
	memcpy(test2, (LPVOID)dwSectionAddress2, 0x2000);
	DWORD dwSectionAddress3 = dwSectionAddress2 + 0x2000;
	memcpy(test3, (LPVOID)dwSectionAddress3, 0x1FFF);
	//�ж�EIP���ĸ�����
	if (EIP >= section1 && EIP < section2) {
		//�ڵ�һ������
		//����һ�����ε�ֵ��д�ϣ�����������������дΪ0xCC
		printf("�޸���һ������\n");
		memcpy((LPVOID)section1, test1, 0x2000);
		memset((LPVOID)section2, 0xCC, 0x2000);
		memset((LPVOID)section3, 0xCC, 0x1FFF);
	}
	else if (EIP >= section2 && EIP < section3) {
		//�ڵڶ�������
		printf("�޸��ڶ�������\n");
		memset((LPVOID)section1, 0xCC, 0x2000);
		memcpy((LPVOID)section2, test2, 0x2000);
		memset((LPVOID)section3, 0xCC, 0x2000);
	}
	else if (EIP >= section3 && EIP < section3 + 0x1FFF) {
		//�ڵ���������
		printf("�޸�����������\n");
		memset((LPVOID)section1, 0xCC, 0x2000);
		memset((LPVOID)section2, 0xCC, 0x2000);
		memcpy((LPVOID)section3, test3, 0x1FFE);
	}
	else {
		//��������
		printf("����������֮��Ĵ���");
		system("pause");
		ExitProcess(0);
	}
	return EXCEPTION_CONTINUE_EXECUTION;
}

void fun() {
	//������Ϣ
	//MessageBox(0, L"DLL���سɹ�", L"��Ϣ", 0);
	HMODULE hModule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(hModule);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)hModule);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	section_header += file_header->NumberOfSections - 1;
	//�´����λ��
	tempAdd = LPVOID(section_header->VirtualAddress + (DWORD)hModule + 0x1000);
	//����δ�С
	size = section_header->SizeOfRawData;
	//ԭ������ε�λ��
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	sectionAdd = (LPVOID)((section_header + 1)->VirtualAddress + (DWORD)hModule);

	//ע��VEH
	AddVectoredExceptionHandler(1, VEH_Handler);
}

void fun1() {
	//���ṩ��������
	MessageBox(0, L"123", 0, 0);
}