#include"Shell.h"

extern TCHAR srcName[256] = { 0 };
extern TCHAR shellName[256] = { 0 };
TCHAR PEName[256] = { 0 };
DWORD textSectionSize = 0;


VOID getPath() {
	setlocale(LC_ALL, "");
	printf("������Ҫ���ܵĳ���·��\n");
	_tscanf_s(_T("%s"), srcName, 256);
	printf("������ǳ���·��\n");
	_tscanf_s(_T("%s"), shellName, 256);
	printf("������ӿǺ���ļ���\n");
	_tscanf_s(_T("%s"), PEName, 256);
}

BOOL moveCode() {
	HANDLE hFile1 = CreateFile(srcName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile1 == INVALID_HANDLE_VALUE) {
		printf("Դ�ļ���ʧ��\n");
		return FALSE;
	}
	DWORD size = GetFileSize(hFile1, NULL);
	LPVOID srcBuf = new CHAR[size]{ 0 };
	DWORD readSize = 0;
	DWORD err_t = ReadFile(hFile1, srcBuf, size, &readSize, NULL);
	if (!err_t) {
		printf("Դ�ļ���ȡʧ��\n");
		return FALSE;
	}
	//��PE�����ڣ��ƶ������
	LPVOID newBuf = PEAddSection(srcBuf, size);
	size += (0x1000 + textSectionSize);

	encry(newBuf, size);
	HANDLE hFile2 = CreateFile(shellName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile2 == INVALID_HANDLE_VALUE) {
		printf("���ļ���ʧ��\n");
		return FALSE;
	}
	DWORD shellSize = GetFileSize(hFile2, NULL);
	LPVOID shellBuf = new CHAR[shellSize]{ 0 };
	err_t = ReadFile(hFile2, shellBuf, shellSize, &readSize, NULL);
	if (!err_t) {
		printf("���ļ���ȡʧ��\n");
		return FALSE;
	}

	HANDLE hFile3 = addSection((DWORD)shellBuf, shellSize, size);
	DWORD writeSize = 0;
	WriteFile(hFile3, newBuf, size, &writeSize, NULL);

	if (srcBuf != NULL) {
		delete[] srcBuf;
		srcBuf = NULL;
	}
	return TRUE;
}

//������
VOID encry(LPVOID srcBuf, DWORD size) {
	for (DWORD i = 0; i < size; i++) {
		((PCHAR)srcBuf)[i] = ((PCHAR)srcBuf)[i] ^ 2;
	}
}

//���ǳ�����ӽ� �������ļ�
HANDLE addSection(DWORD buf, DWORD shellSzie, DWORD srcSize) {
	if (!buf) {
		printf("�ǳ��򻺳�������ȷ\n");
		return FALSE;
	}

	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//��PE����ǰ�Ƹ���dos_stub
	DWORD dos_stub_size = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	//���dos_stub�ļ�����40�ֽڣ�����Ҫ�ϲ����������ӽڵ�����
	if (dos_stub_size < 0x28) {
		//�ϲ���
		//..........
		return (HANDLE)-1;
	}
	//��ȡdosͷ��С
	dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	DWORD all_sections_size = file_header->NumberOfSections * 0x28;
	//��ȥdosͷ����ͷ���Ĵ�С
	DWORD all_headers_size = sizeof(IMAGE_NT_HEADERS) + all_sections_size;
	memcpy(LPVOID(buf + sizeof(IMAGE_DOS_HEADER)), nt_header, all_headers_size);
	//�м䲿����Ϊ0
	memset(LPVOID(buf + sizeof(IMAGE_DOS_HEADER) + all_headers_size), 0, dos_stub_size);

	nt_header = PIMAGE_NT_HEADERS(buf + dos_header->e_lfanew);
	file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	srcSize = Align(srcSize, option_header->FileAlignment);

	//C0000040 data������ �����½�
	IMAGE_SECTION_HEADER new_section = { 0 };
	CHAR section_name[8] = ".msvcjs";
	memcpy(new_section.Name, section_name, 8);
	new_section.Misc.VirtualSize = srcSize;
	new_section.SizeOfRawData = srcSize;
	//���һ���ڵ�RVA+�ļ���С,�ڴ����� = �½ڵ�RVA
	PIMAGE_SECTION_HEADER last_section = section_header + file_header->NumberOfSections - 1;
	new_section.VirtualAddress = Align(DWORD(last_section->VirtualAddress + last_section->SizeOfRawData), option_header->SectionAlignment);
	//�½ڵ�FOA
	new_section.PointerToRawData = Align(DWORD(last_section->PointerToRawData + last_section->SizeOfRawData), option_header->FileAlignment);
	//�½ڵ�����
	new_section.Characteristics = 0xC0000040;
	//���ڵ���Ϣд��buf��
	memcpy(LPVOID(++last_section), &new_section, 0x28);

	//һЩ������Ϣ
	file_header->NumberOfSections += 1;
	srcSize = Align(srcSize, option_header->SectionAlignment);
	option_header->SizeOfImage += srcSize;

	TCHAR tempName[256] = _T("C:\\Users\\�޼�\\Desktop\\");
	_tcscat_s(tempName, 256, PEName);
	//�Ͻ�һЩ�����ж�Դ�ļ���ʲô����pe������ֱ�����û��Լ�����
	_tcscat_s(tempName, 256, _T(".exe"));
	HANDLE hFile = CreateFile(tempName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD writeSize = 0;
	WriteFile(hFile, (LPVOID)buf, shellSzie, &writeSize, NULL);

	return hFile;
}

//��ȡ������ֵ
DWORD Align(DWORD address, DWORD ratio) {
	if (address / ratio == 0) {
		return ratio;
	}
	if (address % ratio == 0) {
		return (address / ratio) * ratio;
	}
	else {
		return (address / ratio + 1) * ratio;
	}
}

//RVAתFOA
DWORD RVA2FOA(LPVOID buf, LPVOID RVA) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);

	if ((DWORD)RVA < section_header->VirtualAddress) {
		return (DWORD)RVA;
	}

	for (int i = 0; i < file_header->NumberOfSections; i++) {
		if ((DWORD)RVA >= section_header->VirtualAddress &&
			(DWORD)RVA < section_header->VirtualAddress + section_header->SizeOfRawData) {
			return ((DWORD)RVA - section_header->VirtualAddress + section_header->PointerToRawData);
		}
		section_header++;
	}
	return 0;
}

//��PE������,�ƶ������,�ƶ������
LPVOID PEAddSection(LPVOID oldBuf, DWORD size) {
	if (!oldBuf) {
		printf("�ǳ��򻺳�������ȷ\n");
		return FALSE;
	}
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(oldBuf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)oldBuf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	PIMAGE_SECTION_HEADER section_header_text = section_header;
	//����δ�С
	section_header_text++;
	DWORD section_text_size = section_header_text->SizeOfRawData;
	section_text_size = Align(section_text_size, 0x1000);

	LPVOID newBuf = new char[size + 0x1000 + section_text_size] {0};
	memcpy(newBuf, oldBuf, size);

	dos_header = PIMAGE_DOS_HEADER(newBuf);
	nt_header = PIMAGE_NT_HEADERS((DWORD)newBuf + dos_header->e_lfanew);
	file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));


	//�����½���Ϣ
	IMAGE_SECTION_HEADER new_section = { 0 };
	CHAR section_name[8] = ".msvcjs";
	memcpy(new_section.Name, section_name, 8);
	new_section.Misc.VirtualSize = 0x1000 + section_text_size;
	new_section.SizeOfRawData = 0x1000 + section_text_size;

	//���һ���ڵ�RVA+�ļ���С,�ڴ����� = �½ڵ�RVA
	PIMAGE_SECTION_HEADER last_section = section_header + file_header->NumberOfSections - 1;
	new_section.VirtualAddress = Align(DWORD(last_section->VirtualAddress + last_section->SizeOfRawData), option_header->SectionAlignment);
	//�½ڵ�FOA
	new_section.PointerToRawData = Align(DWORD(last_section->PointerToRawData + last_section->SizeOfRawData), option_header->FileAlignment);
	//�½ڵ�����
	new_section.Characteristics = 0xC0000040;
	//���ڵ���Ϣд��buf��
	memcpy(LPVOID(++last_section), &new_section, 0x28);

	//һЩ������Ϣ
	file_header->NumberOfSections += 1;
	option_header->SizeOfImage += (0x1000 + section_text_size);

	//��ȡȫ��������С
	PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)(RVA2FOA(newBuf, LPVOID(option_header->DataDirectory[1].VirtualAddress)) + (DWORD)newBuf);
	DWORD temp = (DWORD)import_table;
	DWORD import_table_size = 0;
	while (import_table->FirstThunk) {
		import_table_size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		import_table++;
	}
	//������λ��
	DWORD newSectionAdd = last_section->PointerToRawData + (DWORD)newBuf;
	//������������
	memcpy((LPVOID)newSectionAdd, (LPVOID)temp, import_table_size);
	//������RVA
	DWORD newSectionRVA = last_section->VirtualAddress;
	//����������Ŀ¼���������
	option_header->DataDirectory[1].VirtualAddress = newSectionRVA;
	//temp�����ڷ��µ�����λ��
	temp = (DWORD)newSectionAdd + import_table_size;
	//�Ȱ������ֵ�λ��
	temp += 0xc;
	//���λ��д��RVA RVA���¼��dll������
	DWORD dllNameRVA = newSectionRVA + 0x100;
	memcpy((LPVOID)temp, &dllNameRVA, 4);
	//1.����
	char name[] = "Dll2.dll";
	DWORD dllNameFOA = last_section->PointerToRawData + (DWORD)newBuf + 0x100;
	memcpy((LPVOID)dllNameFOA, name, strlen(name));
	//�����ַ��IAT
	temp += 4;
	DWORD thunkDataRVA = newSectionRVA + 0x110;
	memcpy((LPVOID)temp, &thunkDataRVA, 4);
	//2.thunkDataRVA�ﻹ��һ��RVA ��byName
	DWORD thunkDataFOA = last_section->PointerToRawData + (DWORD)newBuf + 0x110;
	DWORD byNameRVA = newSectionRVA + 0x120;
	memcpy((LPVOID)thunkDataFOA, &byNameRVA, 4);
	//3.byName��д��������
	DWORD byNameFOA = last_section->PointerToRawData + (DWORD)newBuf + 0x122;
	char funName[] = "fun1";
	memcpy((LPVOID)byNameFOA, funName, strlen(funName));

	//����һ���½ڵĽṹ 
	//ǰ0x1000�ֽڸ��µ�����ʹ�á����ಿ�ָ������ʹ��
	//������ο������½�0x1000��λ��
	memcpy(LPVOID(last_section->PointerToRawData + (DWORD)newBuf + 0x1000),
		LPVOID(section_header_text->PointerToRawData + (DWORD)newBuf),
		section_text_size);

	//�������ȫ��дΪCC
	section_header++;
	memset(LPVOID(section_header->PointerToRawData + (DWORD)newBuf), 0xcc, section_header->SizeOfRawData);


	textSectionSize = section_text_size;

	return newBuf;
}