#include"deCodeShell.h"

LPVOID buf = NULL;
LPVOID imageBuf = NULL;



//��ȡ�����ļ� ���뻺����buf
DWORD GetDeCode() {
	//������Ҫ�򿪵�
	//Ϊ�˵������ҹر�
	HANDLE hModuel = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(hModuel);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)hModuel + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	section_header += file_header->NumberOfSections - 1;
	DWORD src_file_size = section_header->SizeOfRawData;
	buf = new char[src_file_size] {0};
	//������pe����buf��
	memcpy(buf, LPVOID(section_header->VirtualAddress + (DWORD)hModuel), src_file_size);

	/*HANDLE hFile = CreateFile(L"C:\\Users\\�޼�\\Desktop\\777.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD size = GetFileSize(hFile, NULL);
	DWORD readSize = 0;
	LPVOID temp = new char[size] {0};
	ReadFile(hFile, temp, size, &readSize, NULL);
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(temp);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)temp + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	section_header += file_header->NumberOfSections - 1;
	DWORD src_file_size = section_header->SizeOfRawData;
	buf = new char[src_file_size] {0};
	memcpy(buf, LPVOID(section_header->PointerToRawData + (DWORD)temp), src_file_size);

	if (temp != NULL) {
		delete[] temp;
		temp = NULL;
	}*/

	return src_file_size;
}
//���ܼ����ļ� ���뻺����buf 
VOID deCode(DWORD srcSize) {
	for (int i = 0; i < srcSize; i++) {
		((PCHAR)buf)[i] = ((PCHAR)buf)[i] ^ 2;
	}
}
//�Թ���ķ�ʽ��������
VOID SusCreateProcess() {
	//��ȡ��������ģ��·��
	TCHAR namePath[256] = { 0 };
	HMODULE hModule = GetModuleHandle(NULL);
	GetModuleFileName(hModule, namePath, 256);
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	//��ָ�������SEH���Ӳ���ϵ�
	wulalalla();
	//��ʾ����
	printf("����Ӳ���ϵ��ַ���");
	CreateProcess(namePath, NULL, NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_FULL;
	//��ȡ�߳������Ķ���
	GetThreadContext(pi.hThread, &context);
	//��ȡOEP
	DWORD OEP = context.Eax;
	char temp[4] = { 0 };
	//��ȡImageBase
	PCHAR baseAddress = (PCHAR)(context.Ebx) + 8;
	if (!baseAddress) {
		printf("��ַ��ȡʧ��");
		return;
	}
	ReadProcessMemory(pi.hProcess, baseAddress, temp, 4, NULL);
	// ��ȡ ZwUnmapViewOfSection ����ָ��
	HMODULE hModuleNt = LoadLibrary(_T("ntdll.dll"));
	if (hModuleNt == NULL)
	{
		printf("��ȡntdll���ʧ��\n");
		TerminateProcess(pi.hProcess, 0);
		return;
	}
	typedef DWORD(WINAPI* _TZwUnmapViewOfSection)(HANDLE, PVOID);
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (pZwUnmapViewOfSection == NULL)
	{
		printf("��ȡ ZwUnmapViewOfSection ����ָ��ʧ��\n");
		TerminateThread(pi.hThread, 0);
		return;
	}
	// ���� ZwUnmapViewOfSection ж���½����ڴ澵��
	pZwUnmapViewOfSection(pi.hProcess, (LPVOID)0x400000);
	//PE�ļ������С
	DWORD imageSize = getSizeOfImage();
	//��ָ����λ�÷���ռ�
	LPVOID newBuf = VirtualAllocEx(pi.hProcess, (LPVOID)0x00400000, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//�������ʧ��
	if (!newBuf) {
		newBuf = VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	//���ļ�����
	fileBufferToImageBuffer(imageSize);
	//�޸��ض�λ��
	fixReloc((DWORD)newBuf);
	//���IAT��
	DWORD PE_OEP = fillIAT();
	//��imageBuf�����³�����
	WriteProcessMemory(pi.hProcess, newBuf, imageBuf, imageSize, NULL);
	//����imageBase��EIP
	WriteProcessMemory(pi.hProcess, baseAddress, &newBuf, 4, NULL);
	context.Eax = PE_OEP + (DWORD)newBuf;
	SetThreadContext(pi.hThread, &context);
	ResumeThread(pi.hThread);
}
//��ȡ�ļ�ӳ���С
DWORD getSizeOfImage() {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_headers = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_headers->OptionalHeader));
	return option_header->SizeOfImage;
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
//�ļ�����
BOOL fileBufferToImageBuffer(DWORD imageSize) {
	//�ж��Ƿ�����PE
	if (*(PWORD)buf != 23117) {
		return FALSE;
	}
	//���ٻ���������׼������������PE
	imageBuf = new CHAR[imageSize]{ 0 };
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	//�������ʵ����nt_header�ĵ�ַ+��չͷ��С(SizeOfOptionHeader) PE������Ҳ����ôȥ�ҵ�һ�����ε�
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	//�Ƚ�ͷ�����뻺������
	memcpy(imageBuf, buf, option_header->SizeOfHeaders);
	//���������η��뻺����
	for (DWORD i = 0; i < file_header->NumberOfSections; i++) {
		//���ε�ַ
		DWORD sectionAddress = section_header->PointerToRawData + (DWORD)buf;
		memcpy(LPVOID((DWORD)imageBuf + section_header->VirtualAddress),
			(LPVOID)sectionAddress, section_header->SizeOfRawData);
		section_header++;
	}
	return TRUE;
}
//�޸��ض�λ
BOOL fixReloc(DWORD address) {
	if (*(PWORD)imageBuf != 23117) {
		return FALSE;
	}
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(imageBuf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)imageBuf + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	//��Ĭ�ϻ�ַ��ƫ��
	DWORD offset = address - option_header->ImageBase;
	if (!offset) {
		return TRUE;
	}
	//��һ���ض�λ��
	PIMAGE_BASE_RELOCATION base_reloc = PIMAGE_BASE_RELOCATION(option_header->DataDirectory[5].VirtualAddress + (DWORD)imageBuf);
	//ƫ�ƽṹ��
	typedef struct _TYPEOFFSET {
		WORD offset : 12;
		WORD type : 4;
	}TYPEOFFSET, * PTYPEOFFSET;
	while (base_reloc->SizeOfBlock && base_reloc->VirtualAddress) {
		PTYPEOFFSET typeOffset = NULL;
		typeOffset = (PTYPEOFFSET)((DWORD)base_reloc + 8);
		for (DWORD i = 0; i < (base_reloc->SizeOfBlock - 8) / 2; i++) {
			if (typeOffset->type == 3) {
				DWORD needRelocRVA = base_reloc->VirtualAddress + typeOffset->offset;
				DWORD temp = needRelocRVA + (DWORD)imageBuf;
				*(PDWORD)temp += offset;
				typeOffset = (PTYPEOFFSET)((DWORD)typeOffset + 2);
			}
		}
		base_reloc = PIMAGE_BASE_RELOCATION((DWORD)base_reloc + base_reloc->SizeOfBlock);
	}
	return TRUE;
}
//���IAT��
DWORD fillIAT() {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(imageBuf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)imageBuf + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	//PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)RVA2FOA(buf, (LPVOID)(option_header->DataDirectory[1].VirtualAddress +(DWORD)buf));
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = PIMAGE_IMPORT_DESCRIPTOR(option_header->DataDirectory[1].VirtualAddress + (DWORD)imageBuf);

	while (import_descriptor->OriginalFirstThunk && import_descriptor->FirstThunk) {
		PCHAR dllName = PCHAR(import_descriptor->Name + (DWORD)imageBuf);
		HMODULE hModuleDll = LoadLibraryA(dllName);
		if (!hModuleDll) {
			continue;
		}
		//IAT��
		DWORD IAT_table = import_descriptor->FirstThunk + (DWORD)imageBuf;
		//thunk_data�ṹ��
		PIMAGE_THUNK_DATA thunk_data = NULL;
		if (import_descriptor->OriginalFirstThunk) {
			thunk_data = PIMAGE_THUNK_DATA(import_descriptor->OriginalFirstThunk + (DWORD)imageBuf);
		}
		else {
			thunk_data = PIMAGE_THUNK_DATA(import_descriptor->FirstThunk + (DWORD)imageBuf);
		}
		//ѭ����ֱ���ṹ������Ϊ0
		while (thunk_data->u1.Function) {
			//���INT��Ϊ0
			if (import_descriptor->OriginalFirstThunk) {
				//���λ���Ϊ1 ��ŵ���
				if (thunk_data->u1.Ordinal & 0x80000000) {
					DWORD oridinal = thunk_data->u1.Ordinal | 0x7FFFFFFF;
					DWORD funAddress = (DWORD)GetProcAddress(hModuleDll, MAKEINTRESOURCEA(oridinal));
					*(PDWORD)IAT_table = funAddress;
					IAT_table += 4;
					thunk_data = PIMAGE_THUNK_DATA((DWORD)thunk_data + 4);
				}
				//���λ���Ϊ0 ���Ƶ���
				else {
					PIMAGE_IMPORT_BY_NAME by_name = PIMAGE_IMPORT_BY_NAME(thunk_data->u1.Function + (DWORD)imageBuf);
					PCHAR funName = by_name->Name;
					DWORD funAddress = (DWORD)GetProcAddress(hModuleDll, funName);
					*(PDWORD)IAT_table = funAddress;
					IAT_table += 4;
					thunk_data = PIMAGE_THUNK_DATA((DWORD)thunk_data + 4);
				}
			}
		}
		import_descriptor++;
	}

	return option_header->AddressOfEntryPoint;
}
//ö�ٽ���(�Ѿ�����)
DWORD enumProcess(HANDLE hProcess) {
	//δ��������
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
	DWORD result = EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
	return TRUE;
}
//��������
BOOL IsInsideVMWare() {
	bool rc = true;
	__try {
		__asm
		{
			push   edx
			push   ecx
			push   ebx
			mov    eax, 'VMXh'
			mov    ebx, 0  // ��ebx����Ϊ�ǻ�����VMXH��������ֵ
			mov    ecx, 10 // ָ�����ܺţ����ڻ�ȡVMWare�汾������Ϊ0x14ʱ���ڻ�ȡVMware�ڴ��С
			mov    edx, 'VX' // �˿ں�
			in     eax, dx // �Ӷ˿�dx��ȡVMware�汾��eax
			//������ָ�����ܺ�Ϊ0x14ʱ����ͨ���ж�eax�е�ֵ�Ƿ����0��������˵�������������
			cmp    ebx, 'VMXh' // �ж�ebx���Ƿ����VMware�汾��VMXh�������������������
			setz[rc] // ���÷���ֵ
			pop    ebx
			pop    ecx
			pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {  //���δ����VMware�У��򴥷����쳣
		rc = false;
	}
	return rc;
}
//�쳣����
DWORD Filter(DWORD code, PEXCEPTION_POINTERS point) {
	point->ContextRecord->ContextFlags = CONTEXT_ALL;
	point->ContextRecord->Eax = (DWORD)buf;
	if (point->ContextRecord->Dr0 ||
		point->ContextRecord->Dr1 ||
		point->ContextRecord->Dr2 ||
		point->ContextRecord->Dr3) {
		MessageBoxA(0, "��⵽�Ƿ��ϵ�", "��Ϣ", 0);
		point->ContextRecord->Dr0 = 0;
		point->ContextRecord->Dr1 = 0;
		point->ContextRecord->Dr2 = 0;
		point->ContextRecord->Dr3 = 0;
		point->ContextRecord->Eip += 2;
	}
	//����ִ��
	return -1;
}
//һЩ����
void wulalalla() {
	//��һ���֣�SEH���Ӳ���ϵ�
	char temp1[] = "GetProcAddressA";
	char temp2[] = "Kernel32.dll";
	//��ָ�� ��GetProce
	char flowerShellcode[] = "\xEB\x03\x90\x05\x00\x8B\xF8\x83\xC1\x08\xE8\x01\x00\x00\x00\x00\xB9\x10\x00\x00\x00\x58\x49\xEB\x01\xE4\x8A\x1F\x33\xD9\x8D\x7F\x01\x85\xC9\x49\x75\xF4\xC3\x90";
	__try {
		__asm {
			//����һЩ��ָ�������
			lea eax, temp1;
			lea edx, flowerShellcode;
			call edx;
			mov eax, 0;
			mov eax, [eax];
		}
	}
	__except (Filter(GetExceptionCode(), GetExceptionInformation())) {
		//printf("��������\n");
	}
}
//�������дΪcc���ҽ�����λ��������Сд�뵼����ڶ��������ֶΣ��Ѿ�������
BOOL CCTextSection(HANDLE hProcess) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_headers = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_headers->OptionalHeader));
	PIMAGE_IMPORT_DESCRIPTOR impotr_descriptor = PIMAGE_IMPORT_DESCRIPTOR(RVA2FOA(buf,LPVOID(option_header->DataDirectory[1].VirtualAddress)) + (DWORD)buf);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_headers));
	//ѭ���ж��Ƿ���.test��  //��������������ƣ���֪Ϊ�ڶ���
	section_header++;
	//�����ָ��
	DWORD size = section_header->SizeOfRawData;
	LPVOID testBuf = new char[size] {0};
	DWORD test_section = RVA2FOA(buf, LPVOID(section_header->VirtualAddress)) + (DWORD)buf;
	//��test�ε��������³����һ���ط�
	LPVOID testBufAdd = VirtualAllocEx(hProcess, (LPVOID)0x00200000, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, testBufAdd, testBuf, size,NULL);


	//�������дΪCC
	memset((LPVOID)test_section, 0xCC, size);




	return TRUE;
}

