#include"Shell.h"

extern TCHAR srcName[256] = { 0 };
extern TCHAR shellName[256] = { 0 };
TCHAR PEName[256] = { 0 };
DWORD textSectionSize = 0;


VOID getPath() {
	setlocale(LC_ALL, "");
	printf("请输入要加密的程序路径\n");
	_tscanf_s(_T("%s"), srcName, 256);
	printf("请输入壳程序路径\n");
	_tscanf_s(_T("%s"), shellName, 256);
	printf("请输入加壳后的文件名\n");
	_tscanf_s(_T("%s"), PEName, 256);
}

BOOL moveCode() {
	HANDLE hFile1 = CreateFile(srcName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile1 == INVALID_HANDLE_VALUE) {
		printf("源文件打开失败\n");
		return FALSE;
	}
	DWORD size = GetFileSize(hFile1, NULL);
	LPVOID srcBuf = new CHAR[size]{ 0 };
	DWORD readSize = 0;
	DWORD err_t = ReadFile(hFile1, srcBuf, size, &readSize, NULL);
	if (!err_t) {
		printf("源文件读取失败\n");
		return FALSE;
	}
	//给PE新增节，移动导入表
	LPVOID newBuf = PEAddSection(srcBuf, size);
	size += (0x1000 + textSectionSize);

	encry(newBuf, size);
	HANDLE hFile2 = CreateFile(shellName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile2 == INVALID_HANDLE_VALUE) {
		printf("壳文件打开失败\n");
		return FALSE;
	}
	DWORD shellSize = GetFileSize(hFile2, NULL);
	LPVOID shellBuf = new CHAR[shellSize]{ 0 };
	err_t = ReadFile(hFile2, shellBuf, shellSize, &readSize, NULL);
	if (!err_t) {
		printf("壳文件读取失败\n");
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

//异或加密
VOID encry(LPVOID srcBuf, DWORD size) {
	for (DWORD i = 0; i < size; i++) {
		((PCHAR)srcBuf)[i] = ((PCHAR)srcBuf)[i] ^ 2;
	}
}

//给壳程序添加节 并生成文件
HANDLE addSection(DWORD buf, DWORD shellSzie, DWORD srcSize) {
	if (!buf) {
		printf("壳程序缓冲区不正确\n");
		return FALSE;
	}

	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//将PE整体前移覆盖dos_stub
	DWORD dos_stub_size = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);
	//如果dos_stub文件不足40字节，则需要合并节来完成添加节的任务
	if (dos_stub_size < 0x28) {
		//合并节
		//..........
		return (HANDLE)-1;
	}
	//获取dos头大小
	dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	DWORD all_sections_size = file_header->NumberOfSections * 0x28;
	//除去dos头所有头部的大小
	DWORD all_headers_size = sizeof(IMAGE_NT_HEADERS) + all_sections_size;
	memcpy(LPVOID(buf + sizeof(IMAGE_DOS_HEADER)), nt_header, all_headers_size);
	//中间部分置为0
	memset(LPVOID(buf + sizeof(IMAGE_DOS_HEADER) + all_headers_size), 0, dos_stub_size);

	nt_header = PIMAGE_NT_HEADERS(buf + dos_header->e_lfanew);
	file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	srcSize = Align(srcSize, option_header->FileAlignment);

	//C0000040 data段属性 构建新节
	IMAGE_SECTION_HEADER new_section = { 0 };
	CHAR section_name[8] = ".msvcjs";
	memcpy(new_section.Name, section_name, 8);
	new_section.Misc.VirtualSize = srcSize;
	new_section.SizeOfRawData = srcSize;
	//最后一个节的RVA+文件大小,内存对齐后 = 新节的RVA
	PIMAGE_SECTION_HEADER last_section = section_header + file_header->NumberOfSections - 1;
	new_section.VirtualAddress = Align(DWORD(last_section->VirtualAddress + last_section->SizeOfRawData), option_header->SectionAlignment);
	//新节的FOA
	new_section.PointerToRawData = Align(DWORD(last_section->PointerToRawData + last_section->SizeOfRawData), option_header->FileAlignment);
	//新节的属性
	new_section.Characteristics = 0xC0000040;
	//将节的信息写入buf中
	memcpy(LPVOID(++last_section), &new_section, 0x28);

	//一些其他信息
	file_header->NumberOfSections += 1;
	srcSize = Align(srcSize, option_header->SectionAlignment);
	option_header->SizeOfImage += srcSize;

	TCHAR tempName[256] = _T("C:\\Users\\罗辑\\Desktop\\");
	_tcscat_s(tempName, 256, PEName);
	//严谨一些可以判断源文件是什么类型pe，或者直接让用户自己输入
	_tcscat_s(tempName, 256, _T(".exe"));
	HANDLE hFile = CreateFile(tempName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD writeSize = 0;
	WriteFile(hFile, (LPVOID)buf, shellSzie, &writeSize, NULL);

	return hFile;
}

//获取对齐后的值
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

//RVA转FOA
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

//给PE新增节,移动导入表,移动代码段
LPVOID PEAddSection(LPVOID oldBuf, DWORD size) {
	if (!oldBuf) {
		printf("壳程序缓冲区不正确\n");
		return FALSE;
	}
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(oldBuf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)oldBuf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	PIMAGE_SECTION_HEADER section_header_text = section_header;
	//代码段大小
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


	//构建新节信息
	IMAGE_SECTION_HEADER new_section = { 0 };
	CHAR section_name[8] = ".msvcjs";
	memcpy(new_section.Name, section_name, 8);
	new_section.Misc.VirtualSize = 0x1000 + section_text_size;
	new_section.SizeOfRawData = 0x1000 + section_text_size;

	//最后一个节的RVA+文件大小,内存对齐后 = 新节的RVA
	PIMAGE_SECTION_HEADER last_section = section_header + file_header->NumberOfSections - 1;
	new_section.VirtualAddress = Align(DWORD(last_section->VirtualAddress + last_section->SizeOfRawData), option_header->SectionAlignment);
	//新节的FOA
	new_section.PointerToRawData = Align(DWORD(last_section->PointerToRawData + last_section->SizeOfRawData), option_header->FileAlignment);
	//新节的属性
	new_section.Characteristics = 0xC0000040;
	//将节的信息写入buf中
	memcpy(LPVOID(++last_section), &new_section, 0x28);

	//一些其他信息
	file_header->NumberOfSections += 1;
	option_header->SizeOfImage += (0x1000 + section_text_size);

	//获取全部导入表大小
	PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)(RVA2FOA(newBuf, LPVOID(option_header->DataDirectory[1].VirtualAddress)) + (DWORD)newBuf);
	DWORD temp = (DWORD)import_table;
	DWORD import_table_size = 0;
	while (import_table->FirstThunk) {
		import_table_size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		import_table++;
	}
	//新区段位置
	DWORD newSectionAdd = last_section->PointerToRawData + (DWORD)newBuf;
	//放入新区段中
	memcpy((LPVOID)newSectionAdd, (LPVOID)temp, import_table_size);
	//新区段RVA
	DWORD newSectionRVA = last_section->VirtualAddress;
	//更改拓数据目录表里的数据
	option_header->DataDirectory[1].VirtualAddress = newSectionRVA;
	//temp是现在放新导入表的位置
	temp = (DWORD)newSectionAdd + import_table_size;
	//先安排名字的位置
	temp += 0xc;
	//这个位置写上RVA RVA里记录着dll的名字
	DWORD dllNameRVA = newSectionRVA + 0x100;
	memcpy((LPVOID)temp, &dllNameRVA, 4);
	//1.名字
	char name[] = "Dll2.dll";
	DWORD dllNameFOA = last_section->PointerToRawData + (DWORD)newBuf + 0x100;
	memcpy((LPVOID)dllNameFOA, name, strlen(name));
	//这个地址放IAT
	temp += 4;
	DWORD thunkDataRVA = newSectionRVA + 0x110;
	memcpy((LPVOID)temp, &thunkDataRVA, 4);
	//2.thunkDataRVA里还是一个RVA 是byName
	DWORD thunkDataFOA = last_section->PointerToRawData + (DWORD)newBuf + 0x110;
	DWORD byNameRVA = newSectionRVA + 0x120;
	memcpy((LPVOID)thunkDataFOA, &byNameRVA, 4);
	//3.byName里写函数名字
	DWORD byNameFOA = last_section->PointerToRawData + (DWORD)newBuf + 0x122;
	char funName[] = "fun1";
	memcpy((LPVOID)byNameFOA, funName, strlen(funName));

	//梳理一下新节的结构 
	//前0x1000字节给新导出表使用。其余部分给代码段使用
	//将代码段拷贝至新节0x1000的位置
	memcpy(LPVOID(last_section->PointerToRawData + (DWORD)newBuf + 0x1000),
		LPVOID(section_header_text->PointerToRawData + (DWORD)newBuf),
		section_text_size);

	//将代码段全部写为CC
	section_header++;
	memset(LPVOID(section_header->PointerToRawData + (DWORD)newBuf), 0xcc, section_header->SizeOfRawData);


	textSectionSize = section_text_size;

	return newBuf;
}