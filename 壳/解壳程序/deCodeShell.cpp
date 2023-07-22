#include"deCodeShell.h"

LPVOID buf = NULL;
LPVOID imageBuf = NULL;



//获取加密文件 放入缓冲区buf
DWORD GetDeCode() {
	//这里是要打开的
	//为了调试暂且关闭
	HANDLE hModuel = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(hModuel);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)hModuel + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER) & (nt_header->FileHeader);
	PIMAGE_OPTIONAL_HEADER option_header = (PIMAGE_OPTIONAL_HEADER) & (nt_header->OptionalHeader);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	section_header += file_header->NumberOfSections - 1;
	DWORD src_file_size = section_header->SizeOfRawData;
	buf = new char[src_file_size] {0};
	//将加密pe放入buf中
	memcpy(buf, LPVOID(section_header->VirtualAddress + (DWORD)hModuel), src_file_size);

	/*HANDLE hFile = CreateFile(L"C:\\Users\\罗辑\\Desktop\\777.exe", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
//解密加密文件 放入缓冲区buf 
VOID deCode(DWORD srcSize) {
	for (int i = 0; i < srcSize; i++) {
		((PCHAR)buf)[i] = ((PCHAR)buf)[i] ^ 2;
	}
}
//以挂起的方式创建进程
VOID SusCreateProcess() {
	//获取当进程主模块路径
	TCHAR namePath[256] = { 0 };
	HMODULE hModule = GetModuleHandle(NULL);
	GetModuleFileName(hModule, namePath, 256);
	STARTUPINFO si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	//花指令，混淆，SEH检测硬件断点
	wulalalla();
	//演示作用
	printf("测试硬件断点字符串");
	CreateProcess(namePath, NULL, NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	CONTEXT context = { 0 };
	context.ContextFlags = CONTEXT_FULL;
	//获取线程上下文对象
	GetThreadContext(pi.hThread, &context);
	//获取OEP
	DWORD OEP = context.Eax;
	char temp[4] = { 0 };
	//获取ImageBase
	PCHAR baseAddress = (PCHAR)(context.Ebx) + 8;
	if (!baseAddress) {
		printf("基址获取失败");
		return;
	}
	ReadProcessMemory(pi.hProcess, baseAddress, temp, 4, NULL);
	// 获取 ZwUnmapViewOfSection 函数指针
	HMODULE hModuleNt = LoadLibrary(_T("ntdll.dll"));
	if (hModuleNt == NULL)
	{
		printf("获取ntdll句柄失败\n");
		TerminateProcess(pi.hProcess, 0);
		return;
	}
	typedef DWORD(WINAPI* _TZwUnmapViewOfSection)(HANDLE, PVOID);
	_TZwUnmapViewOfSection pZwUnmapViewOfSection = (_TZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	if (pZwUnmapViewOfSection == NULL)
	{
		printf("获取 ZwUnmapViewOfSection 函数指针失败\n");
		TerminateThread(pi.hThread, 0);
		return;
	}
	// 调用 ZwUnmapViewOfSection 卸载新进程内存镜像
	pZwUnmapViewOfSection(pi.hProcess, (LPVOID)0x400000);
	//PE文件镜像大小
	DWORD imageSize = getSizeOfImage();
	//在指定的位置分配空间
	LPVOID newBuf = VirtualAllocEx(pi.hProcess, (LPVOID)0x00400000, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//如果分配失败
	if (!newBuf) {
		newBuf = VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	//将文件拉伸
	fileBufferToImageBuffer(imageSize);
	//修复重定位表
	fixReloc((DWORD)newBuf);
	//填充IAT表
	DWORD PE_OEP = fillIAT();
	//将imageBuf放入新程序中
	WriteProcessMemory(pi.hProcess, newBuf, imageBuf, imageSize, NULL);
	//设置imageBase与EIP
	WriteProcessMemory(pi.hProcess, baseAddress, &newBuf, 4, NULL);
	context.Eax = PE_OEP + (DWORD)newBuf;
	SetThreadContext(pi.hThread, &context);
	ResumeThread(pi.hThread);
}
//获取文件映像大小
DWORD getSizeOfImage() {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_headers = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_headers->OptionalHeader));
	return option_header->SizeOfImage;
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
//文件拉伸
BOOL fileBufferToImageBuffer(DWORD imageSize) {
	//判断是否是是PE
	if (*(PWORD)buf != 23117) {
		return FALSE;
	}
	//开辟缓冲区放入准备放入拉伸后的PE
	imageBuf = new CHAR[imageSize]{ 0 };
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	//这个宏其实就是nt_header的地址+拓展头大小(SizeOfOptionHeader) PE加载器也是这么去找第一个区段的
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	//先将头部放入缓冲区中
	memcpy(imageBuf, buf, option_header->SizeOfHeaders);
	//将各个区段放入缓冲区
	for (DWORD i = 0; i < file_header->NumberOfSections; i++) {
		//区段地址
		DWORD sectionAddress = section_header->PointerToRawData + (DWORD)buf;
		memcpy(LPVOID((DWORD)imageBuf + section_header->VirtualAddress),
			(LPVOID)sectionAddress, section_header->SizeOfRawData);
		section_header++;
	}
	return TRUE;
}
//修复重定位
BOOL fixReloc(DWORD address) {
	if (*(PWORD)imageBuf != 23117) {
		return FALSE;
	}
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(imageBuf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)imageBuf + dos_header->e_lfanew);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	//与默认基址的偏移
	DWORD offset = address - option_header->ImageBase;
	if (!offset) {
		return TRUE;
	}
	//第一个重定位表
	PIMAGE_BASE_RELOCATION base_reloc = PIMAGE_BASE_RELOCATION(option_header->DataDirectory[5].VirtualAddress + (DWORD)imageBuf);
	//偏移结构体
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
//填充IAT表
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
		//IAT表
		DWORD IAT_table = import_descriptor->FirstThunk + (DWORD)imageBuf;
		//thunk_data结构体
		PIMAGE_THUNK_DATA thunk_data = NULL;
		if (import_descriptor->OriginalFirstThunk) {
			thunk_data = PIMAGE_THUNK_DATA(import_descriptor->OriginalFirstThunk + (DWORD)imageBuf);
		}
		else {
			thunk_data = PIMAGE_THUNK_DATA(import_descriptor->FirstThunk + (DWORD)imageBuf);
		}
		//循环，直到结构体数组为0
		while (thunk_data->u1.Function) {
			//如果INT不为0
			if (import_descriptor->OriginalFirstThunk) {
				//最高位如果为1 序号导出
				if (thunk_data->u1.Ordinal & 0x80000000) {
					DWORD oridinal = thunk_data->u1.Ordinal | 0x7FFFFFFF;
					DWORD funAddress = (DWORD)GetProcAddress(hModuleDll, MAKEINTRESOURCEA(oridinal));
					*(PDWORD)IAT_table = funAddress;
					IAT_table += 4;
					thunk_data = PIMAGE_THUNK_DATA((DWORD)thunk_data + 4);
				}
				//最高位如果为0 名称导出
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
//枚举进程(已经废弃)
DWORD enumProcess(HANDLE hProcess) {
	//未公开函数
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
	DWORD result = EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
	return TRUE;
}
//检测虚拟机
BOOL IsInsideVMWare() {
	bool rc = true;
	__try {
		__asm
		{
			push   edx
			push   ecx
			push   ebx
			mov    eax, 'VMXh'
			mov    ebx, 0  // 将ebx设置为非幻数’VMXH’的其它值
			mov    ecx, 10 // 指定功能号，用于获取VMWare版本，当它为0x14时用于获取VMware内存大小
			mov    edx, 'VX' // 端口号
			in     eax, dx // 从端口dx读取VMware版本到eax
			//若上面指定功能号为0x14时，可通过判断eax中的值是否大于0，若是则说明处于虚拟机中
			cmp    ebx, 'VMXh' // 判断ebx中是否包含VMware版本’VMXh’，若是则在虚拟机中
			setz[rc] // 设置返回值
			pop    ebx
			pop    ecx
			pop    edx
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {  //如果未处于VMware中，则触发此异常
		rc = false;
	}
	return rc;
}
//异常过滤
DWORD Filter(DWORD code, PEXCEPTION_POINTERS point) {
	point->ContextRecord->ContextFlags = CONTEXT_ALL;
	point->ContextRecord->Eax = (DWORD)buf;
	if (point->ContextRecord->Dr0 ||
		point->ContextRecord->Dr1 ||
		point->ContextRecord->Dr2 ||
		point->ContextRecord->Dr3) {
		MessageBoxA(0, "检测到非法断点", "信息", 0);
		point->ContextRecord->Dr0 = 0;
		point->ContextRecord->Dr1 = 0;
		point->ContextRecord->Dr2 = 0;
		point->ContextRecord->Dr3 = 0;
		point->ContextRecord->Eip += 2;
	}
	//继续执行
	return -1;
}
//一些干扰
void wulalalla() {
	//第一部分，SEH检测硬件断点
	char temp1[] = "GetProcAddressA";
	char temp2[] = "Kernel32.dll";
	//花指令 将GetProce
	char flowerShellcode[] = "\xEB\x03\x90\x05\x00\x8B\xF8\x83\xC1\x08\xE8\x01\x00\x00\x00\x00\xB9\x10\x00\x00\x00\x58\x49\xEB\x01\xE4\x8A\x1F\x33\xD9\x8D\x7F\x01\x85\xC9\x49\x75\xF4\xC3\x90";
	__try {
		__asm {
			//插入一些花指令与混淆
			lea eax, temp1;
			lea edx, flowerShellcode;
			call edx;
			mov eax, 0;
			mov eax, [eax];
		}
	}
	__except (Filter(GetExceptionCode(), GetExceptionInformation())) {
		//printf("继续运行\n");
	}
}
//将代码段写为cc并且将代码段缓冲区与大小写入导出表第二第三个字段（已经废弃）
BOOL CCTextSection(HANDLE hProcess) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_headers = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_headers->OptionalHeader));
	PIMAGE_IMPORT_DESCRIPTOR impotr_descriptor = PIMAGE_IMPORT_DESCRIPTOR(RVA2FOA(buf,LPVOID(option_header->DataDirectory[1].VirtualAddress)) + (DWORD)buf);
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_headers));
	//循环判断是否是.test段  //这里由于特殊设计，已知为第二段
	section_header++;
	//代码段指针
	DWORD size = section_header->SizeOfRawData;
	LPVOID testBuf = new char[size] {0};
	DWORD test_section = RVA2FOA(buf, LPVOID(section_header->VirtualAddress)) + (DWORD)buf;
	//将test段单独放入新程序的一个地方
	LPVOID testBufAdd = VirtualAllocEx(hProcess, (LPVOID)0x00200000, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, testBufAdd, testBuf, size,NULL);


	//将代码段写为CC
	memset((LPVOID)test_section, 0xCC, size);




	return TRUE;
}

