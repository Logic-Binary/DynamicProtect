#include "deCodeShell.h"
#pragma comment(linker,"/INCLUDE:__tls_used")

// TLS回调函数 检测是否被调试
void NTAPI t_TlsCallBack1(PVOID DllHandle, DWORD Reason, PVOID Red) {
	if (Reason == DLL_PROCESS_ATTACH ) {
		BOOL ret;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &ret);
		if (ret) {
			MessageBoxA(0,"Debugged","Info",0);
		}
	}
	return;
}
//TLS回调函数 检测虚拟机
void NTAPI t_TlsCallBack2(PVOID DllHandle, DWORD Reason, PVOID Red) {
	if (Reason == DLL_PROCESS_ATTACH) {
		BOOL result = IsInsideVMWare();
		if (result) {
			MessageBoxA(0,"Running inside VMWare","Info",0);
			ExitProcess(0);
		}
	}
}
//注册TLS
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {
	t_TlsCallBack1,
	t_TlsCallBack2,
	NULL };
#pragma data_seg()

int _tmain(char argc, char* argv[]) {
	//请输入密码(可以写在TLS中)
	printf("Please input PassWord\n");
	DWORD password = 0;
	scanf_s("%d", &password);
	if (password != 1) {
		printf("密码错误\n");
		Sleep(2200);
		ExitProcess(0);
	}
	//获取主模块的数据
	DWORD srcSize = GetDeCode();
	//解密原来的文件
	deCode(srcSize);

	//以挂起的方式创建进程
	SusCreateProcess();
	return 0;
}