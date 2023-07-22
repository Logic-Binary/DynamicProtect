#include<iostream>
#include<Windows.h>
#pragma comment(linker,"/INCLUDE:__tls_used")

void NTAPI t_TlsCallBack(PVOID DllHandle, DWORD Reason, PVOID Red) {
	if (Reason == DLL_PROCESS_ATTACH) {
		MessageBoxA(0, "TLS回调函数", "信息", 0);
	}
}

//注册TLS
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {
	t_TlsCallBack,
	NULL };
#pragma data_seg()

int main() {

	printf("Hello World\n");

	system("pause");

	return 0;
}