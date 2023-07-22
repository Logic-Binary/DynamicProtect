#include "deCodeShell.h"
#pragma comment(linker,"/INCLUDE:__tls_used")

// TLS�ص����� ����Ƿ񱻵���
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
//TLS�ص����� ��������
void NTAPI t_TlsCallBack2(PVOID DllHandle, DWORD Reason, PVOID Red) {
	if (Reason == DLL_PROCESS_ATTACH) {
		BOOL result = IsInsideVMWare();
		if (result) {
			MessageBoxA(0,"Running inside VMWare","Info",0);
			ExitProcess(0);
		}
	}
}
//ע��TLS
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {
	t_TlsCallBack1,
	t_TlsCallBack2,
	NULL };
#pragma data_seg()

int _tmain(char argc, char* argv[]) {
	//����������(����д��TLS��)
	printf("Please input PassWord\n");
	DWORD password = 0;
	scanf_s("%d", &password);
	if (password != 1) {
		printf("�������\n");
		Sleep(2200);
		ExitProcess(0);
	}
	//��ȡ��ģ�������
	DWORD srcSize = GetDeCode();
	//����ԭ�����ļ�
	deCode(srcSize);

	//�Թ���ķ�ʽ��������
	SusCreateProcess();
	return 0;
}