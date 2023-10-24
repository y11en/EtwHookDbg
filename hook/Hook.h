#pragma once
#include <ntifs.h>

typedef struct _HOOK
{
	LIST_ENTRY list;
	PUCHAR oldCode[28];  //����ԭ���ֽ�
	ULONG64  oldSaveLen;  //����ĳ���
	ULONG64 oldFunction;  //�Ϻ�����ַ
	ULONG64 OldCallAddr; // ԭ������CALL
	ULONG64 newFunction;  //�º�����ַ
	ULONG64 AsmDiapthFunction;  //�ɷ���ַ����ʱ����
	ULONG64 retAddr;     //ԭ������HOOK�� ������Ч����ʼ��ַ
	BOOLEAN isHook;      //�Ƿ�HOOK�ɹ�  
}HOOK,*PHOOK;


void InitHookObjectManager();
void DestoryHookObjectManager();
PHOOK FindHOOK(ULONG64 FunctionAddr);
BOOLEAN AddHeadHook(ULONG64 FunctionAddr, ULONG64 newFunctionAddr);
BOOLEAN RemoveHeadHook(ULONG64 FunctionAddr);
VOID RemoveAllHook();