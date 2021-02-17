#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <string.h>

#pragma comment(lib,"ws2_32")

#define TARGETINFOFILENAME "WOLTargetinfo.csv"

int generateTargetInfo(FILE **);
void Eliminate(char* str, char ch);

int main(int argc, char* argv[]) {
	WSADATA wsaData;
	FILE* targetInfofp = fopen(TARGETINFOFILENAME, "r");

	struct sockaddr_in s_sockaddr_in;

	int s_socket;
	int s_value;
	int s_repeat;
	int s_port = 2304;
	int s_send_bytes;

	char tmpStream[1024] = "";
	unsigned char MACAddr[6] = {0, };
	char s_magic_packet[6 + (6 * 16)];

	char* schp0 = 0;
	char* schp1 = 0;

	if (!targetInfofp) {
		if (!generateTargetInfo(&targetInfofp))
			return(EXIT_FAILURE);
		else {
			fprintf(stdout, "WOL 타겟 정보 파일을 성공적으로 생성했습니다.\n");
			system("pause");
			fclose(targetInfofp);
			return(EXIT_SUCCESS);
		}
	}

	while (!feof(targetInfofp)) {
		fgets(tmpStream, 1024, targetInfofp);

		schp0 = strtok(tmpStream, ",");
		while (schp0 != NULL) {
			if (!strcmp(schp0, "MAC")) {
				schp0 = strtok(NULL, ",");
				if (schp0 == NULL)
					break;
				schp1 = strtok(schp0, ":");
				if (schp1 == NULL)
					break;
				for (int i = 0; i < 6; i++) {
					MACAddr[i] = (unsigned char)strtol(schp1, NULL, 16);
					schp1 = strtok(NULL, ":");
					if (schp1 == NULL)
						break;
				}
			}
			else if (!strcmp(schp0, "PORT")) {
				schp0 = strtok(NULL, ",");
				if (schp0 == NULL)
					break;
				s_port = strtol(schp0, NULL, 10);
			}
			schp0 = strtok(NULL, ",");
		}
	}

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		perror("WSAerror");
		return(EXIT_FAILURE);
	}

	s_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (s_socket == -1) {
		perror("socket");
		return(EXIT_FAILURE);
	}

	memset(&s_sockaddr_in, 0, sizeof(s_sockaddr_in));

	s_sockaddr_in.sin_family = AF_INET;
	s_sockaddr_in.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	s_sockaddr_in.sin_port = htons(0);

	if (bind(s_socket, (const struct sockaddr*)(&s_sockaddr_in), sizeof(s_sockaddr_in)) == (-1)) {
		perror("bind");
		closesocket(s_socket);
		return(EXIT_FAILURE);
	}

	s_value = 1;
	setsockopt(s_socket, SOL_SOCKET, SO_BROADCAST, (const char*)(&s_value), sizeof(s_value));

	memset(&s_magic_packet[0], 0xff, (size_t)6u); /* 첫 6byte는 FFH로 채웁니다. */
	for (s_repeat = 0; s_repeat < 16; s_repeat++) { /* 깨우고자 하는 MAC address를 16회 반복하여 채웁니다. */
		memcpy((void*)(&s_magic_packet[6 + (s_repeat * 6)]), (const void*)(&MACAddr[0]), sizeof(MACAddr));
	}

	memset(&s_sockaddr_in, 0, sizeof(s_sockaddr_in));
	s_sockaddr_in.sin_family = AF_INET;
	inet_pton(s_sockaddr_in.sin_family, "255.255.255.255", (void*)(&s_sockaddr_in.sin_addr));
	s_sockaddr_in.sin_port = htons(s_port);

	s_send_bytes = sendto(s_socket, s_magic_packet, sizeof(s_magic_packet), 0, (const struct sockaddr*)(&s_sockaddr_in), (socklen_t)sizeof(s_sockaddr_in));
	if (s_send_bytes == -1) {
		perror("sendto");
		closesocket(s_socket);
		return(EXIT_FAILURE);
	}

	fprintf(stdout, "SUCCESS : WOL packet %ld bytes sent (Target %02X:%02X:%02X:%02X:%02X:%02X)\n",
		(long)s_send_bytes,
		MACAddr[0], MACAddr[1], MACAddr[2], MACAddr[3], MACAddr[4], MACAddr[5]
	);

	fclose(targetInfofp);
	closesocket(s_socket);
	WSACleanup();

	return(EXIT_SUCCESS);
}

int generateTargetInfo(FILE **targetInfo) {
	char input;
	char inputmacaddr[18];
	int inputport;

	printf("WOL 타겟 정보 파일을 형식에 맞도록 생성해 주십시오\n");
	printf("WOL 타겟 정보 파일을 생성하시겠습니까? (Y/N):");
	
	(void)fscanf(stdin, "%c", &input);
	if (input == 'Y' || input == 'y') {
		*targetInfo = fopen(TARGETINFOFILENAME, "w");

		printf("MAC 주소 입력:");
		(void)fscanf(stdin, "%s", inputmacaddr);
		printf("사용할 PORT 입력:");
		(void)fscanf(stdin, "%d", &inputport);

		fprintf(*targetInfo, "MAC,%s\nPORT,%d", inputmacaddr, inputport);
		return 1;
	}
	else
		return 0;
}

void Eliminate(char* str, char ch)
{
	int len = strlen(str) + 1;
	for (; *str != '\0'; str++, len--)//종료 문자를 만날 때까지 반복
	{
		if (*str == ch)//ch와 같은 문자일 때
		{
			strcpy_s(str, len, str + 1);
			str--;
		}
	}
}