/*
* THIS FILE IS FOR TCP TEST
*/

/*
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
*/

#include "sysInclude.h"

#define FIN         0x01
#define SYN         0x02
#define ACK         0x10
#define SYN_ACK     0x12
#define FIN_ACK     0x11

#define CLOSED      0
#define LISTEN      1
#define SYN_RCVD    2
#define SYN_SENT    3
#define ESTABLISHED 4
#define FIN_WAIT_1  5
#define FIN_WAIT_2  6
#define TIME_WAIT   7

#define BUFFER_SIZE 2048
#define TIMEOUT 10

#define GetSeq(p) (ntohl(*((UINT32 *)(p + 4))))
#define GetAck(p) (ntohl(*((UINT32 *)(p + 8))))
//#define GetFlag(p) (p[13] & 0x13)
#define GetFlag(p)(p[13])

int gSrcPort = 2005;
int gDstPort = 2006;
int gSeqNum = 1;
int gAckNum = 1;

extern void tcp_DiscardPkt(char *pBuffer, int type);

extern void tcp_sendReport(int type);

extern void tcp_sendIpPkt(unsigned char *pData, UINT16 len, unsigned int  srcAddr, unsigned int dstAddr, UINT8	ttl);

extern int waitIpPacket(char *pBuffer, int timeout);

extern unsigned int getIpv4Address();

extern unsigned int getServerIpv4Address();

struct TCB{
	TCB* next;

    UINT32 srcAddr;//Դ��ַ 
    UINT32 dstAddr;//Ŀ�ĵ�ַ 
	UINT16 srcPort;//Դ�˿�
	UINT16 dstPort;//Ŀ�Ķ˿�
	UINT32 ack;
	UINT32 seq;
	UINT8 state;
	UINT16 window;//�����������͵Ĵ��ڵ�����

	int socketfd;//socket��ʶ��

	TCB() {
		seq = gSeqNum;
		ack = gAckNum;
		window = 1;
		state = CLOSED;
		next = NULL;

		socketfd = 0;
		srcAddr = getIpv4Address();
		dstAddr = getServerIpv4Address();
		srcPort = gSrcPort;
		dstPort = gDstPort;
	}
	TCB(int _socketfd) // ���ڿͻ���socket�����Ĺ�������
	{
		seq = gSeqNum;
		ack = gAckNum;
		window = 1;
		state = CLOSED;
		next = NULL;

		socketfd = _socketfd;
		//���Ӧ��ҲҪ�а�
		srcAddr = getIpv4Address();
		dstAddr = getServerIpv4Address();
		srcPort = gSrcPort;
		dstPort = gDstPort;
	}
};
        
TCB* tcb_link_head = NULL;//����TCB�����ͷ��
static int socketfd = 1; // ͳһ�����־��

TCB* TCBSearch_Addr(UINT32 srcAddr, UINT16 srcPort, UINT32 dstAddr, UINT16 dstPort) {
	TCB* temp = tcb_link_head;
//	while (temp != NULL && temp->srcAddr != srcAddr && temp->srcPort != srcPort && temp->dstAddr != dstAddr && temp->dstPort != dstPort) {
	while (temp != NULL && (temp->srcAddr != srcAddr || temp->srcPort != srcPort || temp->dstAddr != dstAddr || temp->dstPort != dstPort)) {
		temp = temp->next;
	}
	return temp;
}
TCB* TCBSearch_socket(int _socketfd){
	TCB* temp = tcb_link_head;
	while (temp != NULL && temp->socketfd != _socketfd) {
		temp = temp->next;
	}
	return temp;
}
       
UINT16 checkSum(char *pBuffer,unsigned short len,UINT32 srcAddr,UINT32 dstAddr){
	//TCPЭ�����12���ֽڵ�IPαͷ������Ҫ�������졣
       //��У�����ȷ������Ϊ0 
       UINT32 ckSum = 0;
	   int real_len = len + 12;//��ʵ������Ҫ����12���ֽڵ�α�ײ�
	   char *Buffer = new char[real_len];

	   memset(Buffer, 0, real_len);
	   memcpy(Buffer + 12, pBuffer, len);

	   //����α�ײ���α�ײ�Ϊ��4���ֽ�ԴIP��ַ��4���ֽ�Ŀ��ip��ַ��1���ֽ�0,1���ֽڰ汾�ţ�2���ֽ�TCP������
	   *((UINT32*)Buffer) = htonl(srcAddr);
	   *((UINT32*)(Buffer + 4)) = htonl(dstAddr);
	   Buffer[9] = 6;//�����Э��ţ�TCPΪ6
	   *((UINT16*)(Buffer + 10)) = htons(len);

	   //����У���
	   //��֤real_lenΪż��
	   if (real_len % 2) real_len++;
	   for (int i = 0; i < real_len; i+=2) {
		   ckSum += *((UINT16*)(Buffer + i));
	   }

	   while (ckSum & 0xffff0000) {
		   ckSum = (ckSum >> 16) + (ckSum & 0xffff);
	   }
	   //����͵ĸ�16Ϊ����0���ͽ���16λ���16λ������ӣ�ֱ��Ϊ0��
	   //��16λ��ֵȡ��������
	   ckSum = ~ckSum;

	   delete Buffer;
	   return ckSum;  
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
{
    //1.���У���
	if (checkSum(pBuffer,len,srcAddr,dstAddr) != 0) return -1;
    //  2.�ֽ���ת��
	UINT16 srcPort = ntohs(*((UINT16 *)pBuffer));
	UINT16 dstPort = ntohs(*((UINT16 *)(pBuffer+2)));
	UINT32 seq = ntohl(GetSeq(pBuffer));
	UINT32 ack = ntohl(GetAck(pBuffer));
	UINT8 flag = GetFlag(pBuffer);

    // 3.������к�,������кŲ���ȷ,����discardPkt
	TCB* search_result = TCBSearch_Addr(srcAddr,srcPort,dstAddr,dstPort);
	if (search_result == NULL) return -1;

    if(ack != search_result->seq + 1){
		tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
		return -1;
    }
	//����״̬�����к�������
	if (search_result->state == SYN_SENT && flag == SYN_ACK) {
		search_result->seq = ack;
		search_result->ack = seq + 1;
		stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, search_result->srcPort, search_result->dstPort, search_result->srcAddr, search_result->dstAddr);
		search_result->state = ESTABLISHED;
	}
	else if (search_result->state == FIN_WAIT_1 && flag == ACK) {
		search_result->state = FIN_WAIT_2;
	}
	else if (search_result->state == FIN_WAIT_2 && flag == FIN_ACK) {
		search_result->seq = ack;
		search_result->ack = seq + 1;
		search_result->state = TIME_WAIT;
		stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, search_result->srcPort, search_result->dstPort, search_result->srcAddr, search_result->dstAddr);
		search_result->state = CLOSED;
	}
	return 0;
}

void stud_tcp_output(char *pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr)
{
	TCB *tcb = TCBSearch_Addr(srcAddr, srcPort, dstAddr, dstPort);
	if (tcb_link_head == NULL) {
		tcb = new TCB();
		tcb_link_head = tcb;
	}
	//�����е�TCB���в���
     //Ҫ���յ���һ�����ĵ�ȷ�Ϻ���ܹ��������� 
	 //���ʹ���Ϊ0�����ܷ���
	if (tcb == NULL || tcb->window == 0) {
		return;
	}

	//����ܷ��ͣ������µı���
	unsigned char* newData = new unsigned char[len + 20];
	memset(newData, 0, len + 20);
	memcpy(newData + 20, pData, len);
	*(UINT16*)newData = htons(tcb->srcPort);//Դ�˿�
	*(UINT16*)(newData + 2) = htons(tcb->dstPort);//Ŀ�Ķ˿�
	*(UINT32*)(newData + 4) = htonl(tcb->seq);//���к�
	*(UINT32*)(newData + 8) = htonl(tcb->ack);//ȷ�Ϻ�
	newData[12] = 20<<2;//�ײ�����

     //�ж���Ҫ���͵ı������ͣ�������ض������ͽ�����Ӧ�Ĵ��� 
     switch(flag){
     case PACKET_TYPE_DATA: //����
          break;
     case PACKET_TYPE_SYN://SYN��־λ 
		 newData[13] = SYN;
		 tcb->state = SYN_SENT;
          break;
     case PACKET_TYPE_SYN_ACK://SYN-ACK��־λ 
		 newData[13] = SYN_ACK;
          break;
     case PACKET_TYPE_ACK://ACK��־λ 
		 newData[13] = ACK;
          break;
     case PACKET_TYPE_FIN://FIN��־λ 
		 newData[13] = FIN;
          break;
     case PACKET_TYPE_FIN_ACK://FIN-ACK��־λ 
		 newData[13] = FIN_ACK;
		 tcb->state = FIN_WAIT_1;
          break;
     }
	 // 3.����TCP���ݱ��Ĳ����͡���дTCP���ĸ��Զε����ݺ����ݣ�ת���ֽ��򣬼���У��͡������²�ӿڷ��ͺ���
	 *((UINT16*)(newData + 14)) = htons(tcb->window);//���ô���
	 *((UINT16*)(newData + 16)) = checkSum((char*)newData, len + 20, srcAddr, dstAddr);//����У���

	 tcp_sendIpPkt(newData, len + 20, tcb->srcAddr, tcb->dstAddr, 255);

	 delete newData;
	 return;
}

int stud_tcp_socket(int domain, int type, int protocol)
{//�����µ�TCB�ṹ�����г�ʼ����Ϊÿ���ṹ����Ψһ���׽ӿ������� 
	TCB* tcb = new TCB(socketfd++);
	tcb->next = tcb_link_head;
	tcb_link_head = tcb;
	return tcb->socketfd;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{//�趨Ŀ��IPv4��ַ�Ͷ˿�
	TCB * tcb = TCBSearch_socket(sockfd);
	if (tcb == NULL) return -1;

	//�趨Դ��ַ�Ͷ˿�
	tcb->srcAddr = getIpv4Address();
	tcb->srcPort = gSrcPort;
	tcb->dstAddr = ntohl(addr->sin_addr.s_addr);
	tcb->dstPort = ntohs(addr->sin_port);
	

	/* �������ӣ�����SYN���� */
	stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);
	char Buffer[BUFFER_SIZE];

	/* ����SYN_ACK���� */
	if (waitIpPacket(Buffer, TIMEOUT) == -1 || GetFlag(Buffer) != SYN_ACK)
	{
		return -1;
	}

	tcb->seq = ntohl(GetAck(Buffer));
	tcb->ack = ntohl( GetSeq(Buffer)) + 1;

	/* ����ACK���ģ������������ */
	stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);

	tcb->state = ESTABLISHED;
	return 0;
}

int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags)
{
    //�ж��Ƿ���ESTABLISHED״̬
	TCB* tcb = TCBSearch_socket(sockfd);
	if (tcb == NULL || tcb->state != ESTABLISHED) return -1;

	/* ����DATA���� */
	stud_tcp_output((char *)pData, datalen, PACKET_TYPE_DATA, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);
	
	char buffer[BUFFER_SIZE];
	/* �ȴ�����ACK */
	if (waitIpPacket(buffer, TIMEOUT) == -1 || GetFlag(buffer) != ACK)
	{
		return -1;
	}

	tcb->seq = ntohl(GetAck(buffer));
	tcb->ack = ntohl(GetSeq(buffer))+ 1;

	return 0;
}

int stud_tcp_recv(int sockfd, unsigned char *pData, unsigned short datalen, int flags)
{
	int len = 0;
    //�ж��Ƿ���ESTABLISHED״̬,δ����������ֱ�ӷ���
	TCB *tcb = TCBSearch_socket(sockfd); // �ҵ���ӦTCB����
	if (tcb == NULL || tcb->state != ESTABLISHED)
	{
		return -1;
	}

	char buffer[BUFFER_SIZE];
	/* �ȴ��������� */
	if ((len = waitIpPacket(buffer, TIMEOUT)) == -1)
	{
		return -1;
	}
    //��TCB�����뻺������������
	int header_length = (buffer[12] >> 2) & 0x3C; // TCPͷ�����ȣ���32λΪ������λ��ʵ���ϳ���ֻռ4λ
	memcpy(pData, buffer + header_length, len - header_length);

	tcb->seq = ntohl(GetAck(buffer));
	tcb->ack = ntohl(GetSeq(buffer)) + (len - header_length);//����������Ϊʲô������

	/* ����ACK */
	tcp_sendIpPkt(pData,len-header_length, tcb->srcAddr, tcb->dstAddr,255);

	return 0;
}

int stud_tcp_close(int _sockfd)
{
    //�ж��Ƿ�Ϊ���������ESTABLISHED״̬
	TCB *pre = NULL;
	TCB *tcb = TCBSearch_socket(_sockfd);
	if (tcb == NULL)
	{
		return -1;
	}

	//����������������ֱ��ɾ��TCB�ṹ���˳�
	if (tcb->state != ESTABLISHED)
	{
		if (pre != NULL)
		{
			pre->next = tcb->next;
		}
		else
		{
			tcb_link_head = tcb->next;
		}
		delete tcb;
		return -1;
	}

	//�ǣ�����OUTPUT����������FIN���ģ���������ΪPACKET_TYPE_FIN
	stud_tcp_output(NULL, 0, PACKET_TYPE_FIN, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);

	char buffer[BUFFER_SIZE];
	/* �ȴ�����ACK */
	if (waitIpPacket(buffer, TIMEOUT) == -1)
	{
		return -1;
	}

	if (GetFlag(buffer) == ACK)
	{
		tcb->state = FIN_WAIT_2;
		tcb->seq = ntohl(GetAck(buffer));
		tcb->ack = ntohl(GetSeq(buffer)) + 1;

		/* ׼������FIN_ACK */
		if (waitIpPacket(buffer, TIMEOUT) == -1) // wait for receiving FIN packet
		{
			return -1;
		}

		if (GetFlag(buffer) == FIN_ACK)
		{
			tcb->state = TIME_WAIT;
			tcb->seq = ntohl(GetAck(buffer));
			tcb->ack = ntohl(GetSeq(buffer)) + 1;
			/* ����ACK���ر�������� */
			stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}

	/* ɾ��TCB���� */
	if (pre != NULL)
	{
		pre->next = tcb->next;
	}
	else
	{
		tcb_link_head = tcb->next;
	}
	delete tcb;
	return 0;
}


