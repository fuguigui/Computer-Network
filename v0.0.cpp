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

    UINT32 srcAddr;//源地址 
    UINT32 dstAddr;//目的地址 
	UINT16 srcPort;//源端口
	UINT16 dstPort;//目的端口
	UINT32 ack;
	UINT32 seq;
	UINT8 state;
	UINT16 window;//可以用来发送的窗口的数量

	int socketfd;//socket标识符

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
	TCB(int _socketfd) // 用于客户端socket函数的构建函数
	{
		seq = gSeqNum;
		ack = gAckNum;
		window = 1;
		state = CLOSED;
		next = NULL;

		socketfd = _socketfd;
		//这个应该也要有吧
		srcAddr = getIpv4Address();
		dstAddr = getServerIpv4Address();
		srcPort = gSrcPort;
		dstPort = gDstPort;
	}
};
        
TCB* tcb_link_head = NULL;//定义TCB链表的头部
static int socketfd = 1; // 统一分配标志符

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
	//TCP协议带有12个字节的IP伪头部，需要自主构造。
       //若校验和正确，则结果为0 
       UINT32 ckSum = 0;
	   int real_len = len + 12;//真实长度需要增加12个字节的伪首部
	   char *Buffer = new char[real_len];

	   memset(Buffer, 0, real_len);
	   memcpy(Buffer + 12, pBuffer, len);

	   //构造伪首部。伪首部为：4个字节源IP地址，4个字节目的ip地址，1个字节0,1个字节版本号，2个字节TCP包长度
	   *((UINT32*)Buffer) = htonl(srcAddr);
	   *((UINT32*)(Buffer + 4)) = htonl(dstAddr);
	   Buffer[9] = 6;//传输层协议号：TCP为6
	   *((UINT16*)(Buffer + 10)) = htons(len);

	   //计算校验和
	   //保证real_len为偶数
	   if (real_len % 2) real_len++;
	   for (int i = 0; i < real_len; i+=2) {
		   ckSum += *((UINT16*)(Buffer + i));
	   }

	   while (ckSum & 0xffff0000) {
		   ckSum = (ckSum >> 16) + (ckSum & 0xffff);
	   }
	   //如果和的高16为不是0，就将高16位与低16位反复相加，直到为0；
	   //将16位的值取反，返回
	   ckSum = ~ckSum;

	   delete Buffer;
	   return ckSum;  
}

int stud_tcp_input(char *pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
{
    //1.检查校验和
	if (checkSum(pBuffer,len,srcAddr,dstAddr) != 0) return -1;
    //  2.字节序转换
	UINT16 srcPort = ntohs(*((UINT16 *)pBuffer));
	UINT16 dstPort = ntohs(*((UINT16 *)(pBuffer+2)));
	UINT32 seq = ntohl(GetSeq(pBuffer));
	UINT32 ack = ntohl(GetAck(pBuffer));
	UINT8 flag = GetFlag(pBuffer);

    // 3.检查序列号,如果序列号不正确,调用discardPkt
	TCB* search_result = TCBSearch_Addr(srcAddr,srcPort,dstAddr,dstPort);
	if (search_result == NULL) return -1;

    if(ack != search_result->seq + 1){
		tcp_DiscardPkt(pBuffer, STUD_TCP_TEST_SEQNO_ERROR);
		return -1;
    }
	//有限状态机进行后续处理
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
	//在已有的TCB表中查找
     //要在收到上一个报文的确认后才能够继续发送 
	 //发送窗口为0，则不能发送
	if (tcb == NULL || tcb->window == 0) {
		return;
	}

	//如果能发送，构建新的报文
	unsigned char* newData = new unsigned char[len + 20];
	memset(newData, 0, len + 20);
	memcpy(newData + 20, pData, len);
	*(UINT16*)newData = htons(tcb->srcPort);//源端口
	*(UINT16*)(newData + 2) = htons(tcb->dstPort);//目的端口
	*(UINT32*)(newData + 4) = htonl(tcb->seq);//序列号
	*(UINT32*)(newData + 8) = htonl(tcb->ack);//确认号
	newData[12] = 20<<2;//首部长度

     //判断需要发送的报文类型，并针对特定的类型进行相应的处理 
     switch(flag){
     case PACKET_TYPE_DATA: //数据
          break;
     case PACKET_TYPE_SYN://SYN标志位 
		 newData[13] = SYN;
		 tcb->state = SYN_SENT;
          break;
     case PACKET_TYPE_SYN_ACK://SYN-ACK标志位 
		 newData[13] = SYN_ACK;
          break;
     case PACKET_TYPE_ACK://ACK标志位 
		 newData[13] = ACK;
          break;
     case PACKET_TYPE_FIN://FIN标志位 
		 newData[13] = FIN;
          break;
     case PACKET_TYPE_FIN_ACK://FIN-ACK标志位 
		 newData[13] = FIN_ACK;
		 tcb->state = FIN_WAIT_1;
          break;
     }
	 // 3.构造TCP数据报文并发送。填写TCP报文各自段的内容和数据，转换字节序，计算校验和。调用下层接口发送函数
	 *((UINT16*)(newData + 14)) = htons(tcb->window);//设置窗口
	 *((UINT16*)(newData + 16)) = checkSum((char*)newData, len + 20, srcAddr, dstAddr);//设置校验和

	 tcp_sendIpPkt(newData, len + 20, tcb->srcAddr, tcb->dstAddr, 255);

	 delete newData;
	 return;
}

int stud_tcp_socket(int domain, int type, int protocol)
{//创建新的TCB结构，进行初始化；为每个结构分配唯一的套接口描述符 
	TCB* tcb = new TCB(socketfd++);
	tcb->next = tcb_link_head;
	tcb_link_head = tcb;
	return tcb->socketfd;
}

int stud_tcp_connect(int sockfd, struct sockaddr_in *addr, int addrlen)
{//设定目的IPv4地址和端口
	TCB * tcb = TCBSearch_socket(sockfd);
	if (tcb == NULL) return -1;

	//设定源地址和端口
	tcb->srcAddr = getIpv4Address();
	tcb->srcPort = gSrcPort;
	tcb->dstAddr = ntohl(addr->sin_addr.s_addr);
	tcb->dstPort = ntohs(addr->sin_port);
	

	/* 建立连接：发送SYN报文 */
	stud_tcp_output(NULL, 0, PACKET_TYPE_SYN, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);
	char Buffer[BUFFER_SIZE];

	/* 接收SYN_ACK报文 */
	if (waitIpPacket(Buffer, TIMEOUT) == -1 || GetFlag(Buffer) != SYN_ACK)
	{
		return -1;
	}

	tcb->seq = ntohl(GetAck(Buffer));
	tcb->ack = ntohl( GetSeq(Buffer)) + 1;

	/* 发送ACK报文，建立连接完成 */
	stud_tcp_output(NULL, 0, PACKET_TYPE_ACK, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);

	tcb->state = ESTABLISHED;
	return 0;
}

int stud_tcp_send(int sockfd, const unsigned char *pData, unsigned short datalen, int flags)
{
    //判断是否处于ESTABLISHED状态
	TCB* tcb = TCBSearch_socket(sockfd);
	if (tcb == NULL || tcb->state != ESTABLISHED) return -1;

	/* 发送DATA报文 */
	stud_tcp_output((char *)pData, datalen, PACKET_TYPE_DATA, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);
	
	char buffer[BUFFER_SIZE];
	/* 等待接收ACK */
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
    //判断是否处于ESTABLISHED状态,未建立连接则直接返回
	TCB *tcb = TCBSearch_socket(sockfd); // 找到相应TCB表项
	if (tcb == NULL || tcb->state != ESTABLISHED)
	{
		return -1;
	}

	char buffer[BUFFER_SIZE];
	/* 等待接收数据 */
	if ((len = waitIpPacket(buffer, TIMEOUT)) == -1)
	{
		return -1;
	}
    //从TCB的输入缓冲区读出数据
	int header_length = (buffer[12] >> 2) & 0x3C; // TCP头部长度，以32位为计量单位，实际上长度只占4位
	memcpy(pData, buffer + header_length, len - header_length);

	tcb->seq = ntohl(GetAck(buffer));
	tcb->ack = ntohl(GetSeq(buffer)) + (len - header_length);//？？？？？为什么？？？

	/* 发送ACK */
	tcp_sendIpPkt(pData,len-header_length, tcb->srcAddr, tcb->dstAddr,255);

	return 0;
}

int stud_tcp_close(int _sockfd)
{
    //判断是否为正常情况：ESTABLISHED状态
	TCB *pre = NULL;
	TCB *tcb = TCBSearch_socket(_sockfd);
	if (tcb == NULL)
	{
		return -1;
	}

	//如果不是正常情况，直接删除TCB结构后退出
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

	//是：调用OUTPUT函数，发送FIN报文，发送类型为PACKET_TYPE_FIN
	stud_tcp_output(NULL, 0, PACKET_TYPE_FIN, tcb->srcPort, tcb->dstPort, tcb->srcAddr, tcb->dstAddr);

	char buffer[BUFFER_SIZE];
	/* 等待接收ACK */
	if (waitIpPacket(buffer, TIMEOUT) == -1)
	{
		return -1;
	}

	if (GetFlag(buffer) == ACK)
	{
		tcb->state = FIN_WAIT_2;
		tcb->seq = ntohl(GetAck(buffer));
		tcb->ack = ntohl(GetSeq(buffer)) + 1;

		/* 准备接收FIN_ACK */
		if (waitIpPacket(buffer, TIMEOUT) == -1) // wait for receiving FIN packet
		{
			return -1;
		}

		if (GetFlag(buffer) == FIN_ACK)
		{
			tcb->state = TIME_WAIT;
			tcb->seq = ntohl(GetAck(buffer));
			tcb->ack = ntohl(GetSeq(buffer)) + 1;
			/* 发送ACK，关闭连接完成 */
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

	/* 删除TCB表项 */
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


