/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);
extern void ip_SendtoLower(char*pBuffer,int length);
extern void ip_SendtoUp(char *pBuffer,int length);
extern unsigned int getIpv4Address();

// implemented by students
unsigned short cal_checksum(char* p){
	//给出IP的首部，计算出校验和
	int len = (p[0] & 0xf)*2;//计算出首部以unsigned short 为单位的长度，IHL以4个字节为单位，unsigned short以2个字节为单位
	int sum = 0;
	for(int i =0;i<len;++i){
		sum+=*((unsigned short *)(p+2*i));
	}
	sum-=*((unsigned short*)(p+10));//假设校验和为0
	while(sum > 0xffff)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

	return 0xffff-(unsigned short)sum;
}
int checkIPHead(char* p){
	//检查ip头部，返回是否出错以及错误类型。不出错返回-1，否则返回错误类型
    int version = p[0] >> 4;
    int IHL = p[0] & 0xf;
    int TTL = p[8];
    unsigned short checksum=*((unsigned short*)(p+10));
    unsigned short calcusum = cal_checksum(p);

    //返回IP版本号错误,IPv4的版本号为4
    if(version!=4)return STUD_IP_TEST_VERSION_ERROR;
	//返回头部错误
	if(IHL<5)return STUD_IP_TEST_HEADLEN_ERROR;
	//返回TTL值错误
    if(TTL==0)return STUD_IP_TEST_TTL_ERROR;
	//返回校验和错误
	if(checksum!=calcusum)return STUD_IP_TEST_CHECKSUM_ERROR;
	return -1;
}

int stud_ip_recv(char *pBuffer,unsigned short length)
{
	int result = checkIPHead(pBuffer);
    if(result!=-1){
    	//如果头部出错，根据错误类型，丢弃返回
		ip_DiscardPkt(pBuffer,result);
		return 1;
	}
	//判断本机是否该接收
	//获得ip分组中的目的ip地址和本机的ip地址
	unsigned int dst = ntohl(*((unsigned int *)(pBuffer+16)));
	unsigned int self = getIpv4Address();
	if(dst == self || dst==0xffff){
	//目的地址是本机地址或广播地址，本机接收，调用上层协议函数
		ip_SendtoUp(pBuffer,length);
		return 0;
	}
	else {
		//错误类型为地址错误，丢弃返回
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
		return 1;
	}
}

void makeIpHead(char *head,unsigned short len,unsigned int srcAddr,unsigned int dstAddr,byte protocol,byte ttl){
	//设置版本号和首部长度
	head[0]=0x45;
	//设置生存时间
	head[8]=ttl;
	//设置协议
	head[9]=protocol;
	//设置总长度
	unsigned short tlen = htons(len + 20);
	memcpy(head + 2, &tlen, sizeof(unsigned short));
	//设置源地址和目的地址
	unsigned int src = htonl(srcAddr);
	unsigned int dis = htonl(dstAddr);
	memcpy(head + 12, &src, sizeof(unsigned int));
	memcpy(head + 16, &dis, sizeof(unsigned int));
	//计算并设置校验和
	unsigned short checksum = cal_checksum(head);
	memcpy(head + 10, &checksum, sizeof(unsigned short));
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	char ip[len + 20];//申请所需存储空间
	memset(ip,0,len+20);//初始化字符指针的空间
	/*制作ip头部*/
	makeIpHead(ip,len,srcAddr,dstAddr,protocol,ttl);
	memcpy(ip + 20, pBuffer, len);

	ip_SendtoLower(ip,len+20);
	return 0;
}

