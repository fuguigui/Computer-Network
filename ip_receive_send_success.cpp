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
	//����IP���ײ��������У���
	int len = (p[0] & 0xf)*2;//������ײ���unsigned short Ϊ��λ�ĳ��ȣ�IHL��4���ֽ�Ϊ��λ��unsigned short��2���ֽ�Ϊ��λ
	int sum = 0;
	for(int i =0;i<len;++i){
		sum+=*((unsigned short *)(p+2*i));
	}
	sum-=*((unsigned short*)(p+10));//����У���Ϊ0
	while(sum > 0xffff)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }

	return 0xffff-(unsigned short)sum;
}
int checkIPHead(char* p){
	//���ipͷ���������Ƿ�����Լ��������͡���������-1�����򷵻ش�������
    int version = p[0] >> 4;
    int IHL = p[0] & 0xf;
    int TTL = p[8];
    unsigned short checksum=*((unsigned short*)(p+10));
    unsigned short calcusum = cal_checksum(p);

    //����IP�汾�Ŵ���,IPv4�İ汾��Ϊ4
    if(version!=4)return STUD_IP_TEST_VERSION_ERROR;
	//����ͷ������
	if(IHL<5)return STUD_IP_TEST_HEADLEN_ERROR;
	//����TTLֵ����
    if(TTL==0)return STUD_IP_TEST_TTL_ERROR;
	//����У��ʹ���
	if(checksum!=calcusum)return STUD_IP_TEST_CHECKSUM_ERROR;
	return -1;
}

int stud_ip_recv(char *pBuffer,unsigned short length)
{
	int result = checkIPHead(pBuffer);
    if(result!=-1){
    	//���ͷ���������ݴ������ͣ���������
		ip_DiscardPkt(pBuffer,result);
		return 1;
	}
	//�жϱ����Ƿ�ý���
	//���ip�����е�Ŀ��ip��ַ�ͱ�����ip��ַ
	unsigned int dst = ntohl(*((unsigned int *)(pBuffer+16)));
	unsigned int self = getIpv4Address();
	if(dst == self || dst==0xffff){
	//Ŀ�ĵ�ַ�Ǳ�����ַ��㲥��ַ���������գ������ϲ�Э�麯��
		ip_SendtoUp(pBuffer,length);
		return 0;
	}
	else {
		//��������Ϊ��ַ���󣬶�������
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);
		return 1;
	}
}

void makeIpHead(char *head,unsigned short len,unsigned int srcAddr,unsigned int dstAddr,byte protocol,byte ttl){
	//���ð汾�ź��ײ�����
	head[0]=0x45;
	//��������ʱ��
	head[8]=ttl;
	//����Э��
	head[9]=protocol;
	//�����ܳ���
	unsigned short tlen = htons(len + 20);
	memcpy(head + 2, &tlen, sizeof(unsigned short));
	//����Դ��ַ��Ŀ�ĵ�ַ
	unsigned int src = htonl(srcAddr);
	unsigned int dis = htonl(dstAddr);
	memcpy(head + 12, &src, sizeof(unsigned int));
	memcpy(head + 16, &dis, sizeof(unsigned int));
	//���㲢����У���
	unsigned short checksum = cal_checksum(head);
	memcpy(head + 10, &checksum, sizeof(unsigned short));
}

int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	char ip[len + 20];//��������洢�ռ�
	memset(ip,0,len+20);//��ʼ���ַ�ָ��Ŀռ�
	/*����ipͷ��*/
	makeIpHead(ip,len,srcAddr,dstAddr,protocol,ttl);
	memcpy(ip + 20, pBuffer, len);

	ip_SendtoLower(ip,len+20);
	return 0;
}

