#include "sysInclude.h"
#include<vector>
using std::vector;
// system support
extern void fwd_LocalRcv(char *pBuffer, int length);
extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);
extern void fwd_DiscardPkt(char *pBuffer, int type);
extern unsigned int getIpv4Address( );
// implemented by students
struct route_table{
  int dest;
  int nexthop;
};
vector<route_table> mytable;           
void stud_Route_Init(){
  mytable.clear();                    
  return;
}
void stud_route_add(stud_route_msg *proute)
{
  route_table t;
  t.dest=(ntohl(proute->dest))&(0xffffffff<<(32-htonl(proute->masklen)));
  t.nexthop=ntohl(proute->nexthop);
  mytable.push_back(t);
    return;
}

int stud_fwd_deal(char *pBuffer, int length)
{
  int IHL=pBuffer[0]&0xf;
  int TTL=(int)pBuffer[8];
  int Head_Checksum=ntohs(*(unsigned short*)(pBuffer+10));
  int Dst_IP=ntohl(*(unsigned*)(pBuffer+16));
  if(Dst_IP==getIpv4Address())
  {
    fwd_LocalRcv(pBuffer,length);
    return 0;
  }
 
  if(TTL<=0)
  {
    fwd_DiscardPkt(pBuffer,STUD_FORWARD_TEST_TTLERROR);
    return 1;
  }
  vector<route_table>::iterator ii;
  for(ii=mytable.begin();ii!=mytable.end();ii++)
  {
    if(ii->dest==Dst_IP)
    {
      char *buffer=new char[length];
      memcpy(buffer,pBuffer,length);
      buffer[8]--;
      int sum=0,i=0;
      unsigned short Local_Checksum=0;
      for(;i<2*IHL;i++)
      {
        if(i!=5)
        {
          sum+=(buffer[2*i]<<8)+(buffer[2*i+1]);
          sum%=65535;
        }
      }
    Local_Checksum=htons(0xffff-(unsigned short)sum);
    memcpy(buffer+10,&Local_Checksum,2);
    fwd_SendtoLower(buffer,length,ii->nexthop);
    return 0;
    }
  }
  fwd_DiscardPkt(pBuffer,STUD_FORWARD_TEST_NOROUTE);
  return 1;
}