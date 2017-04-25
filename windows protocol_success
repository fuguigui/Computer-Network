#include <queue>
#include <vector>

#include "sysinclude.h"

extern void SendFRAMEPacket(unsigned char* pData, unsigned int len);

#define WINDOW_SIZE_STOP_WAIT 1
#define WINDOW_SIZE_BACK_N_FRAME 4

typedef enum{data, ack, nak} frame_kind;
typedef struct frame_head
{
    frame_kind kind;
    unsigned int seq;
    unsigned int ack;
    unsigned char data[100];
};

typedef struct frame
{
    frame_head head;
    unsigned int size;
};

typedef struct Frame
{
    frame* pframe;
    int size;
};

queue<Frame>SendQue;
queue<Frame> WaitQue;
vector<Frame> SendVec;
vector<Frame>::iterator it;

/*
* 停等协议测试函数
*/
int stud_slide_window_stop_and_wait(char *pBuffer, int bufferSize, UINT8 messageType)
{
    if(messageType == MSG_TYPE_SEND)
    {
        Frame tmpframe;
        tmpframe.pframe = new frame;
        *tmpframe.pframe = *(frame*)pBuffer;
        tmpframe.size = bufferSize;
	if(SendQue.size() < WINDOW_SIZE_STOP_WAIT){
		//如果发送缓存没有满,直接发送
 		SendQue.push(tmpframe);
        	SendFRAMEPacket((unsigned char*)(tmpframe.pframe), tmpframe.size);
	}
	else{
	//否则，存入等待队列
        WaitQue.push(tmpframe);
	}
    }
    if(messageType == MSG_TYPE_RECEIVE)
    {
        unsigned ack = ((frame*)pBuffer)->head.ack;
        Frame receiveframe;
        if(SendQue.size() > 0)
        {
            receiveframe = SendQue.front();
            if(ack == ((receiveframe.pframe)->head.seq))
            {
                SendQue.pop();
                if(WaitQue.size() > 0 ) {
        		Frame sendframe = WaitQue.front();
        		WaitQue.pop();
        		SendQue.push(sendframe);
        		SendFRAMEPacket((unsigned char*)(sendframe.pframe), sendframe.size);
   		    }
            }
        }
    }
    if(messageType == MSG_TYPE_TIMEOUT)
    {
        if(SendQue.size() > 0)
        {
            unsigned seq = ntohl(*((unsigned*)pBuffer));
            Frame resendframe = SendQue.front();
            if(seq == ((resendframe.pframe)->head.seq))
            {
                SendFRAMEPacket((unsigned char*)(resendframe.pframe), resendframe.size);
            }
        }
    }
	return 0;
}

/*
* 把等待缓存中的frame尽可能地发送出去，并存入发送缓存
*/
void wait_to_send ()
{
    while((SendVec.size() < WINDOW_SIZE_BACK_N_FRAME) && (WaitQue.size() != 0)) {
        Frame sendframe = WaitQue.front();
        WaitQue.pop();
        SendVec.push_back(sendframe);
        SendFRAMEPacket((unsigned char*)(sendframe.pframe), sendframe.size);
    }
}
/*
*重发发送缓存中的所有frame
*/
void resend_all(){
	vector<Frame>::iterator reit;
    Frame resendframe;
    for(reit = SendVec.begin(); reit != SendVec.end(); ++ reit)
        {
           resendframe = *reit;
         SendFRAMEPacket((unsigned char*)(resendframe.pframe), resendframe.size);
      }
}

/*
* 回退n帧测试函数
*/
int stud_slide_window_back_n_frame(char *pBuffer, int bufferSize, UINT8 messageType)
{
    if(messageType == MSG_TYPE_SEND)
    {
        Frame tmpframe;
        tmpframe.pframe = new frame;
        *tmpframe.pframe = *(frame*)pBuffer;
        tmpframe.size = bufferSize;
        WaitQue.push(tmpframe);
	  wait_to_send();
    }
    if(messageType == MSG_TYPE_RECEIVE)
    {
        unsigned ack = ((frame*)pBuffer)->head.ack;
        Frame receiveframe;
        for(it = SendVec.begin(); it != SendVec.end(); ++ it)
        {
            receiveframe = *it;
            if(ack == ((receiveframe.pframe)->head.seq))
            {
                SendVec.erase(SendVec.begin(), it + 1);
                wait_to_send();
                break;
            }
        }
    }
    if(messageType == MSG_TYPE_TIMEOUT)
    {
        for(it = SendVec.begin(); it != SendVec.end(); ++ it)
        {
            unsigned seq = htonl(*((unsigned*)pBuffer));
            Frame searchframe = *it;
            if(seq == ((searchframe.pframe)->head.seq))
            {
                resend_all();
                break;
            }
        }
    }
	return 0;
}

/*
* 选择性重传测试函数
*/
int stud_slide_window_choice_frame_resend(char *pBuffer, int bufferSize, UINT8 messageType)
{
    if(messageType == MSG_TYPE_SEND)
    {
        Frame tmpframe;
        tmpframe.pframe = new frame;
        *tmpframe.pframe = *(frame*)pBuffer;
        tmpframe.size = bufferSize;
        WaitQue.push(tmpframe);
        wait_to_send();
    }
    if(messageType == MSG_TYPE_RECEIVE)
    {
        frame_kind frametype = (frame_kind)ntohl((((frame*)pBuffer)->head.kind));
        unsigned ack = ((frame*)pBuffer)->head.ack;
        Frame receiveframe;
        if(frametype == nak)
        {
            for(it = SendVec.begin(); it != SendVec.end(); ++ it)
            {
                receiveframe = *it;
                if(ack == ((receiveframe.pframe)->head.seq))
                {
			//重传特定的frame
                    SendFRAMEPacket((unsigned char*)(receiveframe.pframe), receiveframe.size);
                }
                break;
            }
        }
        else
        {     
		//确认该frame发送成功，从发送缓存中清除  
            for(it = SendVec.begin(); it != SendVec.end(); ++ it)
            {
                receiveframe = *it;
                if(ack == ((receiveframe.pframe)->head.seq))
                {
                    SendVec.erase(SendVec.begin(), it + 1);
                    wait_to_send();
                    break;
                }
            }
        }
    }
    if(messageType == MSG_TYPE_TIMEOUT)
    {
        for(it = SendVec.begin(); it != SendVec.end(); ++ it)
        {
            unsigned seq = htonl(*((unsigned*)pBuffer));
            Frame searchframe = *it;
            if(seq == ((searchframe.pframe)->head.seq))
            {
                resend_all();
                break;
            }
        }
    }
	return 0;
}
