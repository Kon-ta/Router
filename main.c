#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<poll.h>
#include	<errno.h>
#include	<signal.h>
#include	<stdarg.h>
#include	<sys/socket.h>
#include	<arpa/inet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip_icmp.h>
#include	<pthread.h>
#include	<stdbool.h> 
#include	"netutil.h"
#include	"base.h"
#include	"ip2mac.h"
#include	"sendBuf.h"


/*各バッファのサイズ*/
#define QUEUE_SIZE 10000

#define TRUE 0
#define FALSE 1

/*優先パケット判定フラグ*/
int P_FLAG;

typedef struct	{
	char	*Device1;
	char	*Device2;
	int	DebugOut;
	char	*NextRouter;
}PARAM;
PARAM	Param={"eth1","eth0",1,"172.20.69.254"};

struct in_addr	NextRouter;

DEVICE	Device[2];

int	EndFlag=0;


/*優先キューの構造体*/
typedef struct{
	u_char *data;
	int size;
	int tno;
	int flag;
}P_QUEUE;

/*ノーマルキューの構造体*/
typedef struct{
	u_char *data;
	int size;
	int tno;
	int flag;
}N_QUEUE;


P_QUEUE p_queue[QUEUE_SIZE];
N_QUEUE n_queue[QUEUE_SIZE];

static int p_enq_point;
static int p_deq_point;

static int n_enq_point;
static int n_deq_point;


/*各キューの初期化関数*/
void init_p_queue(){

	p_enq_point = p_deq_point =-1;
}

void init_n_queue(){

	n_enq_point = n_deq_point =-1;
}

int DebugPrintf(char *fmt,...)
{
	if(Param.DebugOut){
		va_list	args;

		va_start(args,fmt);
		vfprintf(stderr,fmt,args);
		va_end(args);
	}

	return(0);
}

/*キューの次の要素の添字を求める関数*/
int next(int index){
	return((index +1)% QUEUE_SIZE);

}


/*優先キューにデータを追加する関数*/
int p_enqueue(P_QUEUE enq_data){

	
	P_QUEUE x;
	
	p_enq_point=next(p_enq_point);
	
	x=p_queue[p_enq_point];

	if(x.flag ==1){
		DebugPrintf("can't p_enqueue queue is full");
		return 1;
	}else{

	x.flag=1;
	x.size=enq_data.size;
	x.data=enq_data.data;
	x.tno=enq_data.tno;
	
	p_queue[p_enq_point]=x;
	
	
	}
	
	return 0;
}

/*ノーマルキューにデータを追加する関数*/

int n_enqueue(N_QUEUE enq_data){

	N_QUEUE x;
 
	n_enq_point=next(n_enq_point);
	
	x = n_queue[n_enq_point];
	
	if(x.flag ==1){
		//DebugPrintf("can't n_enqueue queue is full");
		return 1;
	}else{

	x.flag=1;
	x.size=enq_data.size;
	x.data=enq_data.data;
	x.tno=enq_data.tno;
	
	//n_queue[next(n_enq_point)]=x;
	n_queue[n_enq_point]=x;
	
	//DebugPrintf("do in n packet");
	
	}
	return 0;
}





/*時間超過パケット通知関数*/
int SendIcmpTimeExceeded(int deviceNo,struct ether_header *eh,struct iphdr *iphdr,u_char *data,int size)
{
struct ether_header	reh;
struct iphdr	rih;
struct icmp	icmp;
u_char	*ipptr;
u_char	*ptr,buf[1500];
int	len;

	memcpy(reh.ether_dhost,eh->ether_shost,6);
	memcpy(reh.ether_shost,Device[deviceNo].hwaddr,6);
	reh.ether_type=htons(ETHERTYPE_IP);

	rih.version=4;
	rih.ihl=20/4;
	rih.tos=0;
	rih.tot_len=htons(sizeof(struct icmp)+64);
	rih.id=0;
	rih.frag_off=0;
	rih.ttl=64;
	rih.protocol=IPPROTO_ICMP;
	rih.check=0;
	rih.saddr=Device[deviceNo].addr.s_addr;
	rih.daddr=iphdr->saddr;

	rih.check=checksum((u_char *)&rih,sizeof(struct iphdr));

	icmp.icmp_type=ICMP_TIME_EXCEEDED;
	icmp.icmp_code=ICMP_TIMXCEED_INTRANS;
	icmp.icmp_cksum=0;
	icmp.icmp_void=0;

	ipptr=data+sizeof(struct ether_header);

	icmp.icmp_cksum=checksum2((u_char *)&icmp,8,ipptr,64);

	ptr=buf;
	memcpy(ptr,&reh,sizeof(struct ether_header));
	ptr+=sizeof(struct ether_header);
	memcpy(ptr,&rih,sizeof(struct iphdr));
	ptr+=sizeof(struct iphdr);
	memcpy(ptr,&icmp,8);
	ptr+=8;
	memcpy(ptr,ipptr,64);
	ptr+=64;
	len=ptr-buf;

	DebugPrintf("write:SendIcmpTimeExceeded:[%d] %dbytes\n",deviceNo,len);
	write(Device[deviceNo].soc,buf,len);

	return(0);
}


/*格納の際に呼び出されるパケット解析関数*/
int Pre_AnalyzePacket(int deviceNo,u_char *data,int size){

u_char	*ptr;
int	lest;
 
struct ether_header	*eh;
char	buf[80];


/*各バッファの構造体宣言*/
P_QUEUE p;
N_QUEUE n;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ether_header)){
		DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_header)\n",deviceNo,lest);
		return(-1);
	}
        /*キャスト*/
	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);

	if(memcmp(&eh->ether_dhost,Device[deviceNo].hwaddr,6)!=0){
		DebugPrintf("[%d]:dhost not match %s\n",deviceNo,my_ether_ntoa_r((u_char *)&eh->ether_dhost,buf,sizeof(buf)));
		return(-1);
	}


　　　　　/*Arp処理:*/
	if(ntohs(eh->ether_type)==ETHERTYPE_ARP){
		struct ether_arp	*arp;

		if(lest<sizeof(struct ether_arp)){
			DebugPrintf("[%d]:lest(%d)<sizeof(struct ether_arp)\n",deviceNo,lest);
			return(-1);
		}
		arp=(struct ether_arp *)ptr;
		ptr+=sizeof(struct ether_arp);
		lest-=sizeof(struct ether_arp);

		if(arp->arp_op==htons(ARPOP_REQUEST)){
			DebugPrintf("[%d]recv:ARP REQUEST:%dbytes\n",deviceNo,size);
			Ip2Mac(deviceNo,*(in_addr_t *)arp->arp_spa,arp->arp_sha);
		}
		if(arp->arp_op==htons(ARPOP_REPLY)){
			DebugPrintf("[%d]recv:ARP REPLY:%dbytes\n",deviceNo,size);
			Ip2Mac(deviceNo,*(in_addr_t *)arp->arp_spa,arp->arp_sha);
		}
	}

　　　　/*IPパケットの場合の処理*/
	else if(ntohs(eh->ether_type)==ETHERTYPE_IP){
		struct iphdr	*iphdr;
		u_char	option[1500];
		int	optionLen;

		if(lest<sizeof(struct iphdr)){
			DebugPrintf("[%d]:lest(%d)<sizeof(struct iphdr)\n",deviceNo,lest);
			return(-1);
		}
		iphdr=(struct iphdr *)ptr;
		ptr+=sizeof(struct iphdr);
		lest-=sizeof(struct iphdr);

		optionLen=iphdr->ihl*4-sizeof(struct iphdr);
		if(optionLen>0){
			if(optionLen>=1500){
				DebugPrintf("[%d]:IP optionLen(%d):too big\n",deviceNo,optionLen);
				return(-1);
			}
			memcpy(option,ptr,optionLen);
			ptr+=optionLen;
			lest-=optionLen;
		}

		if(checkIPchecksum(iphdr,option,optionLen)==0){
			DebugPrintf("[%d]:bad ip checksum\n",deviceNo);
fprintf(stderr,"IP checksum error\n");
			return(-1);
		}

		if(iphdr->ttl-1==0){
			DebugPrintf("[%d]:iphdr->ttl==0 error\n",deviceNo);
			SendIcmpTimeExceeded(deviceNo,eh,iphdr,data,size);
			return(-1);
		}

		/*パケット格納処理*/
		if(iphdr->tos == 150){
			p.size = size;
			p.tno = deviceNo;
			p.data =data;
			/*優先バッファへの格納処理*/
			DebugPrintf("in P QUEUE");
			P_FLAG = TRUE;
			p_enqueue(p);
			
		}else{
			n.size=size;
	              n.tno =deviceNo;
			n.data =data;
			/*ノーマルバッファへの格納処理*/
			n_enqueue(n);
			DebugPrintf("in N QUEUE");
			
		}
	
		

		
	}
	return 0;
}


/*バッファから取り出した後に使用するパケット解析関数*/
int AnalyzePacket(int deviceNo,u_char *data,int size)
{
u_char	*ptr;
int	lest;

 
struct ether_header	*eh;
char	buf[80];
int	tno;
u_char	hwaddr[6];


	ptr=data;
	lest=size;

	
	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);

		struct iphdr	*iphdr;
		u_char	option[1500];
		int	optionLen;

		if(lest<sizeof(struct iphdr)){
			DebugPrintf("[%d]:lest(%d)<sizeof(struct iphdr)\n",deviceNo,lest);
			return(-1);
		}
		iphdr=(struct iphdr *)ptr;
		ptr+=sizeof(struct iphdr);
		lest-=sizeof(struct iphdr);

		optionLen=iphdr->ihl*4-sizeof(struct iphdr);
		if(optionLen>0){
			if(optionLen>=1500){
				DebugPrintf("[%d]:IP optionLen(%d):too big\n",deviceNo,optionLen);
				return(-1);
			}
			memcpy(option,ptr,optionLen);
			ptr+=optionLen;
			lest-=optionLen; 
		}

		if(checkIPchecksum(iphdr,option,optionLen)==0){
			DebugPrintf("[%d]:bad ip checksum\n",deviceNo);
fprintf(stderr,"IP checksum error\n");
			return(-1);
		}

		if(iphdr->ttl-1==0){
			DebugPrintf("[%d]:iphdr->ttl==0 error\n",deviceNo);
			SendIcmpTimeExceeded(deviceNo,eh,iphdr,data,size);
			return(-1);
		}
		//送信先へのインタフェース番号の取得
		tno=(!deviceNo);
		




                /*送信されてきたパケットがネットワークインタフェースに対応したセグメントと一致している場合*/
		if((iphdr->daddr&Device[tno].netmask.s_addr)==Device[tno].subnet.s_addr){
			IP2MAC	*ip2mac;

			DebugPrintf("[%d]:%s to TargetSegment\n",deviceNo,in_addr_t2str(iphdr->daddr,buf,sizeof(buf)));
			
			if(iphdr->daddr==Device[tno].addr.s_addr){
				DebugPrintf("[%d]:recv:myaddr\n",deviceNo);
				return(1);
			}

			ip2mac=Ip2Mac(tno,iphdr->daddr,NULL);
			/*Arpテーブルを調べた結果、送信対象パケットのMACアドレスがテーブルに存在しない時の処理*/
			if(ip2mac->flag==FLAG_NG||ip2mac->sd.dno!=0){
				DebugPrintf("[%d]:Ip2Mac:error or sending\n",deviceNo);
				return(-1);
				
			}

			else{
				memcpy(hwaddr,ip2mac->hwaddr,6);
			}
		}
		else{
			IP2MAC	*ip2mac;

			DebugPrintf("[%d]:%s to NextRouter\n",deviceNo,in_addr_t2str(iphdr->daddr,buf,sizeof(buf)));

			ip2mac=Ip2Mac(tno,NextRouter.s_addr,NULL);
		
			if(ip2mac->flag==FLAG_NG||ip2mac->sd.dno!=0){
				DebugPrintf("[%d]:Ip2Mac:error or sending\n",deviceNo);
				//AppendSendData(ip2mac,1,NextRouter.s_addr,data,size);
				return(-1);
			}
			else{
				memcpy(hwaddr,ip2mac->hwaddr,6);
			}
		}

		/*最終的な宛先MACアドレスの書き換え。*/
		memcpy(eh->ether_dhost,hwaddr,6);
		//発信元のMACアドレスを発信するインタフェースのMACアドレスに
		memcpy(eh->ether_shost,Device[tno].hwaddr,6);

		iphdr->ttl--;
		iphdr->check=0;
		iphdr->check=checksum2((u_char *)iphdr,sizeof(struct iphdr),option,optionLen);
		
		/*writeの第二引数はポインタ*/
		write(Device[tno].soc,data,size);
		//DebugPrintf("Sendpacket");
	

	return(0);
}


/*優先キューに入っているデータを1個取り出して送信する関数*/

int p_dequeue(){
	
	P_QUEUE x;
	
	int deviceNO;
	u_char *data;
	int	size;
	
	p_deq_point=next(p_deq_point);
	
	x=p_queue[p_deq_point];
	if(x.flag !=1){
		//printf("can't not deque queue is empty");
		P_FLAG = FALSE;
		return 1;
	}
	else{
	
		
		deviceNO = x.tno;
		data=x.data;
		size=x.size; 
		/*P_QUEUE型のdeq_dataをAnalyzepaket関数に送信する*/
		AnalyzePacket(deviceNO,data,size);
		
		x.flag =0;
	       p_queue[p_deq_point]=x;
		
		return 0;
	}

		
}




/*ノーマルキューに入っているデータを1個取り出して送信する関数*/

int n_dequeue(){
	
	
	N_QUEUE x;
	
	int deviceNO;
	u_char *data;
	int	size;
	n_deq_point =next(n_deq_point);
	
	
	x=n_queue[n_deq_point];
	if(x.flag !=1){
		//DebugPrintf("can't not deque queue is empty");
		return 1;
	}
	else{

		deviceNO = x.tno;
		data=x.data;
		size=x.size; 

		
		AnalyzePacket(deviceNO,data,size);
	
		
		 x.flag =0;
	        n_queue[n_deq_point]=x;
		
		
		return 0;
	}
		
}

/*キューの送信の大本の関数。優先キューのチェックも行う。*/

int check_queue_transmit(){

	DebugPrintf("BufferSend:start\n");
  	while(EndFlag==0){
		
		
		while(1){
		//GetSendQueData関数でqueueの先頭を確保、そして送信先情報を引数でもらった構造体ポインタに格納
			
			int i;
			for(i=0;i<100;i++){
				
			}
			
			if(EndFlag==1){
				break;
			}
			else {
				if((p_dequeue())==1){
			
					if(P_FLAG==FALSE){
						n_dequeue();
					}
				}
			
			}

			
		}
		
 	 }
	return(0);
}



/*送信スレッド起動の大本*/

void *BufThread(void *arg){

	check_queue_transmit();

	return(NULL);

}

/*デバッグプリント表示関数*/
int DebugPerror(char *msg)
{
	if(Param.DebugOut){
		fprintf(stderr,"%s : %s\n",msg,strerror(errno));
	}

	return(0);
}



int Router()
{
struct pollfd	targets[2];
int	nready,i,size;

/*パケットデータ格納バッファ*/
 static u_char	buf[100000000];

	targets[0].fd=Device[0].soc;
	targets[0].events=POLLIN|POLLERR;
	targets[1].fd=Device[1].soc;
	targets[1].events=POLLIN|POLLERR;

	while(EndFlag==0){
		switch(nready=poll(targets,2,100)){
			case	-1:
				if(errno!=EINTR){
					DebugPerror("poll");
				}
				break;
			case	0:
				break;
			default:
				for(i=0;i<2;i++){
					if(targets[i].revents&(POLLIN|POLLERR)){
						
						if((size=read(Device[i].soc,buf,sizeof(buf)))<=0){
							DebugPerror("read");
						}
						else{
							//一回のreadで読み込まれるのは70~90バイト（ping送信時）
							Pre_AnalyzePacket(i,buf,size);
						}
					}
				}
		}
	}
	return(0);
}



int DisableIpForward()
{
FILE    *fp;

	if((fp=fopen("/proc/sys/net/ipv4/ip_forward","w"))==NULL){
		DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
		return(-1);
	}
	fputs("0",fp);
	fclose(fp);

	return(0);
}



void EndSignal(int sig)
{
	EndFlag=1;
}

pthread_t	BufTid;

int main(int argc,char *argv[],char *envp[])
{
char	buf[80];
pthread_attr_t	attr;
int	status;


	inet_aton(Param.NextRouter,&NextRouter);
	DebugPrintf("NextRouter=%s\n",my_inet_ntoa_r(&NextRouter,buf,sizeof(buf)));

	if(GetDeviceInfo(Param.Device1,Device[0].hwaddr,&Device[0].addr,&Device[0].subnet,&Device[0].netmask)==-1){
		DebugPrintf("GetDeviceInfo:error:%s\n",Param.Device1);
		return(-1);
	}
	if((Device[0].soc=InitRawSocket(Param.Device1,0,0))==-1){
		DebugPrintf("InitRawSocket:error:%s\n",Param.Device1);
		return(-1);
	}
	DebugPrintf("%s OK\n",Param.Device1);
	DebugPrintf("addr=%s\n",my_inet_ntoa_r(&Device[0].addr,buf,sizeof(buf)));
	DebugPrintf("subnet=%s\n",my_inet_ntoa_r(&Device[0].subnet,buf,sizeof(buf)));
	DebugPrintf("netmask=%s\n",my_inet_ntoa_r(&Device[0].netmask,buf,sizeof(buf)));

	if(GetDeviceInfo(Param.Device2,Device[1].hwaddr,&Device[1].addr,&Device[1].subnet,&Device[1].netmask)==-1){
		DebugPrintf("GetDeviceInfo:error:%s\n",Param.Device2);
		return(-1);
	}
	if((Device[1].soc=InitRawSocket(Param.Device2,0,0))==-1){
		DebugPrintf("InitRawSocket:error:%s\n",Param.Device1);
		return(-1);
	}
	DebugPrintf("%s OK\n",Param.Device2);
	DebugPrintf("addr=%s\n",my_inet_ntoa_r(&Device[1].addr,buf,sizeof(buf)));
	DebugPrintf("subnet=%s\n",my_inet_ntoa_r(&Device[1].subnet,buf,sizeof(buf)));
	DebugPrintf("netmask=%s\n",my_inet_ntoa_r(&Device[1].netmask,buf,sizeof(buf)));

	DisableIpForward();

	/*送信用スレッドの作成*/
	pthread_attr_init(&attr);
	if((status=pthread_create(&BufTid,NULL,BufThread,NULL))!=0){
		DebugPrintf("pthread_create:%s\n",strerror(status));
	}
	/*設定したシグナルハンドラ*/
	signal(SIGINT,EndSignal);
	signal(SIGTERM,EndSignal);
	signal(SIGQUIT,EndSignal); 

	signal(SIGPIPE,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);

	DebugPrintf("router start\n");
	/*キューの初期化処理*/
	init_p_queue();
	init_n_queue();
	////////////////////////////////////////////////////////////////////////////////////
	Router();
	/////////////////////////////////////////////////////////////////////////////////////
	DebugPrintf("router end\n");

	pthread_join(BufTid,NULL);

	close(Device[0].soc);
	close(Device[1].soc);

	return(0);
	
}
