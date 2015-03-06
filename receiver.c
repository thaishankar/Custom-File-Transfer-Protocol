#include "header.h"

pthread_t receive_ack_thread;
/*Global variables for pcap use*/
struct ether_header header;
struct in_addr dest_ip;
sniff_ip iph;
pcap_t *handle,*rhandle;  
pcap_t *handle1,*rhandle1;                       /* packet capture handle */

FILE *new_recv_file,*recv_file;
int fd,result,size_send_file,closeflg = 0,closeflg1 =0, probe_count = 0,max_flood=3;
struct timeval start_time,end_time;
char *dev,* base_ptr,*file_name,max;
long int number_of_packets;
char static hash_map[MAX_ALLOWED_PACKETS];
pthread_mutex_t hash_map_mutex = PTHREAD_MUTEX_INITIALIZER;

int hashMapFunc(char value, int key) 
{
	return (value >> key) & 0x01;
}


void got_packet(const struct pcap_pkthdr *header, const u_char *packet)		
{		
	packet = (char *)packet+34;
	unsigned int ack_seq_num = atol(packet);
	pthread_mutex_lock( &hash_map_mutex );
	hash_map[ack_seq_num/8] |= 1 << ack_seq_num%8;
	pthread_mutex_unlock( &hash_map_mutex );
	return;
}

int receive_ack_function()
{
	struct pcap_pkthdr header;
	const u_char *packet;		/* The actual packet */
	while(closeflg!=1)
	{
		packet = pcap_next(rhandle1, &header);
		got_packet(&header,packet);
	}
	return;
}

int sender_function()
{
	int result;
	int bit,flag=0;		
	struct sockaddr_in serv_addr;
	unsigned int counter;

	number_of_packets = size_send_file/MAX_PAYLOAD_SIZE + ((size_send_file%MAX_PAYLOAD_SIZE > 0) ? 1:0);
	
	/*Send 1 buffer length of data back*/
	for(counter =0 ; counter<number_of_packets; counter++)
	{		
		memcpy(&iph.ip_id,&counter,4);
		char *seek_ptr = base_ptr + counter * MAX_PAYLOAD_SIZE;
		if(counter == number_of_packets - 1)
			result = size_send_file - ((counter) * MAX_PAYLOAD_SIZE);		
		else
			result = MAX_PAYLOAD_SIZE;
			
		iph.ip_len = result;
		iph.ip_tos = max;
		
		/*Construct the frame*/
		char frame[sizeof(struct ether_header)+sizeof(iph)+result]; 
		memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
		memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
		memcpy((void*)(frame+sizeof(struct ether_header)+sizeof(iph)),(void*)seek_ptr, result);
	
		if (pcap_inject(handle1,frame,result+sizeof(struct ether_header)+sizeof(iph))==-1)
		{
			pcap_perror(handle1,0);
			pcap_close(handle1);
			return -1;
		}
	}

	/*Retransmission loop*/
	while(1) 
	{

		flag=0;
		for(counter =0 ; counter<number_of_packets; counter++)
		{
			pthread_mutex_lock( &hash_map_mutex );
			bit = hashMapFunc(hash_map[counter/8],counter%8);
			pthread_mutex_unlock( &hash_map_mutex );
			if(!bit)
			{
				flag = 1;
				memcpy(&iph.ip_id,&counter,4);
				char *seek_ptr = base_ptr + counter * MAX_PAYLOAD_SIZE;
				if(counter == number_of_packets - 1)
					result = size_send_file - ((counter) * MAX_PAYLOAD_SIZE);		
				else
					result = MAX_PAYLOAD_SIZE;
				
				iph.ip_len = result;
				/*Send the frame*/
				char frame[sizeof(struct ether_header)+sizeof(iph)+result];
				memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
				memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
				memcpy((void*)(frame+sizeof(struct ether_header)+sizeof(iph)),(void*)seek_ptr, result);
	
				if (pcap_inject(handle1,frame,result+sizeof(struct ether_header)+sizeof(iph))==-1) 
				{
					pcap_perror(handle1,0);
					pcap_close(handle1);
					return -1;
				}
			}
		}
		if(flag == 0)
		{	
			break;
		}
	}	
	/*Done with retrans. All pkts ack'd*/

	char eof[4] ="NULL";
	unsigned int end =  7588;
	memcpy(&iph.ip_id,&end,4);
	char frame[sizeof(struct ether_header)+sizeof(iph)+sizeof(eof)];
	memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
	memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
	memcpy((void*)(frame+sizeof(struct ether_header)+sizeof(iph)),(void*)eof,4);
	for(counter=0; counter<3 ;counter++)
	{
		if (pcap_inject(handle1,frame,result+sizeof(struct ether_header)+sizeof(iph))==-1)
		{
			pcap_perror(handle1,0);
			pcap_close(handle1);
			return -1;
		}
	}
	gettimeofday(&end_time,NULL);
	printf("Total time taken for receiving and sending back the file: %Lf seconds \n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
	closeflg =1;
	return;
}

void receive_packet(const struct pcap_pkthdr *pheader, const u_char *packet)	    
{
	static int tcount =0;
	if(tcount == 0){
		gettimeofday(&start_time,NULL);
		printf("Start of the FTP Program: %Lf seconds \n",(long double)(start_time.tv_sec*1000000+start_time.tv_usec)/1000000);
		tcount++;
	}	
	
	unsigned int seq_num,length;
	int flood;
	struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	memcpy(&seq_num,(int*)&ip->ip_id,4);
	memcpy(&length,&ip->ip_len,2);
	/*Get dst IP from received packet*/
	iph.ip_dst = ip->ip_src;
	dest_ip = ip->ip_src;
	
	char *last_pkt = (char *)packet+34;
	if((strcmp(last_pkt,"NULL")==0) && seq_num == 7588)
	{
		gettimeofday(&end_time,NULL);
		printf("Time taken for one way file transfer: %Lf seconds\n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
		closeflg1 =1;
		return;
	}
	if((seq_num == 7588) &&(strcmp(packet+34,"LENGTH") == 0))
	{
		if(probe_count == 1)
		{
			base_ptr = (char*) malloc(size_send_file);
			if(base_ptr == NULL)
			{
				printf("Malloc failed\n");
				exit(0);
			}
		}
		size_send_file=atol(packet+34+7);
		probe_count++;
		return;
	}
	
	if(probe_count >= 48){
		max_flood = 1; max = '1';}
	else if(probe_count >= 44 && probe_count < 48 ){
		max_flood = 2; max = '2';}
	else if(probe_count > 0 && probe_count < 44){
		max_flood = 3; max = '3';}
		
	probe_count = 0;
	char *data = (char *)packet + 34;
	char* seek_ptr = base_ptr + seq_num*MAX_PAYLOAD_SIZE;
	memcpy(seek_ptr,data,length);
	
	for(flood =0; flood < max_flood; flood++) 
	{	
		unsigned char frame[sizeof(struct ether_header)+sizeof(iph)+32];
		memcpy(frame,&header,sizeof(struct ether_header));
		memcpy(frame+sizeof(struct ether_header),&iph,sizeof(iph));
		char payload[32];
		sprintf(payload,"%u",seq_num);
		memcpy(frame+sizeof(struct ether_header)+sizeof(iph),payload,32);
		if (pcap_inject(handle,frame,32+sizeof(struct ether_header)+sizeof(iph))==-1) {
			pcap_perror(handle,0);
			pcap_close(handle);
			exit(1);
		}
	}
	return;
}


int main(int argc, char** argv)
{
	if(argc < 2)
	{
		printf("\n Usage ./<executable> dstFilename \n");
		return -1;
	}
	file_name = argv[1];
	handle = pcap_inject_init();
	rhandle = pcap_init();
	set_headers();	
	fd = open(file_name,O_CREAT | O_WRONLY | O_TRUNC);		
	struct pcap_pkthdr header;
	const u_char *packet;		/* The actual packet */
	rhandle = pcap_init();
	while(closeflg1!=1)
	{
		packet = pcap_next(rhandle, &header);
		receive_packet(&header,packet);
	}
	pcap_close(handle);
	pcap_close(rhandle);
	
	handle1 = pcap_inject_init();
	rhandle1 = pcap_init();
	/*CALLING SEND FUNCTIONALITY*/
	iph.ip_dst = dest_ip;
	int err = pthread_create(&receive_ack_thread, NULL,(void *)&receive_ack_function, NULL);
	if(err != 0) 
		perror("Thread creation error");
	sender_function();
	pthread_cancel(receive_ack_thread);
	
	/*Can spawn a thread to parallelize this write*/
	write(fd,base_ptr,size_send_file);
	close(fd);
	free(base_ptr);
	pcap_close(handle1);
	pcap_close(rhandle1);	
	return 0;
}
