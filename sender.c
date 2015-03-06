#include "header.h"

pthread_t sender_thread, receive_ack_thread;
char file_name[50];
char static hash_map[MAX_ALLOWED_PACKETS];
pthread_mutex_t hash_map_mutex = PTHREAD_MUTEX_INITIALIZER;
int size_send_file,max_flood =1,number_of_packets,closeflg = 0, recv_file; /*FD for received file*/

/*Global variables for pcap use*/
pcap_t *handle,*rhandle;                         /* packet capture handle */
pcap_t *handle1,*rhandle1;
struct ether_header header;
sniff_ip iph;
char *dev, *base_ptr;
struct timeval start_time,end_time;

int hashMapFunc(char value, int key) {
    return (value >> key) & 0x01;
}

int sender_function()
{
	gettimeofday(&start_time,NULL);
	printf("Start of the FTP Program: %Lf seconds \n",(long double)(start_time.tv_sec*1000000+start_time.tv_usec)/1000000);
	FILE *send_file;
    int result;
    int bit,flag=0;
    struct sockaddr_in serv_addr;
    unsigned int counter;
	int fd = open(file_name,O_RDONLY);
	
	/*To calculate file size*/
    send_file = fopen(file_name,"rb");
    if(send_file == NULL)
        printf("Error: opening file\n");
    fseek(send_file, 0, SEEK_END); // seek to end of file
    size_send_file = ftell(send_file); // get current file pointer
	
	base_ptr = (char*)malloc(size_send_file);
	if(base_ptr  == NULL)
	{		printf("TODO: Malloc failed, switching to non-optimized mode\n");
		exit(0);
	
	}
	/*No of packets*/
    number_of_packets = size_send_file/MAX_PAYLOAD_SIZE + ((size_send_file%MAX_PAYLOAD_SIZE > 0) ? 1:0);
	/*Close the send_file pointer after transmission - f(time)*/
	
	/* Sending data packets */	
	char *seek_ptr;
	
	/*Write the entire file in the buffer. This is 1 window of transmission*/
	/*Loop here for file sizes greater than 2^31 */
	int bytes_read = read(fd,base_ptr,size_send_file);	
	if(bytes_read == 0)
		fprintf(stderr,"Error reading from file \n");
	
    for(counter =0 ; counter<number_of_packets; counter++)
    {  
		if (counter == 0)
		{
			/*Probing link for delay and sharing file size with the other node */
			int file_size_seq=7588;
			memcpy(&iph.ip_id,&file_size_seq,4);		
			char frame[sizeof(struct ether_header)+sizeof(iph)+32+7]; 
			memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
			memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
			memcpy(frame+sizeof(struct ether_header)+sizeof(iph),"LENGTH",7);
			char payload[32];
			sprintf(payload,"%u",size_send_file);
			memcpy(frame+sizeof(struct ether_header)+sizeof(iph)+7,payload,32);
			
			int j;
			for(j=0;j<50;j++)
			{
				if (pcap_inject(handle,frame,32+7+sizeof(struct ether_header)+sizeof(iph))==-1)
				{
					pcap_perror(handle,0);
					pcap_close(handle);
					return -1;
				}
			}
		}
	
	
		memcpy(&iph.ip_id,&counter,4);		
		seek_ptr = base_ptr + counter * MAX_PAYLOAD_SIZE;
		if(counter == number_of_packets - 1)
			result = size_send_file - ((counter) * MAX_PAYLOAD_SIZE);
		else
			result = MAX_PAYLOAD_SIZE;
		iph.ip_len = result;
		
		/*Construct the frame*/
		char frame[sizeof(struct ether_header)+sizeof(iph)+result]; 
		memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
		memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
		memcpy((void*)(frame+sizeof(struct ether_header)+sizeof(iph)),(void*)seek_ptr, result);

		if (pcap_inject(handle,frame,result+sizeof(struct ether_header)+sizeof(iph))==-1)
	    {
			pcap_perror(handle,0);
			pcap_close(handle);
			return -1;
		}
	}
	/*End of 1 window transmission*/
	
	/*Start retransmission (loop till all packets have been ackd)*/
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
				seek_ptr = base_ptr + counter * MAX_PAYLOAD_SIZE;
				if(counter == number_of_packets - 1)
					result = size_send_file - ((counter) * MAX_PAYLOAD_SIZE);		
				else
					result = MAX_PAYLOAD_SIZE;
				iph.ip_len = result;	

				/*Construct frame*/	
				char frame[sizeof(struct ether_header)+sizeof(iph)+result];
				memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
				memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
				memcpy((void*)(frame+sizeof(struct ether_header)+sizeof(iph)),(void*)seek_ptr, result);

				if (pcap_inject(handle,frame,result+sizeof(struct ether_header)+sizeof(iph))==-1) 
				{
					pcap_perror(handle,0);
					pcap_close(handle);
					return -1;
				}
			}
		}
		if(flag == 0)
		{
			/*All packts have been ack'd*/
            break;
        }
	}	
		/*Done with sending*/
		close(fd); 
		char eof[4] ="NULL";
		unsigned int end =  7588;
		memcpy(&iph.ip_id,&end,4);
		char frame[sizeof(struct ether_header)+sizeof(iph)+sizeof(eof)];
		memcpy((void*)frame,(void*)&header,sizeof(struct ether_header));
		memcpy((void*)(frame+sizeof(struct ether_header)),(void*)&iph,sizeof(iph));
		memcpy((void*)(frame+sizeof(struct ether_header)+sizeof(iph)),(void*)eof,4);
        for(counter=0; counter<3 ;counter++)
		{
            if (pcap_inject(handle,frame,result+sizeof(struct ether_header)+sizeof(iph))==-1)
			{
				pcap_perror(handle,0);
				pcap_close(handle);
				return -1;
			}
		}
        gettimeofday(&end_time,NULL);
		/*Clear the buffer*/
		memset(base_ptr, 0, size_send_file);
		fclose(send_file);
        printf("Time taken to send the file: %Lf seconds \n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
		closeflg = 1;
        pthread_exit(0);
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
		packet = pcap_next(rhandle, &header);
		got_packet(&header,packet);
	}
	pthread_exit(0);
}

void recvr_packet(const struct pcap_pkthdr *pheader, const u_char *packet)	    
{
	static int i = 1;
	unsigned int seq_num;
	int length;
	int pkt_chk;
	struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	
	memcpy(&seq_num,(int*)&ip->ip_id,4);
	length = ip->ip_len;
	iph.ip_dst = ip->ip_src;
	char *last_pkt=(char *)packet+34;

	if((strcmp(last_pkt,"NULL")==0) && seq_num == 7588)
	{
		gettimeofday(&end_time,NULL);
		printf("Time taken to receive back the file: %Lf seconds \n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
		printf("Now Writing to a file \n");
		write(recv_file,base_ptr,size_send_file);
		close(recv_file);
		free(base_ptr);
		pcap_close(handle1);
		pcap_close(rhandle1);
		gettimeofday(&end_time,NULL);
		printf("Total Execution Time: %Lf seconds \n",(long double)((end_time.tv_sec*1000000+end_time.tv_usec) - (start_time.tv_sec*1000000+start_time.tv_usec))/1000000);
		exit(0);
	}

	if (ip->ip_tos == '1')
		max_flood = 1;
	else if(ip->ip_tos == '2') 
		max_flood = 2;
	else if(ip->ip_tos == '3')
		max_flood = 3;
	
	char *data = (char *)packet + 34;
	char* seek_ptr = base_ptr + seq_num*MAX_PAYLOAD_SIZE;
	memcpy(seek_ptr,data,length);
	
	
	int flood;
	for(flood =0; flood < max_flood; flood++) 
	{	
		unsigned char frame[sizeof(struct ether_header)+sizeof(iph)+32];
		memcpy(frame,&header,sizeof(struct ether_header));
		memcpy(frame+sizeof(struct ether_header),&iph,sizeof(iph));
		char payload[32];
		sprintf(payload,"%u",seq_num);
		memcpy(frame+sizeof(struct ether_header)+sizeof(iph),payload,32);
		if (pcap_inject(handle1,frame,32+sizeof(struct ether_header)+sizeof(iph))==-1) {
			pcap_perror(handle1,0);
			pcap_close(handle1);
			exit(1);
        }
    }

	return;
}

int main(int argc, char* argv[])
{
	if(argc < 4)
    {
        printf("\n Usage ./<executable> srcFilename ServerIPAddress dstFilename <interface>\n");
        return -1;
    }
	int err;
	handle = pcap_inject_init();
	rhandle = pcap_send_init();
	set_headers();
    strcpy(file_name,argv[1]);
    set_target_ip(&iph, argv[2]);

    err = pthread_create(&sender_thread, NULL, (void *)&sender_function, NULL);
    if(err != 0) 
		perror("Thread creation error");
	err = pthread_create(&receive_ack_thread, NULL,(void *)&receive_ack_function, NULL);
    if(err != 0) 
		perror("Thread creation error");			
	
    /*Wait here till the sender is done reliably sending all packets*/	
    pthread_join(sender_thread, NULL);
	pthread_cancel(receive_ack_thread);
	pcap_close(handle);
	pcap_close(rhandle);
	
	handle1 = pcap_inject_init();
	rhandle1 = pcap_send_init();
	char * dst_name = argv[3];	
	recv_file = open(dst_name,O_CREAT | O_WRONLY | O_TRUNC);	
	if(recv_file < 0)
		printf("Error: opening file\n");
	
	struct pcap_pkthdr header;
	const u_char *packet;		/* The actual packet */
	while(1)
	{
		packet = pcap_next(rhandle1, &header);
		recvr_packet(&header,packet);
	}	
    return 0;
}

