#include "header.h"

extern struct ether_header header;
extern sniff_ip iph;
extern char *dev;                       /* capture device name */

/*Init function for pcap - Sets eth frame, IP header and creates a handle*/
pcap_t* pcap_init()
{
	char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
	
	
	char filter_exp[] = "ip and dst host 10.1.2.1 and src host 10.1.1.1";               /* filter expression [3] */
	struct bpf_program fp;                  /* compiled filter program (expression) */
	bpf_u_int32 mask;                       /* subnet mask */
	bpf_u_int32 net;                        /* ip */
	
	
	/* find a capture device if not specified on command-line */
//	dev = pcap_lookupdev(errbuf);
	dev = "eth0";
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
			net = 0;
			mask = 0;
	}
	
	/* print capture info */
	//printf("Device: %s\n", dev);
	//printf("Filter expression: %s\n", filter_exp);
	
	/* open capture device */
	pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
	if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
	}
	
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
	}
	
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
	}
	
	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
	}
	return handle;
}


pcap_t* pcap_send_init()
{
	char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
	
	
	char filter_exp[] = "ip and dst host 10.1.1.1 and src host 10.1.2.1";               /* filter expression [3] */
	struct bpf_program fp;                  /* compiled filter program (expression) */
	bpf_u_int32 mask;                       /* subnet mask */
	bpf_u_int32 net;                        /* ip */
	
	
	/* find a capture device if not specified on command-line */
	//dev = pcap_lookupdev(errbuf);
	dev = "eth0";
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
			net = 0;
			mask = 0;
	}
	
	/* print capture info */
	//pintf("Device: %s\n", dev);
	//pintf("Filter expression: %s\n", filter_exp);
	
	/* open capture device */
	pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
	if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
	}
	
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
	}
	
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
	}
	
	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
	}
	return handle;
}

pcap_t* pcap_inject_init()
{
	dev="eth0";
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0]='\0';
	pcap_t* pcap=pcap_open_live(dev,SNAP_LEN,1,0,pcap_errbuf);
	if (pcap_errbuf[0]!='\0') {
		fprintf(stderr,"%s",pcap_errbuf);
	}
	if (!pcap) {
		exit(1);
	}
	return pcap;
}

void set_target_ip(sniff_ip* iph, char *target_ip_string)
	{
	struct in_addr target_ip_addr={0};
	if (!inet_aton(target_ip_string,&target_ip_addr)) {
	fprintf(stderr,"%s is not a valid IP address",target_ip_string);
	exit(1);
	}
	memcpy(&iph->ip_dst,(void*)&target_ip_addr.s_addr,sizeof(iph->ip_dst));
		
	}

void set_headers()
  {      /*Set headers*/

    header.ether_type=htons(0x0800);
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));
	
    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len=strlen(dev);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,dev,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
        fprintf(stderr,"interface name is too long");
        exit(1);
    }

    // Open an IPv4-family socket for use when calling ioctl.
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        perror(0);
        exit(1);
    }

    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&iph.ip_src,&source_ip_addr->sin_addr.s_addr,sizeof(iph.ip_src));

    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
        fprintf(stderr,"not an Ethernet interface");
        close(fd);
        exit(1);
    }
    //const unsigned char* source_mac_addr= (unsigned char*)&ifr.ifr_hwaddr.sa_data;
    //strcpy(header.ether_shost,source_mac_addr);
    //memcpy(&header.ether_shost,(void*)source_mac_addr,sizeof(header.ether_shost));
  memset(header.ether_shost,0xff,sizeof(header.ether_shost));    
close(fd);
}



