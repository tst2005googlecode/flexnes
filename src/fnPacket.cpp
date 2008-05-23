#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <libnet.h>


#include "fnPacket.h"


/**
* @brief Constructor for fnPacket class
* 
* @detailed Creates a new packet object based on a packet from libipq
* 
* @param nfa [IN] packet reference from libipq

*/
fnPacket::fnPacket(struct nfq_data *nfa)
{
	m_nfData = nfa;
	u_int32_t ifi;
	char	buf[IF_NAMESIZE];

	m_nPacketDataLen = nfq_get_payload(m_nfData, (char**)&m_pPacketData);

	
	ifi = nfq_get_indev(m_nfData);
	if (ifi)
	{
		if (if_indextoname(ifi, buf))
		{
			m_strInboundInterface.clear();
			m_strInboundInterface = buf;
		}
	}

	ifi = nfq_get_outdev(m_nfData);
	if (ifi)
	{
		if (if_indextoname(ifi, buf))
		{
			m_strOutboundInterface.clear();
			m_strOutboundInterface = buf;
		}
	}

}

/**
* @brief Destructor for fnState class
* 
* @detailed Doesn't do anything yet.
*/
fnPacket::~fnPacket()
{
	
}


/**
* @brief The getNetfilterID function provides the Netfliter ID for this packet
* 
* @detailed The netfilter ID is used to inform the kernel what action to take with this packet
* 
* @return The netfilter ID
*/

const int fnPacket::getNetfilterID() const
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
		
	ph = nfq_get_msg_packet_hdr(m_nfData);
	if (ph)
	{
		id = ntohl(ph->packet_id);
	}
	
	return id;
}

/**
* @brief The send function sends the packet based on its internal information
* 
* @detailed The packet is sent out of its outbound interface
* 
* @return Status of packet send.
*
* @retval FN_E_FAIL Packet not sent
* @retval FN_S_OK Packet sent

*/

FN_STATUS fnPacket::send()
{
	FN_STATUS ret = FN_E_UNDEFINED;
	libnet_t *l;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t ip_ptag = 0;
    int count;
    std::string strOutboundInterface;
    
    l = libnet_init(LIBNET_RAW4,(char*)m_strOutboundInterface.c_str(),errbuf);

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        ret = FN_E_FAIL;
    }
    else
    {
    	//printf("Sending out %s\n",m_strOutboundInterface.c_str());
    	ret = FN_S_OK;
    }


	if (SUCCEEDED(ret))
	{
		// Build packet
		
		// Advance pointer past any options headers.
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		
		ip_ptag = libnet_build_ipv4(
			LIBNET_IPV4_H + ntohs(m_pPacketData->nPacketLength) - this->getPacketHeaderLength(),                  /* length */
			m_pPacketData->flagsTOS,		/* TOS */
			this->getFragmentID(),			/* IP fragment ID */
			this->getFragmentFlags(),		/* IP Frag flags*/
			m_pPacketData->TTL,				/* TTL */
			m_pPacketData->nProtocol,		/* protocol */
			0,								/* checksum (let libnet calculate) */
			m_pPacketData->srcIP.raw,		/* source IP */
			m_pPacketData->dstIP.raw,		/* destination IP */
			pData,							/* payload */
			ntohs(m_pPacketData->nPacketLength) - this->getPacketHeaderLength(),                                  /* payload size */
			l,								/* libnet handle */
			ip_ptag);						/* libnet id */
			
			
		if (ip_ptag == -1)
		{
			fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
			ret = FN_E_FAIL;
		}
		else
		{
			ret = FN_S_OK;
		}
		
		// TODO: Add IP options (if any)
		
	
		if (SUCCEEDED(ret))
		{
			// Write to network
			
			count = libnet_write(l);
			if (count == -1)
			{
				fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
				ret = FN_E_FAIL;
			}
			else
			{
			//	fprintf(stderr, "Wrote %d byte IP packet\n", count);
				ret = FN_S_OK;

			}
		}
		
	
		libnet_destroy(l);
	}

	return ret;
}

/**
* @brief Debug function that prvides a text dump of the packet.
*/
void fnPacket::dump()
{
	printf("\tInbound interface: %s\n",m_strInboundInterface.c_str());
	printf("\tOutbound interface: %s\n",m_strOutboundInterface.c_str());
//	printf("\n");
	
//	printf("\tPacket Version: %d\n",(m_pPacketData->nVersionLength & 0xF0 ) >> 4);
//	printf("\tPacket Header Length: %d\n",(m_pPacketData->nVersionLength & 0x0F) << 2);
//	printf("\tTOS flags: 0x%02X\n",m_pPacketData->flagsTOS);
//	printf("\tFrag flags: 0x%02X\n",this->getFragmentFlags());
//	printf("\tPacket Length: %d\n",ntohs(m_pPacketData->nPacketLength));

	// TODO: these two printfs will break if Network order != Host order
	printf("\tSource IP: %d.%d.%d.%d\n",
		m_pPacketData->srcIP.octet[0],
		m_pPacketData->srcIP.octet[1],
		m_pPacketData->srcIP.octet[2],
		m_pPacketData->srcIP.octet[3]);
	
	printf("\tDestination IP: %d.%d.%d.%d\n",
		m_pPacketData->dstIP.octet[0],
		m_pPacketData->dstIP.octet[1],
		m_pPacketData->dstIP.octet[2],
		m_pPacketData->dstIP.octet[3]);
		
	if (this->getProtocol() == PROTO_ICMP)
	{
		printf("\tICMP Packet\n");
	}
	else if (this->getProtocol() == PROTO_UDP)
	{
//		printf("\tUDP Packet\n");

		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		udpPacket* udp = (udpPacket*)pData;
		
		printf("\tUDP Source Port: %d\n",ntohs(udp->srcPort));
		printf("\tUDP Destination Port: %d\n",ntohs(udp->dstPort));
		
		calcUDPchecksum();

	}
	else if (this->getProtocol() == PROTO_TCP)
	{
//		printf("\tTCP Packet\n");
		
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		tcpPacket* tcp = (tcpPacket*)pData;
		
		printf("\tTCP Source Port: %d\n",ntohs(tcp->srcPort));
		printf("\tTCP Destination Port: %d\n",ntohs(tcp->dstPort));
	}
	else
	{
		printf("\tUnknown Protocol\n");
	}
	
		
	//printf("L3 data\n");
	//this->dumpMem(m_pPacketData->data,ntohs(m_pPacketData->nPacketLength) - this->getPacketHeaderLength());
}

/**
* @brief Provides copy of packet source destination info - ICMP version
* 
* @detailed Copies the ICMP data into the parameter
* 
* @return Status of packet info.
*
* @retval FN_E_INVALID_PROTOCOL Invalid protocol requested
* @retval FN_S_OK Data set

*/
FN_STATUS fnPacket::getPacketTuple(icmp_packet_tuple &tuple) const
{
	FN_STATUS ret = FN_E_INVALID_PROTOCOL;
	
	if (this->getProtocol() == PROTO_ICMP)
	{
		tuple.src_ip = this->getSourceIP();
		tuple.dest_ip = this->getDestinationIP();
		
		ret = FN_S_OK;
	}
	
	return ret;
}

/**
* @brief Provides copy of packet source destination info - UDP version
* 
* @detailed Copies the UDP data into the parameter
* 
* @return Status of packet info.
*
* @retval FN_E_INVALID_PROTOCOL Invalid protocol requested
* @retval FN_S_OK Data set

*/
FN_STATUS fnPacket::getPacketTuple(udp_packet_tuple &tuple) const
{
	FN_STATUS ret = FN_E_INVALID_PROTOCOL;

	
	if (this->getProtocol() == PROTO_UDP)
	{
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		udpPacket* udp = (udpPacket*)pData;

		tuple.src_ip = this->getSourceIP();
		tuple.dest_ip = this->getDestinationIP();
		tuple.src_port = ntohs(udp->srcPort);
		tuple.dest_port = ntohs(udp->dstPort);
		
		ret = FN_S_OK;
	}
	
	return ret;
}

/**
* @brief Provides copy of packet source destination info - TCP version
* 
* @detailed Copies the TCP data into the parameter
* 
* @return Status of packet info.
*
* @retval FN_E_INVALID_PROTOCOL Invalid protocol requested
* @retval FN_S_OK Data set

*/
FN_STATUS fnPacket::getPacketTuple(tcp_packet_tuple &tuple) const
{
	FN_STATUS ret = FN_E_INVALID_PROTOCOL;

	
	if (this->getProtocol() == PROTO_TCP)
	{
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		tcpPacket* tcp = (tcpPacket*)pData;

		tuple.src_ip = this->getSourceIP();
		tuple.dest_ip = this->getDestinationIP();
		tuple.src_port = ntohs(tcp->srcPort);
		tuple.dest_port = ntohs(tcp->dstPort);
		
		ret = FN_S_OK;
	}
	
	return ret;
}

/**
* @brief Sets source and destination information of packet - ICMP version
* 
* @detailed Copies the ICMP data from the parameter to the packet
* 
* @return Status of packet info.
*
* @retval FN_E_INVALID_PROTOCOL Invalid protocol requested
* @retval FN_S_OK Data set

*/
FN_STATUS fnPacket::setPacketTuple(const icmp_packet_tuple &tuple)
{
	FN_STATUS ret = FN_E_INVALID_PROTOCOL;
	
	if (this->getProtocol() == PROTO_ICMP)
	{
		m_pPacketData->srcIP.raw = htonl(tuple.src_ip);
		m_pPacketData->dstIP.raw = htonl(tuple.dest_ip);
		
		this->calcIPchecksum();
		ret = FN_S_OK;
	}
	
	return ret;
}

/**
* @brief Sets source and destination information of packet - UDP version
* 
* @detailed Copies the UDP data from the parameter to the packet
* 
* @return Status of packet info.
*
* @retval FN_E_INVALID_PROTOCOL Invalid protocol requested
* @retval FN_S_OK Data set

*/
FN_STATUS fnPacket::setPacketTuple(const udp_packet_tuple &tuple)
{
	FN_STATUS ret = FN_E_INVALID_PROTOCOL;
	
	if (this->getProtocol() == PROTO_UDP)
	{
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		udpPacket* udp = (udpPacket*)pData;

		
		m_pPacketData->srcIP.raw = htonl(tuple.src_ip);
		m_pPacketData->dstIP.raw = htonl(tuple.dest_ip);
		
		udp->srcPort = htons(tuple.src_port);
		udp->dstPort = htons(tuple.dest_port);
		
		
		this->calcUDPchecksum();
		this->calcIPchecksum();
		
		ret = FN_S_OK;
	}

	
	return ret;
}

/**
* @brief Sets source and destination information of packet - TCP version
* 
* @detailed Copies the TCP data from the parameter to the packet
* 
* @return Status of packet info.
*
* @retval FN_E_INVALID_PROTOCOL Invalid protocol requested
* @retval FN_S_OK Data set

*/
FN_STATUS fnPacket::setPacketTuple(const tcp_packet_tuple &tuple)
{
	FN_STATUS ret = FN_E_INVALID_PROTOCOL;
	
	if (this->getProtocol() == PROTO_TCP)
	{
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		tcpPacket* tcp = (tcpPacket*)pData;

		
		m_pPacketData->srcIP.raw = htonl(tuple.src_ip);
		m_pPacketData->dstIP.raw = htonl(tuple.dest_ip);
		
		tcp->srcPort = htons(tuple.src_port);
		tcp->dstPort = htons(tuple.dest_port);
		
		
		this->calcTCPchecksum();
		this->calcIPchecksum();
		
		ret = FN_S_OK;
	}

	
	return ret;
}




/**
* @brief Returns the IP protocol number
* 
* @return IP protocol
*/
const uint8_t fnPacket::getProtocol() const
{
	return m_pPacketData->nProtocol;
}

/**
* @brief Returns the IP source address in host byte order
* 
* @return source IP address
*/
const uint32_t fnPacket::getSourceIP() const
{
	return ntohl(m_pPacketData->srcIP.raw);
}

/**
* @brief Returns the IP destination address in host byte order
* 
* @return destination IP address
*/
const uint32_t fnPacket::getDestinationIP() const
{
	return ntohl(m_pPacketData->dstIP.raw);
}

/**
* @brief Returns the interface the packet was received on
* 
* @param in [OUT] interface name
*
*/		
void fnPacket::getInboundInterface(std::string & in) const
{
	in = m_strInboundInterface;
}

/**
* @brief Returns the interface the packet will be sent out of
* 
* @param out [OUT] interface name
*
*/	
void fnPacket::getOutboundInterface(std::string & out) const
{
	out = m_strOutboundInterface;
}

/**
* @brief Sets the interface the packet will be sent out of
* 
* @param out [IN] interface name
*
*/	
void fnPacket::setOutboundInterface(const std::string & out)
{
	m_strOutboundInterface = out;
}

/**
* @brief Returns the IP fragment flas
* 
* @return IP fragmentation flags
*/
const uint16_t fnPacket::getFragmentFlags() const
{
	uint16_t data = ntohs(m_pPacketData->nFragFlagsOffset);
	return data & 0xE000;
}


/**
* @brief Returns the IP fragment ID
* 
* @return IP fragmentation ID
*/
const uint16_t fnPacket::getFragmentID() const
{
	uint16_t data = ntohs(m_pPacketData->nFragFlagsOffset);
	return data & 0x1FFF;  // mask out first 3 bits 
}

/**
* @brief Returns the IP header length
* 
* @return IP header length
*/
inline short fnPacket::getPacketHeaderLength() const
{
	return (m_pPacketData->nVersionLength & 0x0F) << 2;
}


/**
* @brief Calculate the IP Header checksum
* 
*/
void fnPacket::calcIPchecksum()
{
	uint32_t sum = 0;
	uint16_t hdrlen = (m_pPacketData->nVersionLength & 0x0F) << 2;
	unsigned char*	data = (unsigned char*)m_pPacketData;
	
//	printf("Old Checksum: 0x%02X\n",m_pPacketData->nHeaderChecksum);
	
	// Reset checksum prior to calculation
	m_pPacketData->nHeaderChecksum = 0;
    
	// make 16 bit words out of every two adjacent 8 bit words in the packet
	// and add them up
	for (uint16_t i = 0; i < hdrlen ;i=i+2)
	{
		uint16_t w = ((data[i]<<8)&0xFF00)+(data[i+1]&0xFF);
		sum = sum + (uint32_t) w;	
	}
	
	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
	  sum = (sum & 0xFFFF) + (sum >> 16);

	// one's complement and we have a new checksum
	m_pPacketData->nHeaderChecksum = htons(~sum);
	
//	printf("New Checksum: 0x%02X\n",m_pPacketData->nHeaderChecksum);

}

/**
* @brief Calculate the UDP Header checksum
* 
*/
void fnPacket::calcUDPchecksum()
{
	
	if (this->getProtocol() == PROTO_UDP)
	{
		uint32_t sum = 0;
		unsigned char* pData = (m_pPacketData->data) + this->getPacketHeaderLength() - LIBNET_IPV4_H;
		udpPacket* udp = (udpPacket*)pData;
		uint16_t len = ntohs(udp->nLength);

//		printf("\tOriginal UDP checksum: 0x%X\n",udp->nChecksum);

		// clear the existing checksum
		udp->nChecksum = 0;
		
		for (uint16_t i = 0; i< len; i+=2)
		{
				sum += pData[i] << 8 & 0xFF00;
				
				if (i+1 < len)
				{
					sum += pData[i+1] & 0xFF;
				}
		}
		
		sum += PROTO_UDP;
		sum += len;
		sum += m_pPacketData->dstIP.octet[0]*256 + m_pPacketData->dstIP.octet[1];
		sum += m_pPacketData->dstIP.octet[2]*256 + m_pPacketData->dstIP.octet[3];
		sum += m_pPacketData->srcIP.octet[0]*256 + m_pPacketData->srcIP.octet[1];
		sum += m_pPacketData->srcIP.octet[2]*256 + m_pPacketData->srcIP.octet[3];
		
		while (sum>>16)
			sum = (sum & 0xFFFF)+(sum >> 16);
			
		udp->nChecksum = htons(~sum);
		
//		printf("\tNew UDP checksum: 0x%X\n",udp->nChecksum);
	}
}

/**
* @brief Calculate the TCP Header checksum
* 
*/
void fnPacket::calcTCPchecksum()
{
	// TODO write this function
}

/**
* @brief Utility function to dump a region of memory
*/
void fnPacket::dumpMem(unsigned char* p,int len)
{
	printf("\t\t------------------------------------------------");
	for (int i = 0 ; i < len; i++ )
	{
		if (i%16==0)
		{
			printf("\n\t\t");
		}
		
		printf( "%02X:", *(p+i));
	}
	
	printf("\n");
	printf("\t\t------------------------------------------------\n");

}

