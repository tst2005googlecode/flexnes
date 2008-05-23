/*

flexNES - Flexible NAT Emulation Software

Copyright (C) 2008, Jeremy Beker <gothmog@confusticate.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

#ifndef FN_FNPACKET_H // one-time include
#define FN_FNPACKET_H

extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libipq.h>
#include <linux/netfilter.h>
}

#include <string>

#include "fn_error.h"
#include "structures.h"

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef union _ipAddr
{
	uint32_t	raw;
	unsigned char	octet[4];
} ipAddr;

typedef struct _rawPacket
{
	uint8_t		nVersionLength;
	uint8_t		flagsTOS;
	uint16_t	nPacketLength;
	uint16_t	nFragmentID;
	uint16_t	nFragFlagsOffset;
	uint8_t		TTL;
	uint8_t		nProtocol;
	uint16_t	nHeaderChecksum;
	ipAddr		srcIP;
	ipAddr		dstIP;
	
	unsigned char	data[];
} rawPacket;

typedef struct _udpPacket
{
	uint16_t srcPort;
	uint16_t dstPort;
	uint16_t nLength;
	uint16_t nChecksum;

	unsigned char	data[];
} udpPacket;

typedef struct _tcpPacket
{
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t nSeqNum;
	uint32_t nAckId;
	uint32_t nHeaderLenFlags; // Combined header length, Reserved, and flag bits
	uint16_t nWindowSize;
	uint16_t nUrgPtr;
	
	unsigned char	data[];

} tcpPacket;

class fnPacket
{
	public:
	
		fnPacket(struct nfq_data *nfa);
		~fnPacket();
		
		const int getNetfilterID() const;
		const uint32_t getSourceIP() const;
		const uint32_t getDestinationIP() const;
		const uint16_t getFragmentFlags() const;
		const uint16_t getFragmentID() const;
		
		const uint8_t getProtocol() const;
		
		FN_STATUS getPacketTuple(icmp_packet_tuple &tuple) const;
		FN_STATUS getPacketTuple(udp_packet_tuple &tuple) const;
		FN_STATUS getPacketTuple(tcp_packet_tuple &tuple) const;

		FN_STATUS setPacketTuple(const icmp_packet_tuple &tuple);
		FN_STATUS setPacketTuple(const udp_packet_tuple &tuple);
		FN_STATUS setPacketTuple(const tcp_packet_tuple &tuple);

		
		void getInboundInterface(std::string & in) const;
		void getOutboundInterface(std::string & out) const;
		void setOutboundInterface(const std::string & out);
		
		FN_STATUS send();

		
		void dump();
		
		
	protected:
		struct nfq_data* m_nfData;
		rawPacket* m_pPacketData;
		int m_nPacketDataLen;
		std::string	m_strInboundInterface;
		std::string	m_strOutboundInterface;
		
		
		void calcIPchecksum();
		void calcUDPchecksum();
		void calcTCPchecksum();

	
	private:
		void dumpMem(unsigned char* p,int len);
		short getPacketHeaderLength() const;


};

#endif
