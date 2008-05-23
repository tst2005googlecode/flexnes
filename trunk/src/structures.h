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

#ifndef FN_STRUCTURES_H // one-time include
#define FN_STRUCTURES_H

#include <string>

typedef struct _udp_packet_tuple
{
	uint32_t	src_ip;
	uint16_t	src_port;
	uint32_t	dest_ip;
	uint16_t	dest_port;
} udp_packet_tuple;

typedef struct _tcp_packet_tuple
{
	uint32_t	src_ip;
	uint16_t	src_port;
	uint32_t	dest_ip;
	uint16_t	dest_port;
} tcp_packet_tuple;

typedef struct _icmp_packet_tuple
{
	uint32_t	src_ip;
	uint32_t	dest_ip;
} icmp_packet_tuple;



typedef struct _nat_map_entry
{
//	char		entry_id[64];
	std::string		in_interface;
	std::string		out_interface;
	uint16_t	protocol;
	time_t		activity;
	
	union
	{
		udp_packet_tuple inside_udp;
		tcp_packet_tuple inside_tcp;
		icmp_packet_tuple inside_icmp;
	};
	
	union
	{
		udp_packet_tuple outside_udp;
		tcp_packet_tuple outside_tcp;
		icmp_packet_tuple outside_icmp;
	};
	
	// expiration timestamp
} nat_map_entry;


#endif
