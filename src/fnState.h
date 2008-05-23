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

#ifndef FN_FNSTATE_H // one-time include
#define FN_FNSTATE_H

#include <list>
#include <vector>
#include <map>

#include "fnPacket.h"
#include "fn_error.h"
#include "structures.h"


class fnState
{
   public:
        static fnState* getInstance();
        ~fnState();
        
        FN_STATUS getOutBoundMap(const udp_packet_tuple& udp, nat_map_entry& map);
        FN_STATUS getOutBoundMap(const tcp_packet_tuple& tcp, nat_map_entry& map);
        FN_STATUS getOutBoundMap(const icmp_packet_tuple& icmp, nat_map_entry& map);
        
        FN_STATUS createOutBoundMap(const fnPacket& packet, nat_map_entry& map);
        
        FN_STATUS getInBoundMap(const udp_packet_tuple& udp, nat_map_entry& map);
        FN_STATUS getInBoundMap(const tcp_packet_tuple& tcp, nat_map_entry& map);
        FN_STATUS getInBoundMap(const icmp_packet_tuple& icmp, nat_map_entry& map);

	
    protected:
    	fnState(); ///< Protected constructor prevents creation of object my non-members
        static fnState* s_Instance; ///< The singleton instance
	
	private:
	
		unsigned short getFreeTCPPort();
		unsigned short getFreeUDPPort(const unsigned short old);
		
		void duplicateMap(const nat_map_entry &src, nat_map_entry &dest);
	
		std::list<nat_map_entry*> m_mapsUDP;
		std::list<nat_map_entry*> m_mapsTCP;
		std::list<nat_map_entry*> m_mapsICMP;
		
		std::map<unsigned short,bool> m_mapUDPPorts;
		std::map<unsigned short,bool> m_mapTCPPorts;

};

#endif
