/**
* @file fnState.cpp
* @author Jeremy Beker
* @version 
*
* @overview
*/

#include <arpa/inet.h>
#include <stddef.h>
#include "fnState.h"
#include "fnOptions.h"

// Ensure that the singleton instance always starts out as NULL.
fnState* fnState::s_Instance = NULL;

/**
* @brief Constructor for fnState class
* 
* @detailed Populates free port lists
* 
* @post
* - m_availUDPPorts is populated
* - m_availTCPPorts is populated
*/
fnState::fnState()
{
	for (unsigned short i=0;i< 1024;i++)
	{
		m_mapUDPPorts[i] = false;
		m_mapTCPPorts[i] = false;
	}
	
	for (unsigned short i=1024;i< 65535 ;i++)
	{
		m_mapUDPPorts[i] = true;
		m_mapTCPPorts[i] = true;
	}
	
	// TODO: remove reserved ports from configuration

}

/**
* @brief Destructor for fnState class
* 
* @detailed Deletes all of the map entries that have been created
* 
* @post
* - m_mapsUDP is empty
* - m_mapsTCP is empty
* - m_mapsICMP is empty
*/
fnState::~fnState()
{
 	for(std::list<nat_map_entry *>::iterator i=m_mapsUDP.begin();
		i != m_mapsUDP.end(); i++ )
	{
		nat_map_entry * pEntry = *i;
		m_mapsUDP.erase(i);
		delete pEntry;
	}

	for(std::list<nat_map_entry *>::iterator i=m_mapsTCP.begin();
		i != m_mapsTCP.end(); i++ )
	{
		nat_map_entry * pEntry = *i;
		m_mapsTCP.erase(i);
		delete pEntry;
	}
	for(std::list<nat_map_entry *>::iterator i=m_mapsICMP.begin();
		i != m_mapsICMP.end(); i++ )
	{
		nat_map_entry * pEntry = *i;
		m_mapsICMP.erase(i);
		delete pEntry;
	}


}

/**
* @brief The getInstance function provides access to the singleton instance of the class
* 
* @detailed This class is defined as a singleton so there is exactly one instance of the class throughout the calling program.  This class
*           should never be created by the calling program through new.  It should only be accessed by the getInstance method to get
*           a pointer to the singleton instance.
* 
* @post
* - A non-null pointer to the singleton instance is returned
* 
* @return A non-null pointer to the singleton instance
*/
fnState* fnState::getInstance()
{
    if ( s_Instance == NULL )
    {
        s_Instance = new fnState();
    }
      
    return s_Instance;
}

/**
* @brief Returns a free UDP port based on configuration rules
* 
* @detailed Based on the rules specified by the user, return the next available UDP port
* 
* @return A UDP port number
*/
unsigned short fnState::getFreeUDPPort(const unsigned short old)
{
	fnOptions *pOptions = fnOptions::getInstance();
	unsigned short ret;
	PORT_ASSIGNMENT_METHOD port_method;
	PORT_PARITY parity_method;
	
	pOptions->getPortAssigmentMethod(port_method);
	pOptions->getPortParity(parity_method);

	switch(port_method)
	{
		// if we can preserve the old port number, do so, otherwise fall through
		case PORT_PRESERVE:
		{
			if (m_mapUDPPorts[old])
			{
				m_mapUDPPorts[old] = false;
				ret = old;
				break;
			}
		}
		
		case PORT_NONE:
		{
			unsigned short base = 0;
			unsigned short inc = 1;
			
			if (parity_method == PARITY_ENABLED)
			{
				base = old%2?1:0;  // old is even, set base to 0, otherwise 1
				inc = 2;
			}
		
			for (unsigned short i=base;i< 65535 ;i+=inc)
			{
				if (m_mapUDPPorts[i])
				{
					m_mapUDPPorts[i] = false;
					ret = i;
					break;
				}
			}
			break;
		}
	
		case PORT_OVERLOAD:
			ret = old;
			break;
	}

	return ret;
}

/**
* @brief Returns a free TCP port based on configuration rules
* 
* @detailed Based on the rules specified by the user, return the next available TCP port
* 
* @return A TCP port number
*/
unsigned short fnState::getFreeTCPPort()
{
	for (unsigned short i=0;i< 65535 ;i++)
	{
		if (m_mapTCPPorts[i])
		{
			m_mapTCPPorts[i] = false;
			return i;
		}
	}
	
	return 0;
}

/**
* @brief getOutBoundMap returns an existing outbound map - UDP version
* 
* @detailed getOutBoundMap takes a packet that is being investigated and returns an
*			outbound map (if it exists) that can be used to transform the packet.
* 
* @param udp [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_NO_MAP_FOUND No existing maps were found
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/
FN_STATUS fnState::getOutBoundMap(const udp_packet_tuple& udp, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_NO_MAP_FOUND;
	fnOptions *pOptions = fnOptions::getInstance();
	std::list<nat_map_entry *>::iterator iterEntry;
	
	for(std::list<nat_map_entry *>::iterator i=m_mapsUDP.begin();
		i != m_mapsUDP.end() && ret == FN_E_NO_MAP_FOUND;
		i++ )
	{
		nat_map_entry * pEntry = *i;
		
		if (pEntry->protocol != PROTO_UDP)
		{
			ret = FN_E_INVALID_PROTOCOL;
		}
		else
		{
			MAPPING_METHOD method;
			pOptions->getMappingMethod(method);
			
			switch (method)
			{
				case MAP_INDEPENDENT:
				{
					if (pEntry->inside_udp.src_ip == udp.src_ip && 
						pEntry->inside_udp.src_port == udp.src_port)
					{
						//printf("fnState::getOutBoundMap: Found existing map\n");
		
						duplicateMap(*pEntry,map);
		
						map.inside_udp.dest_ip = udp.dest_ip;
						map.inside_udp.dest_port = udp.dest_port;
		
						map.outside_udp.dest_ip = udp.dest_ip;
						map.outside_udp.dest_port = udp.dest_port;
		
						iterEntry = i;
		
						ret = FN_S_OK;
					}
				}
				break;
				
				case MAP_ADDRESS_DEPENDENT:
				{
					if (pEntry->inside_udp.src_ip == udp.src_ip && 
						pEntry->inside_udp.src_port == udp.src_port &&
						pEntry->outside_udp.dest_ip == udp.dest_ip)
					{
						//printf("fnState::getOutBoundMap: Found existing map\n");
		
						duplicateMap(*pEntry,map);
		
						map.inside_udp.dest_ip = udp.dest_ip;
						map.inside_udp.dest_port = udp.dest_port;
		
						map.outside_udp.dest_ip = udp.dest_ip;
						map.outside_udp.dest_port = udp.dest_port;
		
						iterEntry = i;

						ret = FN_S_OK;
					}
				}
				break;

				case MAP_ADDRESS_PORT_DEPENDENT:
				{
					if (pEntry->inside_udp.src_ip == udp.src_ip && 
						pEntry->inside_udp.src_port == udp.src_port &&
						pEntry->outside_udp.dest_ip == udp.dest_ip &&
						pEntry->outside_udp.dest_port == udp.dest_port)
					{
						//printf("fnState::getOutBoundMap: Found existing map\n");
		
						duplicateMap(*pEntry,map);
		
						map.inside_udp.dest_ip = udp.dest_ip;
						map.inside_udp.dest_port = udp.dest_port;
		
						map.outside_udp.dest_ip = udp.dest_ip;
						map.outside_udp.dest_port = udp.dest_port;
		
						iterEntry = i;

						ret = FN_S_OK;
					}
				}
				break;
				default:
					break;		
			}
			
		}
	
	}
	
	// Check timestamp on map if we found one.
	
	if (SUCCEEDED(ret))
	{
		time_t current;
		time_t max;
		MAPPING_REFRESH_METHOD method;
			
		// get current time
		current = time(NULL);

		// get max lifetime and refresh method from options
		pOptions->getMappingLifetime(max);
		pOptions->getMapRefreshMethod(method);

		// if map age is less than max 

		//printf ("time difference: %d\n", (int)(current - map.activity));

		if (current - map.activity < max)
		{
			// if  mode is update on outbound, update timestamp
			if (method == REFRESH_BOTH || method == REFRESH_OUT)
			{
				//printf("fnState::getOutBoundMap: map timestamp updated\n");
				map.activity = current;	
			}
			else
			{
				//printf("fnState::getOutBoundMap: map timestamp NOT updated\n");
			}
		}
		else
		{
			printf("fnState::getOutBoundMap: map expired\n");
			// free up port
			m_mapUDPPorts[map.outside_udp.src_port] = true;
		
			// delete map, change return code
			m_mapsUDP.erase(iterEntry);
			ret = FN_E_NO_MAP_FOUND;
		}
	}
	
	return ret;
}

/**
* @brief getOutBoundMap returns an existing outbound map - TCP version
* 
* @detailed getOutBoundMap takes a packet that is being investigated and returns an
*			outbound map (if it exists) that can be used to transform the packet.
* 
* @param udp [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_NO_MAP_FOUND No existing maps were found
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/
FN_STATUS fnState::getOutBoundMap(const tcp_packet_tuple& udp, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_NO_MAP_FOUND;
	
	return ret;
}

/**
* @brief getOutBoundMap returns an existing outbound map - ICMP version
* 
* @detailed getOutBoundMap takes a packet that is being investigated and returns an
*			outbound map (if it exists) that can be used to transform the packet.
* 
* @param udp [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_NO_MAP_FOUND No existing maps were found
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/
FN_STATUS fnState::getOutBoundMap(const icmp_packet_tuple& udp, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_NO_MAP_FOUND;
	
	return ret;
}

/**
* @brief getInBoundMap generates a map to transform an inbound packet - UDP version
* 
* @detailed Generate a new map based upon an existing map to transform the 
*			inbound packet to an internal packet.
* 
* @param udp [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_NO_MAP_FOUND No existing maps were found
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/
FN_STATUS fnState::getInBoundMap(const udp_packet_tuple& udp, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_NO_MAP_FOUND;
	fnOptions *pOptions = fnOptions::getInstance();
	std::list<nat_map_entry *>::iterator iterEntry;



	for(std::list<nat_map_entry *>::iterator i=m_mapsUDP.begin();
		i != m_mapsUDP.end() && ret == FN_E_NO_MAP_FOUND;
		i++ )
	{
		// TODO make compare based on filter configuration
		
		nat_map_entry * pEntry = *i;

		if (pEntry->protocol != PROTO_UDP)
		{
			ret = FN_E_FAIL;
		}
		else
		{
			FILTER_METHOD method;
			pOptions->getFilterMethod(method);

			switch (method)
			{
				case FILTER_INDEPENDENT:
				{
					// Endpoint-Independant Filtering
					if (pEntry->outside_udp.src_ip == udp.dest_ip && 
						pEntry->outside_udp.src_port == udp.dest_port)
					{
						//printf("fnState::getInBoundMap: Found existing map\n");

						duplicateMap(*pEntry,map);

						// Update map entry with specific info
				
						// Swap interfaces
						map.out_interface = pEntry->in_interface;
						map.in_interface = pEntry->out_interface;
				
						// The new destination should be the original src
						map.inside_udp.dest_ip = map.inside_udp.src_ip;
						map.inside_udp.dest_port = map.inside_udp.src_port;
					
						// New source should be the actual source of the packet
						map.inside_udp.src_ip = udp.src_ip;
						map.inside_udp.src_port = udp.src_port;
	
						iterEntry = i;
						
						ret = FN_S_OK;
					}
				}
				break;
				
				case FILTER_ADDRESS_DEPENDENT:
				{
					if (pEntry->outside_udp.src_ip == udp.dest_ip && 
						pEntry->outside_udp.src_port == udp.dest_port &&
						pEntry->outside_udp.dest_ip == udp.src_ip)
					{
						//printf("fnState::getInBoundMap: Found existing map\n");

						duplicateMap(*pEntry,map);

						// Update map entry with specific info
				
						// Swap interfaces
						map.out_interface = pEntry->in_interface;
						map.in_interface = pEntry->out_interface;
				
						// The new destination should be the original src
						map.inside_udp.dest_ip = map.inside_udp.src_ip;
						map.inside_udp.dest_port = map.inside_udp.src_port;
					
						// New source should be the actual source of the packet
						map.inside_udp.src_ip = udp.src_ip;
						map.inside_udp.src_port = udp.src_port;
	
						iterEntry = i;
							
						ret = FN_S_OK;
					}
				}
				break;
				
				case FILTER_ADDRESS_PORT_DEPENDENT:
				{
					// Endpoint-Independant Filtering
					if (pEntry->outside_udp.src_ip == udp.dest_ip && 
						pEntry->outside_udp.src_port == udp.dest_port &&
						pEntry->outside_udp.dest_ip == udp.src_ip &&
						pEntry->outside_udp.dest_port == udp.src_port)
					{
						//printf("fnState::getInBoundMap: Found existing map\n");

						duplicateMap(*pEntry,map);

						// Update map entry with specific info
				
						// Swap interfaces
						map.out_interface = pEntry->in_interface;
						map.in_interface = pEntry->out_interface;
				
						// The new destination should be the original src
						map.inside_udp.dest_ip = map.inside_udp.src_ip;
						map.inside_udp.dest_port = map.inside_udp.src_port;
					
						// New source should be the actual source of the packet
						map.inside_udp.src_ip = udp.src_ip;
						map.inside_udp.src_port = udp.src_port;
	
						iterEntry = i;
						
						ret = FN_S_OK;
					}
				}
				break;
				
				default:
					break;
			}	
		}
	
	}
	
	// Check timestamp on map if we found one.
	
	if (SUCCEEDED(ret))
	{
		time_t current;
		time_t max;
		MAPPING_REFRESH_METHOD method;
			
		// get current time
		current = time(NULL);

		// get max lifetime and refresh method from options
		pOptions->getMappingLifetime(max);
		pOptions->getMapRefreshMethod(method);

	//	printf ("time difference: %d max: %d\n", (int)(current - map.activity),(int)max);


		// if map age is less than max 
		if (current - map.activity < max)
		{
			// if  mode is update on outbound, update timestamp
			if (method == REFRESH_BOTH || method == REFRESH_IN)
			{
				//printf("fnState::getInBoundMap: map timestamp updated\n");
				map.activity = current;	
			}
			else
			{
				//printf("fnState::getInBoundMap: map timestamp NOT updated\n");
			}
		}
		else
		{
			//printf("fnState::getInBoundMap: map expired\n");
			// free up port
			m_mapUDPPorts[map.outside_udp.src_port] = true;
		
			// delete map, change return code
			m_mapsUDP.erase(iterEntry);
			ret = FN_E_NO_MAP_FOUND;
		}
	}
	
	return ret;
}

/**
* @brief getInBoundMap generates a map to transform an inbound packet - TCP version
* 
* @detailed Generate a new map based upon an existing map to transform the 
*			inbound packet to an internal packet.
* 
* @param udp [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_NO_MAP_FOUND No existing maps were found
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/
FN_STATUS fnState::getInBoundMap(const tcp_packet_tuple& udp, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_NO_MAP_FOUND;
	
	return ret;
}

/**
* @brief getInBoundMap generates a map to transform an inbound packet - ICMP version
* 
* @detailed Generate a new map based upon an existing map to transform the 
*			inbound packet to an internal packet.
* 
* @param udp [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_NO_MAP_FOUND No existing maps were found
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/
FN_STATUS fnState::getInBoundMap(const icmp_packet_tuple& udp, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_NO_MAP_FOUND;
	
	return ret;
}

/**
* @brief createOutBoundMap generates a map to transform based on a new packet
* 
* @detailed Generate a new map based upon an outbound packet to transform the 
*			inside packet to an outside packet.
* 
* @param packet [IN] Packet to be sent
* @param map [OUT] Resultant map to be filled in
* 
* @return Status of map search
* 
* @retval FN_E_INVALID_PROTOCOL Invalid protocol
* @retval FN_S_OK Map found and copied to out param
*/

FN_STATUS fnState::createOutBoundMap(const fnPacket& packet, nat_map_entry& map)
{
	FN_STATUS ret = FN_E_UNDEFINED;
	
	fnOptions *pOptions = fnOptions::getInstance();
	nat_map_entry *pEntry = new nat_map_entry;
	
	switch (packet.getProtocol())
	{
		
		case PROTO_UDP:
		{
			// Copy in known information
			pEntry->protocol = PROTO_UDP;
			packet.getPacketTuple(pEntry->inside_udp);
			packet.getInboundInterface(pEntry->in_interface);
			
			// Copy over destination
			pEntry->outside_udp.dest_port = pEntry->inside_udp.dest_port;
			pEntry->outside_udp.dest_ip = pEntry->inside_udp.dest_ip;
			
			// Set new information
			pOptions->getExternalInterface(pEntry->out_interface);
			pOptions->getExternalIP(pEntry->outside_udp.src_ip);
			pEntry->outside_udp.src_port = getFreeUDPPort(pEntry->inside_udp.src_port);
			
			pEntry->activity = time(NULL);

			m_mapsUDP.push_front(pEntry);
			duplicateMap(*pEntry,map);
			ret = FN_S_OK;
			
		}
		break;
			
		case PROTO_TCP:
		case PROTO_ICMP:

		default:
			ret = FN_E_INVALID_PROTOCOL;
			printf("Unsupported protocol: %d\n",packet.getProtocol());
			break;
	}		
	
	
	
	return ret;
}

/**
* @brief duplicateMap copies a map entry to a new structure
* 
* @detailed Generate a new map based upon an outbound packet to transform the 
*			inside packet to an outside packet.
* 
* @param src [IN] Map to be copied
* @param dest [OUT] copy of src
* 
*/

void fnState::duplicateMap(const nat_map_entry &src, nat_map_entry &dest)
{
	dest.in_interface = src.in_interface;
	dest.out_interface = src.out_interface;
	dest.protocol = src.protocol;
	dest.activity = src.activity;
	
	switch (src.protocol)
	{
		case PROTO_UDP:
			dest.inside_udp.src_ip = src.inside_udp.src_ip;
			dest.inside_udp.src_port = src.inside_udp.src_port;
			dest.inside_udp.dest_ip = src.inside_udp.dest_ip;
			dest.inside_udp.dest_port = src.inside_udp.dest_port;

			dest.outside_udp.src_ip = src.outside_udp.src_ip;
			dest.outside_udp.src_port = src.outside_udp.src_port;
			dest.outside_udp.dest_ip = src.outside_udp.dest_ip;
			dest.outside_udp.dest_port = src.outside_udp.dest_port;
			break;
			
		case PROTO_TCP:
		case PROTO_ICMP:

		default:
			printf("fnState::duplicateMap: Invalid Map\n");
	
	}

}



