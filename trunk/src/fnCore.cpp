/**
* @file fnCore.cpp
* @author Jeremy Beker
* @version 
*
* @overview
*/

#include <stddef.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "structures.h"
#include "fnCore.h"
#include "fnOptions.h"
#include "fnState.h"

// Ensure that the singleton instance always starts out as NULL.
fnCore* fnCore::s_Instance = NULL;

/**
* @brief Constructor for the fnCore class
*/
fnCore::fnCore()
{
}

/**
* @brief Deconstructor for the fnCore class
*/
fnCore::~fnCore()
{
 
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
fnCore* fnCore::getInstance()
{
    if ( s_Instance == NULL )
    {
        s_Instance = new fnCore();
    }
      
    return s_Instance;
}

/**
* @brief Packet handler callback
* 
* @detailed Callback function for received packets.  Immediately passes packet 
* to fnCore::processPacket
* 
* @param qh [IN] Netfilter handle
* @param nfmsg [IN]
* @param nfa [IN] packet data
* @param data [IN] unused
* 
*/
static int packet_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	fnCore* core = fnCore::getInstance();
	return core->processPacket(qh,nfmsg,nfa,data);
}

/**
* @brief Core packet handling loop
* 
* @detailed Main program logic for packet handling.  Implements a process control
* loop which manages the identification and transformation of all packets
* 
* @param qh [IN] Netfilter handle
* @param nfmsg [IN]
* @param nfa [IN] packet data
* @param data [IN] unused
* 
*/
int fnCore::processPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	CORE_PCL_STATES state = PCL_DETERMINE_DIRECTION;
	bool bProcessing = true;
	int ret;
	fnPacket packet(nfa);
	fnOptions *pOptions = fnOptions::getInstance();
	fnState *pState = fnState::getInstance();
	nat_map_entry MapEntry;


	printf("--------------- NEW PACKET ----------------------------------\n");

	while (bProcessing)
	{
		switch (state)
		{
			case PCL_DETERMINE_DIRECTION:
			{
				std::string strExternalInterface;
				std::string strInternalInterface;
				std::string strPacketReceivedInterface;
				
				pOptions->getExternalInterface(strExternalInterface);
				pOptions->getInternalInterface(strInternalInterface);
				packet.getInboundInterface(strPacketReceivedInterface);
				
				
				if (strPacketReceivedInterface == strExternalInterface)
				{
					printf("** Packet received on external interface\n");
					state = PCL_FIND_INBOUND_MAP;
				}
				else if (strPacketReceivedInterface == strInternalInterface)
				{
					printf("** Packet received on internal interface\n");
					state = PCL_FIND_OUTBOUND_MAP;
				}
				else
				{
					printf("** Packet received from unknown interface %s\n",strPacketReceivedInterface.c_str());
					state = PCL_ERROR;
				}

				packet.dump();

			}
			break;
			
		
			
			case PCL_FIND_OUTBOUND_MAP:	// Looks up map to transform packet on way out
			{
				printf("** Process outbound packet\n");
				
				switch (packet.getProtocol())
				{
					case PROTO_ICMP:
						state = PCL_TRANSFORM_OUTBOUND_ICMP;
						break;
					
					case PROTO_UDP:
						{
							FN_STATUS ret;
							udp_packet_tuple tuple;

							packet.getPacketTuple(tuple);

							ret = pState->getOutBoundMap(tuple,MapEntry);
					
							if (SUCCEEDED(ret))
							{
								printf(" * Found existing NAT map entry \n");
								state = PCL_TRANSFORM_OUTBOUND_UDP;
							}
							else if (ret == FN_E_NO_MAP_FOUND)
							{
								ret = pState->createOutBoundMap(packet,MapEntry);
								
								if (SUCCEEDED(ret))
								{
									printf(" * Created new NAT map entry \n");

									state = PCL_TRANSFORM_OUTBOUND_UDP;
								}
								else
								{
									printf(" * Couldn't create map\n");
									state = PCL_ERROR;
								}
							}
							else
							{
								printf(" * Couldn't find or create map\n");
								state = PCL_ERROR;
							}
					
							
						}
						break;
						
					case PROTO_TCP:
					default:
						printf("** Unsupported protocol: %d\n",packet.getProtocol());
						state = PCL_DROP_PACKET;
						break;
				}			
			}
			break;
			
			
			case PCL_FIND_INBOUND_MAP:	// Looks up map to transform packet on way back in	
			{
				printf("** Process inbound packet\n");
				
				switch (packet.getProtocol())
				{
					case PROTO_ICMP:
						state = PCL_TRANSFORM_OUTBOUND_ICMP;
						break;
					
					case PROTO_UDP:
						{
							FN_STATUS ret;
							udp_packet_tuple tuple;

							packet.getPacketTuple(tuple);

							ret = pState->getInBoundMap(tuple,MapEntry);
					
							if (SUCCEEDED(ret))
							{
								printf(" * Found existing NAT map entry\n");
								state = PCL_TRANSFORM_INBOUND_UDP;
							}
							else
							{
								printf(" * No existing NAT map entry exists\n");
								state = PCL_DROP_PACKET;
							}
						}
						break;
						
					case PROTO_TCP:
					default:
						printf(" * Unsupported protocol: %d\n",packet.getProtocol());
						state = PCL_DROP_PACKET;
						break;
				}			
			}
			break;
			
			
			
			case PCL_TRANSFORM_OUTBOUND_ICMP:	// Apply map to ICMP packet
			{
				printf("** Transform outbound ICMP packet\n");
				packet.setOutboundInterface(MapEntry.out_interface);
				packet.setPacketTuple(MapEntry.outside_icmp);
				
				state = PCL_VERIFY_DESTINATION;
			
			}
			break;


			case PCL_TRANSFORM_OUTBOUND_UDP:	// Apply map to UDP packet
			{
				printf("** Transform outbound UDP packet\n");
				packet.setOutboundInterface(MapEntry.out_interface);
				packet.setPacketTuple(MapEntry.outside_udp);
				
				state = PCL_VERIFY_DESTINATION;
			
			}
			break;
			
			case PCL_TRANSFORM_OUTBOUND_TCP:	// Apply map to TCP packet
			{
				printf("** Transform outbound TCP packet\n");
				packet.setOutboundInterface(MapEntry.out_interface);
				packet.setPacketTuple(MapEntry.outside_tcp);
				
				state = PCL_VERIFY_DESTINATION;
			
			}
			break;
			
			//  INBOUND TRANSFORMS
			
			case PCL_TRANSFORM_INBOUND_ICMP:	// Apply map to ICMP packet
			{
				printf("** Transform inbound ICMP packet\n");
				packet.setOutboundInterface(MapEntry.out_interface);
				packet.setPacketTuple(MapEntry.inside_icmp);
				
				state = PCL_SEND_PACKET;
			
			}
			break;


			case PCL_TRANSFORM_INBOUND_UDP:	// Apply map to UDP packet
			{
				printf("** Transform inbound UDP packet\n");
				packet.setOutboundInterface(MapEntry.out_interface);
				packet.setPacketTuple(MapEntry.inside_udp);
				
				state = PCL_SEND_PACKET;
			
			}
			break;
			
			
			case PCL_TRANSFORM_INBOUND_TCP:	// Apply map to UDP packet
			{
				printf("** Transform inbound TCP packet\n");
				packet.setOutboundInterface(MapEntry.out_interface);
				packet.setPacketTuple(MapEntry.inside_tcp);
				
				state = PCL_SEND_PACKET;
			}
			break;
			
			case PCL_VERIFY_DESTINATION:// Check to see if hairpinning rule needs apply
			{
				printf("** Verify outbound destination for hairpinning\n");
				fnOptions *pOptions = fnOptions::getInstance();
				HAIRPIN hairpin;
				uint32_t external_addr;
				uint32_t destination_addr;
				
				pOptions->getHairpinning(hairpin);
				
				// get destination address of packet
				
				destination_addr = packet.getDestinationIP();
				pOptions->getExternalIP(external_addr);
				
				// if address matches external interface address
				if (destination_addr == external_addr)
				{
				
					// if hairpinning enabled, remap packet
					if (hairpin == HAIRPIN_ALLOW)
					{
						printf(" * Hairpin detected - remapping\n");
						state = PCL_FIND_INBOUND_MAP;	
					}
					else  // else drop it.
					{
						printf(" * Attempted Hairpin detected - dropping\n");
						state = PCL_DROP_PACKET;
					}
				}
				else
				{
					state = PCL_SEND_PACKET;
				}
			}
			break;
			
			case PCL_SEND_PACKET:		// Send the packet
			{
				FN_STATUS status;
				// Send packet out new interface

				printf("** Retransmitting packet\n");
				packet.dump();

				status = packet.send();
				
				// Drop it out of netfilter_queue
				ret = nfq_set_verdict(qh, packet.getNetfilterID(), NF_DROP, 0, NULL); 
				state = PCL_DONE;
			}
			break;
			
			case PCL_DROP_PACKET:		// Drop the packet
			{
				printf("** Dropping packet\n");
				ret = nfq_set_verdict(qh, packet.getNetfilterID(), NF_DROP, 0, NULL); 
				state = PCL_DONE;
			}
			break;
			
			
			case PCL_DONE:				// Done processing this packet, wait for a new one
			{
				bProcessing = false;
			}
			break;
			
			case PCL_ERROR:				// Something bad happened
			{
				printf("** Error\n");
				bProcessing = false;
			}
			break;
			
			default:
				printf("Invalid state\n");
		
		}
	}

	return ret;
}

/**
* @brief fnCore entry point
* 
* @detailed Loops over all incoming packets and dispatches them to the packet handler
* 
*/
FN_STATUS fnCore::executeNAT()
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096];

	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		return FN_E_FAIL;
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		return FN_E_FAIL;
	}

	qh = nfq_create_queue(h,  0, &packet_callback, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		return FN_E_FAIL;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		return FN_E_FAIL;
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	nfq_destroy_queue(qh);

	nfq_close(h);

	return FN_S_OK;

}

