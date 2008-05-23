/**
* @file fnOptions.cpp
* @author Jeremy Beker
* @version 
*
* @overview
*/

#include <boost/program_options.hpp>
namespace po = boost::program_options;


#include <iostream>
#include <fstream>
#include <iterator>
using namespace std;

#include <stddef.h>
#include <net/if.h>
#include <resolv.h>
#include <sys/ioctl.h>

#include "fnOptions.h"

// Ensure that the singleton instance always starts out as NULL.
fnOptions* fnOptions::s_Instance = NULL;

/**
* @brief Constructor for the fnOptions class
*/
fnOptions::fnOptions()
{
	m_bInitialized = false;
	
	m_strInternalInterface = "vmnet2";
	m_strExternalInterface = "eth0";
	m_MappingMethod = MAP_INDEPENDENT;
	m_FilterMethod = FILTER_INDEPENDENT;
	m_PortAssignmentMethod = PORT_PRESERVE;
	m_MappingRefreshMethod = REFRESH_BOTH;
	m_PortParity = PARITY_ENABLED;
	m_Hairpinning = HAIRPIN_ALLOW;
	m_ulMappingLifetime = 0;

}

/**
* @brief Deconstructor for the fnOptions class
*/
fnOptions::~fnOptions()
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
fnOptions* fnOptions::getInstance()
{
    if ( s_Instance == NULL )
    {
        s_Instance = new fnOptions();
    }
      
    return s_Instance;
}

/**
* @brief Initializes the fnOptions class from the command line parameters
* 
* @param argc [IN] count of command line arguments
* @param argv [IN] command line arguments
* 
* @return Success or failure of parsing
* 
* @retval FN_S_OK success
* @retval FN_S_HELP_REQUESTED Help was requested
* @retval FN_E_FAIL Failed. Command line option was missing
*/
FN_STATUS fnOptions::initialize(int argc, char* argv[])
{
	FN_STATUS retval = FN_E_UNDEFINED;

	// Set up Command line options
    try 
    {
	    po::options_description config_opts("Configuration");
        config_opts.add_options()
			("help", "This help")
			("internal", po::value<string>()->composing(), "Inside interface")
			("external", po::value<string>()->composing(), "External interface")
			("filter_method", po::value<string>()->composing(), "Filter Method [ind|addr|port]")
			("map_method", po::value<string>()->composing(), "Mapping Method [ind|addr|port]")
			("port_assign", po::value<string>()->composing(), "Port Assignment Method [pres|over|none]")
			("port_parity","Port Parity Enforced")
			("hairpin","Hairpinning allowed")
			("map_lifetime", po::value<int>(),"Map Lifetime")
			;
			
		// Parse command line
		
		po::variables_map configuration;
		po::store(po::parse_command_line(argc, argv, config_opts), configuration);
		po::notify(configuration); 
		
		
		if (configuration.count("help")) 
		{
			cout << config_opts << "\n";
			retval = FN_S_HELP_REQUESTED;
		}
		else
		{
			retval = FN_S_OK;
			
			if (configuration.count("internal")) 
			{
				m_strInternalInterface = configuration["internal"].as<string>();
			} 
			else 
			{
				printf("Internal Interface required\n");
				retval = FN_E_FAIL;
			}

			if (configuration.count("external"))
			{
				m_strExternalInterface = configuration["external"].as<string>();
			}
			else
			{
				printf("External Interface required\n");
				retval = FN_E_FAIL;
			}

			if (configuration.count("port_parity"))
			{
				m_PortParity = PARITY_ENABLED;
			}
			else
			{
				 m_PortParity = PARITY_DISABLED;
			}

			if (configuration.count("hairpin"))
			{
				m_Hairpinning = HAIRPIN_ALLOW;
			}
			else
			{
				m_Hairpinning = HAIRPIN_DISABLE;
			}
			
			if (configuration.count("map_lifetime"))
			{
				m_ulMappingLifetime = configuration["map_lifetime"].as<int>();
			}


			if (configuration.count("filter_method"))
			{
				if(configuration["filter_method"].as<string>() == "ind")
				{
					m_FilterMethod = FILTER_INDEPENDENT;
				}
				else if (configuration["filter_method"].as<string>() == "addr")
				{
					m_FilterMethod = FILTER_ADDRESS_DEPENDENT;
				}
				else if (configuration["filter_method"].as<string>() == "port")
				{
					m_FilterMethod = FILTER_ADDRESS_PORT_DEPENDENT;
				}
				else
				{
					printf("Invalid Filter Method: [ind|addr|port]\n");
					retval = FN_E_FAIL;
				}

			}
			else
			{
				printf("Filter Method Required\n");
				retval = FN_E_FAIL;
			}
			
			if (configuration.count("port_assign"))
			{
				if(configuration["port_assign"].as<string>() == "pres")
				{
					m_PortAssignmentMethod = PORT_PRESERVE;
				}
				else if (configuration["port_assign"].as<string>() == "over")
				{
					m_PortAssignmentMethod = PORT_OVERLOAD;
				}
				else if (configuration["port_assign"].as<string>() == "none")
				{
					m_PortAssignmentMethod = PORT_NONE;
				}
				else
				{
					printf("Invalid Port Preservation Method: [pres|over|none]\n");
					retval = FN_E_FAIL;
				}

			}
			else
			{
				printf("Port Preservation Method Required\n");
				retval = FN_E_FAIL;
			}
		
			if (configuration.count("map_method"))
			{
				if(configuration["map_method"].as<string>() == "ind")
				{
					m_MappingMethod = MAP_INDEPENDENT;
				}
				else if (configuration["map_method"].as<string>() == "addr")
				{
					m_MappingMethod = MAP_ADDRESS_DEPENDENT;
				}
				else if (configuration["map_method"].as<string>() == "port")
				{
					m_MappingMethod = MAP_ADDRESS_PORT_DEPENDENT;
				}
				else
				{
					printf("Invalid Mapping Method: [ind|addr|port]\n");
					retval = FN_E_FAIL;
				}

			}
			else
			{
				printf("Filter Method Required\n");
				retval = FN_E_FAIL;
			}
		}
	}
	catch (exception &e)
	{
		cout << e.what() << "\n";
        retval = FN_E_INVALID_CONFIG;
	}
	
	return retval;
	
}


/**
 * @brief Provides the name of the external interface
 *
 * @param interface [OUT] Name of interface
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */

FN_STATUS fnOptions::getInternalInterface(std::string &interface)
{
	FN_STATUS retval = FN_S_OK;
	
	interface = m_strInternalInterface;

	return retval;
}


/**
 * @brief Provides the ip address of the internal interface
 * 
 * @param ip [OUT] Internal IP address 
 * 
 * @return Success or failure
 * 
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getInternalIP(uint32_t &ip)
{
	FN_STATUS retval = FN_E_UNDEFINED;

	int fd;
	struct ifreq ifr; 
	struct sockaddr_in saddr;

	fd=socket(PF_INET,SOCK_STREAM,0);
	strcpy(ifr.ifr_name,m_strInternalInterface.c_str());
	ioctl(fd,SIOCGIFADDR,&ifr);
	saddr=*((struct sockaddr_in *)(&(ifr.ifr_addr))); /* is the address */
	
	ip = ntohl(saddr.sin_addr.s_addr);

	return retval;
}

/**
 * @brief Provides the ip address of the external interface
 *
 * @param ip [OUT] External IP address
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getExternalIP(uint32_t &ip)
{
	FN_STATUS retval = FN_E_UNDEFINED;

	int fd;
	struct ifreq ifr; 
	struct sockaddr_in saddr;

	fd=socket(PF_INET,SOCK_STREAM,0);
	strcpy(ifr.ifr_name,m_strExternalInterface.c_str());
	ioctl(fd,SIOCGIFADDR,&ifr);
	saddr=*((struct sockaddr_in *)(&(ifr.ifr_addr))); /* is the address */
	
	ip = ntohl(saddr.sin_addr.s_addr);


	return retval;
}

/**
 * @brief Provides the name of the external interface
 *
 * @param interface [OUT] External interface name 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getExternalInterface(std::string &interface)
{
	FN_STATUS retval = FN_S_OK;

	interface = m_strExternalInterface;

	return retval;
}

/**
 * @brief Provides the mapping method in use
 *
 * @param method [OUT] Mapping method 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getMappingMethod(MAPPING_METHOD &method)
{
	FN_STATUS retval = FN_S_OK;

	method = m_MappingMethod;
	
	return retval;
}

/**
 * @brief Provides the filtering method in use
 *
 * @param method [OUT] filtering method 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getFilterMethod(FILTER_METHOD &method)
{
	FN_STATUS retval = FN_S_OK;

	method = m_FilterMethod;
	
	return retval;
}

/**
 * @brief Provides the port assignment method in use
 *
 * @param method [OUT] port mapping method 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getPortAssigmentMethod(PORT_ASSIGNMENT_METHOD &method)
{
	FN_STATUS retval = FN_S_OK;

	method = m_PortAssignmentMethod;
 
	return retval;
}

/**
 * @brief Returns if hairpinning is enabled
 *
 * @param hairpin [OUT] Hairpin enabled/disabled 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getHairpinning(HAIRPIN & hairpin)
{
	FN_STATUS retval = FN_S_OK;
	hairpin = m_Hairpinning;
	return retval;
}

/**
 * @brief Provides the mapping refresh method in use
 *
 * @param method [OUT] Mapping refresh method 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getMapRefreshMethod(MAPPING_REFRESH_METHOD &method)
{
	FN_STATUS retval = FN_S_OK;

	method = m_MappingRefreshMethod;
 
	return retval;
}

/**
 * @brief Provides the port parity method in use
 *
 * @param parity [OUT] Port parity method 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getPortParity(PORT_PARITY &parity)
{
	FN_STATUS retval = FN_S_OK;

	parity = m_PortParity;
 
	return retval;
}

/**
 * @brief Provides the mapping lifetime in use
 *
 * @param lifetime [OUT] Mapping lifetime 
 *
 * @return Success or failure
 *
 * @retval FN_S_OK success
 */
FN_STATUS fnOptions::getMappingLifetime(time_t &lifetime)
{
	FN_STATUS retval = FN_S_OK;

	lifetime = m_ulMappingLifetime;

	return retval;
}




