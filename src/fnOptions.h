#ifndef FN_FNOPTIONS_H // one-time include
#define FN_FNOPTIONS_H

#include <string>
#include "fn_error.h"


typedef enum _MAPPING_METHOD
{
	MAP_INDEPENDENT,
	MAP_ADDRESS_DEPENDENT,
	MAP_ADDRESS_PORT_DEPENDENT,
} MAPPING_METHOD;

typedef enum _FILTER_METHOD
{
	FILTER_INDEPENDENT,
	FILTER_ADDRESS_DEPENDENT,
	FILTER_ADDRESS_PORT_DEPENDENT,
} FILTER_METHOD;

typedef enum _PORT_ASSIGNMENT_METHOD
{
	PORT_PRESERVE,
	PORT_OVERLOAD,
	PORT_NONE,
} PORT_ASSIGNMENT_METHOD;

typedef enum _MAPPING_REFRESH_METHOD
{
	REFRESH_NONE,
	REFRESH_IN,
	REFRESH_OUT,
	REFRESH_BOTH,
} MAPPING_REFRESH_METHOD;

typedef enum _PORT_PARITY
{
	PARITY_ENABLED,
	PARITY_DISABLED,
} PORT_PARITY;

typedef enum _HAIRPIN
{
	HAIRPIN_ALLOW,
	HAIRPIN_DISABLE
} HAIRPIN;

class fnOptions
{
   public:
		static fnOptions* getInstance();
		~fnOptions();
	
		FN_STATUS initialize(int argc, char* argv[]);
	
		FN_STATUS getInternalInterface(std::string &interface);
		FN_STATUS getInternalIP(uint32_t &ip);
		FN_STATUS getExternalIP(uint32_t &ip);
		FN_STATUS getExternalInterface(std::string &interface); 
		FN_STATUS getMappingMethod(MAPPING_METHOD &method);
		FN_STATUS getFilterMethod(FILTER_METHOD &method);
		FN_STATUS getPortAssigmentMethod(PORT_ASSIGNMENT_METHOD &method);
		FN_STATUS getMapRefreshMethod(MAPPING_REFRESH_METHOD &method);
		FN_STATUS getPortParity(PORT_PARITY &parity);
		FN_STATUS getMappingLifetime(time_t &lifetime);
		FN_STATUS getHairpinning(HAIRPIN & hairpin);
		       	
    protected:
    	fnOptions(); ///< Protected constructor prevents creation of object my non-members
        static fnOptions* s_Instance; ///< The singleton instance
	
	private:
		bool m_bInitialized;
		
		std::string m_strInternalInterface;
		std::string m_strExternalInterface;
		MAPPING_METHOD m_MappingMethod;
		FILTER_METHOD m_FilterMethod;
		PORT_ASSIGNMENT_METHOD m_PortAssignmentMethod;
		MAPPING_REFRESH_METHOD m_MappingRefreshMethod;
		PORT_PARITY m_PortParity;
		HAIRPIN m_Hairpinning;
		time_t m_ulMappingLifetime;
	
		
		

};

#endif
