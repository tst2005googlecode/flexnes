#include <stddef.h>

#include "fnOptions.h"
#include "fnState.h"
#include "fnCore.h"


/**
* @brief Main flexNES entry point
* 
* @detailed Application entry point
* 
* @param argc [IN] count of command line arguments
* @param argv [IN] command line arguments

*/
int main (int argc, char* argv[])
{
	fnOptions* 	options = NULL;
	fnState*	state = NULL;
	fnCore*		core = NULL;
	
	options = fnOptions::getInstance();
	state = fnState::getInstance();
	core = fnCore::getInstance();

	if (options == NULL || state == NULL || core == NULL )
	{
		printf("Failed to initialize\n");
	}
	else
	{
		FN_STATUS err;
		
		err = options->initialize(argc,argv);
	
		if (err == FN_S_HELP_REQUESTED)
		{
			// exit gracefully
			printf("Help requested\n");
		}
		else if (FAILED(err))
		{
			printf("Failed to parse command line\n");
			// Exit with error
		}
		else
		{
			// execute core
			core->executeNAT();
			
			// Clean up
			delete core;
			delete state;
			delete options;
		}
	}
}
