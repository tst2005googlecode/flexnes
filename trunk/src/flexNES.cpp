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
