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

#ifndef FN_ERROR_H // one-time include
#define FN_ERROR_H


typedef int32_t FN_STATUS;


#define FN_SUCCESS 0 ///< Success flag for use in MAKE_FN_STATUS
#define FN_FAILURE 1 ///< Failure flag for use in MAKE_FN_STATUS

#define MAKE_FN_STATUS( successFlag, facility, code ) ( (FN_STATUS)(((unsigned long)(successFlag)<<31) | ((unsigned long)(facility)<<16) | ((unsigned long)(code))) )


#define SUCCEEDED(Status) ((FN_STATUS)(Status) >= 0)
#define FAILED(Status) ((FN_STATUS)(Status) < 0)


/****************************************
*    Facility Codes
*    For use in creating FN_STATUS values through the MAKE_FN_STATUS macro
*/
#define FN_FAC_NULL 0 
#define FN_FAC_CONFIG 1
#define FN_FAC_PACKET 2
#define FN_FAC_STATE 3


/****************************************
*    STATUS CODES 
*/
#define FN_S_OK MAKE_FN_STATUS( FN_SUCCESS, FN_FAC_NULL, 0 ) ///< Generic success code
#define FN_E_FAIL MAKE_FN_STATUS( FN_FAILURE, FN_FAC_NULL, 1 ) ///< Generic failure code
#define FN_E_NULLPOINTER MAKE_FN_STATUS( FN_FAILURE, FN_FAC_NULL, 2 ) ///< Null Pointer error
#define FN_E_UNDEFINED MAKE_FN_STATUS( FN_FAILURE, FN_FAC_NULL, 3 ) ///< Used to initialize error codes.  Should never be returned


#define FN_E_INVALID_CONFIG MAKE_FN_STATUS( FN_FAILURE, FN_FAC_CONFIG, 1 ) ///< Invalid configuration data
#define FN_S_HELP_REQUESTED MAKE_FN_STATUS( FN_SUCCESS, FN_FAC_CONFIG, 2 ) ///< User requested help screen

#define FN_E_INVALID_PROTOCOL MAKE_FN_STATUS( FN_FAILURE, FN_FAC_PACKET, 1 ) ///< Packet/Protocol mismatch

#define FN_E_NO_MAP_FOUND MAKE_FN_STATUS( FN_FAILURE, FN_FAC_STATE, 1 ) ///< No NAT map found


#endif
