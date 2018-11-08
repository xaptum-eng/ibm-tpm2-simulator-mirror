/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriCryptPri.c 141 2015-03-16 17:08:34Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

/* rev 122 */

// B.6	CpriCryptPri.c
// B.6.1.	Introduction

// This file contains the interface to the initialization, startup and shutdown functions of the
// crypto library.

// B.6.2. Includes and Locals

#include "OsslCryptoEngine.h"
NORETURN static void Trap(const char *function, int line, int code);
FAIL_FUNCTION       TpmFailFunction = (FAIL_FUNCTION)&Trap;

// B.6.3.	Functions
// B.6.3.1.	TpmFail()

// This is a shim function that is called when a failure occurs. It simply relays the call to the
// callback pointed to by TpmFailFunction(). It is only defined for the sake of specifier
// that cannot be added to a function pointer with some compilers.

/* kgold, commented, since there's another in // 9.15.4.2	TpmFail() */
#if 0
NORETURN void
TpmFail(
	const char          *function,
	int                  line,
	int                  code)
{
    TpmFailFunction(function, line, code);
}
#endif

// B.6.3.2.	FAILURE_TRAP()
// This function is called if the caller to _cpri__InitCryptoUnits() doesn't provide a call back address.

NORETURN static void
Trap(
     const char      *function,
     int              line,
     int              code
     )
{
    NOT_REFERENCED(function);
    NOT_REFERENCED(line);
    NOT_REFERENCED(code);
    abort();
}

// B.6.3.3.	_cpri__InitCryptoUnits()

// This function calls the initialization functions of the other crypto modules that are part of the
// crypto engine for this implementation. This function should be called as a result of
// _TPM_Init(). The parameter to this function is a call back function it TPM.lib that is called
// when the crypto engine has a failure.

LIB_EXPORT CRYPT_RESULT
_cpri__InitCryptoUnits(
		       FAIL_FUNCTION    failFunction
		       )
{
    TpmFailFunction = failFunction;
    
    _cpri__RngStartup();
    _cpri__HashStartup();
    _cpri__SymStartup();
    
#ifdef TPM_ALG_RSA
    _cpri__RsaStartup();
#endif
    
#ifdef TPM_ALG_ECC
    _cpri__EccStartup();
#endif
    
    return CRYPT_SUCCESS;
}

// B.6.3.4.	_cpri__StopCryptoUnits()

// This function calls the shutdown functions of the other crypto modules that are part of the
// crypto engine for this implementation.

LIB_EXPORT void
_cpri__StopCryptoUnits(
		       void
		       )
{
    return;
}

// B.6.3.5.	_cpri__Startup()

// This function calls the startup functions of the other crypto modules that are part of the crypto
// engine for this implementation. This function should be called during processing of
// TPM2_Startup().

LIB_EXPORT BOOL
_cpri__Startup(
	       void
	       )
{
    
    return(   _cpri__HashStartup()
	      && _cpri__RngStartup()
#ifdef TPM_ALG_RSA
	      && _cpri__RsaStartup()
#endif // TPM_ALG_RSA
#ifdef TPM_ALG_ECC
	      && _cpri__EccStartup()
#endif // TPM_ALG_ECC
	      && _cpri__SymStartup());
}
