/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriMisc.c 64 2015-02-09 16:33:11Z kgoldman $		*/
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

/* rev 119 */

// B.10	CpriMisc.c
// B.10.1.	Includes

#include "OsslCryptoEngine.h"

// B.10.2.	Functions
// B.10.2.1.	BnTo2B()

// This function is used to convert a BigNum() to a byte array of the specified size.  If the number
// is too large to fit, then 0 is returned. Otherwise, the number is converted into the low-order
// bytes of the provided array and the upper bytes are set to zero.

//     Return Value	Meaning
//     0	failure (probably fatal)
//     1	conversion successful

BOOL
BnTo2B(
       TPM2B           *outVal,        // OUT: place for the result
       BIGNUM          *inVal,         // IN: number to convert
       UINT16           size           // IN: size of the output.
       )
{
    BYTE    *pb = outVal->buffer;
    
    outVal->size = size;
    
    size = size - (((UINT16) BN_num_bits(inVal) + 7) / 8);
    if(size < 0)
	return FALSE;
    for(;size > 0; size--)
	*pb++ = 0;
    BN_bn2bin(inVal, pb);
    return TRUE;
}

// B.10.2.2.	Copy2B()

// This function copies a TPM2B structure. The compiler can't generate a copy of a TPM2B generic
// structure because the actual size is not known. This function performs the copy on any TPM2B
// pair. The size of the destination should have been checked before this call to make sure that it
// will hold the TPM2B being copied.

// This replicates the functionality in the MemoryLib.c.

void
Copy2B(
       TPM2B           *out,           // OUT: The TPM2B to receive the copy
       TPM2B           *in             // IN: the TPM2B to copy
       )
{
    BYTE        *pIn = in->buffer;
    BYTE        *pOut = out->buffer;
    int          count;
    out->size = in->size;
    for(count = in->size; count > 0; count--)
	*pOut++ = *pIn++;
    return;
}

// B.10.2.3.	BnFrom2B()
// This function creates a BIGNUM from a TPM2B and fails if the conversion fails.

BIGNUM *
BnFrom2B(
	 BIGNUM          *out,           // OUT: The BIGNUM
	 const TPM2B     *in             // IN: the TPM2B to copy
	 )
{
    if(BN_bin2bn(in->buffer, in->size, out) == NULL)
	FAIL(FATAL_ERROR_INTERNAL);
    return out;
}
