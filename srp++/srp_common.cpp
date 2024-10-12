#include "srp_common.h"
#include "srp_gn.h"

SRP::CSRPCommon::CSRPCommon(const EHashAlgorithm algorithm, const ENGType type)
	: m_eHashAlgorithm(algorithm), m_eNGType(type)
{
	SetupNG();
}

void SRP::CSRPCommon::SetupNG()
{
	BIGNUM* N = BN_new();
	if (!BN_hex2bn(&N, g_NGConstants[(int)m_eNGType].nHex.data()))
		throw srp_runtime_error("CSRPCommon::SetupNG failed to generate 'N'");
	m_pBnPrime_N = BIGNUM_ptr(N, ::BN_free);

	BIGNUM* p = BN_new();
	if (!BN_hex2bn(&p, g_NGConstants[(int)m_eNGType].gHex.data()))
		throw srp_runtime_error("CSRPCommon::SetupNG failed to generate 'g'");
	m_pBnGenerator_g = BIGNUM_ptr(p, ::BN_free);
}
