#include "srp_client.h"

#include <cassert>
#include <vector>

namespace SRP
{
CSRPClient::CSRPClient(const EHashAlgorithm algorithm, const ENGType type)
	: CSRPCommon(algorithm, type)
{
}

void CSRPClient::Step1(std::string_view identity, std::string_view password, std::string_view salt, std::string_view privateKey)
{
	SaveIdentity(identity);
	SavePrivateKey(privateKey);
	SaveSalt(salt);

	GeneratePublicKey();
	GenerateSaltedHashedPassword(password);
	GenerateVerifier();
}

void CSRPClient::Step2(std::string_view serverPublicKey)
{
	SaveServerPublicKey(serverPublicKey);

	GenerateVerifierProtector();
	GenerateSecret();
	GenerateSecretHash(m_pBnSecret_S.get());
	GenerateClientEvidence();
}

bool CSRPClient::Step3(std::string_view serverEvidence)
{
	BIGNUM* serverM2tmp = nullptr;
	if (!BN_hex2bn(&serverM2tmp, serverEvidence.data()))
		throw srp_invalid_argument("CSRPClient::Step3 failed to transform serverEvidence to BIGNUM");
	BIGNUM_ptr serverM2(serverM2tmp, ::BN_free);

	GenerateServerEvidence();

	return !BN_cmp(serverM2.get(), m_pBnServerEvidence_M2.get());
}

std::string CSRPClient::GetPublicKey() const
{
	assert(m_pBnPublicKey_A);
	return Bn2HexStr(m_pBnPublicKey_A.get());
}

std::string CSRPClient::GetVerifier() const
{
	assert(m_pBnVerifier_v);
	return Bn2HexStr(m_pBnVerifier_v.get());
}

std::string CSRPClient::GetEvidence() const
{
	assert(m_pBnClientEvidence_M1);
	return Bn2HexStr(m_pBnClientEvidence_M1.get());
}

void CSRPClient::SavePrivateKey(std::string_view aHex)
{
	BIGNUM* a = nullptr;
	if (!BN_hex2bn(&a, aHex.data()))
		throw srp_invalid_argument("CSRPServer::SavePrivateKey failed to transform bHex to BIGNUM");
	SavePrivateKey(a);
}

void CSRPClient::SavePrivateKey(BIGNUM* a)
{
	assert(a);
	m_pBnPrivateKey_a.reset(a);
}

void CSRPClient::SaveSaltedHashedPassword(BIGNUM* x)
{
	assert(x);
	m_pBnSaltedHashedPassword_x.reset(x);
}

void CSRPClient::SaveVerifier(BIGNUM* v)
{
	assert(v);
	m_pBnVerifier_v.reset(v);
}

void CSRPClient::SaveSecret(BIGNUM* S)
{
	assert(S);
	m_pBnSecret_S.reset(S);
}

void CSRPClient::GeneratePublicKey()
{
	assert(m_pBnPrivateKey_a);
	assert(m_pBnPrime_N);
	assert(m_pBnGenerator_g);

	SaveClientPublicKey(Calculate_A(m_pBnPrivateKey_a.get(), m_pBnPrime_N.get(), m_pBnGenerator_g.get()));
}

void CSRPClient::GenerateSaltedHashedPassword(std::string_view P)
{
	assert(!P.empty());
	assert(!m_szIdentity_I.empty());
	assert(m_pBnSalt_s);

	SaveSaltedHashedPassword(Calculate_x(m_szIdentity_I, P, m_pBnSalt_s.get()));
}

void CSRPClient::GenerateVerifier()
{
	assert(m_pBnGenerator_g);
	assert(m_pBnPrime_N);
	assert(m_pBnSaltedHashedPassword_x);

	SaveVerifier(Calculate_v(m_pBnGenerator_g.get(), m_pBnPrime_N.get(), m_pBnSaltedHashedPassword_x.get()));
}

void CSRPClient::GenerateSecret()
{
	assert(m_pBnPrime_N);
	assert(m_pBnPublicKey_B);
	assert(m_pBnSaltedHashedPassword_x);
	assert(m_pBnPrivateKey_a);
	assert(m_pBnVerifierProtector_u);

	SaveSecret(Calculate_S(m_pBnPrime_N.get(), m_pBnPublicKey_B.get(), m_pBnGenerator_g.get(),
		m_pBnSaltedHashedPassword_x.get(), m_pBnPrivateKey_a.get(), m_pBnVerifierProtector_u.get()));


}

BIGNUM* CSRPClient::Calculate_A(const BIGNUM* a, const BIGNUM* N, const BIGNUM* g) const
{
	assert(a);
	assert(N);
	assert(g);

	BN_CTX_ptr ctx(BN_CTX_new(), ::BN_CTX_free);
	if (!ctx)
		throw srp_runtime_error("CSRPClient::Calculate_A failed to create BN_CTX");

	BIGNUM_ptr A(BN_new(), ::BN_free);
	if (!A)
		throw srp_runtime_error("CSRPClient::Calculate_A failed to create A");

	if (!BN_mod_exp(A.get(), g, a, N, ctx.get()))
	{
		throw srp_runtime_error("CSRPClient::Calculate_A failed to calculate A");
	}

	return A.release();
}

BIGNUM* CSRPClient::Calculate_x(std::string_view I, std::string_view P, BIGNUM* s)
{
	assert(!I.empty());
	assert(!P.empty());
	assert(s);

	unsigned int digestLen;
	unsigned char digest[EVP_MAX_MD_SIZE]{};
	EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);

	if (!InitDigest(m_eHashAlgorithm, ctx.get()) ||
		!UpdateDigest(ctx.get(), I.data(), I.length()) ||
		!UpdateDigest(ctx.get(), ":", 1) ||
		!UpdateDigest(ctx.get(), P.data(), P.size()) ||
		!FinalizeDigest(ctx.get(), digest, &digestLen) ||
		!InitDigest(m_eHashAlgorithm, ctx.get()))
	{
		throw srp_runtime_error("CSRPClient::Calculate_x Failed to hash I:P");
	}

	std::vector<uint8_t> saltBytes(BN_num_bytes(s));
	if (BN_bn2bin(s, saltBytes.data()) < 0)
	{
		throw srp_runtime_error("CSRPClient::Calculate_X Failed BN_bn2bin salt 's'");
	}

	if (!UpdateDigest(ctx.get(), saltBytes.data(), saltBytes.size()) ||
		!UpdateDigest(ctx.get(), digest, digestLen) ||
		!FinalizeDigest(ctx.get(), digest, &digestLen))
	{
		throw srp_runtime_error("CSRPClient::Calculate_x Failed to hash S:D");
	}

	return BN_bin2bn(digest, digestLen, NULL);
}

BIGNUM* CSRPClient::Calculate_v(BIGNUM* g, BIGNUM* N, BIGNUM* x)
{
	assert(g);
	assert(N);
	assert(x);

	BN_CTX_ptr ctx(BN_CTX_new(), ::BN_CTX_free);
	if (!ctx)
		throw srp_invalid_argument("CSRPClient::Calculate_v failed to get BIGNUM ctx");

	BIGNUM_ptr v(BN_new(), ::BN_free);
	if (!BN_mod_exp(v.get(), g, x, N, ctx.get()))
		throw srp_runtime_error("CSRPClient::Calculate_v failed to calculate verifier 'v'");
	return v.release();
}

BIGNUM* CSRPClient::Calculate_S(const BIGNUM* N, const BIGNUM* B, const BIGNUM* g, const BIGNUM* x, const BIGNUM* a, const BIGNUM* u)
{
	assert(N);
	assert(B);
	assert(g);
	assert(x);
	assert(a);
	assert(u);


	BN_CTX_ptr ctx(BN_CTX_new(), ::BN_CTX_free);
	if (!ctx)
		throw srp_runtime_error("CSRPClient::Calculate_S failed to create BN_CTX");

	BIGNUM_ptr tmp(BN_new(), ::BN_free);
	BIGNUM_ptr tmp2(BN_new(), ::BN_free);
	BIGNUM_ptr tmp3(BN_new(), ::BN_free);
	BIGNUM_ptr xtmp(BN_new(), ::BN_free);

	BN_with_flags(xtmp.get(), x, BN_FLG_CONSTTIME);
	BN_set_flags(tmp.get(), BN_FLG_CONSTTIME);

	if (!BN_mod_exp(tmp.get(), g, xtmp.get(), N, ctx.get()))
		throw srp_runtime_error("CSRPClient::Calculate_S Failed to compute step1");

	BIGNUM_ptr k(Calculate_k(N, g), ::BN_free);
	if (!k)
		throw srp_runtime_error("CSRPClient::Calculate_S failed to calculate 'k'");

	if (!BN_mod_mul(tmp2.get(), tmp.get(), k.get(), N, ctx.get()) ||
		!BN_mod_sub(tmp.get(), B, tmp2.get(), N, ctx.get()) ||
		!BN_mul(tmp3.get(), u, xtmp.get(), ctx.get()) ||
		!BN_add(tmp2.get(), a, tmp3.get()))
		throw srp_runtime_error("CSRPClient::Calculate_S failed to compute step2");

	BIGNUM_ptr S(BN_new(), ::BN_free);
	if (!S)
		throw srp_runtime_error("CSRPClient::Calculate_S failed to alloc 'S'");

	if (!BN_mod_exp(S.get(), tmp.get(), tmp2.get(), N, ctx.get()))
		throw srp_runtime_error("CSRPClient::Calculate_S failed to calculate S");

	return S.release();
}

}
