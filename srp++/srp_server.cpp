#include "srp_server.h"

#include <cassert>

#include <openssl/rand.h>

#include "srp_gn.h"

namespace SRP
{

	CSRPServer::CSRPServer(const EHashAlgorithm algorithm, const ENGType type)
		: CSRPCommon(algorithm, type)
	{
	}

	void CSRPServer::Step1(std::string_view identity, std::string_view salt, std::string_view verifier)
	{
		Step1(identity, salt, verifier, g_NGConstants[(int)m_eNGType].exponentSize);
	}

	void CSRPServer::Step1(std::string_view identity, std::string_view salt, std::string_view verifier, int privateKeyLen)
	{
		privateKeyLen = std::max(privateKeyLen, MIN_EXPONEN_SIZE);

		BIGNUM_ptr b(BN_new(), ::BN_free);
		if (!BN_rand(b.get(), privateKeyLen * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
			throw srp_runtime_error("CSRPServer::Step1 failed to generate random private key");

		Step1(identity, salt, verifier, Bn2HexStr(b.get()));
	}

	void CSRPServer::Step1(std::string_view identity, std::string_view salt, std::string_view verifier, std::string_view privateKey)
	{
		SaveIdentity(identity);
		SavePrivateKey(privateKey);
		SaveSalt(salt);
		SaveVerifier(verifier);

		GeneratePublicKey();
	}

	bool CSRPServer::Step2(std::string_view clientPublic, std::string_view clientEvidence)
	{
		BIGNUM* clientM1tmp = nullptr;
		if (!BN_hex2bn(&clientM1tmp, clientEvidence.data()))
			throw srp_invalid_argument("CSRPServer::Step2 failed to transform clientEvidence to BIGNUM");
		BIGNUM_ptr clientM1(clientM1tmp, ::BN_free);

		SaveClientPublicKey(clientPublic);

		GenerateVerifierProtector();
		GenerateSecret();
		GenerateSecretHash(m_pBnSecret_S.get());
		GenerateClientEvidence();
		if (BN_cmp(clientM1.get(), m_pBnClientEvidence_M1.get()))
			return false;

		GenerateServerEvidence();

		return true;
	}

	std::string CSRPServer::GetPublicKey() const
	{
		assert(m_pBnPublicKey_B);
		return Bn2HexStr(m_pBnPublicKey_B.get());
	}

	std::string CSRPServer::GetEvidence() const
	{
		assert(m_pBnServerEvidence_M2);
		return Bn2HexStr(m_pBnServerEvidence_M2.get());;
	}

	void CSRPServer::SavePrivateKey(std::string_view bHex)
	{
		assert(!bHex.empty());
		BIGNUM* b = nullptr;
		if (!BN_hex2bn(&b, bHex.data()))
			throw srp_invalid_argument("CSRPServer::SavePrivateKey failed to transform bHex to BIGNUM");
		SavePrivateKey(b);
	}

	void CSRPServer::SavePrivateKey(BIGNUM* b)
	{
		assert(b);
		m_pBnPrivateKey_b.reset(b);
	}

	void CSRPServer::SaveSecret(BIGNUM* S)
	{
		assert(S);
		m_pBnSecret_S.reset(S);
	}

	void CSRPServer::GeneratePublicKey()
	{
		assert(m_pBnPrivateKey_b.get());
		assert(m_pBnPrime_N.get());
		assert(m_pBnGenerator_g.get());
		assert(m_pBnVerifier_v.get());

		SaveServerPublicKey(Calculate_B(m_pBnPrivateKey_b.get(), m_pBnPrime_N.get(), m_pBnGenerator_g.get(), m_pBnVerifier_v.get()));
	}

	void CSRPServer::GenerateSecret()
	{
		assert(m_pBnPublicKey_A);
		assert(m_pBnVerifier_v);
		assert(m_pBnVerifierProtector_u);
		assert(m_pBnPrivateKey_b);
		assert(m_pBnPrime_N);

		SaveSecret(Calculate_S(m_pBnPublicKey_A.get(), m_pBnVerifier_v.get(), m_pBnVerifierProtector_u.get(), 
			m_pBnPrivateKey_b.get(), m_pBnPrime_N.get()));
	}

	//B = k*v + g^b % N
	BIGNUM* CSRPServer::Calculate_B(const BIGNUM* b, const BIGNUM* N, const BIGNUM* g, const BIGNUM* v) const
	{
		assert(b);
		assert(N);
		assert(g);
		assert(v);

		BN_CTX_ptr ctx(BN_CTX_new(), ::BN_CTX_free);
		if (!ctx)
			throw srp_runtime_error("CSRPServer::CalculateB failed to create BN_CTX");

		BIGNUM_ptr B(BN_new(), ::BN_free);
		BIGNUM_ptr kv(BN_new(), ::BN_free);
		BIGNUM_ptr gb(BN_new(), ::BN_free);
		if (!B || !kv || !gb)
			throw srp_runtime_error("CSRPServer::CalculateB failed to create BIGNUM");

		BIGNUM_ptr k(Calculate_k(N, g), ::BN_free);
		if (!k)
			throw srp_runtime_error("CSRPServer::CalculateB failed to calculate 'k'");

		if (!BN_mod_exp(gb.get(), g, b, N, ctx.get()) ||
			!BN_mod_mul(kv.get(), v, k.get(), N, ctx.get()) ||
			!BN_mod_add(B.get(), gb.get(), kv.get(), N, ctx.get()))
			throw srp_runtime_error("CSRPServer::CalculateB failed to calculate 'B'");

		return B.release();
	}

	BIGNUM* CSRPServer::Calculate_S(const BIGNUM* A, const BIGNUM* v, const BIGNUM* u, const BIGNUM* b, const BIGNUM* N) const
	{
		assert(A);
		assert(v);
		assert(u);
		assert(b);
		assert(N);

		BN_CTX_ptr ctx(BN_CTX_new(), ::BN_CTX_free);
		if (!ctx)
			throw srp_runtime_error("CSRPServer::Calculate_S failed to create BN_CTX");

		BIGNUM_ptr tmp(BN_new(), ::BN_free);
		if (!tmp)
			throw srp_runtime_error("CSRPServer::Calculate_S failed to create BIGNUM");

		if (!BN_mod_exp(tmp.get(), v, u, N, ctx.get()) ||
			!BN_mod_mul(tmp.get(), A, tmp.get(), N, ctx.get()))
			throw srp_runtime_error("CSRPServer::Calculate_S failed to do first calcul");

		BIGNUM_ptr S(BN_new(), ::BN_free);
		if (!S)
			throw srp_runtime_error("CSRPServer::Calculate_S failed to create 'S'");

		if (!BN_mod_exp(S.get(), tmp.get(), b, N, ctx.get()))
			throw srp_runtime_error("CSRPServer::Calculate_S failed to do final calcul");

		return S.release();
	}


}
