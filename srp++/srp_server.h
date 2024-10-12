#pragma once
#include "srp_common.h"

namespace SRP
{
	class CSRPServer : public CSRPCommon
	{
	public:
		CSRPServer(const EHashAlgorithm algorithm, const ENGType type);

		void Step1(std::string_view identity, std::string_view salt, std::string_view verifier, std::string_view privateKey);

		bool Step2(std::string_view clientPublic, std::string_view clientEvidence);

		std::string GetPublicKey() const;
		std::string GetEvidence() const;
	private:
		void SavePrivateKey(std::string_view bHex);
		void SavePrivateKey(BIGNUM* b);

		void SaveSecret(BIGNUM* S);

		void GeneratePublicKey();
		void GenerateSecret();

		//B = k*v + g^b % N
		BIGNUM* Calculate_B(const BIGNUM* b, const BIGNUM* N, const BIGNUM* g, const BIGNUM* v) const;

		// (A * v^u) ^ b % N
		BIGNUM* Calculate_S(const BIGNUM* A, const BIGNUM* v, const BIGNUM* u, const BIGNUM* b, const BIGNUM* N) const;
	private:
		BIGNUM_ptr m_pBnPrivateKey_b = BIGNUM_ptr(nullptr, ::BN_free);///< 'b' = random(), Server private key
		BIGNUM_ptr m_pBnSecret_S = BIGNUM_ptr(nullptr, ::BN_free);///< 'S' = (A * v^u) ^ b % N Pre-master secret (The secure common session key)
	};
}