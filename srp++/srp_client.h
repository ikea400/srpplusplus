#pragma once
#include "srp_common.h"

namespace SRP
{
	class CSRPClient : public CSRPCommon
	{
	public:
		CSRPClient(const EHashAlgorithm algorithm, const ENGType type);

		void Step1(std::string_view identity, std::string_view password, std::string_view salt);
		void Step1(std::string_view identity, std::string_view password, std::string_view salt, int privateKeyLen);
		void Step1(std::string_view identity, std::string_view password, std::string_view salt, std::string_view privateKey);

		void Step2(std::string_view serverPublicKey);

		bool Step3(std::string_view serverEvidence);

		std::string GetPublicKey() const;
		std::string GetVerifier() const;
		std::string GetEvidence() const;

	private:
		void SavePrivateKey(std::string_view aHex);
		void SavePrivateKey(BIGNUM* a);

		void SaveSaltedHashedPassword(BIGNUM* x);

		void SaveVerifier(BIGNUM* v);

		void SaveSecret(BIGNUM* S);


		void GeneratePublicKey();
		void GenerateSaltedHashedPassword(std::string_view P);
		void GenerateVerifier();
		void GenerateSecret();

		//A = g^a % N
		BIGNUM* Calculate_A(const BIGNUM* a, const BIGNUM* N, const BIGNUM* g) const;

		//x = SHA1(s | SHA1(I | ":" | P))
		BIGNUM* Calculate_x(std::string_view I, std::string_view P, BIGNUM* s);

		//v = g^x % N
		BIGNUM* Calculate_v(BIGNUM* g, BIGNUM* N, BIGNUM* x);

		//S = (B - (k * g^x)) ^ (a + (u * x)) % N
		BIGNUM* Calculate_S(const BIGNUM* N, const BIGNUM* B, const BIGNUM* g, const BIGNUM* x, const BIGNUM* a, const BIGNUM* u);
	private:
		BIGNUM_ptr m_pBnPrivateKey_a = BIGNUM_ptr(nullptr, ::BN_free);///< 'a' = random(), Client private key
		BIGNUM_ptr m_pBnSaltedHashedPassword_x = BIGNUM_ptr(nullptr, ::BN_free); ///< 'x' = SHA1(s | SHA1(I | ":" | P)) The hash of salt + identity + password
		BIGNUM_ptr m_pBnSecret_S = BIGNUM_ptr(nullptr, ::BN_free);///< 'S' = (B - (k * g^x)) ^ (a + (u * x)) % N Pre-master secret (The secure common session key)
	};
}