#pragma once

#include <stdexcept>
#include <string>
#include <memory>

#include <openssl/bn.h>
#include <openssl/evp.h>

namespace SRP
{
	using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
	using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;
	using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;

	enum class EHashAlgorithm
	{
		SHA1,
		SHA224,
		SHA256,
		SHA384,
		SHA512
	};

	enum class ENGType
	{
		NG_1024,
		NG_1536,
		NG_2048,
		NG_4096,
		NG_8192
	};

	int InitDigest(EHashAlgorithm alg, EVP_MD_CTX* ctx);

	int UpdateDigest(EVP_MD_CTX* ctx, const void* data, size_t len);

	int FinalizeDigest(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* len);

	int Digest(EHashAlgorithm alg, const void* data, size_t count, unsigned char* md, unsigned int* size);

	std::string Bn2HexStr(BIGNUM* bn);

	class CSRPCommon
	{
	public:
		CSRPCommon(const EHashAlgorithm algorithm, const ENGType type);
	protected:
		void SaveIdentity(std::string_view identity);

		void SaveSalt(std::string_view sHex);
		void SaveSalt(BIGNUM* s);
		
		void SaveVerifier(std::string_view vHex);
		void SaveVerifier(BIGNUM* v);

		void SaveServerPublicKey(std::string_view B);
		void SaveServerPublicKey(BIGNUM* B);

		void SaveClientPublicKey(std::string_view A);
		void SaveClientPublicKey(BIGNUM* A);

		void SaveVerifierProtector(BIGNUM* u);

		void SaveSecretHash(BIGNUM* K);

		void SaveClientEvidence(BIGNUM* M1);

		void SaveServerEvidence(BIGNUM* M2);

		void GenerateVerifierProtector();

		void GenerateSecretHash(BIGNUM* S);

		void GenerateClientEvidence();

		void GenerateServerEvidence();

		// k = SHA1(N | PAD(g)) -- tls-srp RFC 5054
		BIGNUM* Calculate_k(const BIGNUM* N, const BIGNUM* g) const;

		// u = H(PAD(A) | PAD(B))
		BIGNUM* Calculate_u(const BIGNUM* A, const BIGNUM* B, const BIGNUM* N) const;

		BIGNUM* Calculate_K(const BIGNUM* S) const;

		//M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
		BIGNUM* Calculate_M1(std::string_view I, const BIGNUM* N, const BIGNUM* A, const BIGNUM* B, const BIGNUM* g,
			const BIGNUM* s, const BIGNUM* K) const;

		// M2 = H(A | M1 | K) // K = SHA1(S)
		BIGNUM* Calculate_M2(const BIGNUM* A, const BIGNUM* M1, const BIGNUM* K) const;

		//calculate = SHA1(PAD(x) || PAD(y))
		BIGNUM* Calculate_XY(const BIGNUM* x, const BIGNUM* y, const BIGNUM* N) const;
	protected:

		std::string m_szIdentity_I; ///< 'I' The main identity (username or email).
		BIGNUM_ptr m_pBnPrime_N = BIGNUM_ptr(nullptr, ::BN_free); ///< 'N' A large safe prime, All arithmetic is done modulo N.
		BIGNUM_ptr m_pBnGenerator_g = BIGNUM_ptr(nullptr, ::BN_free); ///< 'g' A generator modulo N
		BIGNUM_ptr m_pBnSalt_s = BIGNUM_ptr(nullptr, ::BN_free); ///< 's' The user salt
		BIGNUM_ptr m_pBnVerifier_v = BIGNUM_ptr(nullptr, ::BN_free); ///< 'v' Password Verifier
		BIGNUM_ptr m_pBnPublicKey_A = BIGNUM_ptr(nullptr, ::BN_free); ///< 'A' = g^a % N, Client public key
		BIGNUM_ptr m_pBnPublicKey_B = BIGNUM_ptr(nullptr, ::BN_free); ///< 'B' = k*v + g^b % N, Server public key
		BIGNUM_ptr m_pBnVerifierProtector_u = BIGNUM_ptr(nullptr, ::BN_free); ///< 'u' = H(PAD(A) | PAD(B)) The value of preventing attacker who learns a user's verifier
		BIGNUM_ptr m_pBnClientEvidence_M1 = BIGNUM_ptr(nullptr, ::BN_free); ///< 'M1' = H(H(N) XOR H(g) | H(U) | s | A | B | K) Evidence message 1, To verify both sides generated the same session key
		BIGNUM_ptr m_pBnServerEvidence_M2 = BIGNUM_ptr(nullptr, ::BN_free); ///< 'M2' = H(A | M | K) Evidence message 2, To verify both sides generated the same session key
		BIGNUM_ptr m_pBnHashedSecret_K = BIGNUM_ptr(nullptr, ::BN_free); ///< 'K' = H(S) The session key hash for used to generate M

		const EHashAlgorithm m_eHashAlgorithm; /// The hashing algorithm used. Typically SHA1
		const ENGType m_eNGType; // The size of the primer number use. Exemple 2048bit
	private:
		void SetupNG();
	};

	class srp_invalid_argument : public std::invalid_argument
	{
	public:
		using _Mybase = std::invalid_argument;

		explicit srp_invalid_argument(const std::string& _Message) : _Mybase(_Message.c_str()) {}

		explicit srp_invalid_argument(const char* _Message) : _Mybase(_Message) {}
	};

	class srp_runtime_error : public std::runtime_error
	{
	public:
		using _Mybase = std::runtime_error;

		explicit srp_runtime_error(const std::string& _Message) : _Mybase(_Message.c_str()) {}

		explicit srp_runtime_error(const char* _Message) : _Mybase(_Message) {}
	};
}