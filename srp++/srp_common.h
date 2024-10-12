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

	class CSRPCommon
	{
	public:
		CSRPCommon(const EHashAlgorithm algorithm, const ENGType type);
	protected:
		BIGNUM_ptr m_pBnPrime_N = BIGNUM_ptr(nullptr, ::BN_free); ///< 'N' A large safe prime, All arithmetic is done modulo N.
		BIGNUM_ptr m_pBnGenerator_g = BIGNUM_ptr(nullptr, ::BN_free); ///< 'g' A generator modulo N

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