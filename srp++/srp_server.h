#pragma once
#include "srp_common.h"

namespace SRP
{

	class CSRPServer : public CSRPCommon
	{
	public:
		/**
		* @brief Initialize srp server class
		* 
		* Will initialize N, g based on type params
		* 
		* @params algorithm The digest algorithm used in calculations. Example(SHA-1, SHA-256...)
		* @params type The size of the prime number 'N' used in calcualtions. Example(2048bits, 4096bits...)
		* 
		* @throws srp_runtime_error If failed to get  'N' or 'g'
		*/
		CSRPServer(const EHashAlgorithm algorithm, const ENGType type);

		/**
		* @brief Execute first step of rsp server
		* 
		* Will generate server private key 'b' with a size based on N size or type
		* Will calculate server public key 'B' using B = k*v + g^b % N where N, g, k where decided based on ENGType on construction.
		* 
		* @params identity 'I' The main identity (username or email) received by the client.
		* 
		* @params salt 's' The hex value of salt used for generating verifier.
		* 
		* @params verifier 'v' The verifier saved in db from user registration.
		* 
		* @throws srp_runtime_error If calculation fail.
		*/
		void Step1(std::string_view identity, std::string_view salHext, std::string_view verifierHex);

		/**
		* @brief Execute first step of rsp server.
		* 
		* Will generate server private key 'b' of size max(privateKeyLen, 32).
		* Will calculate server public key 'B' using B = k*v + g^b % N where N, g, k where decided based on ENGType on construction.
		* 
		* @params identity 'I' The main identity (username or email) received by the client.
		* 
		* @params salt 's' The hex value of salt used for generating verifier.
		* 
		* @params verifier 'v' The verifier saved in db from user registration.
		* 
		* @params privateKeyLen The size used for generating the private key.
		* 
		* @throws srp_runtime_error if failed to generate private key.
		* @throws srp_runtime_error If calculation fail.
		*/
		void Step1(std::string_view identity, std::string_view saltHex, std::string_view verifierHex, int privateKeyLen);

		/**
		* @brief Execute first step of srp server.
		*
		* Will calculate server public key 'B' using B = k*v + g^b % N where N, g, k where decided based on ENGType on construction.
		*
		* @params identity 'I' The main identity (username or email) received by the client.
		*
		* @params salt 's' The hex value of salt used for generating verifier.
		*
		* @params verifier 'v' The verifier saved in db from user registration.
		*
		* @params privateKey The hex value of the server private key 'b'.
		* 
		* @throws srp_runtime_error If calculation fail.
		*/
		void Step1(std::string_view identity, std::string_view saltHex, std::string_view verifierHex, std::string_view privateKeyHex);

		/**
		* @brief Execute second step of srp server.
		* 
		* Will generate verifier protector 'u' with u = H(PAD(A) | PAD(B)).
		* 
		* Will generate secret 'S' with S = (A * v^u) ^ b % N.
		* 
		* Will generate secret digest 'K' with K = H(S).
		* 
		* Will generate client evidence to confirm the evidence received from client.
		* 
		* Will generate server evidence to send to client 'M2' with M2 = H(A | M1 | K).
		* 
		* @params clientPublicHex The hex representation of the client public key 'A'.
		* 
		* @params clientEvidenceHex The hex representation of the client evidence 'M1'.
		* 
		* @return true if success to verify client evidence or false on failure.
		* 
		* @throws srp_invalid_argument If arguments are invalid.
		* @throws srp_runtime_error If calculation fail.
		*/
		bool Step2(std::string_view clientPublicHex, std::string_view clientEvidenceHex);

		/**
		* The hex representation of the server public key 'B' 
		* 
		* @throws srp_runtime_error if failed to represent in hex
		*/
		std::string GetPublicKey() const;

		/**
		* The hex representation of the server evidence 'M2'
		*
		* @throws srp_runtime_error if failed to represent in hex
		*/
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