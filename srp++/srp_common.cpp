#include "srp_common.h"

#include <cassert>
#include <vector>

#include "srp_gn.h"

namespace SRP
{
CSRPCommon::CSRPCommon(const EHashAlgorithm algorithm, const ENGType type)
	: m_eHashAlgorithm(algorithm), m_eNGType(type)
{
	SetupNG();
}

void CSRPCommon::SaveIdentity(std::string_view identity)
{
	assert(!identity.empty());

	m_szIdentity_I = identity;
}

void CSRPCommon::SaveSalt(std::string_view sHex)
{
	assert(!sHex.empty());
	BIGNUM* s = nullptr;
	if (!BN_hex2bn(&s, sHex.data()))
		throw srp_invalid_argument("CSRPCommon::SaveSalt failed to transform sHex to BIGNUM");
	SaveSalt(s);
}

void CSRPCommon::SaveSalt(BIGNUM* s)
{
	assert(s);
	m_pBnSalt_s.reset(s);
}

void CSRPCommon::SaveVerifier(std::string_view vHex)
{
	assert(!vHex.empty());
	BIGNUM* v = nullptr;
	if (!BN_hex2bn(&v, vHex.data()))
		throw srp_invalid_argument("CSRPCommon::SaveVerifier failed to transform vHex to BIGNUM");
	SaveVerifier(v);
}

void CSRPCommon::SaveVerifier(BIGNUM* v)
{
	assert(v);
	m_pBnVerifier_v.reset(v);
}

void CSRPCommon::SaveServerPublicKey(std::string_view BHex)
{
	assert(!BHex.empty());
	BIGNUM* B = nullptr;
	if (!BN_hex2bn(&B, BHex.data()))
		throw srp_invalid_argument("CSRPCommon::SaveServerPublicKey failed to transform BHex to BIGNUM");
	SaveServerPublicKey(B);
}

void CSRPCommon::SaveServerPublicKey(BIGNUM* B)
{
	assert(B);
	m_pBnPublicKey_B.reset(B);
}

void CSRPCommon::SaveClientPublicKey(std::string_view AHex)
{
	assert(!AHex.empty());
	BIGNUM* A = nullptr;
	if (!BN_hex2bn(&A, AHex.data()))
		throw srp_invalid_argument("CSRPCommon::SaveClientPublicKey failed to transform AHex to BIGNUM");
	SaveClientPublicKey(A);
}

void CSRPCommon::SaveClientPublicKey(BIGNUM* A)
{
	assert(A);
	m_pBnPublicKey_A.reset(A);
}

void CSRPCommon::SaveVerifierProtector(BIGNUM* u)
{
	assert(u);
	m_pBnVerifierProtector_u.reset(u);
}

void CSRPCommon::SaveSecretHash(BIGNUM* K)
{
	m_pBnHashedSecret_K.reset(K);
}

void CSRPCommon::SaveClientEvidence(BIGNUM* M1)
{
	assert(M1);
	m_pBnClientEvidence_M1.reset(M1);
}

void CSRPCommon::SaveServerEvidence(BIGNUM* M2)
{
	assert(M2);
	m_pBnServerEvidence_M2.reset(M2);
}

void CSRPCommon::GenerateVerifierProtector()
{
	assert(m_pBnPublicKey_A);
	assert(m_pBnPublicKey_B);
	assert(m_pBnPrime_N);

	SaveVerifierProtector(Calculate_u(m_pBnPublicKey_A.get(), m_pBnPublicKey_B.get(), m_pBnPrime_N.get()));
}

void CSRPCommon::GenerateSecretHash(BIGNUM* S)
{
	SaveSecretHash(Calculate_K(S));
}

void CSRPCommon::GenerateClientEvidence()
{
	assert(!m_szIdentity_I.empty());
	assert(m_pBnPrime_N);
	assert(m_pBnPublicKey_A);
	assert(m_pBnPublicKey_B);
	assert(m_pBnGenerator_g);
	assert(m_pBnSalt_s);
	assert(m_pBnHashedSecret_K);

	SaveClientEvidence(Calculate_M1(m_szIdentity_I, m_pBnPrime_N.get(), m_pBnPublicKey_A.get(), m_pBnPublicKey_B.get(),
		m_pBnGenerator_g.get(), m_pBnSalt_s.get(), m_pBnHashedSecret_K.get()));
}

void CSRPCommon::GenerateServerEvidence()
{
	assert(m_pBnClientEvidence_M1);
	assert(m_pBnPublicKey_A);
	assert(m_pBnHashedSecret_K);
	SaveServerEvidence(Calculate_M2(m_pBnPublicKey_A.get(), m_pBnClientEvidence_M1.get(), m_pBnHashedSecret_K.get()));
}

BIGNUM* CSRPCommon::Calculate_k(const BIGNUM* N, const BIGNUM* g) const
{
	assert(N);
	assert(g);
	return Calculate_XY(N, g, N);
}

BIGNUM* CSRPCommon::Calculate_u(const BIGNUM* A, const BIGNUM* B, const BIGNUM* N) const
{
	return Calculate_XY(A, B, N);
}

BIGNUM* CSRPCommon::Calculate_K(const BIGNUM* S) const
{
	unsigned int digLen;
	unsigned char dig[EVP_MAX_MD_SIZE];
	std::vector<uint8_t> temp(BN_num_bytes(S));
	if (!BN_bn2bin(S, temp.data()) ||
		!Digest(m_eHashAlgorithm, temp.data(), temp.size(), dig, &digLen))
		throw srp_runtime_error("CSRPCommon::Calculate_K failed to calc 'S' digest");

	return BN_bin2bn(dig, digLen, nullptr);
}

//M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
BIGNUM* CSRPCommon::Calculate_M1(std::string_view I, const BIGNUM* N, const BIGNUM* A, const BIGNUM* B, const BIGNUM* g,
	const BIGNUM* s, const BIGNUM* K) const
{
	assert(!I.empty());
	assert(N);
	assert(A);
	assert(B);
	assert(g);
	assert(s);
	assert(K);

	unsigned int digLen = 0;
	unsigned char dig1[EVP_MAX_MD_SIZE];
	unsigned char dig2[EVP_MAX_MD_SIZE];

	// H(N) -> dig1
	std::vector<uint8_t> tmp(BN_num_bytes(N));
	if (!BN_bn2bin(N, tmp.data()) ||
		!Digest(m_eHashAlgorithm, tmp.data(), tmp.size(), dig1, &digLen))
		throw srp_runtime_error("CSRPCommon::CalculateM1 failed to H(N)");

	//H(g) -> dig2
	if (!BN_bn2bin(g, tmp.data()) ||
		!Digest(m_eHashAlgorithm, tmp.data(), BN_num_bytes(g), dig2, &digLen))
		throw srp_runtime_error("CSRPCommon::CalculateM1 failed to H(g)");

	//H(N) XOR H(g) -> dig1
	for (unsigned i = 0; i < digLen; i++)
	{
		dig1[i] ^= dig2[i];
	}

	if (!Digest(m_eHashAlgorithm, I.data(), I.length(), dig2, &digLen))
		throw srp_runtime_error("CSRPCommon::CalculateM1 failed to H(I)");

	EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);

	if (!InitDigest(m_eHashAlgorithm, ctx.get()))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to init EVP_MD_CTX");

	if (!UpdateDigest(ctx.get(), dig1, digLen) ||
		!UpdateDigest(ctx.get(), dig2, digLen))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to update hash #1");

	if (!BN_bn2bin(s, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), BN_num_bytes(s)))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to add salt");

	if (!BN_bn2bin(A, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), BN_num_bytes(A)))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to add client public");

	if (!BN_bn2bin(B, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), BN_num_bytes(B)))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to add server public");

	if (!BN_bn2bin(K, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), BN_num_bytes(K)))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to add client hashed secret 'K'");

	if (!FinalizeDigest(ctx.get(), dig1, &digLen))
		throw srp_runtime_error("CSRPCommon::Calculate_M1 failed to finalize hash");

	return BN_bin2bn(dig1, digLen, nullptr);
}

// M2 = H(A | M1 | K)
BIGNUM* CSRPCommon::Calculate_M2(const BIGNUM* A, const BIGNUM* M1, const BIGNUM* K) const
{
	assert(A);
	assert(M1);
	assert(K);

	unsigned int digLen;
	unsigned char dig1[EVP_MAX_MD_SIZE];
	std::vector<uint8_t> tmp(BN_num_bytes(A));

	EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);
	if (!ctx || !InitDigest(m_eHashAlgorithm, ctx.get()))
		throw srp_runtime_error("CSRPCommon::Calculate_M2 failed to init hash");

	if (!BN_bn2bin(A, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), tmp.size()))
		throw srp_runtime_error("CSRPCommon::Calculate_M2 failed to start hash A");

	tmp.resize(BN_num_bytes(M1));
	if (!BN_bn2bin(M1, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), tmp.size()))
		throw srp_runtime_error("CSRPCommon::Calculate_M2 failed to continue hash M1");

	tmp.resize(BN_num_bytes(K));
	if (!BN_bn2bin(K, tmp.data()) ||
		!UpdateDigest(ctx.get(), tmp.data(), tmp.size()))
		throw srp_runtime_error("CSRPCommon::Calculate_M2 failed to finish hash K");

	if (!FinalizeDigest(ctx.get(), dig1, &digLen))
		throw srp_runtime_error("CSRPCommon::Calculate_M2 failed to finalize hash");

	return BN_bin2bn(dig1, digLen, nullptr);
}

BIGNUM* CSRPCommon::Calculate_XY(const BIGNUM* x, const BIGNUM* y, const BIGNUM* N) const
{
	assert(x);
	assert(y);
	assert(N);

	unsigned char digest[EVP_MAX_MD_SIZE]{};
	if (x != N && BN_ucmp(x, N) >= 0)
		throw srp_invalid_argument("CSRPCommon::Calculate_XY x is invalid");
	if (y != N && BN_ucmp(y, N) >= 0)
		throw srp_invalid_argument("CSRPCommon::Calculate_XY y is invalid");

	int numN = BN_num_bytes(N);
	std::vector<unsigned char> tmp(numN * 2);

	unsigned int digestLen = 0;
	if (BN_bn2binpad(x, tmp.data(), numN) < 0
		|| BN_bn2binpad(y, tmp.data() + numN, numN) < 0
		|| !Digest(m_eHashAlgorithm, tmp.data(), static_cast<size_t>(numN) * 2, digest, &digestLen))
		throw srp_runtime_error("CSRPCommon::Calculate_XY Failed to compute XY");
	

	return BN_bin2bn(digest, digestLen, NULL);
}


void CSRPCommon::SetupNG()
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

int InitDigest(EHashAlgorithm alg, EVP_MD_CTX* ctx)
{
	assert(ctx);

	switch (alg)
	{
	case EHashAlgorithm::SHA1: return EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr);
	case EHashAlgorithm::SHA224: return EVP_DigestInit_ex(ctx, EVP_sha224(), nullptr);
	case EHashAlgorithm::SHA256: return EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
	case EHashAlgorithm::SHA384: return EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr);
	case EHashAlgorithm::SHA512: return EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr);
	case EHashAlgorithm::SHA3_224: return EVP_DigestInit_ex(ctx, EVP_sha3_224(), nullptr);
	case EHashAlgorithm::SHA3_256: return EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
	case EHashAlgorithm::SHA3_384: return EVP_DigestInit_ex(ctx, EVP_sha3_384(), nullptr);
	case EHashAlgorithm::SHA3_512: return EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr);
	default:
		return 0;
	};
}

int UpdateDigest(EVP_MD_CTX* ctx, const void* data, size_t len)
{
	assert(ctx);
	return EVP_DigestUpdate(ctx, data, len);
}

int FinalizeDigest(EVP_MD_CTX* ctx, unsigned char* md, unsigned int* len)
{
	assert(ctx);
	return EVP_DigestFinal(ctx, md, len);
}

int Digest(EHashAlgorithm alg, const void* data, size_t count, unsigned char* md, unsigned int* size)
{
	assert(data);
	assert(count);
	assert(md);

	switch (alg)
	{
	case EHashAlgorithm::SHA1: return EVP_Digest(data, count, md, size, EVP_sha1(), nullptr);
	case EHashAlgorithm::SHA224: return EVP_Digest(data, count, md, size, EVP_sha224(), nullptr);
	case EHashAlgorithm::SHA256: return EVP_Digest(data, count, md, size, EVP_sha256(), nullptr);
	case EHashAlgorithm::SHA384: return EVP_Digest(data, count, md, size, EVP_sha384(), nullptr);
	case EHashAlgorithm::SHA512: return EVP_Digest(data, count, md, size, EVP_sha512(), nullptr);
	case EHashAlgorithm::SHA3_224: return EVP_Digest(data, count, md, size, EVP_sha3_224(), nullptr);
	case EHashAlgorithm::SHA3_256: return EVP_Digest(data, count, md, size, EVP_sha3_256(), nullptr);
	case EHashAlgorithm::SHA3_384: return EVP_Digest(data, count, md, size, EVP_sha3_384(), nullptr);
	case EHashAlgorithm::SHA3_512: return EVP_Digest(data, count, md, size, EVP_sha3_512(), nullptr);
	default:
		return 0;
	};
}

std::string Bn2HexStr(BIGNUM* bn)
{
	assert(bn);
	char* const str = BN_bn2hex(bn);
	if (!str)
		throw srp_runtime_error("Bn2HexStr failed to transform BIGNUM to hex");
	std::string result(str);
	OPENSSL_free(str);
	return result;
}
}
