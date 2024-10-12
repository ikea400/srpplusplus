#pragma once
#include "srp_common.h"

namespace SRP
{
	class CSRPServer : public CSRPCommon
	{
	public:
		CSRPServer(const EHashAlgorithm algorithm, const ENGType type);

		void Step1(std::string_view identifier, std::string_view salt, std::string_view verifier, std::string_view privateKey);
	};
}