#include "srp_server.h"

SRP::CSRPServer::CSRPServer(const EHashAlgorithm algorithm, const ENGType type)
	: CSRPCommon(algorithm, type)
{

}

void SRP::CSRPServer::Step1(std::string_view identifier, std::string_view salt, std::string_view verifier)
{
}
