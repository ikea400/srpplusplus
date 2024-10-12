#include <iostream>

#include "srp_server.h"
#include "srp_client.h"

void Test1()
{
	const char I[] = "alice";
	const char s[] = "BEB25379D1A8581EB5A727673A2441EE";
	const char v[] = "7E273DE8696FFC4F4E337D05B4B375BEB0DDE1569E8FA00A9886D812"
		"9BADA1F1822223CA1A605B530E379BA4729FDC59F105B4787E5186F5"
		"C671085A1447B52A48CF1970B4FB6F8400BBF4CEBFBB168152E08AB5"
		"EA53D15C1AFF87B2B9DA6E04E058AD51CC72BFC9033B564E26480D78"
		"E955A5E29E7AB245DB2BE315E2099AFB";
	const char b[] = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20";
	const char P[] = "password123";
	const char a[] = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393";

	SRP::CSRPServer server(SRP::EHashAlgorithm::SHA1, SRP::ENGType::NG_1024);
	server.Step1(I, s, v, b);

	if (server.GetPublicKey() != "BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011"
		"BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC99"
		"6C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA"
		"37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAE"
		"EB4012B7D7665238A8E3FB004B117B58")
	{
		std::cout << "Server failed to generate the good public key 'B'\n";
		return;
	}

	std::cout << "B = " << server.GetPublicKey() << "\n";

	SRP::CSRPClient client(SRP::EHashAlgorithm::SHA1, SRP::ENGType::NG_1024);
	client.Step1(I, P, s, a);

	if (client.GetPublicKey() != "61D5E490F6F1B79547B0704C436F523DD0E560F0C64115BB72557EC4"
		"4352E8903211C04692272D8B2D1A5358A2CF1B6E0BFCF99F921530EC"
		"8E39356179EAE45E42BA92AEACED825171E1E8B9AF6D9C03E1327F44"
		"BE087EF06530E69F66615261EEF54073CA11CF5858F0EDFDFE15EFEA"
		"B349EF5D76988A3672FAC47B0769447B")
	{
		std::cout << "Client failed to generate the good public key 'A'\n";
		return;
	}

	if (client.GetVerifier() != v)
	{
		std::cout << "Client failed to generate the good verifier 'v'\n";
		return;
	}

	std::cout << "A = " << client.GetPublicKey() << "\n";
	std::cout << "v = " << client.GetVerifier() << "\n";

	client.Step2(server.GetPublicKey());

	std::cout << "M1 = " << client.GetEvidence() << "\n";

	if (!server.Step2(client.GetPublicKey(), client.GetEvidence()))
		std::cout << "client evidence is wrong\n";
	else
		std::cout << "Client M1 is good\n";

	std::cout << "M2 = " << server.GetEvidence() << "\n";

	if (!client.Step3(server.GetEvidence()))
		std::cout << "Server evidence is wrong\n";
	else
		std::cout << "Server M2 is good\n";
}

int main()
{
	Test1();
}