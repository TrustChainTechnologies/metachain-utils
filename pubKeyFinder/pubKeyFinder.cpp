/*********************************************************************
* Copyright (c) 2017 TCT DEVs	                                     *
* Distributed under the GPLv3.0 software license					 *
* contact us before using our code									 *
**********************************************************************/


#include <sstream>
#include <chrono>
#include "../common/ArgsManager.h"
#include "../common/logger.h"
#include "../keygenerator/src/MCP39/Mnemonic.h"
#include "../keygenerator/src/MCP39/dictionairy.h"
#include "../keygenerator/src/MCP01/Account.h"
#include "boost/algorithm/string.hpp"
#include "../keygenerator/src/base16.h"

#ifdef _WIN32
#include <SDKDDKVer.h>
#ifdef _MSC_VER
#include <basetsd.h>
#endif
#endif

// argument manager
ArgsManager gArgs;

// random seed generation function. Not perfectly random but enough for testing
std::string getRandomSeed(const int len)
{
	static const char hex[] =
		"0123456789"
		"abcdef";

	std::string output;

	for (int i = 0; i < len; ++i) {
		output += hex[rand() % (sizeof(hex) - 1)];
	}

	return output;
}

// main entry point
int main(int argc, char* argv[])
{
	// borrowed from the bitcoin core we initialize the argmanager and parse the arguments if provided
	ParseParameters(argc, argv);

	// seed
	srand(time(NULL));

	LOGS("MetaChain-Utils: pubKeyFinder");
	LOGS("=============================");

	// Process help and version
	if (IsArgSet("-?") || IsArgSet("-h") || IsArgSet("--help"))
	{
		LOGS("Arguments:");
		LOGS("-?, -h, --help: print this help and exit");
		LOGS("-l=<language>: select a language from the dictionary. possible variants are en, es, ja, it, fr, cs, ru, uk, zh_Hans, zh_Hant; defaults to en");
		LOGS("-p=<passphrase>: using this passphrase to decode the mnemonic. Can be empty");
		LOGS("-c=<chain name>: chain name to create the key for. possible variants are MC, TCT, MINE; defaults to MC");
		LOGS("-f=<wish>: define with what the pub key should start with (base58)");
		getchar();
		return 1;
	}

	// LANGUAGE functions
	std::string strLanguage = GetArg("-l", "en");
	MCP39::dictionary_list dictLanguage;
	if (strLanguage == "es")
		dictLanguage = { &MCP39::language::es };
	else if (strLanguage == "ja")
		dictLanguage = { &MCP39::language::ja };
	else if (strLanguage == "it")
		dictLanguage = { &MCP39::language::it };
	else if (strLanguage == "fr")
		dictLanguage = { &MCP39::language::fr };
	else if (strLanguage == "cs")
		dictLanguage = { &MCP39::language::cs };
	else if (strLanguage == "ru")
		dictLanguage = { &MCP39::language::ru };
	else if (strLanguage == "uk")
		dictLanguage = { &MCP39::language::uk };
	else if (strLanguage == "zh_Hans")
		dictLanguage = { &MCP39::language::zh_Hans };
	else if (strLanguage == "zh_Hant")
		dictLanguage = { &MCP39::language::zh_Hant };
	else
		dictLanguage = { &MCP39::language::en };

	LOGS("Using Language: " + strLanguage);

	std::string strFront = GetArg("-f", "");
	if (strFront == "")
	{
		LOG_ERROR("Set -f parameter to define what we're looking for.", "Wrong Parameter");
		getchar();
		return 1;
	}
	unsigned int uiWishLength = strFront.length();
	if (uiWishLength >= 10)
	{
		LOG_ERROR("-f Parameter too long, this will take ages. Aborting since useless", "Wrong Parameter");
		getchar();
		return 1;
	}
	uint8_t uiTmp[64];
	if( !MCP01::base58::decode(strFront, uiTmp))
	{
		LOG_ERROR("-f Parameter is not base58. Impossible combination found", "Wrong Parameter");
		getchar();
		return 1;
	}

	std::string strPassphrase = GetArg("-p", "");
	LOGS("Using Passphrase: " + strPassphrase);
		
	const auto dictionary = dictLanguage.front();
	MCP39::Mnemonic mnem;
	
	std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
	std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();
	unsigned int uiCount = 0;
	while(++uiCount)
	{
		std::string strSeed = getRandomSeed(64);
#ifdef _DEBUG
		LOGS("Using Seed: " + strSeed);
#endif
		base16 b16Seed(strSeed);
		data_chunk entropy(b16Seed);

		const auto words = mnem.create(entropy, *dictionary);
#ifdef _DEBUG
		LOGS("Mnemonic: " + boost::join(words, " "));
#endif

		MCP01::Account acc(mnem.decode(words, strPassphrase));
		if (!acc.calcPubKey(MCP01::Account::ECDSA::SECP256k1))
			continue;

		// print some performance info
		if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - t1).count() >= 30)
		{
			t1 = std::chrono::high_resolution_clock::now();
			LOGS("Performance: " + std::to_string(uiCount/30) + " calcs/s");
			uiCount = 0;
		}

		if (acc.getPubKeyStr58().compare(0, uiWishLength, strFront) == 0)
		{
			continue;
			LOGS("=============================");
			LOGS("    !!!! FOUND ONE !!!!");
			LOGS("It took " + std::to_string(std::chrono::duration_cast<std::chrono::seconds>(t1 - t2).count()) + " seconds to find this pub key. Enjoy :)");
			LOGS("=============================");

			LOGS("Using Seed: " + strSeed);
			LOGS("Mnemonic: " + boost::join(words, " "));
			LOG("Private key: " + acc.getPrivKeyStr(), "base16");
			LOG("Private key: " + acc.getPrivKeyStr58(), "base58");

			LOG("The public key is: " + acc.getPubKeyStr(), "SECP256K1 - base16");
			LOG("The public key is: " + acc.getPubKeyStr58(), "SECP256K1 - base58");

			// Wallet Address
			LOGS("The wallet address is (Mainnet | SECP256k1): " + acc.getWalletAddress(GetArg("-c", "MC")));
			LOGS("The wallet address is (Testnet | SECP256k1): " + acc.getWalletAddress(GetArg("-c", "MC"), true));

			// Verifying Address
			LOGS("=============================");
			LOGS("Verifying Mainnet SECP256k1 address: " + std::to_string(acc.verifyWalletAddress(acc.getWalletAddress(GetArg("-c", "MC")))));
			LOGS("Verifying Testnet SECP256k1 address: " + std::to_string(acc.verifyWalletAddress(acc.getWalletAddress(GetArg("-c", "MC"), true))));

			getchar();
			return 1;
		}

	}
}
