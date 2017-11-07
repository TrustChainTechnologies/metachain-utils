/*********************************************************************
* Copyright (c) 2017 TCT DEVs	                                     *
* Distributed under the GPLv3.0 software license					 *
* contact us before using our code									 *
**********************************************************************/


#include <sstream>
#include "../common/ArgsManager.h"
#include "../common/logger.h"
#include "src/MCP39/Mnemonic.h"
#include "src/MCP39/dictionairy.h"
#include "src/MCP01/Account.h"
#include "boost/algorithm/string.hpp"
#include "src/base16.h"

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
	srand(time(NULL));

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

	LOGS("MetaChain-Utils: keygenerator");
	LOGS("=============================");

	// Process help and version
	if (IsArgSet("-?") || IsArgSet("-h") || IsArgSet("--help") )
	{
		LOGS("Arguments:");
		LOGS("-?, -h, --help: print this help and exit");
		LOGS("-l=<language>: select a language from the dictionary. possible variants are en, es, ja, it, fr, cs, ru, uk, zh_Hans, zh_Hant; defaults to en");
		LOGS("-s=<seed>: a seed to build the mnemonic, in hex format, multiple of 8");
		LOGS("-p=<passphrase>: using this passphrase to decode the mnemonic. Can be empty");
		LOGS("-c=<chain name>: chain name to create the key for. possible variants are MC, TCT, MINE; defaults to MC" );
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

	// SEED functions
	const std::string strSeed = GetArg("-s", getRandomSeed(64) );
	LOGS("Using Seed: " + strSeed);
	base16 b16Seed(strSeed);
	data_chunk entropy(b16Seed);	
	const auto entropy_size = entropy.size();

	if ((entropy_size % MCP39::mnemonic_seed_multiple) != 0)
	{
		LOG_ERROR("Mnemonic invalid entropy", "KEYGEN");
		getchar();
		return 1;
	}

	// PASSPHRASE functions
	std::string strPassphrase = GetArg("-p", "");
	LOGS("Using Passphrase: " + strPassphrase);

	// Mnemonic functions
	LOGS("=============================");
	const auto dictionary = dictLanguage.front();
	MCP39::Mnemonic mnem;
	const auto words = mnem.create(entropy, *dictionary);

	LOGS( "Mnemonic: " + boost::join(words, " ") );
	LOGS("Is Mnemonic valid: " + std::to_string(mnem.isValid(words, *dictionary)));

	// Private Key
	MCP01::Account acc(mnem.decode(words, strPassphrase));
	LOG("Private key: " + acc.getPrivKeyStr(), "base16" );
	LOG("Private key: " + acc.getPrivKeyStr58(), "base58");

	// Public Key
	if (!acc.calcPubKey(MCP01::Account::ECDSA::SECP256k1))
	{
		LOG_ERROR("Problem calculating public key", "SECP256k1");
		getchar();
		return 1;
	}
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
