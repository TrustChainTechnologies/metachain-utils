// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ArgsManager.h"

#include <string>
#include <boost/algorithm/string.hpp>
#include "../common/utilstrencodings.h"

/** Interpret string as boolean, for argument parsing */
static bool InterpretBool(const std::string& strValue)
{
	if (strValue.empty())
		return true;
	return (atoi(strValue.c_str()) != 0);
}

/** Turn -noX into -X=0 */
static void InterpretNegativeSetting(std::string& strKey, std::string& strValue)
{
	if (strKey.length()>3 && strKey[0] == '-' && strKey[1] == 'n' && strKey[2] == 'o')
	{
		strKey = "-" + strKey.substr(3);
		strValue = InterpretBool(strValue) ? "0" : "1";
	}
}


void ArgsManager::ParseParameters(int argc, const char* const argv[])
{
	mapArgs.clear();
	mapMultiArgs.clear();

	for (int i = 1; i < argc; i++)
	{
		std::string str(argv[i]);
		std::string strValue;
		size_t is_index = str.find('=');
		if (is_index != std::string::npos)
		{
			strValue = str.substr(is_index + 1);
			str = str.substr(0, is_index);
		}
#ifdef _WINDOWS
		boost::to_lower(str);
		if (boost::algorithm::starts_with(str, "/"))
			str = "-" + str.substr(1);
#endif

		if (str[0] != '-')
			break;

		// If both --foo and -foo are set, the last takes effect.
		InterpretNegativeSetting(str, strValue);

		mapArgs[str] = strValue;
		mapMultiArgs[str].push_back(strValue);
	}
}

std::vector<std::string> ArgsManager::GetArgs(const std::string& strArg)
{
	if (IsArgSet(strArg))
		return mapMultiArgs.at(strArg);
	return {};
}

bool ArgsManager::IsArgSet(const std::string& strArg)
{
	return mapArgs.count(strArg);
}

std::string ArgsManager::GetArg(const std::string& strArg, const std::string& strDefault)
{
	if (mapArgs.count(strArg))
		return mapArgs[strArg];
	return strDefault;
}

int64_t ArgsManager::GetArg(const std::string& strArg, int64_t nDefault)
{
	if (mapArgs.count(strArg))
		return atoi64(mapArgs[strArg]);
	return nDefault;
}

bool ArgsManager::GetBoolArg(const std::string& strArg, bool fDefault)
{
	if (mapArgs.count(strArg))
		return InterpretBool(mapArgs[strArg]);
	return fDefault;
}

bool ArgsManager::SoftSetArg(const std::string& strArg, const std::string& strValue)
{
	if (mapArgs.count(strArg))
		return false;
	ForceSetArg(strArg, strValue);
	return true;
}

bool ArgsManager::SoftSetBoolArg(const std::string& strArg, bool fValue)
{
	if (fValue)
		return SoftSetArg(strArg, std::string("1"));
	else
		return SoftSetArg(strArg, std::string("0"));
}

void ArgsManager::ForceSetArg(const std::string& strArg, const std::string& strValue)
{
	mapArgs[strArg] = strValue;
	mapMultiArgs[strArg].clear();
	mapMultiArgs[strArg].push_back(strValue);
}