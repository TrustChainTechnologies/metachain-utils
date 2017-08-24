#pragma once

/**
* Copyright (c) 2011-2017 libbitcoin developers (see AUTHORS)
*
* This file is part of libbitcoin.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/*********************************************************************
* Copyright (c) 2017 TCT DEVs	                                     *
* Distributed under the GPLv3.0 software license					 *
* contact us before using our code									 *
**********************************************************************/

#ifndef __MCP39_DICTIONARY_H__
#define __MCP39_DICTIONARY_H__

#include <array>
#include <vector>
#include <cstdint>

namespace MCP39 {

	/**
	* A valid mnemonic dictionary has exactly this many words.
	*/
	#define DICTIONARY_SIZE 2048

	/**
	* A dictionary for creating mnemonics.
	* The bip39 spec calls this a "wordlist".
	* This is a POD type, which means the compiler can write it directly
	* to static memory with no run-time overhead.
	*/
	typedef std::array<const char*, DICTIONARY_SIZE> dictionary;

	/**
	* A collection of candidate dictionaries for mnemonic validation.
	*/
	typedef std::vector<const dictionary*> dictionary_list;

	namespace language
	{
		// Individual built-in languages:
		extern const dictionary en;
		extern const dictionary es;
		extern const dictionary ja;
		extern const dictionary it;
		extern const dictionary fr;
		extern const dictionary cs;
		extern const dictionary ru;
		extern const dictionary uk;
		extern const dictionary zh_Hans;
		extern const dictionary zh_Hant;

		// All built-in languages:
		extern const dictionary_list all;
	}
} 

#endif