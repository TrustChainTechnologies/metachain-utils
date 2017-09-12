#pragma once

/*********************************************************************
* Copyright (c) 2017 TCT DEVs	                                     *
* Distributed under the GPLv3.0 software license					 *
* contact us before using our code									 *
**********************************************************************/

// MCP01 Account functions: Wallet Address Generation, Checking

#ifndef __MCP01_ACCOUNT_H__
#define __MCP01_ACCOUNT_H__

#include <string>
#include "../MCP39/Mnemonic.h"
#include "../base16.h"

namespace MCP01
{
#define WALLET_ADDRESS_STD_PREFIX "MC"
#define WALLET_ADDRESS_VERSION 1
#define CHAINIDENTIFIER_BASECHAIN 0

	// 0 0 0 0		0 0 0 0
	// first bit: ECDSA algorithm. 1 = k1, 0 = r1
	// fifth bit: TESTNET flag
#define BITFIELD_TESTNET	0x10
#define BITFIELD_ECDSA_k1	0x01
#define BITFIELD_ECDSA_r1	0x00

	class Account
	{
	public:
		enum ECDSA {
			SECP256k1,
			SECP256r1,
			not_calculated
		};
		Account();
		Account(uint8_t *keyPriv);
		Account(MCP39::long_hash keyPriv);
		Account(uint8_t *keyPriv, uint8_t *keyPub, ECDSA ecdsaPubKey);
		~Account();

		bool						calcPubKey(ECDSA type);
		bool						calcWalletAddress(uint8_t* walletAddress, uint16_t uiChainIdentifier, bool bTestNet = false);

		uint8_t*					getPrivKey() { return m_keyPriv; };
		std::string					getPrivKeyStr() { return encode_base16(m_keyPriv, 64); };
		uint8_t*					getPubKey() { return m_keyPub; };
		std::string					getPubKeyStr() { return encode_base16(m_keyPub, 64); };

		void						setWalletAddress(std::string strWalletAddress) { m_strWalletAddress = strWalletAddress; };
		std::string					getWalletAddress() { return m_strWalletAddress; };
		std::string					getWalletAddress(std::string strChainIdentifier, bool bTestNet = false);
		bool						verifyWalletAddress() { return verifyWalletAddress(m_strWalletAddress); };
		bool						verifyWalletAddress(std::string);

		// getter
		bool						isTestNet() { return m_uiFlags & BITFIELD_TESTNET; };
		bool						isSECPk1() { return m_uiFlags & BITFIELD_ECDSA_k1; };
		bool						isSECPr1() { return m_uiFlags & BITFIELD_ECDSA_r1; };
		bool						isBaseAddress() { return m_uint16ChainIdentifier == CHAINIDENTIFIER_BASECHAIN; };

	private:
		uint8_t						m_keyPriv[64];
		uint8_t						m_keyPub[64];
		ECDSA						m_ecdsaPubKey;

		// the wallet address and the details of it
		std::string					m_strWalletAddress;
		uint16_t					m_uint16ChainIdentifier;
		uint8_t						m_uint8VersionNumber;
		uint8_t						m_uiFlags;

		std::string					tokenize(std::string strWalletAddress);
		std::string					untokenize(std::string strWalletAddress);
	};
}
#endif