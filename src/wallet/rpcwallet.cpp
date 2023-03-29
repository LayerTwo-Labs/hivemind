// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <base58.h>
#include <bmmcache.h>
#include <chain.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <httpserver.h>
#include <validation.h>
#include <net.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/market.h>
#include <rpc/mining.h>
#include <rpc/rawtransaction.h>
#include <rpc/safemode.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/sign.h>
#include <timedata.h>
#include <txdb.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>

#include <init.h>  // For StartShutdown

#include <stdint.h>

#include <univalue.h>

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";

static inline uint64_t rounduint64(double d)
{
    return (uint64_t)(d + 0.5);
}

CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    if (request.URI.substr(0, WALLET_ENDPOINT_BASE.size()) == WALLET_ENDPOINT_BASE) {
        // wallet endpoint was used
        std::string requestedWallet = urlDecode(request.URI.substr(WALLET_ENDPOINT_BASE.size()));
        for (CWalletRef pwallet : ::vpwallets) {
            if (pwallet->GetName() == requestedWallet) {
                return pwallet;
            }
        }
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }
    return ::vpwallets.size() == 1 || (request.fHelp && ::vpwallets.size() > 0) ? ::vpwallets[0] : nullptr;
}

std::string HelpRequiringPassphrase(CWallet * const pwallet)
{
    return pwallet && pwallet->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(CWallet * const pwallet, bool avoidException)
{
    if (pwallet) return true;
    if (avoidException) return false;
    if (::vpwallets.empty()) {
        // Note: It isn't currently possible to trigger this error because
        // wallet RPC methods aren't registered unless a wallet is loaded. But
        // this error is being kept as a precaution, because it's possible in
        // the future that wallet RPC methods might get or remain registered
        // when no wallets are loaded.
        throw JSONRPCError(
            RPC_METHOD_NOT_FOUND, "Method not found (wallet method is disabled because no wallet is loaded)");
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path).");
}

void EnsureWalletIsUnlocked(CWallet * const pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.pushKV("confirmations", confirms);
    if (wtx.IsCoinBase())
        entry.pushKV("generated", true);
    if (confirms > 0)
    {
        entry.pushKV("blockhash", wtx.hashBlock.GetHex());
        entry.pushKV("blockindex", wtx.nIndex);
        entry.pushKV("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime());
    } else {
        entry.pushKV("trusted", wtx.IsTrusted());
    }
    uint256 hash = wtx.GetHash();
    entry.pushKV("txid", hash.GetHex());
    UniValue conflicts(UniValue::VARR);
    for (const uint256& conflict : wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.pushKV("walletconflicts", conflicts);
    entry.pushKV("time", wtx.GetTxTime());
    entry.pushKV("timereceived", (int64_t)wtx.nTimeReceived);

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        LOCK(mempool.cs);
        RBFTransactionState rbfState = IsRBFOptIn(*wtx.tx, mempool);
        if (rbfState == RBF_TRANSACTIONSTATE_UNKNOWN)
            rbfStatus = "unknown";
        else if (rbfState == RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125)
            rbfStatus = "yes";
    }
    entry.pushKV("bip125-replaceable", rbfStatus);

    for (const std::pair<std::string, std::string>& item : wtx.mapValue)
        entry.pushKV(item.first, item.second);
}

std::string AccountFromValue(const UniValue& value)
{
    std::string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

UniValue getnewaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "getnewaddress ( \"account\" \"address_type\" )\n"
            "\nReturns a new Bitcoin address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "2. \"address_type\"   (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -addresstype.\n"
            "\nResult:\n"
            "\"address\"    (string) The new bitcoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (!request.params[0].isNull())
        strAccount = AccountFromValue(request.params[0]);

    OutputType output_type = g_address_type;
    if (!request.params[1].isNull()) {
        output_type = ParseOutputType(request.params[1].get_str(), g_address_type);
        if (output_type == OUTPUT_TYPE_NONE) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[1].get_str()));
        }
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    pwallet->LearnRelatedScripts(newKey, output_type);
    CTxDestination dest = GetDestinationForKey(newKey, output_type);

    pwallet->SetAddressBook(dest, strAccount, "receive");

    return EncodeDestination(dest);
}

UniValue getdepositaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "getdepositaddress\n"
            "\nReturns a new sidechain deposit address for receiving deposits from the mainchain.\n"
            "\nResult:\n"
            "\"address\"    (string) The new sidechain deposit address\n"
            "\nExamples:\n"
            + HelpExampleCli("getdepositaddress", "")
            + HelpExampleRpc("getdepositaddress", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    OutputType output_type = OUTPUT_TYPE_LEGACY;

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    pwallet->LearnRelatedScripts(newKey, output_type);
    CTxDestination dest = GetDestinationForKey(newKey, output_type);

    pwallet->SetAddressBook(dest, "sidechain", "deposit");

    return GenerateDepositAddress(EncodeDestination(dest));
}

CTxDestination GetAccountDestination(CWallet* const pwallet, std::string strAccount, bool bForceNew=false)
{
    CTxDestination dest;
    if (!pwallet->GetAccountDestination(dest, strAccount, bForceNew)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    return dest;
}

UniValue getaccountaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current Bitcoin address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"address\"          (string) The account bitcoin address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountaddress", "")
            + HelpExampleCli("getaccountaddress", "\"\"")
            + HelpExampleCli("getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(request.params[0]);

    UniValue ret(UniValue::VSTR);

    ret = EncodeDestination(GetAccountDestination(pwallet, strAccount));
    return ret;
}


UniValue getrawchangeaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getrawchangeaddress ( \"address_type\" )\n"
            "\nReturns a new Bitcoin address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nArguments:\n"
            "1. \"address_type\"           (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -changetype.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    OutputType output_type = g_change_type != OUTPUT_TYPE_NONE ? g_change_type : g_address_type;
    if (!request.params[0].isNull()) {
        output_type = ParseOutputType(request.params[0].get_str(), output_type);
        if (output_type == OUTPUT_TYPE_NONE) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[0].get_str()));
        }
    }

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey, true))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    pwallet->LearnRelatedScripts(vchPubKey, output_type);
    CTxDestination dest = GetDestinationForKey(vchPubKey, output_type);

    return EncodeDestination(dest);
}


UniValue setaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "setaccount \"address\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The bitcoin address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"tabby\"")
            + HelpExampleRpc("setaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }

    std::string strAccount;
    if (!request.params[1].isNull())
        strAccount = AccountFromValue(request.params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, dest)) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(dest)) {
            std::string strOldAccount = pwallet->mapAddressBook[dest].name;
            if (dest == GetAccountDestination(pwallet, strOldAccount)) {
                GetAccountDestination(pwallet, strOldAccount, true);
            }
        }
        pwallet->SetAddressBook(dest, strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue;
}


UniValue getaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaccount \"address\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The bitcoin address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")
            + HelpExampleRpc("getaccount", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }

    std::string strAccount;
    std::map<CTxDestination, CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(dest);
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty()) {
        strAccount = (*mi).second.name;
    }
    return strAccount;
}


UniValue getaddressesbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"address\"         (string) a bitcoin address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const std::pair<CTxDestination, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CTxDestination& dest = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount) {
            ret.push_back(EncodeDestination(dest));
        }
    }
    return ret;
}

static void SendMoney(CWallet * const pwallet, const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CCoinControl& coin_control)
{
    CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

UniValue sendtoaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw std::runtime_error(
            "sendtoaddress \"address\" amount ( \"comment\" \"comment_to\" subtractfeefromamount replaceable conf_target \"estimate_mode\")\n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"address\"            (string, required) The bitcoin address to send to.\n"
            "2. \"amount\"             (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"            (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment_to\"         (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "6. replaceable            (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
            "7. conf_target            (numeric, optional) Confirmation target (in blocks)\n"
            "8. \"estimate_mode\"      (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    CWalletTx wtx;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"]      = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (!request.params[4].isNull()) {
        fSubtractFeeFromAmount = request.params[4].get_bool();
    }

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.signalRbf = request.params[5].get_bool();
    }

    if (!request.params[6].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[6]);
    }

    if (!request.params[7].isNull()) {
        if (!FeeModeFromString(request.params[7].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }


    EnsureWalletIsUnlocked(pwallet);

    SendMoney(pwallet, dest, nAmount, fSubtractFeeFromAmount, wtx, coin_control);

    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"address\",            (string) The bitcoin address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) DEPRECATED. The account\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (const std::set<CTxDestination>& grouping : pwallet->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        for (const CTxDestination& address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(EncodeDestination(address));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwallet->mapAddressBook.find(address) != pwallet->mapAddressBook.end()) {
                    addressInfo.push_back(pwallet->mapAddressBook.find(address)->second.name);
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue signmessage(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessage \"address\" \"message\"\n"
            "\nSign a message with the private key of an address"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The bitcoin address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"my message\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

UniValue getreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaddress \"address\" ( minconf )\n"
            "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The bitcoin address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", 6")
       );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Bitcoin address
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    CScript scriptPubKey = GetScriptForDestination(dest);
    if (!IsMine(*pwallet, scriptPubKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        for (const CTxOut& txout : wtx.tx->vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(request.params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        for (const CTxOut& txout : wtx.tx->vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwallet, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
            }
        }
    }

    return ValueFromAmount(nAmount);
}


UniValue getbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "getbalance ( \"account\" minconf include_watchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "The available balance is what the wallet considers currently spendable, and is\n"
            "thus affected by options which limit spendability such as -spendzeroconfchange.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"         (string, optional) DEPRECATED. The account string may be given as a\n"
            "                     specific account name to find the balance associated with wallet keys in\n"
            "                     a named account, or as the empty string (\"\") to find the balance\n"
            "                     associated with wallet keys not in any named account, or as \"*\" to find\n"
            "                     the balance associated with all wallet keys regardless of account.\n"
            "                     When this option is specified, it calculates the balance in a different\n"
            "                     way than when it is not specified, and which can count spends twice when\n"
            "                     there are conflicting pending transactions (such as those created by\n"
            "                     the bumpfee command), temporarily resulting in low or even negative\n"
            "                     balances. In general, account balance calculation is not considered\n"
            "                     reliable and has resulted in confusing outcomes, so it is recommended to\n"
            "                     avoid passing this argument.\n"
            "2. minconf           (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. include_watchonly (bool, optional, default=false) Also include balance in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet with 1 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 6 blocks confirmed\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    const UniValue& account_value = request.params[0];
    const UniValue& minconf = request.params[1];
    const UniValue& include_watchonly = request.params[2];

    if (account_value.isNull()) {
        if (!minconf.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "getbalance minconf option is only currently supported if an account is specified");
        }
        if (!include_watchonly.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "getbalance include_watchonly option is only currently supported if an account is specified");
        }
        return ValueFromAmount(pwallet->GetBalance());
    }

    const std::string& account_param = account_value.get_str();
    const std::string* account = account_param != "*" ? &account_param : nullptr;

    int nMinDepth = 1;
    if (!minconf.isNull())
        nMinDepth = minconf.get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(!include_watchonly.isNull())
        if(include_watchonly.get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    return ValueFromAmount(pwallet->GetLegacyBalance(filter, nMinDepth, account));
}

UniValue getunconfirmedbalance(const JSONRPCRequest &request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}


UniValue movecmd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. (dummy)           (numeric, optional) Ignored. Remains for backward compatibility.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"
            "\nExamples:\n"
            "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
            + HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
            + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strFrom = AccountFromValue(request.params[0]);
    std::string strTo = AccountFromValue(request.params[1]);
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (!request.params[3].isNull())
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)request.params[3].get_int();
    std::string strComment;
    if (!request.params[4].isNull())
        strComment = request.params[4].get_str();

    if (!pwallet->AccountMove(strFrom, strTo, nAmount, strComment)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

    return true;
}


UniValue sendfrom(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 6)
        throw std::runtime_error(
            "sendfrom \"fromaccount\" \"toaddress\" amount ( minconf \"comment\" \"comment_to\" )\n"
            "\nDEPRECATED (use sendtoaddress). Sent an amount from an account to a bitcoin address."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "                       Specifying an account does not influence coin selection, but it does associate the newly created\n"
            "                       transaction with the account, so the account's balance computation and transaction history can reflect\n"
            "                       the spend.\n"
            "2. \"toaddress\"         (string, required) The bitcoin address to send funds to.\n"
            "3. amount                (numeric or string, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment_to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "\nResult:\n"
            "\"txid\"                 (string) The transaction id.\n"
            "\nExamples:\n"
            "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
            + HelpExampleCli("sendfrom", "\"\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
            + HelpExampleCli("sendfrom", "\"tabby\" \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendfrom", "\"tabby\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.01, 6, \"donation\", \"seans outpost\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);
    CTxDestination dest = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1;
    if (!request.params[3].isNull())
        nMinDepth = request.params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (!request.params[4].isNull() && !request.params[4].get_str().empty())
        wtx.mapValue["comment"] = request.params[4].get_str();
    if (!request.params[5].isNull() && !request.params[5].get_str().empty())
        wtx.mapValue["to"]      = request.params[5].get_str();

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    CCoinControl no_coin_control; // This is a deprecated API
    SendMoney(pwallet, dest, nAmount, false, wtx, no_coin_control);

    return wtx.GetHash().GetHex();
}


UniValue sendmany(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw std::runtime_error(
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] replaceable conf_target \"estimate_mode\")\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The bitcoin address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. subtractfeefrom         (array, optional) A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
            "                           If no addresses are specified here, the sender pays the fee.\n"
            "    [\n"
            "      \"address\"          (string) Subtract fee from this address\n"
            "      ,...\n"
            "    ]\n"
            "6. replaceable            (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
            "7. conf_target            (numeric, optional) Confirmation target (in blocks)\n"
            "8. \"estimate_mode\"      (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
             "\nResult:\n"
            "\"txid\"                   (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\":0.01,\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\":0.02}\" 1 \"\" \"[\\\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\\\",\\\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendmany", "\"\", {\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\":0.01,\"1353tsE8YMTA4EuV7dgUXGjNFf9KpVvKHz\":0.02}, 6, \"testing\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    std::string strAccount = AccountFromValue(request.params[0]);
    UniValue sendTo = request.params[1].get_obj();
    int nMinDepth = 1;
    if (!request.params[2].isNull())
        nMinDepth = request.params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["comment"] = request.params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (!request.params[4].isNull())
        subtractFeeFromAmount = request.params[4].get_array();

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.signalRbf = request.params[5].get_bool();
    }

    if (!request.params[6].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[6]);
    }

    if (!request.params[7].isNull()) {
        if (!FeeModeFromString(request.params[7].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }

    std::set<CTxDestination> destinations;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    std::vector<std::string> keys = sendTo.getKeys();
    for (const std::string& name_ : keys) {
        CTxDestination dest = DecodeDestination(name_);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + name_);
        }

        if (destinations.count(dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
        }
        destinations.insert(dest);

        CScript scriptPubKey = GetScriptForDestination(dest);
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) {
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwallet);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    std::string strFailReason;
    bool fCreated = pwallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, coin_control);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, keyChange, g_connman.get(), state)) {
        strFailReason = strprintf("Transaction commit failed:: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    return wtx.GetHash().GetHex();
}

UniValue addmultisigaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4) {
        std::string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" \"address_type\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.\n"
            "Each key is a Bitcoin address or hex-encoded public key.\n"
            "This functionality is only intended for use with non-watchonly addresses.\n"
            "See `importaddress` for watchonly p2sh address support.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired                      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"                         (string, required) A json array of bitcoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"                  (string) bitcoin address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"                      (string, optional) DEPRECATED. An account to assign the addresses to.\n"
            "4. \"address_type\"                 (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -addresstype.\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",    (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"         (string) The string value of the hex-encoded redemption script.\n"
            "}\n"
            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5\\\",\\\"171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount;
    if (!request.params[2].isNull())
        strAccount = AccountFromValue(request.params[2]);

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys_or_addrs = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys_or_addrs.size(); ++i) {
        if (IsHex(keys_or_addrs[i].get_str()) && (keys_or_addrs[i].get_str().length() == 66 || keys_or_addrs[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys_or_addrs[i].get_str()));
        } else {
            pubkeys.push_back(AddrToPubKey(pwallet, keys_or_addrs[i].get_str()));
        }
    }

    OutputType output_type = g_address_type;
    if (!request.params[3].isNull()) {
        output_type = ParseOutputType(request.params[3].get_str(), output_type);
        if (output_type == OUTPUT_TYPE_NONE) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[3].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    pwallet->AddCScript(inner);
    CTxDestination dest = pwallet->AddAndGetDestinationForScript(inner, output_type);
    pwallet->SetAddressBook(dest, strAccount, "send");

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));
    return result;
}

class Witnessifier : public boost::static_visitor<bool>
{
public:
    CWallet * const pwallet;
    CTxDestination result;
    bool already_witness;

    explicit Witnessifier(CWallet *_pwallet) : pwallet(_pwallet), already_witness(false) {}

    bool operator()(const CKeyID &keyID) {
        if (pwallet) {
            CScript basescript = GetScriptForDestination(keyID);
            CScript witscript = GetScriptForWitness(basescript);
            if (!IsSolvable(*pwallet, witscript)) {
                return false;
            }
            return ExtractDestination(witscript, result);
        }
        return false;
    }

    bool operator()(const CScriptID &scriptID) {
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            int witnessversion;
            std::vector<unsigned char> witprog;
            if (subscript.IsWitnessProgram(witnessversion, witprog)) {
                ExtractDestination(subscript, result);
                already_witness = true;
                return true;
            }
            CScript witscript = GetScriptForWitness(subscript);
            if (!IsSolvable(*pwallet, witscript)) {
                return false;
            }
            return ExtractDestination(witscript, result);
        }
        return false;
    }

    bool operator()(const WitnessV0KeyHash& id)
    {
        already_witness = true;
        result = id;
        return true;
    }

    bool operator()(const WitnessV0ScriptHash& id)
    {
        already_witness = true;
        result = id;
        return true;
    }

    template<typename T>
    bool operator()(const T& dest) { return false; }
};

UniValue addwitnessaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
    {
        std::string msg = "addwitnessaddress \"address\" ( p2sh )\n"
            "\nDEPRECATED: set the address_type argument of getnewaddress, or option -addresstype=[bech32|p2sh-segwit] instead.\n"
            "Add a witness address for a script (with pubkey or redeemscript known). Requires a new wallet backup.\n"
            "It returns the witness script.\n"

            "\nArguments:\n"
            "1. \"address\"       (string, required) An address known to the wallet\n"
            "2. p2sh            (bool, optional, default=true) Embed inside P2SH\n"

            "\nResult:\n"
            "\"witnessaddress\",  (string) The value of the new address (P2SH or BIP173).\n"
            "}\n"
        ;
        throw std::runtime_error(msg);
    }

    if (!IsDeprecatedRPCEnabled("addwitnessaddress")) {
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "addwitnessaddress is deprecated and will be fully removed in v0.17. "
            "To use addwitnessaddress in v0.16, restart hivemindd with -deprecatedrpc=addwitnessaddress.\n"
            "Projects should transition to using the address_type argument of getnewaddress, or option -addresstype=[bech32|p2sh-segwit] instead.\n");
    }

    {
        LOCK(cs_main);
        if (!IsWitnessEnabled(chainActive.Tip(), Params().GetConsensus()) && !gArgs.GetBoolArg("-walletprematurewitness", false)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Segregated witness not enabled on network");
        }
    }

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }

    bool p2sh = true;
    if (!request.params[1].isNull()) {
        p2sh = request.params[1].get_bool();
    }

    Witnessifier w(pwallet);
    bool ret = boost::apply_visitor(w, dest);
    if (!ret) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Public key or redeemscript not known to wallet, or the key is uncompressed");
    }

    CScript witprogram = GetScriptForDestination(w.result);

    if (p2sh) {
        w.result = CScriptID(witprogram);
    }

    if (w.already_witness) {
        if (!(dest == w.result)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot convert between witness address types");
        }
    } else {
        pwallet->AddCScript(witprogram); // Implicit for single-key now, but necessary for multisig and for compatibility with older software
        pwallet->SetAddressBook(w.result, "", "receive");
    }

    return EncodeDestination(w.result);
}

struct tallyitem
{
    CAmount nAmount;
    int nConf;
    std::vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(CWallet * const pwallet, const UniValue& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if(!params[2].isNull())
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        for (const CTxOut& txout : wtx.tx->vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwallet, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> mapAccountTally;
    for (const std::pair<CTxDestination, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CTxDestination& dest = item.first;
        const std::string& strAccount = item.second.name;
        std::map<CTxDestination, tallyitem>::iterator it = mapTally.find(dest);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts)
        {
            tallyitem& _item = mapAccountTally[strAccount];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("address",       EncodeDestination(dest));
            obj.pushKV("account",       strAccount);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            if (!fByAccounts)
                obj.pushKV("label", strAccount);
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end())
            {
                for (const uint256& _item : (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.pushKV("txids", transactions);
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (const auto& entry : mapAccountTally)
        {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            if (entry.second.fIsWatchonly)
                obj.pushKV("involvesWatchonly", true);
            obj.pushKV("account",       entry.first);
            obj.pushKV("amount",        ValueFromAmount(nAmount));
            obj.pushKV("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue listreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaddress ( minconf include_empty include_watchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\",               (string) A comment for the address/transaction, if any\n"
            "    \"txids\": [\n"
            "       n,                                (numeric) The ids of transactions received with the address \n"
            "       ...\n"
            "    ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, false);
}

UniValue listreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaccount ( minconf include_empty include_watchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaccount", "")
            + HelpExampleCli("listreceivedbyaccount", "6 true")
            + HelpExampleRpc("listreceivedbyaccount", "6, true, true")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest)) {
        entry.pushKV("address", EncodeDestination(dest));
    }
}

/**
 * List transactions based on the given criteria.
 *
 * @param  pwallet    The wallet.
 * @param  wtx        The wallet transaction.
 * @param  strAccount The account, if any, or "*" for all.
 * @param  nMinDepth  The minimum confirmation depth.
 * @param  fLong      Whether to include the JSON version of the transaction.
 * @param  ret        The UniValue into which the result is stored.
 * @param  filter     The "is mine" filter bool.
 */
void ListTransactions(CWallet* const pwallet, const CWalletTx& wtx, const std::string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == std::string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY)) {
                entry.pushKV("involvesWatchonly", true);
            }
            entry.pushKV("account", strSentAccount);
            MaybePushAddress(entry, s.destination);
            entry.pushKV("category", "send");
            entry.pushKV("amount", ValueFromAmount(-s.amount));
            if (pwallet->mapAddressBook.count(s.destination)) {
                entry.pushKV("label", pwallet->mapAddressBook[s.destination].name);
            }
            entry.pushKV("vout", s.vout);
            entry.pushKV("fee", ValueFromAmount(-nFee));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.pushKV("abandoned", wtx.isAbandoned());
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        for (const COutputEntry& r : listReceived)
        {
            std::string account;
            if (pwallet->mapAddressBook.count(r.destination)) {
                account = pwallet->mapAddressBook[r.destination].name;
            }
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY)) {
                    entry.pushKV("involvesWatchonly", true);
                }
                entry.pushKV("account", account);
                MaybePushAddress(entry, r.destination);
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.pushKV("category", "orphan");
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.pushKV("category", "immature");
                    else
                        entry.pushKV("category", "generate");
                }
                else
                {
                    entry.pushKV("category", "receive");
                }
                entry.pushKV("amount", ValueFromAmount(r.amount));
                if (pwallet->mapAddressBook.count(r.destination)) {
                    entry.pushKV("label", account);
                }
                entry.pushKV("vout", r.vout);
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const std::string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == std::string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("account", acentry.strAccount);
        entry.pushKV("category", "move");
        entry.pushKV("time", acentry.nTime);
        entry.pushKV("amount", ValueFromAmount(acentry.nCreditDebit));
        entry.pushKV("otheraccount", acentry.strOtherAccount);
        entry.pushKV("comment", acentry.strComment);
        ret.push_back(entry);
    }
}

UniValue listtransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
            "listtransactions ( \"account\" count skip include_watchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. skip           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. include_watchonly (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"address\",    (string) The bitcoin address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"label\": \"label\",       (string) A comment for the address/transaction, if any\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx,           (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"otheraccount\": \"accountname\",  (string) DEPRECATED. For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                         'send' category of transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::string strAccount = "*";
    if (!request.params[0].isNull())
        strAccount = request.params[0].get_str();
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].get_int();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[3].isNull())
        if(request.params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    {
        LOCK2(cs_main, pwallet->cs_wallet);

        const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
        {
            CWalletTx *const pwtx = (*it).second.first;
            if (pwtx != nullptr)
                ListTransactions(pwallet, *pwtx, strAccount, 0, true, ret, filter);
            CAccountingEntry *const pacentry = (*it).second.second;
            if (pacentry != nullptr)
                AcentryToJSON(*pacentry, strAccount, ret);

            if ((int)ret.size() >= (nCount+nFrom)) break;
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    std::vector<UniValue> arrTmp = ret.getValues();

    std::vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    std::vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue listaccounts(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "listaccounts ( minconf include_watchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf             (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. include_watchonly   (bool, optional, default=false) Include balances in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n"
            + HelpExampleCli("listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n"
            + HelpExampleCli("listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n"
            + HelpExampleCli("listaccounts", "6") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("listaccounts", "6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    int nMinDepth = 1;
    if (!request.params[0].isNull())
        nMinDepth = request.params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(!request.params[1].isNull())
        if(request.params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    std::map<std::string, CAmount> mapAccountBalances;
    for (const std::pair<CTxDestination, CAddressBookData>& entry : pwallet->mapAddressBook) {
        if (IsMine(*pwallet, entry.first) & includeWatchonly) {  // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
        }
    }

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        CAmount nFee;
        std::string strSentAccount;
        std::list<COutputEntry> listReceived;
        std::list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for (const COutputEntry& s : listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth)
        {
            for (const COutputEntry& r : listReceived)
                if (pwallet->mapAddressBook.count(r.destination)) {
                    mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
                }
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const std::list<CAccountingEntry>& acentries = pwallet->laccentries;
    for (const CAccountingEntry& entry : acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    for (const std::pair<std::string, CAmount>& accountBalance : mapAccountBalances) {
        ret.pushKV(accountBalance.first, ValueFromAmount(accountBalance.second));
    }
    return ret;
}

UniValue listsinceblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
            "listsinceblock ( \"blockhash\" target_confirmations include_watchonly include_removed )\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
            "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
            "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n"
            "\nArguments:\n"
            "1. \"blockhash\"            (string, optional) The block hash to list transactions since\n"
            "2. target_confirmations:    (numeric, optional, default=1) Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value\n"
            "3. include_watchonly:       (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "4. include_removed:         (bool, optional, default=true) Show transactions that were removed due to a reorg in the \"removed\" array\n"
            "                                                           (not guaranteed to work on pruned nodes)\n"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"address\",    (string) The bitcoin address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "                                          When it's < 0, it means the transaction conflicted that many blocks ago.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"removed\": [\n"
            "    <structure is the same as \"transactions\" above, only present if include_removed=true>\n"
            "    Note: transactions that were readded in the active chain will appear as-is in this array, and may thus have a positive confirmation count.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the block (target_confirmations-1) from the best block on the main chain. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    const CBlockIndex* pindex = nullptr;    // Block index of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    const CBlockIndex* paltindex = nullptr; // Block index of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        uint256 blockId;

        blockId.SetHex(request.params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it == mapBlockIndex.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        paltindex = pindex = it->second;
        if (chainActive[pindex->nHeight] != pindex) {
            // the block being asked for is a part of a deactivated chain;
            // we don't want to depend on its perceived height in the block
            // chain, we want to instead use the last common ancestor
            pindex = chainActive.FindFork(pindex);
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    bool include_removed = (request.params[3].isNull() || request.params[3].get_bool());

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        CWalletTx tx = pairWtx.second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth) {
            ListTransactions(pwallet, tx, "*", 0, true, transactions, filter);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && paltindex && paltindex != pindex) {
        CBlock block;
        if (!ReadBlockFromDisk(block, paltindex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            auto it = pwallet->mapWallet.find(tx->GetHash());
            if (it != pwallet->mapWallet.end()) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(pwallet, it->second, "*", -100000000, true, removed, filter);
            }
        }
        paltindex = paltindex->pprev;
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("transactions", transactions);
    if (include_removed) ret.pushKV("removed", removed);
    ret.pushKV("lastblock", lastblock.GetHex());

    return ret;
}

UniValue gettransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "gettransaction \"txid\" ( include_watchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"                  (string, required) The transaction id\n"
            "2. \"include_watchonly\"     (bool, optional, default=false) Whether to include watch-only addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
            "  \"fee\": x.xxx,            (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                              'send' category of transactions.\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The index of the transaction in the block that includes it\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",      (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"address\",          (string) The bitcoin address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "      \"fee\": x.xxx,                     (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                           'send' category of transactions.\n"
            "      \"abandoned\": xxx                  (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                           'send' category of transactions.\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[1].isNull())
        if(request.params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    auto it = pwallet->mapWallet.find(hash);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = it->second;

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.tx->GetValueOut() - nDebit : 0);

    entry.pushKV("amount", ValueFromAmount(nNet - nFee));
    if (wtx.IsFromMe(filter))
        entry.pushKV("fee", ValueFromAmount(nFee));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, "*", 0, false, details, filter);
    entry.pushKV("details", details);

    std::string strHex = EncodeHexTx(*wtx.tx, RPCSerializationFlags());
    entry.pushKV("hex", strHex);

    return entry;
}

UniValue abandontransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return NullUniValue;
}


UniValue backupwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return NullUniValue;
}


UniValue keypoolrefill(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(pWallet->cs_wallet);
    pWallet->nRelockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "walletpassphrase \"passphrase\" timeout\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending bitcoins\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds. Limited to at most 1073741824 (2^30) seconds.\n"
            "                                          Any value greater than 1073741824 seconds will be set to 1073741824 seconds.\n"
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 60 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    }

    // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    strWalletPass = request.params[0].get_str().c_str();

    // Get the timeout
    int64_t nSleepTime = request.params[1].get_int64();
    // Timeout cannot be negative, otherwise it will relock immediately
    if (nSleepTime < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
    }
    // Clamp timeout to 2^30 seconds
    if (nSleepTime > (int64_t)1 << 30) {
        nSleepTime = (int64_t)1 << 30;
    }

    if (strWalletPass.length() > 0)
    {
        if (!pwallet->Unlock(strWalletPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }
    }
    else
        throw std::runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwallet->TopUpKeyPool();

    pwallet->nRelockTime = GetTime() + nSleepTime;
    RPCRunLater(strprintf("lockwallet(%s)", pwallet->GetName()), boost::bind(LockWallet, pwallet), nSleepTime);

    return NullUniValue;
}


UniValue walletpassphrasechange(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw std::runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return NullUniValue;
}


UniValue walletlock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletlock", "")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return NullUniValue;
}


UniValue encryptwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the walletpassphrase call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt your wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending bitcoin\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like sign\n"
            + HelpExampleCli("signmessage", "\"address\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw std::runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwallet->EncryptWallet(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; Bitcoin server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

UniValue lockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "lockunspent unlock ([{\"txid\":\"txid\",\"vout\":n},...])\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending bitcoins.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the listunspent call\n"
            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, optional) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    RPCTypeCheckArgument(request.params[0], UniValue::VBOOL);

    bool fUnlock = request.params[0].get_bool();

    if (request.params[1].isNull()) {
        if (fUnlock)
            pwallet->UnlockAllCoins();
        return true;
    }

    RPCTypeCheckArgument(request.params[1], UniValue::VARR);

    const UniValue& output_params = request.params[1];

    // Create and validate the COutPoints first.

    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (unsigned int idx = 0; idx < output_params.size(); idx++) {
        const UniValue& o = output_params[idx].get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        const std::string& txid = find_value(o, "txid").get_str();
        if (!IsHex(txid)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");
        }

        const int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");
        }

        const COutPoint outpt(uint256S(txid), nOutput);

        const auto it = pwallet->mapWallet.find(outpt.hash);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown transaction");
        }

        const CWalletTx& trans = it->second;

        if (outpt.n >= trans.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(outpt.hash, outpt.n)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(outpt.hash, outpt.n);

        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output already locked");
        }

        outputs.push_back(outpt);
    }

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint& outpt : outputs) {
        if (fUnlock) pwallet->UnlockCoin(outpt);
        else pwallet->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listlockunspent", "")
        );

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (COutPoint &outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.pushKV("txid", outpt.hash.GetHex());
        o.pushKV("vout", (int)outpt.n);
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
            "settxfee amount\n"
            "\nSet the transaction fee per kB. Overwrites the paytxfee parameter.\n"
            "\nArguments:\n"
            "1. amount         (numeric or string, required) The transaction fee in " + CURRENCY_UNIT + "/kB\n"
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n"
            + HelpExampleCli("settxfee", "0.00001")
            + HelpExampleRpc("settxfee", "0.00001")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Amount
    CAmount nAmount = AmountFromValue(request.params[0]);

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletname\": xxxxx,             (string) the wallet name\n"
            "  \"walletversion\": xxxxx,          (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,              (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"unconfirmed_balance\": xxx,      (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"immature_balance\": xxxxxx,      (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"txcount\": xxxxxxx,              (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,         (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,             (numeric) how many new keys are pre-generated (only counts external keys)\n"
            "  \"keypoolsize_hd_internal\": xxxx, (numeric) how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)\n"
            "  \"unlocked_until\": ttt,           (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,              (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
            "  \"hdmasterkeyid\": \"<hash160>\"     (string, optional) the Hash160 of the HD master pubkey (only present when HD is enabled)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.pushKV("walletname", pwallet->GetName());
    obj.pushKV("walletversion", pwallet->GetVersion());
    obj.pushKV("balance",       ValueFromAmount(pwallet->GetBalance()));
    obj.pushKV("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance()));
    obj.pushKV("immature_balance",    ValueFromAmount(pwallet->GetImmatureBalance()));
    obj.pushKV("txcount",       (int)pwallet->mapWallet.size());
    obj.pushKV("keypoololdest", pwallet->GetOldestKeyPoolTime());
    obj.pushKV("keypoolsize", (int64_t)kpExternalSize);
    CKeyID masterKeyID = pwallet->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull() && pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.pushKV("keypoolsize_hd_internal",   (int64_t)(pwallet->GetKeyPoolSize() - kpExternalSize));
    }
    if (pwallet->IsCrypted()) {
        obj.pushKV("unlocked_until", pwallet->nRelockTime);
    }
    obj.pushKV("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK()));
    if (!masterKeyID.IsNull())
         obj.pushKV("hdmasterkeyid", masterKeyID.GetHex());
    return obj;
}

UniValue listwallets(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listwallets\n"
            "Returns a list of currently loaded wallets.\n"
            "For full information on the wallet, use \"getwalletinfo\"\n"
            "\nResult:\n"
            "[                         (json array of strings)\n"
            "  \"walletname\"            (string) the wallet name\n"
            "   ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
        );

    UniValue obj(UniValue::VARR);

    for (CWalletRef pwallet : vpwallets) {

        if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
            return NullUniValue;
        }

        LOCK(pwallet->cs_wallet);

        obj.push_back(pwallet->GetName());
    }

    return obj;
}

UniValue resendwallettransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns an RPC error if -walletbroadcast is set to false.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    if (!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->GetBroadcastTransactions()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast");
    }

    std::vector<uint256> txids = pwallet->ResendWalletTransactionsBefore(GetTime(), g_connman.get());
    UniValue result(UniValue::VARR);
    for (const uint256& txid : txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue listunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 5)
        throw std::runtime_error(
            "listunspent ( minconf maxconf  [\"addresses\",...] [include_unsafe] [query_options])\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"      (string) A json array of bitcoin addresses to filter\n"
            "    [\n"
            "      \"address\"     (string) bitcoin address\n"
            "      ,...\n"
            "    ]\n"
            "4. include_unsafe (bool, optional, default=true) Include outputs that are not safe to spend\n"
            "                  See description of \"safe\" attribute below.\n"
            "5. query_options    (json, optional) JSON with query options\n"
            "    {\n"
            "      \"minimumAmount\"    (numeric or string, default=0) Minimum value of each UTXO in " + CURRENCY_UNIT + "\n"
            "      \"maximumAmount\"    (numeric or string, default=unlimited) Maximum value of each UTXO in " + CURRENCY_UNIT + "\n"
            "      \"maximumCount\"     (numeric or string, default=unlimited) Maximum number of UTXOs\n"
            "      \"minimumSumAmount\" (numeric or string, default=unlimited) Minimum sum value of all UTXOs in " + CURRENCY_UNIT + "\n"
            "    }\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",          (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",    (string) the bitcoin address\n"
            "    \"account\" : \"account\",    (string) DEPRECATED. The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\",   (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction output amount in " + CURRENCY_UNIT + "\n"
            "    \"confirmations\" : n,      (numeric) The number of confirmations\n"
            "    \"redeemScript\" : n        (string) The redeemScript if scriptPubKey is P2SH\n"
            "    \"spendable\" : xxx,        (bool) Whether we have the private keys to spend this output\n"
            "    \"solvable\" : xxx,         (bool) Whether we know how to spend this output, ignoring the lack of keys\n"
            "    \"safe\" : xxx              (bool) Whether this output is considered safe to spend. Unconfirmed transactions\n"
            "                              from outside keys and unconfirmed replacement transactions are considered unsafe\n"
            "                              and are not eligible for spending by fundrawtransaction and sendtoaddress.\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
            + HelpExampleCli("listunspent", "6 9999999 '[]' true '{ \"minimumAmount\": 0.005 }'")
            + HelpExampleRpc("listunspent", "6, 9999999, [] , true, { \"minimumAmount\": 0.005 } ")
        );

    ObserveSafeMode();

    int nMinDepth = 1;
    if (!request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 9999999;
    if (!request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    std::set<CTxDestination> destinations;
    if (!request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CTxDestination dest = DecodeDestination(input.get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Bitcoin address: ") + input.get_str());
            }
            if (!destinations.insert(dest).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
            }
        }
    }

    bool include_unsafe = true;
    if (!request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        if (options.exists("minimumAmount"))
            nMinimumAmount = AmountFromValue(options["minimumAmount"]);

        if (options.exists("maximumAmount"))
            nMaximumAmount = AmountFromValue(options["maximumAmount"]);

        if (options.exists("minimumSumAmount"))
            nMinimumSumAmount = AmountFromValue(options["minimumSumAmount"]);

        if (options.exists("maximumCount"))
            nMaximumCount = options["maximumCount"].get_int64();
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    LOCK2(cs_main, pwallet->cs_wallet);

    pwallet->AvailableCoins(vecOutputs, !include_unsafe, nullptr, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount, nMinDepth, nMaxDepth);
    for (const COutput& out : vecOutputs) {
        CTxDestination address;
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (destinations.size() && (!fValidAddress || !destinations.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.tx->GetHash().GetHex());
        entry.pushKV("vout", out.i);

        if (fValidAddress) {
            entry.pushKV("address", EncodeDestination(address));

            if (pwallet->mapAddressBook.count(address)) {
                entry.pushKV("account", pwallet->mapAddressBook[address].name);
            }

            if (scriptPubKey.IsPayToScriptHash()) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    entry.pushKV("redeemScript", HexStr(redeemScript.begin(), redeemScript.end()));
                }
            }
        }

        entry.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));
        entry.pushKV("amount", ValueFromAmount(out.tx->tx->vout[out.i].nValue));
        entry.pushKV("confirmations", out.nDepth);
        entry.pushKV("spendable", out.fSpendable);
        entry.pushKV("solvable", out.fSolvable);
        entry.pushKV("safe", out.fSafe);
        results.push_back(entry);
    }

    return results;
}

UniValue fundrawtransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                            "fundrawtransaction \"hexstring\" ( options iswitness )\n"
                            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                            "This will not modify existing inputs, and will add at most one change output to the outputs.\n"
                            "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                            "The inputs added will not be signed, use signrawtransaction for that.\n"
                            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                            "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                            "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                            "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
                            "\nArguments:\n"
                            "1. \"hexstring\"           (string, required) The hex string of the raw transaction\n"
                            "2. options                 (object, optional)\n"
                            "   {\n"
                            "     \"changeAddress\"          (string, optional, default pool address) The bitcoin address to receive the change\n"
                            "     \"changePosition\"         (numeric, optional, default random) The index of the change output\n"
                            "     \"change_type\"            (string, optional) The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -changetype.\n"
                            "     \"includeWatching\"        (boolean, optional, default false) Also select inputs which are watch only\n"
                            "     \"lockUnspents\"           (boolean, optional, default false) Lock selected unspent outputs\n"
                            "     \"feeRate\"                (numeric, optional, default not set: makes wallet determine the fee) Set a specific fee rate in " + CURRENCY_UNIT + "/kB\n"
                            "     \"subtractFeeFromOutputs\" (array, optional) A json array of integers.\n"
                            "                              The fee will be equally deducted from the amount of each specified output.\n"
                            "                              The outputs are specified by their zero-based index, before any change output is added.\n"
                            "                              Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                            "                              If no outputs are specified here, the sender pays the fee.\n"
                            "                                  [vout_index,...]\n"
                            "     \"replaceable\"            (boolean, optional) Marks this transaction as BIP125 replaceable.\n"
                            "                              Allows this transaction to be replaced by a transaction with higher fees\n"
                            "     \"conf_target\"            (numeric, optional) Confirmation target (in blocks)\n"
                            "     \"estimate_mode\"          (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
                            "         \"UNSET\"\n"
                            "         \"ECONOMICAL\"\n"
                            "         \"CONSERVATIVE\"\n"
                            "   }\n"
                            "                         for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}\n"
                            "3. iswitness               (boolean, optional) Whether the transaction hex is a serialized witness transaction \n"
                            "                              If iswitness is not present, heuristic tests will be used in decoding\n"

                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                            );

    ObserveSafeMode();
    RPCTypeCheck(request.params, {UniValue::VSTR});

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    CCoinControl coinControl;
    int changePosition = -1;
    bool lockUnspents = false;
    UniValue subtractFeeFromOutputs;
    std::set<int> setSubtractFeeFromOutputs;

    if (!request.params[1].isNull()) {
      if (request.params[1].type() == UniValue::VBOOL) {
        // backward compatibility bool only fallback
        coinControl.fAllowWatchOnly = request.params[1].get_bool();
      }
      else {
        RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ, UniValue::VBOOL});

        UniValue options = request.params[1];

        RPCTypeCheckObj(options,
            {
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"change_type", UniValueType(UniValue::VSTR)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"feeRate", UniValueType()}, // will be checked below
                {"subtractFeeFromOutputs", UniValueType(UniValue::VARR)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("changeAddress")) {
            CTxDestination dest = DecodeDestination(options["changeAddress"].get_str());

            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "changeAddress must be a valid bitcoin address");
            }

            coinControl.destChange = dest;
        }

        if (options.exists("changePosition"))
            changePosition = options["changePosition"].get_int();

        if (options.exists("change_type")) {
            if (options.exists("changeAddress")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both changeAddress and address_type options");
            }
            coinControl.change_type = ParseOutputType(options["change_type"].get_str(), coinControl.change_type);
            if (coinControl.change_type == OUTPUT_TYPE_NONE) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown change type '%s'", options["change_type"].get_str()));
            }
        }

        if (options.exists("includeWatching"))
            coinControl.fAllowWatchOnly = options["includeWatching"].get_bool();

        if (options.exists("lockUnspents"))
            lockUnspents = options["lockUnspents"].get_bool();

        if (options.exists("feeRate"))
        {
            coinControl.m_feerate = CFeeRate(AmountFromValue(options["feeRate"]));
            coinControl.fOverrideFeeRate = true;
        }

        if (options.exists("subtractFeeFromOutputs"))
            subtractFeeFromOutputs = options["subtractFeeFromOutputs"].get_array();

        if (options.exists("replaceable")) {
            coinControl.signalRbf = options["replaceable"].get_bool();
        }
        if (options.exists("conf_target")) {
            if (options.exists("feeRate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both conf_target and feeRate");
            }
            coinControl.m_confirm_target = ParseConfirmTarget(options["conf_target"]);
        }
        if (options.exists("estimate_mode")) {
            if (options.exists("feeRate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both estimate_mode and feeRate");
            }
            if (!FeeModeFromString(options["estimate_mode"].get_str(), coinControl.m_fee_mode)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
            }
        }
      }
    }

    // parse hex string from parameter
    CMutableTransaction tx;
    bool try_witness = request.params[2].isNull() ? true : request.params[2].get_bool();
    bool try_no_witness = request.params[2].isNull() ? true : !request.params[2].get_bool();
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    if (tx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    if (changePosition != -1 && (changePosition < 0 || (unsigned int)changePosition > tx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    for (unsigned int idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].get_int();
        if (setSubtractFeeFromOutputs.count(pos))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated position: %d", pos));
        if (pos < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, negative position: %d", pos));
        if (pos >= int(tx.vout.size()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, position too large: %d", pos));
        setSubtractFeeFromOutputs.insert(pos);
    }

    CAmount nFeeOut;
    std::string strFailReason;

    if (!pwallet->FundTransaction(tx, nFeeOut, changePosition, strFailReason, lockUnspents, setSubtractFeeFromOutputs, coinControl)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hex", EncodeHexTx(tx));
    result.pushKV("changepos", changePosition);
    result.pushKV("fee", ValueFromAmount(nFeeOut));

    return result;
}

UniValue signrawtransactionwithwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "signrawtransactionwithwallet \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            + HelpRequiringPassphrase(pwallet) + "\n"

            "\nArguments:\n"
            "1. \"hexstring\"                      (string, required) The transaction hex string\n"
            "2. \"prevtxs\"                        (string, optional) An json array of previous dependent transaction outputs\n"
            "     [                              (json array of json objects, or 'null' if none provided)\n"
            "       {\n"
            "         \"txid\":\"id\",               (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",     (string, required) script key\n"
            "         \"redeemScript\": \"hex\",     (string, required for P2SH or P2WSH) redeem script\n"
            "         \"amount\": value            (numeric, required) The amount spent\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"sighashtype\"                    (string, optional, default=ALL) The signature hash type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",                  (string) The hex-encoded raw transaction with signature(s)\n"
            "  \"complete\" : true|false,          (boolean) If the transaction has a complete set of signatures\n"
            "  \"errors\" : [                      (json array of objects) Script verification errors (if there are any)\n"
            "    {\n"
            "      \"txid\" : \"hash\",              (string) The hash of the referenced, previous transaction\n"
            "      \"vout\" : n,                   (numeric) The index of the output to spent and used as input\n"
            "      \"scriptSig\" : \"hex\",          (string) The hex-encoded signature script\n"
            "      \"sequence\" : n,               (numeric) Script sequence number\n"
            "      \"error\" : \"text\"              (string) Verification or signing error related to the input\n"
            "    }\n"
            "    ,...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"")
            + HelpExampleRpc("signrawtransactionwithwallet", "\"myhex\"")
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR, UniValue::VSTR}, true);

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request.params[0].get_str(), true)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    // Sign the transaction
    LOCK2(cs_main, pwallet->cs_wallet);
    return SignTransaction(mtx, request.params[1], pwallet, false, request.params[2]);
}

UniValue bumpfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "bumpfee \"txid\" ( options ) \n"
            "\nBumps the fee of an opt-in-RBF transaction T, replacing it with a new transaction B.\n"
            "An opt-in RBF transaction with the given txid must be in the wallet.\n"
            "The command will pay the additional fee by decreasing (or perhaps removing) its change output.\n"
            "If the change output is not big enough to cover the increased fee, the command will currently fail\n"
            "instead of adding new inputs to compensate. (A future implementation could improve this.)\n"
            "The command will fail if the wallet or mempool contains a transaction that spends one of T's outputs.\n"
            "By default, the new fee will be calculated automatically using estimatesmartfee.\n"
            "The user can specify a confirmation target for estimatesmartfee.\n"
            "Alternatively, the user can specify totalFee, or use RPC settxfee to set a higher fee rate.\n"
            "At a minimum, the new fee rate must be high enough to pay an additional new relay fee (incrementalfee\n"
            "returned by getnetworkinfo) to enter the node's mempool.\n"
            "\nArguments:\n"
            "1. txid                  (string, required) The txid to be bumped\n"
            "2. options               (object, optional)\n"
            "   {\n"
            "     \"confTarget\"        (numeric, optional) Confirmation target (in blocks)\n"
            "     \"totalFee\"          (numeric, optional) Total fee (NOT feerate) to pay, in satoshis.\n"
            "                         In rare cases, the actual fee paid might be slightly higher than the specified\n"
            "                         totalFee if the tx change output has to be removed because it is too close to\n"
            "                         the dust threshold.\n"
            "     \"replaceable\"       (boolean, optional, default true) Whether the new transaction should still be\n"
            "                         marked bip-125 replaceable. If true, the sequence numbers in the transaction will\n"
            "                         be left unchanged from the original. If false, any input sequence numbers in the\n"
            "                         original transaction that were less than 0xfffffffe will be increased to 0xfffffffe\n"
            "                         so the new transaction will not be explicitly bip-125 replaceable (though it may\n"
            "                         still be replaceable in practice, for example if it has unconfirmed ancestors which\n"
            "                         are replaceable).\n"
            "     \"estimate_mode\"     (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "         \"UNSET\"\n"
            "         \"ECONOMICAL\"\n"
            "         \"CONSERVATIVE\"\n"
            "   }\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\":    \"value\",   (string)  The id of the new transaction\n"
            "  \"origfee\":  n,         (numeric) Fee of the replaced transaction\n"
            "  \"fee\":      n,         (numeric) Fee of the new transaction\n"
            "  \"errors\":  [ str... ] (json array of strings) Errors encountered during processing (may be empty)\n"
            "}\n"
            "\nExamples:\n"
            "\nBump the fee, get the new transaction\'s txid\n" +
            HelpExampleCli("bumpfee", "<txid>"));
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ});
    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    // optional parameters
    CAmount totalFee = 0;
    CCoinControl coin_control;
    coin_control.signalRbf = true;
    if (!request.params[1].isNull()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"confTarget", UniValueType(UniValue::VNUM)},
                {"totalFee", UniValueType(UniValue::VNUM)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("confTarget") && options.exists("totalFee")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "confTarget and totalFee options should not both be set. Please provide either a confirmation target for fee estimation or an explicit total fee for the transaction.");
        } else if (options.exists("confTarget")) { // TODO: alias this to conf_target
            coin_control.m_confirm_target = ParseConfirmTarget(options["confTarget"]);
        } else if (options.exists("totalFee")) {
            totalFee = options["totalFee"].get_int64();
            if (totalFee <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid totalFee %s (must be greater than 0)", FormatMoney(totalFee)));
            }
        }

        if (options.exists("replaceable")) {
            coin_control.signalRbf = options["replaceable"].get_bool();
        }
        if (options.exists("estimate_mode")) {
            if (!FeeModeFromString(options["estimate_mode"].get_str(), coin_control.m_fee_mode)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
            }
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);


    std::vector<std::string> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    feebumper::Result res = feebumper::CreateTransaction(pwallet, hash, coin_control, totalFee, errors, old_fee, new_fee, mtx);
    if (res != feebumper::Result::OK) {
        switch(res) {
            case feebumper::Result::INVALID_ADDRESS_OR_KEY:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errors[0]);
                break;
            case feebumper::Result::INVALID_REQUEST:
                throw JSONRPCError(RPC_INVALID_REQUEST, errors[0]);
                break;
            case feebumper::Result::INVALID_PARAMETER:
                throw JSONRPCError(RPC_INVALID_PARAMETER, errors[0]);
                break;
            case feebumper::Result::WALLET_ERROR:
                throw JSONRPCError(RPC_WALLET_ERROR, errors[0]);
                break;
            default:
                throw JSONRPCError(RPC_MISC_ERROR, errors[0]);
                break;
        }
    }

    // sign bumped transaction
    if (!feebumper::SignTransaction(pwallet, mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Can't sign transaction.");
    }
    // commit the bumped transaction
    uint256 txid;
    if (feebumper::CommitTransaction(pwallet, hash, std::move(mtx), errors, txid) != feebumper::Result::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR, errors[0]);
    }
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", txid.GetHex());
    result.pushKV("origfee", ValueFromAmount(old_fee));
    result.pushKV("fee", ValueFromAmount(new_fee));
    UniValue result_errors(UniValue::VARR);
    for (const std::string& error : errors) {
        result_errors.push_back(error);
    }
    result.pushKV("errors", result_errors);

    return result;
}

UniValue createwithdrawal(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 5)
        throw std::runtime_error(
            "createwt amount \"address\"\n"
            "\nCreate a withdrawal so that it can be included in a bundle.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"address\"            (string, required) The bitcoin address to send to.\n"
            "2. \"refundaddress\"      (string, required) Destination for refunds.\n"
            "3. \"amount\"             (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "4. \"fee\"                (numeric or string, required) The amount in " + CURRENCY_UNIT + " to be subtracted for fees. eg 0.1\n"
            "5. \"mainchainfee\"       (numeric or string, required) The amount in " + CURRENCY_UNIT + " to be subtracted for fees on the mainchain. eg 0.1\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("createwt", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.3, 0.1, 0.1")
            + HelpExampleRpc("createwt", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", \"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.3, 0.1, 0.1")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str(), true /*fMainchainAddress */);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    CTxDestination refundDest = DecodeDestination(request.params[1].get_str(), false /*fMainchainAddress */);
    if (!IsValidDestination(refundDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid refund address");
    }

    // Amount
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Fee
    CAmount nFee = AmountFromValue(request.params[3]);
    if (nFee <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for fee");

    // Mainchain fee
    CAmount nMainchainFee = AmountFromValue(request.params[4]);
    if (nMainchainFee <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for mainchain fee");

    EnsureWalletIsUnlocked(pwallet);

    std::string strFail = "";
    uint256 txid;
    uint256 wtid;
    if (!pwallet->CreateWithdrawal(nAmount, nFee, nMainchainFee, request.params[0].get_str(), request.params[1].get_str(), strFail, txid, wtid)) {
        throw JSONRPCError(RPC_MISC_ERROR, strFail);
    }

    // Cache user's withdrawal ID
    bmmCache.CacheWithdrawalID(wtid);

    UniValue response(UniValue::VOBJ);
    response.pushKV("txid", txid.ToString());
    return response;
}

UniValue createwithdrawalrefundrequest(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "createwithdrawalrefundrequest \"wtid\"\n"
            "\nCreate a withdrawal refund request.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"id\"        (string, required) The withdrawal ID from leveldb.\n"
            "\nResult:\n"
            "\"txid\"           (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("createwithdrawalrefundrequest", "\"bd63ef0e581c53ec261fea45436c171033a313d6c3a4bcac435da0b8a353249a\"")
            + HelpExampleRpc("createwithdrawalrefundrequest", "\"bd63ef0e581c53ec261fea45436c171033a313d6c3a4bcac435da0b8a353249a\"")
        );

    ObserveSafeMode();

    uint256 wtID = uint256S(request.params[0].get_str());
    if (wtID.IsNull()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid withdrawal ID!");
    }

    // Get withdrawal
    SidechainWithdrawal wt;
    if (!psidechaintree->GetWithdrawal(wtID, wt)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Specified withdrawal not found!");
    }

    // Check status
    if (wt.status != WITHDRAWAL_UNSPENT) {
        throw JSONRPCError(RPC_MISC_ERROR, "Withdrawal is already spent or in a bundle!");
    }

    // Get refund address
    CTxDestination dest = DecodeDestination(wt.strRefundDestination);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Withdrawal has invalid refund address!");
    }

    // Double checking that the destination is for a KeyID
    const CKeyID* id = boost::get<CKeyID>(&dest);
    if (!id) {
        throw JSONRPCError(RPC_MISC_ERROR, "Withdrawal has non P2PKH destination!");
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // Get private key for refund destination from wallet
    CKey privKey;
    if (!pwallet->GetKey(*id, privKey)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Private key for refund address not found in wallet!");
    }

    // Get refund message hash
    uint256 hashMessage = GetWithdrawalRefundMessageHash(wtID);

    // Sign refund message hash
    std::vector<unsigned char> vchSig;
    if (!privKey.SignCompact(hashMessage, vchSig)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to sign!");
    }

    std::string strFail = "";
    uint256 txid;
    if (!pwallet->CreateWithdrawalRefundRequest(wtID, vchSig, strFail, txid)) {
        throw JSONRPCError(RPC_MISC_ERROR, strFail);
    }

    UniValue response(UniValue::VOBJ);
    response.pushKV("txid", txid.ToString());
    return response;
}

UniValue refundallwithdrawals(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "refundallwithdrawals\n"
            "\nCreate a withdrawal refund request for all of my withdrawals.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nResult (array):\n"
            "\"txid\"           (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("refundallwithdrawals", "")
            + HelpExampleRpc("refundallwithdrawals", "")
        );

    ObserveSafeMode();

    UniValue result(UniValue::VARR);
    std::set<uint256> setWithdrawalID = bmmCache.GetCachedWithdrawalID();
    for (const uint256& wtID : setWithdrawalID) {
        if (wtID.IsNull()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Invalid withdrawal ID!");
        }

        // Get withdrawal
        SidechainWithdrawal wt;
        if (!psidechaintree->GetWithdrawal(wtID, wt)) {
            continue;
        }

        // Check status
        if (wt.status != WITHDRAWAL_UNSPENT) {
            continue;
        }

        // Get refund address
        CTxDestination dest = DecodeDestination(wt.strRefundDestination);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Withdrawal has invalid refund address!");
        }

        // Double checking that the destination is for a KeyID
        const CKeyID* id = boost::get<CKeyID>(&dest);
        if (!id) {
            throw JSONRPCError(RPC_MISC_ERROR, "Withdrawal has non P2PKH destination!");
        }

        // Make sure the results are valid at least up to the most recent block
        // the user could have gotten from another RPC command prior to now
        pwallet->BlockUntilSyncedToCurrentChain();

        LOCK2(cs_main, pwallet->cs_wallet);

        EnsureWalletIsUnlocked(pwallet);

        // Get private key for refund destination from wallet
        CKey privKey;
        if (!pwallet->GetKey(*id, privKey)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Private key for refund address not found in wallet!");
        }

        // Get refund message hash
        uint256 hashMessage = GetWithdrawalRefundMessageHash(wtID);

        // Sign refund message hash
        std::vector<unsigned char> vchSig;
        if (!privKey.SignCompact(hashMessage, vchSig)) {
            throw JSONRPCError(RPC_MISC_ERROR, "Failed to sign!");
        }

        std::string strFail = "";
        uint256 txid;
        if (!pwallet->CreateWithdrawalRefundRequest(wtID, vchSig, strFail, txid)) {
            throw JSONRPCError(RPC_MISC_ERROR, strFail);
        }

        UniValue obj(UniValue::VOBJ);
        obj.pushKV("txid", txid.ToString());
        result.push_back(obj);
    }

    return result;
}

UniValue rescanblockchain(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "rescanblockchain (\"start_height\") (\"stop_height\")\n"
            "\nRescan the local blockchain for wallet related transactions.\n"
            "\nArguments:\n"
            "1. \"start_height\"    (numeric, optional) block height where the rescan should start\n"
            "2. \"stop_height\"     (numeric, optional) the last block height that should be scanned\n"
            "\nResult:\n"
            "{\n"
            "  \"start_height\"     (numeric) The block height where the rescan has started. If omitted, rescan started from the genesis block.\n"
            "  \"stop_height\"      (numeric) The height of the last rescanned block. If omitted, rescan stopped at the chain tip.\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("rescanblockchain", "100000 120000")
            + HelpExampleRpc("rescanblockchain", "100000, 120000")
            );
    }

    WalletRescanReserver reserver(pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    CBlockIndex *pindexStart = nullptr;
    CBlockIndex *pindexStop = nullptr;
    CBlockIndex *pChainTip = nullptr;
    {
        LOCK(cs_main);
        pindexStart = chainActive.Genesis();
        pChainTip = chainActive.Tip();

        if (!request.params[0].isNull()) {
            pindexStart = chainActive[request.params[0].get_int()];
            if (!pindexStart) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
            }
        }

        if (!request.params[1].isNull()) {
            pindexStop = chainActive[request.params[1].get_int()];
            if (!pindexStop) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stop_height");
            }
            else if (pindexStop->nHeight < pindexStart->nHeight) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be greater then start_height");
            }
        }
    }

    // We can't rescan beyond non-pruned blocks, stop and throw an error
    if (fPruneMode) {
        LOCK(cs_main);
        CBlockIndex *block = pindexStop ? pindexStop : pChainTip;
        while (block && block->nHeight >= pindexStart->nHeight) {
            if (!(block->nStatus & BLOCK_HAVE_DATA)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
            }
            block = block->pprev;
        }
    }

    CBlockIndex *stopBlock = pwallet->ScanForWalletTransactions(pindexStart, pindexStop, reserver, true);
    if (!stopBlock) {
        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
        }
        // if we got a nullptr returned, ScanForWalletTransactions did rescan up to the requested stopindex
        stopBlock = pindexStop ? pindexStop : pChainTip;
    }
    else {
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
    }
    UniValue response(UniValue::VOBJ);
    response.pushKV("start_height", pindexStart->nHeight);
    response.pushKV("stop_height", stopBlock->nHeight);
    return response;
}

class DescribeWalletAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    CWallet * const pwallet;

    void ProcessSubScript(const CScript& subscript, UniValue& obj, bool include_addresses = false) const
    {
        // Always present: script type and redeemscript
        txnouttype which_type;
        std::vector<std::vector<unsigned char>> solutions_data;
        Solver(subscript, which_type, solutions_data);
        obj.pushKV("script", GetTxnOutputType(which_type));
        obj.pushKV("hex", HexStr(subscript.begin(), subscript.end()));

        CTxDestination embedded;
        UniValue a(UniValue::VARR);
        if (ExtractDestination(subscript, embedded)) {
            // Only when the script corresponds to an address.
            UniValue subobj(UniValue::VOBJ);
            UniValue detail = DescribeAddress(embedded);
            subobj.pushKVs(detail);
            UniValue wallet_detail = boost::apply_visitor(*this, embedded);
            subobj.pushKVs(wallet_detail);
            subobj.pushKV("address", EncodeDestination(embedded));
            subobj.pushKV("scriptPubKey", HexStr(subscript.begin(), subscript.end()));
            // Always report the pubkey at the top level, so that `getnewaddress()['pubkey']` always works.
            if (subobj.exists("pubkey")) obj.pushKV("pubkey", subobj["pubkey"]);
            obj.pushKV("embedded", std::move(subobj));
            if (include_addresses) a.push_back(EncodeDestination(embedded));
        } else if (which_type == TX_MULTISIG) {
            // Also report some information on multisig scripts (which do not have a corresponding address).
            // TODO: abstract out the common functionality between this logic and ExtractDestinations.
            obj.pushKV("sigsrequired", solutions_data[0][0]);
            UniValue pubkeys(UniValue::VARR);
            for (size_t i = 1; i < solutions_data.size() - 1; ++i) {
                CPubKey key(solutions_data[i].begin(), solutions_data[i].end());
                if (include_addresses) a.push_back(EncodeDestination(key.GetID()));
                pubkeys.push_back(HexStr(key.begin(), key.end()));
            }
            obj.pushKV("pubkeys", std::move(pubkeys));
        }

        // The "addresses" field is confusing because it refers to public keys using their P2PKH address.
        // For that reason, only add the 'addresses' field when needed for backward compatibility. New applications
        // can use the 'embedded'->'address' field for P2SH or P2WSH wrapped addresses, and 'pubkeys' for
        // inspecting multisig participants.
        if (include_addresses) obj.pushKV("addresses", std::move(a));
    }

    explicit DescribeWalletAddressVisitor(CWallet* _pwallet) : pwallet(_pwallet) {}

    UniValue operator()(const CNoDestination& dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID& keyID) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        if (pwallet && pwallet->GetPubKey(keyID, vchPubKey)) {
            obj.pushKV("pubkey", HexStr(vchPubKey));
            obj.pushKV("iscompressed", vchPubKey.IsCompressed());
        }
        return obj;
    }

    UniValue operator()(const CScriptID& scriptID) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            ProcessSubScript(subscript, obj, IsDeprecatedRPCEnabled("validateaddress"));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0KeyHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CPubKey pubkey;
        if (pwallet && pwallet->GetPubKey(CKeyID(id), pubkey)) {
            obj.pushKV("pubkey", HexStr(pubkey));
        }
        return obj;
    }

    UniValue operator()(const WitnessV0ScriptHash& id) const
    {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        CRIPEMD160 hasher;
        uint160 hash;
        hasher.Write(id.begin(), 32).Finalize(hash.begin());
        if (pwallet && pwallet->GetCScript(CScriptID(hash), subscript)) {
            ProcessSubScript(subscript, obj);
        }
        return obj;
    }

    UniValue operator()(const WitnessUnknown& id) const { return UniValue(UniValue::VOBJ); }
};

UniValue DescribeWalletAddress(CWallet* pwallet, const CTxDestination& dest)
{
    UniValue ret(UniValue::VOBJ);
    UniValue detail = DescribeAddress(dest);
    ret.pushKVs(detail);
    ret.pushKVs(boost::apply_visitor(DescribeWalletAddressVisitor(pwallet), dest));
    return ret;
}

UniValue getaddressinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "getaddressinfo \"address\"\n"
            "\nReturn information about the given bitcoin address. Some information requires the address\n"
            "to be in the wallet.\n"
            "\nArguments:\n"
            "1. \"address\"                    (string, required) The bitcoin address to get the information of.\n"
            "\nResult:\n"
            "{\n"
            "  \"address\" : \"address\",        (string) The bitcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"iswitness\" : true|false,     (boolean) If the address is a witness address\n"
            "  \"witness_version\" : version   (numeric, optional) The version number of the witness program\n"
            "  \"witness_program\" : \"hex\"     (string, optional) The hex value of the witness program\n"
            "  \"script\" : \"type\"             (string, optional) The output script type. Only if \"isscript\" is true and the redeemscript is known. Possible types: nonstandard, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_keyhash, witness_v0_scripthash, witness_unknown\n"
            "  \"hex\" : \"hex\",                (string, optional) The redeemscript for the p2sh address\n"
            "  \"pubkeys\"                     (string, optional) Array of pubkeys associated with the known redeemscript (only if \"script\" is \"multisig\")\n"
            "    [\n"
            "      \"pubkey\"\n"
            "      ,...\n"
            "    ]\n"
            "  \"sigsrequired\" : xxxxx        (numeric, optional) Number of signatures required to spend multisig output (only if \"script\" is \"multisig\")\n"
            "  \"pubkey\" : \"publickeyhex\",    (string, optional) The hex value of the raw public key, for single-key addresses (possibly embedded in P2SH or P2WSH)\n"
            "  \"embedded\" : {...},           (object, optional) Information about the address embedded in P2SH or P2WSH, if relevant and known. It includes all getaddressinfo output fields for the embedded address, excluding metadata (\"timestamp\", \"hdkeypath\", \"hdmasterkeyid\") and relation to the wallet (\"ismine\", \"iswatchonly\", \"account\").\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) The account associated with the address, \"\" is the default account\n"
            "  \"timestamp\" : timestamp,      (number, optional) The creation time of the key if available in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressinfo", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
            + HelpExampleRpc("getaddressinfo", "\"1PSSGeFHDnKNxiEyFrD1wcEaHr9hrQDDWc\"")
        );
    }

    LOCK(pwallet->cs_wallet);

    UniValue ret(UniValue::VOBJ);
    CTxDestination dest = DecodeDestination(request.params[0].get_str());

    // Make sure the destination is valid
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::string currentAddress = EncodeDestination(dest);
    ret.pushKV("address", currentAddress);

    CScript scriptPubKey = GetScriptForDestination(dest);
    ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

    isminetype mine = IsMine(*pwallet, dest);
    ret.pushKV("ismine", bool(mine & ISMINE_SPENDABLE));
    ret.pushKV("iswatchonly", bool(mine & ISMINE_WATCH_ONLY));
    UniValue detail = DescribeWalletAddress(pwallet, dest);
    ret.pushKVs(detail);
    if (pwallet->mapAddressBook.count(dest)) {
        ret.pushKV("account", pwallet->mapAddressBook[dest].name);
    }
    const CKeyMetadata* meta = nullptr;
    CKeyID key_id = GetKeyForDestination(*pwallet, dest);
    if (!key_id.IsNull()) {
        auto it = pwallet->mapKeyMetadata.find(key_id);
        if (it != pwallet->mapKeyMetadata.end()) {
            meta = &it->second;
        }
    }
    if (!meta) {
        auto it = pwallet->m_script_metadata.find(CScriptID(scriptPubKey));
        if (it != pwallet->m_script_metadata.end()) {
            meta = &it->second;
        }
    }
    if (meta) {
        ret.pushKV("timestamp", meta->nCreateTime);
        if (!meta->hdKeypath.empty()) {
            ret.pushKV("hdkeypath", meta->hdKeypath);
            ret.pushKV("hdmasterkeyid", meta->hdMasterKeyID.GetHex());
        }
    }
    return ret;
}

UniValue listbranches(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size())
        throw std::runtime_error(
            "listbranches\n"
            "\nReturns an array of all branches.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments: None\n"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    std::vector<marketBranch> vBranch = pmarkettree->GetBranches();

    UniValue response(UniValue::VARR);

    for (const marketBranch& branch : vBranch) {
        UniValue obj(UniValue::VOBJ);

        obj.pushKV("branchid", branch.GetHash().ToString());
        obj.pushKV("txid", branch.txid.ToString());
        obj.pushKV("name", branch.name);
        obj.pushKV("description", branch.description);
        obj.pushKV("baselistingfee", ValueFromAmount(branch.baseListingFee));
        obj.pushKV("freedecisions", (int)branch.freeDecisions);
        obj.pushKV("targetdecisions", (int)branch.targetDecisions);
        obj.pushKV("maxdecisions", (int)branch.maxDecisions);
        obj.pushKV("mintradingfee", ValueFromAmount(branch.minTradingFee));
        obj.pushKV("tau", (int)branch.tau);
        obj.pushKV("ballottime", (int)branch.ballotTime);
        obj.pushKV("unsealtime", (int)branch.unsealTime);
        obj.pushKV("consensusthreshold", ValueFromAmount(branch.consensusThreshold));
        obj.pushKV("alpha", ValueFromAmount(branch.alpha));
        obj.pushKV("tol", ValueFromAmount(branch.tol));

        response.push_back(obj);
    }

    return response;
}

UniValue listdecisions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listdecisions\n"
            "\nReturns an array of all decisions.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. branchid     (uint256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 branchid;
    branchid.SetHex(request.params[0].get_str());
    // TODO obj.pushKV("branchid", branchid.ToString()));

    std::vector<marketDecision> vDecision = pmarkettree->GetDecisions(branchid);

    UniValue response(UniValue::VARR);

    for (const marketDecision& decision : vDecision) {
        UniValue obj(UniValue::VOBJ);

        obj.pushKV("decisionid", decision.GetHash().ToString());
        obj.pushKV("txid", decision.txid.ToString());

        // TODO
        //CHivemindAddress addr;
        //if (addr.Set(obj->keyID))
        //    obj.pushKV(("keyID", addr.ToString()));
        obj.pushKV("branchid", decision.branchid.ToString());
        obj.pushKV("prompt", decision.prompt);
        obj.pushKV("eventoverby", (int)decision.eventOverBy);
        obj.pushKV("isScaled", (int)decision.isScaled);
        obj.pushKV("min", ValueFromAmount(decision.min));
        obj.pushKV("max", ValueFromAmount(decision.max));
        obj.pushKV("answerOptionality", (int)decision.answerOptionality);

        response.push_back(obj);
    }

    return response;
}

UniValue listmarkets(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listmarkets\n"
            "\nReturns an array of all markets depending on decision.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. decisionid      (uint256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 decisionid;
    decisionid.SetHex(request.params[0].get_str());

    std::vector<marketMarket> vMarket = pmarkettree->GetMarkets(decisionid);

    UniValue response(UniValue::VARR);

    for (const marketMarket& market : vMarket) {
        UniValue obj(UniValue::VOBJ);

        obj.pushKV("marketid", market.GetHash().ToString());
        obj.pushKV("txid", market.txid.ToString());
        // CHivemindAddress addr;
        // if (addr.Set(obj->keyID))
        //    obj.pushKV("keyID", addr.ToString());
        obj.pushKV("B", ValueFromAmount(market.B));
        obj.pushKV("tradingFee", ValueFromAmount(market.tradingFee));
        obj.pushKV("maxCommission", ValueFromAmount(market.maxCommission));
        obj.pushKV("title", market.title);
        obj.pushKV("description", market.description);
        obj.pushKV("tags", market.tags);
        obj.pushKV("maturation", (int)market.maturation);

        UniValue darray(UniValue::VARR);
        for(uint32_t i=0; i < market.decisionIDs.size(); i++)
            darray.pushKV("decisionid", market.decisionIDs[i].ToString());
        obj.pushKV("decisionIDs", darray);

        response.push_back(obj);
    }

    return response;
}

UniValue listoutcomes(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listoutcomes\n"
            "\nReturns an array of all outcomes in a branch.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1.branchid      (uint256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 branchid;
    branchid.SetHex(request.params[0].get_str());

    std::vector<marketOutcome> vOutcome = pmarkettree->GetOutcomes(branchid);

    UniValue response(UniValue::VARR);

    for (const marketOutcome& outcome : vOutcome) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("outcomeid", outcome.GetHash().ToString());
        obj.pushKV("height", (int)outcome.nHeight);
        response.push_back(obj);
    }

    return response;
}

UniValue listtrades(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listtrades\n"
            "\nReturns an array of all trades for the market.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. marketid      (uint256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 marketid;
    marketid.SetHex(request.params[0].get_str());


    std::vector<marketTrade> vTrade = pmarkettree->GetTrades(marketid);

    UniValue response(UniValue::VARR);

    for (const marketTrade& trade : vTrade) {
        UniValue obj(UniValue::VOBJ);

        obj.pushKV("tradeid", trade.GetHash().ToString());
        obj.pushKV("txid", trade.txid.ToString());
        // TODO
        //CHivemindAddress addr;
        //if (addr.Set(keyID))
        //    obj.pushKV("keyID", trade.addr.ToString());
        obj.pushKV("marketid", trade.marketid.ToString());
        obj.pushKV("isbuy", (trade.isBuy)? "buy":"sell");
        obj.pushKV("nshares", ValueFromAmount(trade.nShares));
        obj.pushKV("price", ValueFromAmount(trade.price));
        obj.pushKV("decision_state", (int)trade.decisionState);
        obj.pushKV("nonce", (int)trade.nonce);
        response.push_back(obj);
    }

    return response;
}

UniValue listvotes(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "listtrades\n"
            "\nReturns an array of all votes for the ballot.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. branchid      (uint256 string)"
            "\n2. height        (numeric)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 branchid;
    branchid.SetHex(request.params[0].get_str());

    uint32_t nHeight = request.params[1].get_int();

    std::vector<marketRevealVote> vVote = pmarkettree->GetRevealVotes(branchid, nHeight);

    UniValue response(UniValue::VARR);

    for (const marketRevealVote& vote : vVote) {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("voteid", vote.ToString());
        obj.pushKV("txid", vote.txid.ToString());
        obj.pushKV("NA", ValueFromAmount(vote.NA));

        UniValue darray(UniValue::VARR);
        for(uint32_t i = 0; i < vote.decisionIDs.size(); i++) {
            UniValue decision(UniValue::VOBJ);
            decision.pushKV("decisionid", vote.decisionIDs[i].ToString());
            if (i < vote.decisionVotes.size())
                decision.pushKV("vote", ValueFromAmount(vote.decisionVotes[i]));

            darray.push_back(decision);
        }
        response.push_back(obj);
    }

    return response;
}

UniValue createbranch(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 13)
        throw std::runtime_error(
            "createbranch\n"
            "\n\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. name                (string) the name of the branch"
            "\n2. description         (string) a short description of the branch"
            "\n3. baselistingfee      (numeric)"
            "\n4. freedecisions       (numeric < 65536)"
            "\n5. targetdecisions     (numeric < 65536)"
            "\n6. maxdecisions        (numeric < 65536)"
            "\n7. mintradingfee       (numeric)"
            "\n8. tau                 (block number < 65536)"
            "\n9. ballottime          (block number < 65536)"
            "\n10. unsealtime         (block number < 65536)"
            "\n11. consensusthreshold (numeric)"
            "\n12. alpha (numeric)"
            "\n13. tol (numeric)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketBranch branch;
    branch.name = request.params[0].get_str();
    branch.description = request.params[1].get_str();
    branch.baseListingFee = (uint64_t)request.params[2].get_int();
    branch.freeDecisions = (uint16_t)request.params[3].get_int();
    branch.targetDecisions = (uint16_t)request.params[4].get_int();
    branch.maxDecisions = (uint16_t)request.params[5].get_int();
    branch.minTradingFee = (uint64_t)request.params[6].get_int();
    branch.tau = (uint16_t)request.params[7].get_int();
    branch.ballotTime = (uint16_t)request.params[8].get_int();
    branch.unsealTime = (uint16_t)request.params[9].get_int();
    branch.consensusThreshold = (uint64_t)request.params[10].get_int();
    branch.alpha = (uint64_t)request.params[11].get_int();
    branch.tol = (uint64_t)request.params[12].get_int();

    // Check if object is a duplicate
    uint256 objid = branch.GetHash();
    marketBranch tmpBranch;
    if (pmarkettree->GetBranch(objid, tmpBranch)) {
        string strError = std::string("Error: branchid ")
        + objid.ToString() + " already exists!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = branch.GetScript();

    CAmount nValue = 1 * CENT;

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("branchid", objid.ToString());

    return obj;
}

UniValue createdecision(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || (request.params.size() != 6 && request.params.size() != 8))
        throw std::runtime_error(
            "createdecision\n"
            "\nCreates a new decision within the branch.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. address             (base58 address)"
            "\n2. branchid            (uint256 string)"
            "\n3. prompt              (string)"
            "\n4. eventoverby         (block number)"
            "\n5. answer optionality  (false=mandatory to answer, true=optional to answer)"
            "\n6. is_scaled           (boolean)"
            "\n7. scaled min          (if scaled, numeric)"
            "\n8. scaled max          (if scaled, numeric)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketDecision decision;

    // Get address
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid address!");
    }

    // Double checking that the destination is for a KeyID
    const CKeyID* id = boost::get<CKeyID>(&dest);
    if (!id) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid non P2PKH destination!");
    }

    decision.keyID = *id;
    decision.branchid.SetHex(request.params[1].get_str());
    decision.prompt = request.params[2].get_str();
    decision.eventOverBy = (uint32_t) request.params[3].get_int();
    decision.answerOptionality = (request.params[4].get_bool())? 1: 0;
    decision.isScaled = (request.params[5].get_bool())? 1: 0;
    if ((decision.isScaled) && (request.params.size() != 8))
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing params!\n");
    decision.min = (request.params.size() == 6)? CAmount(0): AmountFromValue(request.params[6]);
    decision.max = (request.params.size() == 6)? 1 * COIN: AmountFromValue(request.params[7]);

    // Check if branch exists
    marketBranch branch;
    if (!pmarkettree->GetBranch(decision.branchid, branch)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Branch not found!\n");
    }

    // Check if decision already exists
    marketDecision tmpDecision;
    if (pmarkettree->GetDecision(decision.GetHash(), tmpDecision)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Decision already exists!\n");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = decision.GetScript();

    CAmount nValue = 1 * CENT;

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("decisionid", decision.GetHash().ToString());

    return obj;
}

UniValue createmarket(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 11)
        throw std::runtime_error(
            "createmarket\n"
            "\nCreates a new market on the decisions.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. address             (base58 address)"
            "\n2. decisionid[,...]    (comma-separated list of decisions)"
            "\n3. B                   (numeric) liquidity parameter"
            "\n4. tradingfee          (numeric)"
            "\n5. max commission      (numeric)"
            "\n6. title               (string)"
            "\n7. description         (string)"
            "\n8. tags[,...]          (comma-separated list of strings)"
            "\n9. maturation          (block number)"
            "\n10. tx PoW hash id     (numeric)"
            "\n11. tx PoW difficulty  (numeric)"
            "\nEach decisionid is a hash of a decision optionally followed by a function code."
            "\nThe available function codes are"
            "\n    :X1   X, identity [default]"
            "\n    :X2   X^2"
            "\n    :X3   X^3"
            "\n    :LNX1  LN(X)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketMarket market;

    // Get address
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid address!");
    }

    // Double checking that the destination is for a KeyID
    const CKeyID* id = boost::get<CKeyID>(&dest);
    if (!id) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid non P2PKH destination!");
    }
    market.keyID = *id;

    uint32_t nStates = 1;
    std::string param_decision = request.params[1].get_str();
    std::vector<string> strs;
    boost::split(strs, param_decision, boost::algorithm::is_any_of(", "));
    for(uint32_t i=0; i < strs.size(); i++) {
        uint256 decisionID;
        int decisionFunctionID = DFID_X1;
        size_t separator = strs[i].find(":");
        if (separator != std::string::npos) {
            std::string function_code = strs[i].substr(separator+1);
            decisionFunctionID = decisionFunctionToInt(function_code);
            if (decisionFunctionID < 0) {
                string strError = std::string("Error: decision function ")
                    + function_code + " does not exist!";
                throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
            }
            strs[i].erase(separator);
        }
        decisionID.SetHex(strs[i].c_str());

        marketDecision decision;
        if (!pmarkettree->GetDecision(decisionID, decision)) {
            string strError = std::string("Error: decisionID ")
                + decisionID.ToString() + " does not exist!";
            throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
        }

        market.decisionIDs.push_back(decisionID);
        market.decisionFunctionIDs.push_back(decisionFunctionID);

        nStates *= 2;
    }
    if ((!market.decisionIDs.size()) || (nStates == 1)) {
        string strError = std::string("Error: There are no decisionids!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }
    market.B = (uint64_t)request.params[2].get_int();
    market.tradingFee = (uint64_t)request.params[3].get_int();
    market.maxCommission = (uint64_t)request.params[4].get_int();
    market.title = request.params[5].get_str();
    market.description = request.params[6].get_str();
    market.tags = request.params[7].get_str();
    market.maturation = (uint32_t)request.params[8].get_int();
    market.txPoWh = (uint32_t)request.params[9].get_int();
    market.txPoWd = (uint32_t)request.params[10].get_int();

    // TODO use this???
    double capitalrequired = marketAccountValue(market.maxCommission, 1e-8*market.B, nStates, NULL);

    // Check if market already exists
    marketMarket tmpMarket;
    if (pmarkettree->GetMarket(market.GetHash(), tmpMarket)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Market already exists!\n");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = market.GetScript();

    CAmount nValue = 1 * CENT;

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("marketid", market.GetHash().ToString());

    return obj;
}

UniValue createtrade(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || (request.params.size() != 6 && request.params.size() != 7))
        throw std::runtime_error(
            "createtrade\n"
            "\nCreates a new trade order in the market.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\nResult:\n"
            "\n1. address             (base58 address)"
            "\n2. marketid            (u256 string)"
            "\n3. buy_or_sell         (string)"
            "\n4. number_shares       (numeric)"
            "\n5. price               (numeric)"
            "\n6. decision_state      (string)"
            "\n7. nonce               (optional numeric)"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketTrade trade;

    // TODO
    //
    //CHivemindAddress address(params[0].get_str());
    //if (!address.IsValid())
    //    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
    //        "Invalid Hivemind address");
    //address.GetKeyID(obj.keyID);
    //
    // Get address
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid address!");
    }

    // Double checking that the destination is for a KeyID
    const CKeyID* id = boost::get<CKeyID>(&dest);
    if (!id) {
        throw JSONRPCError(RPC_MISC_ERROR, "Invalid non P2PKH destination!");
    }
    trade.keyID = *id;

    /* Add market id to the object, checked later (performance) */
    trade.marketid.SetHex(request.params[1].get_str());

    /* double-check buy_or_sell */
    std::string buy_or_sell = request.params[2].get_str();
    if ((buy_or_sell != "buy") && (buy_or_sell != "sell")) {
        string strError = std::string("Error: '")
            + buy_or_sell + "' must be buy or sell!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* double-check nShares */
    if (request.params[3].get_real() <= 0.0) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%.8f", request.params[3].get_real());
        string strError = std::string("Error: number of shares ")
            + tmp + " must be positive!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* double-check price */
    if (request.params[4].get_real() <= 0.0) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%.8f", request.params[4].get_real());
        string strError = std::string("Error: price ")
            + tmp + " must be positive!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* double-check marketid */
    marketMarket market;
    if (!pmarkettree->GetMarket(trade.marketid, market)) {
        string strError = std::string("Error: marketid ")
            + trade.marketid.ToString() + " does not exist!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    // Add params to the trade object
    trade.isBuy = (buy_or_sell == "buy")? true: false;
    trade.nShares = (uint64_t)request.params[3].get_int();
    trade.price = (uint64_t)request.params[4].get_int();
    trade.decisionState = (uint32_t)request.params[5].get_int();
    trade.nonce = (request.params.size() != 7)? 0: (uint32_t)request.params[6].get_int();

    /* double-check decisionState */
    uint32_t nStates = marketNStates(market);
    if (trade.decisionState >= nStates) {
        char tmp0[32];
        snprintf(tmp0, sizeof(tmp0), "%u", trade.decisionState);
        char tmp1[32];
        snprintf(tmp1, sizeof(tmp1), "%u", nStates);
        string strError = std::string("Error: decision state ")
            + tmp0 + " is above the number of states "
            + tmp1 + " in the market!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    // TODO: Increase nonce for repeated trades
    /* double-check object is not a duplicate */
    uint256 objid = trade.GetHash();
    marketTrade tmpTrade;
    if (pmarkettree->GetTrade(objid, tmpTrade)) {
        string strError = std::string("Error: tradeid ")
            + objid.ToString() + " already exists!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* trades of the market */
    vector<marketTrade> vTrades = pmarkettree->GetTrades(market.GetHash());

    /* current shares of the market */
    double *nShares = new double [nStates];
    marketNShares(vTrades, nStates, nShares);
    double currAccount = marketAccountValue(market.maxCommission, 1e-8*market.B, nStates, nShares);

    /* new shares to be added to the market */
    nShares[trade.decisionState] += (trade.isBuy)? 1e-8*trade.nShares: -1e-8*trade.nShares;
    double nextAccount = marketAccountValue(market.maxCommission, 1e-8*market.B, nStates, nShares);

    /* the price difference to move from the current to the new */
    double price = (trade.isBuy)? (nextAccount - currAccount) / (1e-8 * trade.nShares)
        : (currAccount - nextAccount) / (1e-8 * trade.nShares);

    // TODO use ???
    double totalCost = price * (1e-8 * trade.nShares);

    if ((trade.isBuy) && (1e-8*price > 1e-8*trade.price)) {
        string strError = std::string("Error: price needs to be at least ")
            + FormatMoney(price);
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = trade.GetScript();

    CAmount nValue = 1 * CENT;

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("tradeid", trade.GetHash().ToString());
    obj.pushKV("B", 1e-8*market.B);
    obj.pushKV("buy_or_sell", buy_or_sell);
    obj.pushKV("nShares", nShares);
    obj.pushKV("price", price);
    obj.pushKV("total", ((1e-8 * trade.nShares))*price);

    delete nShares;

    return obj;
}

UniValue createsealedvote(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "createsealedvote\n"
            "\nCreates a new sealedvote for the branch height.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. branchid            (u256 string)"
            "\n2. height              (numeric)"
            "\n3. voteid              (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketSealedVote vote;
    vote.branchid.SetHex(request.params[0].get_str());
    vote.height = request.params[1].get_int();
    vote.voteid.SetHex(request.params[2].get_str());

    // Check if branch exists
    marketBranch branch;
    if (!pmarkettree->GetBranch(vote.branchid, branch)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Branch not found!\n");
    }

    // Validate vote nHeight
    if (vote.height % branch.tau != 0) {
        string strError = std::string("Error: Invalid height ")
            + " for the branch's tau!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = vote.GetScript();

    CAmount nValue = 1 * CENT;

    // TODO
    // Use votecoins to pay for the vote
    //string strAccount = obj.branchid.ToString();
    //CHivemindAddress voterAddress = GetBranchAccountAddress(strAccount);
    //
    //CCoinControl *control = new CCoinControl;
    //control->destChange = voterAddress.Get();

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("sealedvoteid", vote.GetHash().ToString());

    return obj;
}

UniValue createstealvote(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "createstealvote\n"
            "\nCreates a new stealvote for vote.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. branchid            (u256 string)"
            "\n2. height              (numeric)"
            "\n3. voteid              (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketStealVote vote;
    vote.branchid.SetHex(request.params[0].get_str());
    vote.height = request.params[1].get_int();
    vote.voteid.SetHex(request.params[2].get_str());

    // Check if branch exists
    marketBranch branch;
    if (!pmarkettree->GetBranch(vote.branchid, branch)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Branch not found!\n");
    }

    // Validate vote nHeight
    if (vote.height % branch.tau != 0) {
        string strError = std::string("Error: Invalid height ")
            + " for the branch's tau!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = vote.GetScript();

    CAmount nValue = 1 * CENT;

    // TODO
    // Use votecoins to pay for the vote
    //string strAccount = obj.branchid.ToString();
    //CHivemindAddress voterAddress = GetBranchAccountAddress(strAccount);
    //
    //CCoinControl *control = new CCoinControl;
    //control->destChange = voterAddress.Get();

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("stealvoteid", vote.GetHash().ToString());

    return obj;
}

UniValue createrevealvote(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 6)
        throw std::runtime_error(
            "createrevealvote\n"
            "\nReveal the vote from a sealed vote.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. address           (u256 string)"
            "\n2. branchid          (u256 string)"
            "\n3. height            (numeric)"
            "\n4. voteid            (u256 string)"
            "\n5. NA                (u256 string)"
            "\n6. decisionid,vote   (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    struct marketRevealVote vote;


    // TODO
    // CHivemindAddress address;
    // address.is_votecoin = 1;
    // address.SetString(params[0].get_str());
    // if (!address.IsValid())
    //    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Votecoin address");
    vote.branchid.SetHex(request.params[1].get_str());
    vote.height = request.params[2].get_int();
    vote.voteid.SetHex(request.params[3].get_str());
    // TODO ??? vote.NA.SetHex(request.params[4].get_str());

    // Check if branch exists
    marketBranch branch;
    if (!pmarkettree->GetBranch(vote.branchid, branch)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Branch not found!\n");
    }

    // Validate vote nHeight
    if (vote.height % branch.tau != 0) {
        string strError = std::string("Error: Invalid height ")
            + " for the branch's tau!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* record the ballot */
    vector<uint256> decisionIDs;
    vector<uint64_t> decisionVotes;
    for(uint32_t i=5; i < request.params.size(); i++) {
        string str = request.params[i].get_str();
        size_t separator = str.find(",");
        if (separator == std::string::npos) {
            string strError = std::string("Error: decisionid,vote ")
                + str + " is not in correct form!";
            throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
        }
        std::string strVote = str.substr(separator+1);
        str.erase(separator);
        uint256 decisionid;
        decisionid.SetHex(str.c_str());
        vote.decisionIDs.push_back(decisionid);
        vote.decisionVotes.push_back(rounduint64(atof(strVote.c_str())* COIN));
    }


    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    // create output script
    CScript scriptPubKey = vote.GetScript();

    CAmount nValue = 1 * CENT;

    // TODO
    // Use votecoins to pay for the vote
    //string strAccount = obj.branchid.ToString();
    //CHivemindAddress voterAddress = GetBranchAccountAddress(strAccount);
    //
    //CCoinControl *control = new CCoinControl;
    //control->destChange = voterAddress.Get();

    // Create and send the transaction
    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    CCoinControl coin_control;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, true};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid", wtx.GetHash().ToString());
    obj.pushKV("voteid", vote.GetHash().ToString());

    return obj;
}

UniValue getbranch(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getbranch\n"
            "\nReturns the branch.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. branchid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 branchid;
    branchid.SetHex(request.params[0].get_str());

    marketBranch branch;
    if (!pmarkettree->GetBranch(branchid, branch)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Branch not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("branchid", branchid.ToString());
    obj.pushKV("txid", branch.txid.ToString());
    obj.pushKV("name", branch.name);
    obj.pushKV("description", branch.description);
    obj.pushKV("baselistingfee", ValueFromAmount(branch.baseListingFee));
    obj.pushKV("freedecisions", (int)branch.freeDecisions);
    obj.pushKV("targetdecisions", (int)branch.targetDecisions);
    obj.pushKV("maxdecisions", (int)branch.maxDecisions);
    obj.pushKV("mintradingfee", ValueFromAmount(branch.minTradingFee));
    obj.pushKV("tau", (int)branch.tau);
    obj.pushKV("ballottime", (int)branch.ballotTime);
    obj.pushKV("unsealtime", (int)branch.unsealTime);
    obj.pushKV("consensusthreshold", ValueFromAmount(branch.consensusThreshold));

    return obj;
}

UniValue getdecision(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getdecision\n"
            "\nReturns the decision.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. decisionid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 decisionid;
    decisionid.SetHex(request.params[0].get_str());

    marketDecision decision;
    if (!pmarkettree->GetDecision(decisionid, decision)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Decision not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("decisionid", decisionid.ToString());
    obj.pushKV("txid", decision.txid.ToString());
    // TODO
    // CHivemindAddress addr;
    // if (addr.Set(obj->keyID))
    //    obj.pushKV("keyID", addr.ToString()));
    obj.pushKV("branchid", decision.branchid.ToString());
    obj.pushKV("prompt", decision.prompt);
    obj.pushKV("eventoverby", (int)decision.eventOverBy);
    obj.pushKV("isScaled", (int)decision.isScaled);
    obj.pushKV("min", ValueFromAmount(decision.min));
    obj.pushKV("max", ValueFromAmount(decision.max));
    obj.pushKV("answerOptionality", (int)decision.answerOptionality);

    return obj;
}

UniValue getmarket(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getmarket\n"
            "\nReturns the market.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. marketid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 marketid;
    marketid.SetHex(request.params[0].get_str());

    marketMarket market;
    if (!pmarkettree->GetMarket(marketid, market)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Market not found!\n");
    }

    // Get market trades
    std::vector<marketTrade> vTrade = pmarkettree->GetTrades(market.GetHash());

    /* current shares of the market */
    uint32_t nStates = marketNStates(market);
    double *nShares = new double [nStates];
    marketNShares(vTrade, nStates, nShares);

    /* current account value */
    double currAccount = marketAccountValue(market.maxCommission, 1e-8*market.B, nStates, nShares);

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("marketid", marketid.ToString());
    obj.pushKV("txid", market.txid.ToString());
    // TODO
    // CHivemindAddress addr;
    // if (addr.Set(obj->keyID))
    //    obj.pushKV("keyID", addr.ToString()));
    obj.pushKV("B", ValueFromAmount(market.B));
    obj.pushKV("tradingFee", ValueFromAmount(market.tradingFee));
    obj.pushKV("maxCommission", ValueFromAmount(market.maxCommission));
    obj.pushKV("title", market.title);
    obj.pushKV("description", market.description);
    obj.pushKV("tags", market.tags);
    obj.pushKV("maturation", (int)market.maturation);
    obj.pushKV("txPoWh", (int)market.txPoWh);
    obj.pushKV("txPoWd", (int)market.txPoWd);

    UniValue array(UniValue::VARR);
    for(uint32_t i=0; i < market.decisionIDs.size(); i++) {
        string str = market.decisionIDs[i].ToString();
        str += ":";
        if (i < market.decisionFunctionIDs.size())
            str += decisionFunctionIDToString(market.decisionFunctionIDs[i]);
        array.pushKV("id:function", str);
    }
    obj.pushKV("decisions", array);

    for(uint32_t i=0; i < nStates; i++) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "nShares%u", i);
        obj.pushKV(tmp, nShares[i]);
    }

    obj.pushKV("currAccount", currAccount);

    delete nShares;

    return obj;
}

UniValue getoutcome(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getoutcome\n"
            "\nReturns the outcome.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. outcomeid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 outcomeid;
    outcomeid.SetHex(request.params[0].get_str());

    marketOutcome outcome;
    if (!pmarkettree->GetOutcome(outcomeid, outcome)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Outcome not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("outcomeid", outcomeid.ToString());
    obj.pushKV("txid", outcome.txid.ToString());
    obj.pushKV("nVoters", (int)outcome.nVoters);
    obj.pushKV("nDecisions", (int)outcome.nDecisions);
    obj.pushKV("NA", ValueFromAmount(outcome.NA));
    obj.pushKV("tol", ValueFromAmount(outcome.tol));
    obj.pushKV("alpha", ValueFromAmount(outcome.alpha));

    UniValue arrayVote(UniValue::VARR);
    for(uint32_t i=0; i < outcome.voteMatrix.size(); i++)
        arrayVote.pushKV(std::to_string(i), ValueFromAmount(outcome.voteMatrix[i]));
    obj.pushKV("voteMatrix", arrayVote);

        /* Voter Vectors */
    UniValue voterIDs(UniValue::VARR);
    for(uint32_t i=0; i < outcome.voterIDs.size(); i++)
        voterIDs.pushKV(std::to_string(i), outcome.voterIDs[i].ToString());
    obj.pushKV("voterIDs", voterIDs);

    UniValue oldRep(UniValue::VARR);
    for(uint32_t i=0; i < outcome.oldRep.size(); i++)
        oldRep.pushKV(std::to_string(i), ValueFromAmount(outcome.oldRep[i]));
    obj.pushKV("oldRep", oldRep);

    UniValue thisRep(UniValue::VARR);
    for(uint32_t i=0; i < outcome.thisRep.size(); i++)
        thisRep.pushKV(std::to_string(i), ValueFromAmount(outcome.thisRep[i]));
    obj.pushKV("thisRep", oldRep);

    UniValue smoothedRep(UniValue::VARR);
    for(uint32_t i=0; i < outcome.smoothedRep.size(); i++)
        smoothedRep.pushKV(std::to_string(i), ValueFromAmount(outcome.smoothedRep[i]));
    obj.pushKV("smoothedRep", oldRep);

    UniValue NARow(UniValue::VARR);
    for(uint32_t i=0; i < outcome.NARow.size(); i++)
        NARow.pushKV(std::to_string(i), ValueFromAmount(outcome.NARow[i]));
    obj.pushKV("NARow", oldRep);

    UniValue particRow(UniValue::VARR);
    for(uint32_t i=0; i < outcome.particRow.size(); i++)
        particRow.pushKV(std::to_string(i), ValueFromAmount(outcome.particRow[i]));
    obj.pushKV("particRow", oldRep);

    UniValue particRel(UniValue::VARR);
    for(uint32_t i=0; i < outcome.particRel.size(); i++)
        particRel.pushKV(std::to_string(i), ValueFromAmount(outcome.particRel[i]));
    obj.pushKV("particRel", oldRep);

    UniValue rowBonus(UniValue::VARR);
    for(uint32_t i=0; i < outcome.rowBonus.size(); i++)
        rowBonus.pushKV(std::to_string(i), ValueFromAmount(outcome.rowBonus[i]));
    obj.pushKV("rowBonus", oldRep);

    /* Decision Vectors */

    UniValue decisionIDs(UniValue::VARR);
    for(uint32_t i=0; i < outcome.decisionIDs.size(); i++)
        decisionIDs.pushKV(std::to_string(i), outcome.decisionIDs[i].ToString());
    obj.pushKV("decisionIDs", decisionIDs);

    UniValue isScaled(UniValue::VARR);
    for(uint32_t i=0; i < outcome.isScaled.size(); i++)
        isScaled.pushKV(std::to_string(i), ValueFromAmount(outcome.isScaled[i]));
    obj.pushKV("isScaled", isScaled);

    UniValue firstLoading(UniValue::VARR);
    for(uint32_t i=0; i < outcome.firstLoading.size(); i++)
        firstLoading.pushKV(std::to_string(i), ValueFromAmount(outcome.firstLoading[i]));
    obj.pushKV("firstLoading", firstLoading);

    UniValue decisionsRaw(UniValue::VARR);
    for(uint32_t i=0; i < outcome.decisionsRaw.size(); i++)
        decisionsRaw.pushKV(std::to_string(i), ValueFromAmount(outcome.decisionsRaw[i]));
    obj.pushKV("decisionsRaw", decisionsRaw);

    UniValue consensusReward(UniValue::VARR);
    for(uint32_t i=0; i < outcome.consensusReward.size(); i++)
        consensusReward.pushKV(std::to_string(i), ValueFromAmount(outcome.consensusReward[i]));
    obj.pushKV("consensusReward", consensusReward);

    UniValue certainty(UniValue::VARR);
    for(uint32_t i=0; i < outcome.certainty.size(); i++)
        certainty.pushKV(std::to_string(i), ValueFromAmount(outcome.certainty[i]));
    obj.pushKV("certainty", certainty);

    UniValue NACol(UniValue::VARR);
    for(uint32_t i=0; i < outcome.NACol.size(); i++)
        NACol.pushKV(std::to_string(i), ValueFromAmount(outcome.NACol[i]));
    obj.pushKV("NACol", NACol);

    UniValue particCol(UniValue::VARR);
    for(uint32_t i=0; i < outcome.particCol.size(); i++)
        particCol.pushKV(std::to_string(i), ValueFromAmount(outcome.particCol[i]));
    obj.pushKV("particCol", particCol);

    UniValue authorBonus(UniValue::VARR);
    for(uint32_t i=0; i < outcome.authorBonus.size(); i++)
        authorBonus.pushKV(std::to_string(i), ValueFromAmount(outcome.authorBonus[i]));
    obj.pushKV("authorBonus", authorBonus);

    UniValue decisionsFinal(UniValue::VARR);
    for(uint32_t i=0; i < outcome.decisionsFinal.size(); i++)
        decisionsFinal.pushKV(std::to_string(i), ValueFromAmount(outcome.decisionsFinal[i]));
    obj.pushKV("decisionsFinal", decisionsFinal);

    return obj;
}

UniValue gettrade(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "gettrade\n"
            "\nReturns the trade.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. tradeid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 tradeid;
    tradeid.SetHex(request.params[0].get_str());

    marketTrade trade;
    if (!pmarkettree->GetTrade(tradeid, trade)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Trade not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("tradeid", tradeid.ToString());
    // TODO

    return obj;
}

UniValue getsealedvote(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getsealedvote\n"
            "\nReturns the vote.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. voteid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 voteid;
    voteid.SetHex(request.params[0].get_str());

    marketSealedVote vote;
    if (!pmarkettree->GetSealedVote(voteid, vote)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Vote not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("voteid", voteid.ToString());
    obj.pushKV("branchid", vote.branchid.ToString());
    obj.pushKV("height", (int)vote.height);
    obj.pushKV("txid", vote.txid.ToString());

    return obj;
}

UniValue getrevealvote(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getrevealvote\n"
            "\nReturns the vote.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. voteid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 voteid;
    voteid.SetHex(request.params[0].get_str());

    marketRevealVote vote;
    if (!pmarkettree->GetRevealVote(voteid, vote)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Vote not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("voteid", voteid.ToString());
    obj.pushKV("branchid", vote.branchid.ToString());
    obj.pushKV("height", (int)vote.height);
    obj.pushKV("txid", vote.txid.ToString());

    // Get decision ID(s)
    UniValue decisionArray(UniValue::VARR);
    for (unsigned int i = 0; i < vote.decisionIDs.size(); i++) {
        decisionArray.pushKV(std::to_string(i), vote.decisionIDs.at(i).GetHex());
    }

    obj.pushKV("decisions", decisionArray);

    // Get decision vote(s)
    UniValue voteArray(UniValue::VARR);
    for (unsigned int i = 0; i < vote.decisionVotes.size(); i++) {
        voteArray.pushKV(std::to_string(i), (int)vote.decisionVotes.at(i));
    }

    obj.pushKV("votes", voteArray);

    return obj;
}

UniValue getstealvote(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getstealvote\n"
            "\nReturns the vote.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. voteid          (u256 string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 voteid;
    voteid.SetHex(request.params[0].get_str());

    marketStealVote vote;
    if (!pmarkettree->GetStealVote(voteid, vote)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Vote not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("voteid", voteid.ToString());
    obj.pushKV("branchid", vote.branchid.ToString());
    obj.pushKV("height", (int)vote.height);
    obj.pushKV("txid", vote.txid.ToString());

    return obj;
}

UniValue getballot(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || (request.params.size() != 1 && request.params.size() != 2))
        throw std::runtime_error(
            "getballot\n"
            "\nReturns the ballot (terminated decisionids) for the given branchid.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. branchid          (u256 string)"
            "\n2. height            (optional, numeric)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    uint256 branchid;
    branchid.SetHex(request.params[0].get_str());

    marketBranch branch;
    if (!pmarkettree->GetBranch(branchid, branch)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Branch not found!\n");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("branchid", branchid.ToString());

    uint32_t block_num = 0;
    if (request.params.size() == 2)
        block_num = (uint32_t) request.params[1].get_int();
    else {
        LOCK(cs_main);
        block_num = chainActive.Height();
    }
    uint32_t minblock = branch.tau * ((block_num - 1)/ branch.tau) + 1;
    uint32_t maxblock = minblock + branch.tau - 1;
    obj.pushKV("minblock", (int)minblock);
    obj.pushKV("maxblock", (int)maxblock);

    UniValue array(UniValue::VARR);
    std::vector<marketDecision> vec = pmarkettree->GetDecisions(branchid);
    for(size_t i=0; i < vec.size(); i++) {
        const marketDecision obj = vec[i];
        if ((obj.eventOverBy < minblock)
            || (obj.eventOverBy > maxblock))
            continue;

        UniValue item(UniValue::VOBJ);
        item.pushKV("decisionid", obj.GetHash().ToString());
        item.pushKV("txid", obj.txid.ToString());
        // TODO
        //CHivemindAddress addr;
        //if (addr.Set(obj.keyID))
        //    item.pushKV("keyID", addr.ToString());
        item.pushKV("branchid", obj.branchid.ToString());
        item.pushKV("prompt", obj.prompt);
        item.pushKV("eventoverby", (int)obj.eventOverBy);
        item.pushKV("isScaled", (int)obj.isScaled);
        item.pushKV("min", ValueFromAmount(obj.min));
        item.pushKV("max", ValueFromAmount(obj.max));
        item.pushKV("answerOptionality", (int)obj.answerOptionality);
        array.push_back(item);
    }
    obj.pushKV("decisions", array);

    return obj;
}

UniValue getnewvotecoinaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getnewvotecoinaddress\n"
            "\nReturns a new Votecoin address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. account          (optional, string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    // TODO
    /*
    // Parse the account first so we don't generate a key if there's an error
    string strAccount;
    if (params.size() > 0)
        strAccount = AccountFromValue(params[0]);

    if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();

    pwalletMain->SetAddressBook(keyID, strAccount, "receive");

    // Create a Votecoin address from the new key
    CHivemindAddress votecoinAddress;
    votecoinAddress.is_votecoin = 1;
    votecoinAddress.Set(keyID);

    return votecoinAddress.ToString();
    */

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("address", "");

    return obj;
}

UniValue getcreatetradecapitalrequired(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 4)
        throw std::runtime_error(
            "getcreatetradecapitalrequired\n"
            "\nReturns the capital required to trade.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "\n1. marketid          (u256 string)"
            "\n1. buyorsell         (string)"
            "\n1. numbershares      (numeric)"
            "\n1. decisionstate     (string)"
            "\nResult:\n"
            "\"\"                  (string) .\n"
            "\nExamples:\n"
            + HelpExampleCli("", "")
            + HelpExampleRpc("", "")
        );

    if (!pmarkettree) {
        string strError = std::string("Error: NULL pmarkettree!");
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* double-check buy_or_sell */
    string buy_or_sell = request.params[1].get_str();
    bool isBuy = (buy_or_sell == "buy");
    bool isSell = (buy_or_sell == "sell");
    if (!isBuy && !isSell) {
        string strError = std::string("Error: '")
            + buy_or_sell + "' must be buy or sell!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* double-check dnShares */
    if (request.params[2].get_real() <= 0.0) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%.8f", request.params[2].get_real());
        string strError = std::string("Error: number of shares ")
            + tmp + " must be positive!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }
    uint64_t dnShares = (uint64_t)request.params[2].get_int();

    uint256 marketid;
    marketid.SetHex(request.params[0].get_str());

    marketMarket market;
    if (!pmarkettree->GetMarket(marketid, market)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Vote not found!\n");
    }

    uint32_t nStates = marketNStates(market);

    /* double-check decisionState */
    uint32_t decisionState = request.params[3].get_int();
    if (decisionState >= nStates) {
        char tmp0[32];
        snprintf(tmp0, sizeof(tmp0), "%u", decisionState);
        char tmp1[32];
        snprintf(tmp1, sizeof(tmp1), "%u", nStates);
        string strError = std::string("Error: decision state ")
            + tmp0 + " is above the number of states "
            + tmp1 + " in the market!";
        throw JSONRPCError(RPC_WALLET_ERROR, strError.c_str());
    }

    /* trades of the market */
    std::vector<marketTrade> vTrade = pmarkettree->GetTrades(marketid);

    /* current share totals of the market */
    double *nShares = new double [nStates];
    marketNShares(vTrade, nStates, nShares);

    /* current account value */
    double currAccount = marketAccountValue(market.maxCommission, 1e-8*market.B, nStates, nShares);

    /* new shares to be added to the market */
    nShares[decisionState] += (isBuy)? 1e-8*dnShares: -1e-8*dnShares;
    double nextAccount = marketAccountValue(market.maxCommission, 1e-8*market.B, nStates, nShares);

    /* the price difference to move from the current to the new */
    double price = (isBuy)? (nextAccount - currAccount) / (1e-8*dnShares)
        : (currAccount - nextAccount) / (1e-8*dnShares);

    /* round up because returing value is shown as a string */
    price += 1e-8;

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("marketid", marketid.ToString());
    obj.pushKV("B", 1e-8*market.B);
    obj.pushKV("buy_or_sell", buy_or_sell);
    obj.pushKV("nShares", 1e-8*dnShares);
    obj.pushKV("price", price);
    obj.pushKV("total", (1e-8*dnShares)*price);

    delete nShares;

    return obj;
}

extern UniValue abortrescan(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue importpubkey(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue importprunedfunds(const JSONRPCRequest& request);
extern UniValue removeprunedfunds(const JSONRPCRequest& request);
extern UniValue importmulti(const JSONRPCRequest& request);
extern UniValue rescanblockchain(const JSONRPCRequest& request);

static const CRPCCommand commands[] =
{ //  category              name                                actor (function)                argNames
    //  --------------------- ------------------------          -----------------------         ----------
    { "rawtransactions",    "fundrawtransaction",               &fundrawtransaction,            {"hexstring","options","iswitness"} },
    { "hidden",             "resendwallettransactions",         &resendwallettransactions,      {} },
    { "wallet",             "abandontransaction",               &abandontransaction,            {"txid"} },
    { "wallet",             "abortrescan",                      &abortrescan,                   {} },
    { "wallet",             "addmultisigaddress",               &addmultisigaddress,            {"nrequired","keys","account","address_type"} },
    { "hidden",             "addwitnessaddress",                &addwitnessaddress,             {"address","p2sh"} },
    { "wallet",             "backupwallet",                     &backupwallet,                  {"destination"} },
    { "wallet",             "bumpfee",                          &bumpfee,                       {"txid", "options"} },
    { "wallet",             "dumpprivkey",                      &dumpprivkey,                   {"address"}  },
    { "wallet",             "dumpwallet",                       &dumpwallet,                    {"filename"} },
    { "wallet",             "encryptwallet",                    &encryptwallet,                 {"passphrase"} },
    { "wallet",             "getaccountaddress",                &getaccountaddress,             {"account"} },
    { "wallet",             "getaccount",                       &getaccount,                    {"address"} },
    { "wallet",             "getaddressesbyaccount",            &getaddressesbyaccount,         {"account"} },
    { "wallet",             "getaddressinfo",                   &getaddressinfo,                {"address"} },
    { "wallet",             "getbalance",                       &getbalance,                    {"account","minconf","include_watchonly"} },
    { "wallet",             "getnewaddress",                    &getnewaddress,                 {"account","address_type"} },
    { "wallet",             "getdepositaddress",                &getdepositaddress,             {} },
    { "wallet",             "getrawchangeaddress",              &getrawchangeaddress,           {"address_type"} },
    { "wallet",             "getreceivedbyaccount",             &getreceivedbyaccount,          {"account","minconf"} },
    { "wallet",             "getreceivedbyaddress",             &getreceivedbyaddress,          {"address","minconf"} },
    { "wallet",             "gettransaction",                   &gettransaction,                {"txid","include_watchonly"} },
    { "wallet",             "getunconfirmedbalance",            &getunconfirmedbalance,         {} },
    { "wallet",             "getwalletinfo",                    &getwalletinfo,                 {} },
    { "wallet",             "importmulti",                      &importmulti,                   {"requests","options"} },
    { "wallet",             "importprivkey",                    &importprivkey,                 {"privkey","label","rescan"} },
    { "wallet",             "importwallet",                     &importwallet,                  {"filename"} },
    { "wallet",             "importaddress",                    &importaddress,                 {"address","label","rescan","p2sh"} },
    { "wallet",             "importprunedfunds",                &importprunedfunds,             {"rawtransaction","txoutproof"} },
    { "wallet",             "importpubkey",                     &importpubkey,                  {"pubkey","label","rescan"} },
    { "wallet",             "keypoolrefill",                    &keypoolrefill,                 {"newsize"} },
    { "wallet",             "listaccounts",                     &listaccounts,                  {"minconf","include_watchonly"} },
    { "wallet",             "listaddressgroupings",             &listaddressgroupings,          {} },
    { "wallet",             "listlockunspent",                  &listlockunspent,               {} },
    { "wallet",             "listreceivedbyaccount",            &listreceivedbyaccount,         {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listreceivedbyaddress",            &listreceivedbyaddress,         {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listsinceblock",                   &listsinceblock,                {"blockhash","target_confirmations","include_watchonly","include_removed"} },
    { "wallet",             "listtransactions",                 &listtransactions,              {"account","count","skip","include_watchonly"} },
    { "wallet",             "listunspent",                      &listunspent,                   {"minconf","maxconf","addresses","include_unsafe","query_options"} },
    { "wallet",             "listwallets",                      &listwallets,                   {} },
    { "wallet",             "lockunspent",                      &lockunspent,                   {"unlock","transactions"} },
    { "wallet",             "move",                             &movecmd,                       {"fromaccount","toaccount","amount","minconf","comment"} },
    { "wallet",             "sendfrom",                         &sendfrom,                      {"fromaccount","toaddress","amount","minconf","comment","comment_to"} },
    { "wallet",             "sendmany",                         &sendmany,                      {"fromaccount","amounts","minconf","comment","subtractfeefrom","replaceable","conf_target","estimate_mode"} },
    { "wallet",             "sendtoaddress",                    &sendtoaddress,                 {"address","amount","comment","comment_to","subtractfeefromamount","replaceable","conf_target","estimate_mode"} },
    { "wallet",             "setaccount",                       &setaccount,                    {"address","account"} },
    { "wallet",             "settxfee",                         &settxfee,                      {"amount"} },
    { "wallet",             "signmessage",                      &signmessage,                   {"address","message"} },
    { "wallet",             "signrawtransactionwithwallet",     &signrawtransactionwithwallet,  {"hexstring","prevtxs","sighashtype"} },
    { "wallet",             "walletlock",                       &walletlock,                    {} },
    { "wallet",             "walletpassphrasechange",           &walletpassphrasechange,        {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletpassphrase",                 &walletpassphrase,              {"passphrase","timeout"} },
    { "wallet",             "removeprunedfunds",                &removeprunedfunds,             {"txid"} },
    { "wallet",             "rescanblockchain",                 &rescanblockchain,              {"start_height", "stop_height"} },

    { "sidechain",          "createwithdrawal",                 &createwithdrawal,                      {"address","refundaddress","namount","nfee", "nmainchainfee"} },
    { "sidechain",          "createwithdrawalrefundrequest",    &createwithdrawalrefundrequest,         {"id"} },
    { "sidechain",          "refundallwithdrawals",             &refundallwithdrawals,                  {} },

    { "hivemind",           "listbranches",                     &listbranches,                  {} },
    { "hivemind",           "listdecisions",                    &listdecisions,             {"branchid"} },
    { "hivemind",           "listmarkets",                      &listmarkets,                   {"decisionid"} },
    { "hivemind",           "listoutcomes",                     &listoutcomes,                  {"branchid"} },
    { "hivemind",           "listtrades",                       &listtrades,                    {"marketid"} },
    { "hivemind",           "listvotes",                        &listvotes,                     {"branchid", "height"} },

    { "hivemind",           "createbranch",                     &createbranch,                  {"name","description","baselistingfee","freedecisions","targetdecisions","maxdecisions","mintradingfee","tau","ballottime","unsealtime","consensusthreshold","alpha","tol"} },
    { "hivemind",           "createdecision",                   &createdecision,                {"address","branchid","prompt","eventoverby","answeroptionality","isscaled","scaledmin","scaledmax"} },
    { "hivemind",           "createmarket",                     &createmarket,                  {"address","decisionids","B","tradingfee","maxcomission","title","description","tags","maturation","powhashid","powdiff"} },
    { "hivemind",           "createtrade",                      &createtrade,                   {"address","marketid","buyorsell","numbershares","price","decisionstate","nonce"} },
    { "hivemind",           "createsealedvote",                 &createsealedvote,              {"branchid","height","voteid"} },
    { "hivemind",           "createstealvote",                  &createstealvote ,              {"branchid","height","voteid"} },
    { "hivemind",           "createrevealvote",                 &createrevealvote,              {"address","branchid","height","voteid","na","votes"} },

    { "hivemind",           "getbranch",                        &getbranch,                     {"branchid"} },
    { "hivemind",           "getdecision",                      &getdecision,                   {"decisionid"} },
    { "hivemind",           "getmarket",                        &getmarket,                     {"marketid"} },
    { "hivemind",           "getoutcome",                       &getoutcome,                    {"outcomeid"} },
    { "hivemind",           "gettrade",                         &gettrade,                      {"tradeid"} },
    { "hivemind",           "getsealedvote",                    &getsealedvote,                 {"voteid"} },
    { "hivemind",           "getrevealvote",                    &getrevealvote,                 {"voteid"} },
    { "hivemind",           "getstealvote",                     &getstealvote,                  {"voteid"} },
    { "hivemind",           "getballot",                        &getballot,                     {"branchid", "height"} },
    { "hivemind",           "getnewvotecoinaddress",            &getnewvotecoinaddress,         {"account"} },

    { "hivemind",           "getcreatetradecapitalrequired",    &getcreatetradecapitalrequired, {"marketid","buyorsell","numbershares","decisionstate"} },


};

void RegisterWalletRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
