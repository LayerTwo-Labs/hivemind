// Copyright (c) 2015-2023 The Hivemind Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HIVEMIND_PIMITIVES_MARKET_H
#define HIVEMIND_PIMITIVES_MARKET_H

#include <limits.h>
#include <stdint.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>
#include <primitives/transaction.h>
#include <uint256.h>

using namespace std;

struct marketObj {
    char marketop;
    uint32_t nHeight;
    uint256 txid;

    marketObj(void): nHeight(INT_MAX) { }
    virtual ~marketObj(void) { }

    uint256 GetHash(void) const;
    CScript GetScript(void) const;
    virtual string ToString(void) const;
};
marketObj *marketObjCtr(const CScript &);

struct marketDecision : public marketObj {
    CKeyID keyID;
    uint256 branchid;
    string prompt;
    uint32_t eventOverBy;
    uint8_t isScaled;
    int64_t min;
    int64_t max;
    uint8_t answerOptionality; /* false=not optional, true=optional */

    marketDecision(void) : marketObj() { marketop = 'D'; }
    virtual ~marketDecision(void) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(keyID);
        READWRITE(branchid);
        READWRITE(prompt);
        READWRITE(eventOverBy);
        READWRITE(isScaled);
        READWRITE(min);
        READWRITE(max);
        READWRITE(answerOptionality);
    }

    string ToString(void) const;
};

struct marketTrade : public marketObj {
    CKeyID keyID;
    uint256 marketid;
    bool isBuy;
    uint64_t nShares;
    uint64_t price;
    uint32_t decisionState;
    uint32_t nonce;

    marketTrade(void) : marketObj() { marketop = 'T'; }
    virtual ~marketTrade(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(keyID);
        READWRITE(marketid);
        READWRITE(isBuy);
        READWRITE(nShares);
        READWRITE(price);
        READWRITE(decisionState);
        READWRITE(nonce);
    }

    string ToString(void) const;
};

enum decisionfunctionid {
	DFID_X1 = 1,
	DFID_X2 = 2,
	DFID_X3 = 3,
	DFID_LNX1 = 4,
};

inline int decisionFunctionToInt(const string &s) {
    if (s == "X1") return DFID_X1;
    if (s == "X2") return DFID_X2;
    if (s == "X3") return DFID_X3;
    if (s == "LNX1") return DFID_LNX1;
    return -1;
}

inline string decisionFunctionIDToString(int i) {
    if (i == DFID_X1) return "X1";
    if (i == DFID_X2) return "X2";
    if (i == DFID_X3) return "X3";
    if (i == DFID_LNX1) return "LNX1";
    return "";
}

struct marketMarket : public marketObj {
    CKeyID keyID;
    uint64_t B;
    uint64_t tradingFee;
    uint64_t maxCommission;
    string title;
    string description;
    string tags;
    uint32_t maturation;
    uint256 branchid;
    vector<uint256> decisionIDs;
    vector<uint8_t> decisionFunctionIDs;
    uint32_t txPoWh; /* hash function id */
    uint32_t txPoWd; /* difficulty */

    marketMarket(void) : marketObj() { marketop = 'M'; }
    virtual ~marketMarket(void) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(keyID);
        READWRITE(B);
        READWRITE(tradingFee);
        READWRITE(maxCommission);
        READWRITE(title);
        READWRITE(description);
        READWRITE(tags);
        READWRITE(maturation);
        READWRITE(branchid);
        READWRITE(decisionIDs);
        READWRITE(decisionFunctionIDs);
        READWRITE(txPoWh);
        READWRITE(txPoWd);
    }

    string ToString(void) const;
};

/* query the number of states in the market */
uint32_t marketNStates(const marketMarket *);
/* query the nShares in each state from the set of trades */
int marketNShares(const vector<marketTrade *> &trades, uint32_t nStates, double *nShares);
/* query the account value when given the nshares in each state */
double marketAccountValue(double maxCommission, double B, uint32_t nStates, const double *nShares);

struct marketRevealVote : public marketObj {
    uint256 branchid;
    uint32_t height; /* a multiple of tau */
    uint256 voteid; /* the sealed vote id */
    vector<uint256> decisionIDs;
    vector<uint64_t> decisionVotes;
    uint64_t NA;
    CKeyID keyID;

    marketRevealVote(void) : marketObj() { marketop = 'R'; }
    virtual ~marketRevealVote(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(branchid);
        READWRITE(height);
        READWRITE(decisionIDs);
        READWRITE(decisionVotes);
        READWRITE(NA);
        READWRITE(keyID);
    }

    string ToString(void) const;
};

struct marketSealedVote : public marketObj {
    uint256 branchid;
    uint32_t height; /* a multiple of tau */
    uint256 voteid;

    marketSealedVote(void) : marketObj() { marketop = 'S'; }
    virtual ~marketSealedVote(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(branchid);
        READWRITE(height);
        READWRITE(voteid);
    }

    string ToString(void) const;
};

struct marketStealVote : public marketObj {
    uint256 branchid;
    uint32_t height; /* a multiple of tau */
    uint256 voteid; /* the vote to be stolen */

    marketStealVote(void) : marketObj() { marketop = 'L'; }
    virtual ~marketStealVote(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(branchid);
        READWRITE(height);
        READWRITE(voteid);
    }

    string ToString(void) const;
};

struct marketOutcome : public marketObj {
    uint256 branchid;
    /* size() == nVoters */
    uint32_t nVoters;
    vector<CKeyID> voterIDs;
    vector<uint64_t> oldRep;
    vector<uint64_t> thisRep; /* output */
    vector<uint64_t> smoothedRep; /* output */
    vector<uint64_t> NARow; /* output */
    vector<uint64_t> particRow; /* output */
    vector<uint64_t> particRel; /* output */
    vector<uint64_t> rowBonus; /* output */
    /* size() == nDecisions */
    uint32_t nDecisions;
    vector<uint256> decisionIDs;
    vector<uint64_t> isScaled;
    vector<uint64_t> firstLoading; /* output */
    vector<uint64_t> decisionsRaw; /* output */
    vector<uint64_t> consensusReward; /* output */
    vector<uint64_t> certainty; /* output */
    vector<uint64_t> NACol; /* output */
    vector<uint64_t> particCol; /* output */
    vector<uint64_t> authorBonus; /* output */
    vector<uint64_t> decisionsFinal; /* output */
    vector<uint64_t> voteMatrix; /* [nVoters][nDecisions] */
    /* params */
    uint64_t NA;
    uint64_t alpha; /* for smoothed rep */
    uint64_t tol;
    CTransaction tx; /* transaction with market payouts and reputation (votecoin) transfers */

    marketOutcome(void) : marketObj() { marketop = 'O'; }
    virtual ~marketOutcome(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(nHeight);
        READWRITE(branchid);
        READWRITE(nVoters);
        READWRITE(voterIDs);
        READWRITE(oldRep);
        READWRITE(thisRep);
        READWRITE(smoothedRep);
        READWRITE(NARow);
        READWRITE(particRow);
        READWRITE(particRel);
        READWRITE(rowBonus);
        READWRITE(nDecisions);
        READWRITE(decisionIDs);
        READWRITE(isScaled);
        READWRITE(firstLoading);
        READWRITE(decisionsRaw);
        READWRITE(consensusReward);
        READWRITE(certainty);
        READWRITE(NACol);
        READWRITE(particCol);
        READWRITE(authorBonus);
        READWRITE(decisionsFinal);
        READWRITE(voteMatrix);
        READWRITE(NA);
        READWRITE(alpha);
        READWRITE(tol);
    }
    string ToString(void) const;
    int calc(void);
};

/* market Branch
 * decisions partitioned via ending times in blocks ((n-1)*tau, n*tau]
 * ballots available at block n*tau
 * submit sealed ballots during (n*tau, n*tau+ballotTime]
 * submit unsealed ballots during (n*tau, n*tau+ballotTime+unsealTime]
 * outcomes decided by the miner for block n*tau+ballotTime+unsealTime+1
 */
struct marketBranch : public marketObj {
    string name;
    string description;
    uint64_t baseListingFee;
    uint16_t freeDecisions;
    uint16_t targetDecisions;
    uint16_t maxDecisions;
    uint64_t minTradingFee;
    uint16_t tau;
    uint16_t ballotTime;
    uint16_t unsealTime;
    uint64_t consensusThreshold;
    uint64_t alpha; /* for smoothed rep */
    uint64_t tol;

    marketBranch(void) : marketObj() { marketop = 'B'; }
    virtual ~marketBranch(void) { }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(marketop);
        READWRITE(name);
        READWRITE(description);
        READWRITE(baseListingFee);
        READWRITE(freeDecisions);
        READWRITE(targetDecisions);
        READWRITE(maxDecisions);
        READWRITE(minTradingFee);
        READWRITE(tau);
        READWRITE(ballotTime);
        READWRITE(unsealTime);
        READWRITE(consensusThreshold);
        READWRITE(alpha);
        READWRITE(tol);
    }
    string ToString(void) const;
};

#endif // HIVEMIND_PRIMITIVES_MARKET_H
