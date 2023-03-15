// Copyright (c) 2015-2023 The Hivemind Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/market.h>

#include <vector>
#include <sstream>

#include <clientversion.h>
#include <streams.h>

#include "linalg/src/tc_mat.c"

//extern "C" double FDLIBM_log(double);
//extern "C" double FDLIBM_exp(double);


const uint32_t nType = 1;
const uint32_t nVersion = 1;

uint256 marketObj::GetHash(void) const
{
    uint256 ret;
    if (marketop == 'B')
       ret = SerializeHash(*(marketBranch *) this);
    else
    if (marketop == 'D')
       ret = SerializeHash(*(marketDecision *) this);
    else
    if (marketop == 'L')
       ret = SerializeHash(*(marketStealVote *) this);
    else
    if (marketop == 'M')
       ret = SerializeHash(*(marketMarket *) this);
    else
    if (marketop == 'O')
       ret = SerializeHash(*(marketOutcome *) this);
    else
    if (marketop == 'R')
       ret = SerializeHash(*(marketRevealVote *) this);
    else
    if (marketop == 'S')
       ret = SerializeHash(*(marketSealedVote *) this);
    else
    if (marketop == 'T')
       ret = SerializeHash(*(marketTrade *) this);
    return ret;
}

CScript marketObj::GetScript(void) const
{
    CDataStream ds(SER_DISK, CLIENT_VERSION);
    if (marketop == 'B')
       ((marketBranch *) this)->Serialize(ds);
    else
    if (marketop == 'D')
       ((marketDecision *) this)->Serialize(ds);
    else
    if (marketop == 'L')
       ((marketStealVote *) this)->Serialize(ds);
    else
    if (marketop == 'M')
       ((marketMarket *) this)->Serialize(ds);
    else
    if (marketop == 'O')
       ((marketOutcome *) this)->Serialize(ds);
    else
    if (marketop == 'R')
       ((marketRevealVote *) this)->Serialize(ds);
    else
    if (marketop == 'S')
       ((marketSealedVote *) this)->Serialize(ds);
    else
    if (marketop == 'T')
       ((marketTrade *) this)->Serialize(ds);
    CScript script;
    script << vector<unsigned char>(ds.begin(), ds.end()) << OP_MARKET;
    return script;
}

marketObj *marketObjCtr(const CScript &script)
{
    CScript::const_iterator pc = script.begin();
    vector<unsigned char> vch;
    opcodetype opcode;
    if (!script.GetOp(pc, opcode, vch))
       return NULL;
    if (vch.size() == 0)
       return NULL;
    const char *vch0 = (const char *) &vch.begin()[0];
    CDataStream ds(vch0, vch0+vch.size(), SER_DISK, CLIENT_VERSION);

    if (*vch0 == 'B') {
        marketBranch *obj = new marketBranch;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'D') {
        marketDecision *obj = new marketDecision;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'L') {
        marketStealVote *obj = new marketStealVote;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'M') {
        marketMarket *obj = new marketMarket;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'O') {
        marketOutcome *obj = new marketOutcome;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'R') {
        marketRevealVote *obj = new marketRevealVote;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'S') {
        marketSealedVote *obj = new marketSealedVote;
        obj->Unserialize(ds);
        return obj;
    }
    else
    if (*vch0 == 'T') {
        marketTrade *obj = new marketTrade;
        obj->Unserialize(ds);
        return obj;
    }
    return NULL;
}

string marketObj::ToString(void) const
{
    stringstream str;
    str << "marketop=" << marketop << endl;
    str << "nHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    return str.str();
}

string marketBranch::ToString(void) const
{
    stringstream str;
    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "name=" << name << endl;
    str << "description=" << description << endl;
    str << "baseListingFee=" << baseListingFee/1e8 << endl;
    str << "freeDecisions=" << freeDecisions << endl;
    str << "targetDecisions=" << targetDecisions << endl;
    str << "maxDecisions=" << maxDecisions << endl;
    str << "minTradingFee=" << minTradingFee/1e8 << endl;
    str << "tau=" << tau << endl;
    str << "ballotTime=" << ballotTime << endl;
    str << "unsealTime=" << unsealTime << endl;
    str << "consensusThreshold=" << consensusThreshold/1e8 << endl;
    str << "alpha=" << alpha/1e8 << endl;
    str << "tol=" << tol/1e8 << endl;
    return str.str();
}

string marketDecision::ToString(void) const
{
    stringstream str;
    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "keyID=" << keyID.ToString() << endl;
    str << "branchid=" << branchid.ToString() << endl;
    str << "prompt=" << prompt << endl;
    str << "eventOverBy=" << eventOverBy << endl;
    str << "isScaled=" << ((isScaled)? "true": "false") << endl;
    str << "min=" << min/1e8 << endl;
    str << "max=" << max/1e8 << endl;
    str << "answerOptionality=" << answerOptionality << endl;
    return str.str();
}

string marketMarket::ToString(void) const
{
    stringstream str;
    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "keyID=" << keyID.ToString() << endl;
    str << "branchid=" << branchid.ToString() << endl;
    str << "B=" << B/1e8 << endl;
    str << "tradingFee=" << tradingFee/1e8 << endl;
    str << "maxCommission=" << maxCommission/1e8 << endl;
    str << "title=" << title << endl;
    str << "description=" << description << endl;
    str << "tags=" << tags << endl;
    str << "maturation=" << maturation << endl;
    str << "decisionIDs=";
    for(uint32_t i=0; i < decisionIDs.size(); i++) {
        if (i) str << ",";
        str << decisionIDs[i].ToString() + ":";
        if (i < decisionFunctionIDs.size())
            str << decisionFunctionIDToString(decisionFunctionIDs[i]);
    }
    str << endl;
    str << "txPoWh=" << txPoWh << endl;
    str << "txPoWd=" << txPoWd << endl;
    return str.str();
}

string marketTrade::ToString(void) const
{
    stringstream str;
    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "keyID=" << keyID.ToString() << endl;
    str << "isBuy=" << isBuy << endl;
    str << "nShares=" << nShares/1e8 << endl;
    str << "price=" << price/1e8 << endl;
    str << "decisionState=" << decisionState << endl;
    str << "nonce=" << nonce << endl;
    return str.str();
}

uint32_t marketNStates(const marketMarket& market)
{
    uint32_t nStates = 1;
    for(uint32_t i=0; i < market.decisionIDs.size(); i++)
        nStates *= 2;
    return nStates;
}

int marketNShares(const vector<marketTrade> &trades, uint32_t nStates,
    double *nShares)
{
    if (nShares)
        return -1; /* error */

    for(uint32_t i=0; i < nStates; i++)
        nShares[i] = 0.0;

    for(uint32_t i=0; i < trades.size(); i++) {
        const marketTrade trade = trades[i];
        uint32_t state = trade.decisionState;
        if (state < nStates)
           nShares[state] += (trade.isBuy)? trade.nShares: -trade.nShares;
    }

    for(uint32_t i=0; i < nStates; i++)
        nShares[i] *= 1e-8;

    return 0;
}

/* markets with liquidity sensitivity (LS):
 * The market author purchases an initial minShares shares in each of the
 * N states. Those minShares will never be sold (money to be returned to the
 * author upon market conclusion). The number of minShares is derived from
 * the maxCommission parameter
 *   minShares = B log N / maxCommission.
 * Before the shares are purchased the account value is
 *   B log sum exp(0/B)
 * After the shares are purchased the account value is
 *   B log sum exp(minShares /B)
 * The initial purchase of minShares in each state then costs
 *        = B log sum exp(minShares / B)               - B log sum exp(0/B)
 *        = B log [N exp(B log N / maxCommission / B)] - B log N
 *        = B log [exp(log N / maxCommission)]
 *        = B log [N / maxCommission]
 *        = minShares
 *
 * Note: maxCommission must be greater than zero. A zero maxCommission will
 * designate the market to be "non-LS".
 */


/* FDLIBM version
double marketAccountValue(double maxCommission, double B, uint32_t nStates,
   const double *nShares)
{
    // non-LS
    if (maxCommission == 0.0) {
        double sumExp = 0.0;
        for(uint32_t i=0; i < nStates; i++) {
            double nSharesi = (nShares)? nShares[i]: 0.0;
            if (nSharesi == 0.0)
                continue;
            sumExp += FDLIBM_exp(nSharesi / B);
        }
        return B * FDLIBM_log(sumExp);
    }

    // LS
    double minShares = B * FDLIBM_log(nStates) / maxCommission;
    double sumShares = 0.0;
    for(uint32_t i=0; i < nStates; i++)
        sumShares += (nShares)? nShares[i]: minShares;
    B *= sumShares / (nStates * minShares);

    double sumExp = 0.0;
    for(uint32_t i=0; i < nStates; i++) {
        double nSharesi = (nShares)? nShares[i]: minShares;
        sumExp += FDLIBM_exp(nSharesi / B);
    }
    return B * FDLIBM_log(sumExp);
}
*/

/* standard library version: */
double marketAccountValue(double maxCommission, double B, uint32_t nStates,
   const double *nShares)
{
    /* non-LS */
    if (maxCommission == 0.0) {
        double sumExp = 0.0;
        for(uint32_t i=0; i < nStates; i++) {
            double nSharesi = (nShares)? nShares[i]: 0.0;
            if (nSharesi == 0.0)
                continue;
            sumExp += std::exp(nSharesi / B);
        }
        return B * std::log(sumExp);
    }

    /* LS */
    double minShares = B * std::log(nStates) / maxCommission;
    double sumShares = 0.0;
    for(uint32_t i=0; i < nStates; i++)
        sumShares += (nShares)? nShares[i]: minShares;
    B *= sumShares / (nStates * minShares);

    double sumExp = 0.0;
    for(uint32_t i=0; i < nStates; i++) {
        double nSharesi = (nShares)? nShares[i]: minShares;
        sumExp += std::exp(nSharesi / B);
    }
    return B * std::log(sumExp);
}

string marketOutcome::ToString(void) const
{
    char err[64];
    sprintf(err, " %63s", "-----");

    stringstream str;

    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "branchid=" << branchid.ToString() << endl;
    str << "NA=" << NA/1e8 << endl;
    str << "alpha=" << alpha/1e8 << endl;
    str << "tol=" << tol/1e8 << endl;

    /* matrix */
    str << "voteMatrix=" << endl;
    for(uint32_t i=0; i < voteMatrix.size(); i++) {
        double value = voteMatrix[i];
        char buf[20];
        if (value == NA)
            snprintf(buf, 20, " %16s", "NA");
        else
            snprintf(buf, 20, " %16.8f", value);
        str << buf;
        if ((i + 1) % nDecisions == 0)
            str << endl;
    }

    /* Voter vectors */
    str << "nVoters=" << nVoters << endl;
    vector< const vector<uint64_t> * > rVecs;
    rVecs.push_back(&oldRep);
    rVecs.push_back(&thisRep);
    rVecs.push_back(&smoothedRep);
    rVecs.push_back(&NARow);
    rVecs.push_back(&particRow);
    rVecs.push_back(&particRel);
    rVecs.push_back(&rowBonus);
    for(uint32_t i=0; i < nVoters; i++) {
        char buf[64];
        if (i < voterIDs.size())
            str << err;
        else {
            snprintf(buf, 64, " %62s", voterIDs[i].GetHex().c_str());
            str << buf;
        }
        for(uint32_t j=0; j < rVecs.size(); j++) {
            if (i < rVecs[j]->size())
                str << err;
            else {
                snprintf(buf, 64, " %16.8f", rVecs[j]->at(i)/1e8);
                str << buf;
            }
        }
        str << endl;
    }
    str << endl;

    /* Decision vectors */
    str << "nDecisions=" << nDecisions << endl;
    vector< const vector<uint64_t> * > cVecs;
    cVecs.push_back(&isScaled);
    cVecs.push_back(&firstLoading);
    cVecs.push_back(&decisionsRaw);
    cVecs.push_back(&consensusReward);
    cVecs.push_back(&certainty);
    cVecs.push_back(&NACol);
    cVecs.push_back(&particCol);
    cVecs.push_back(&authorBonus);
    cVecs.push_back(&decisionsFinal);
    for(uint32_t i=0; i < nDecisions; i++) {
        char buf[64];
        if (i < decisionIDs.size())
            str << err;
        else {
            snprintf(buf, 64, " %62s", decisionIDs[i].GetHex().c_str());
            str << buf;
        }
        for(uint32_t j=0; j < cVecs.size(); j++) {
            if (i < cVecs[j]->size())
                str << err;
            else {
                snprintf(buf, 64, " %16.8f", cVecs[j]->at(i)/1e8);
                str << buf;
            }
        }
        str << endl;
    }
    str << endl;

    return str.str();
}

int marketOutcome::calc(void)
{
    struct tc_vote *vote = tc_vote_ctr(nVoters, nDecisions);
    vote->NA = NA;
    vote->alpha = alpha;
    vote->tol = tol;

    double **oldrep = vote->rvecs[TC_VOTE_OLD_REP]->a;
    for(uint32_t i=0; i < nVoters; i++)
        oldrep[i][0] = oldRep[i] * 1e-8;

    double **isbin = vote->cvecs[TC_VOTE_IS_BINARY]->a;
    for(uint32_t j=0; j < nDecisions; j++)
        isbin[0][j] = (isScaled[j])? 0.0: 1.0;

    double **m = vote->M->a;
    for(uint32_t i=0; i < nVoters; i++)
        for(uint32_t j=0; j < nDecisions; j++)
            m[i][j] = voteMatrix[i*nDecisions + j] * 1e-8;

    int rc = tc_vote_proc(vote);
    if (rc < 0) {
        /* something is wrong. */
        tc_vote_dtr(vote);
        return -1;
    }

    /* row (voters) outputs */
    double **thisrep = vote->rvecs[TC_VOTE_THIS_REP]->a;
    double **smoothedrep = vote->rvecs[TC_VOTE_SMOOTHED_REP]->a;
    double **narow = vote->rvecs[TC_VOTE_NA_ROW]->a;
    double **particrow = vote->rvecs[TC_VOTE_PARTIC_ROW]->a;
    double **particrel = vote->rvecs[TC_VOTE_PARTIC_REL]->a;
    double **rowbonus = vote->rvecs[TC_VOTE_ROW_BONUS]->a;
    thisRep.clear();
    smoothedRep.clear();
    NARow.clear();
    particRow.clear();
    particRel.clear();
    rowBonus.clear();
    for(uint32_t i=0; i < nVoters; i++) {
       thisRep.push_back( (uint64_t) (thisrep[0][i] * 1e8) );
       smoothedRep.push_back( (uint64_t) (smoothedrep[0][i] * 1e8) );
       NARow.push_back( (uint64_t) (narow[0][i] * 1e8) );
       particRow.push_back( (uint64_t) (particrow[0][i] * 1e8) );
       particRel.push_back( (uint64_t) (particrel[0][i] * 1e8) );
       rowBonus.push_back( (uint64_t) (rowbonus[0][i] * 1e8) );
    }

    /* column (decisions) outputs */
    double **firstloading = vote->cvecs[TC_VOTE_FIRST_LOADING]->a;
    double **decisionsraw = vote->cvecs[TC_VOTE_DECISIONS_RAW]->a;
    double **consensusrew = vote->cvecs[TC_VOTE_CONSENSUS_REW]->a;
    double **certain = vote->cvecs[TC_VOTE_CERTAINTY]->a;
    double **nacol = vote->cvecs[TC_VOTE_NA_COL]->a;
    double **particcol = vote->cvecs[TC_VOTE_PARTIC_COL]->a;
    double **authorbonus = vote->cvecs[TC_VOTE_AUTHOR_BONUS]->a;
    double **decisionsfinal = vote->cvecs[TC_VOTE_DECISIONS_FINAL]->a;
    firstLoading.clear();
    decisionsRaw.clear();
    consensusReward.clear();
    certainty.clear();
    NACol.clear();
    particCol.clear();
    authorBonus.clear();
    decisionsFinal.clear();
    for(uint32_t i=0; i < nDecisions; i++) {
        firstLoading.push_back( (uint64_t) (firstloading[0][i] * 1e8) );
        decisionsRaw.push_back( (uint64_t) (decisionsraw[0][i] * 1e8) );
        consensusReward.push_back( (uint64_t) (consensusrew[0][i] * 1e8) );
        certainty.push_back( (uint64_t) (certain[0][i] * 1e8) );
        NACol.push_back( (uint64_t) (nacol[0][i] * 1e8) );
        particCol.push_back( (uint64_t) (particcol[0][i] * 1e8) );
        authorBonus.push_back( (uint64_t) (authorbonus[0][i] * 1e8) );
        decisionsFinal.push_back( (uint64_t) (decisionsfinal[0][i] * 1e8) );
    }

    tc_vote_dtr(vote);
    return 0;
}

string marketRevealVote::ToString(void) const
{
    stringstream str;

    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "branchid=" << branchid.ToString() << endl;
    str << "height=" << height << endl;
    str << "voteid=" << voteid.ToString() << endl;
    str << "NA=" << NA/1e8 << endl;

    str << "votes=";
    for(uint32_t i=0; i < decisionIDs.size(); i++) {
        if (i) str << ",";
        str << decisionIDs[i].ToString() + ":";
        if (i < decisionVotes.size())
            str << decisionVotes[i] / 1e8;
    }
    str << endl;

    return str.str();
}

string marketSealedVote::ToString(void) const
{
    stringstream str;

    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "branchid=" << branchid.ToString() << endl;
    str << "voteid=" << voteid.ToString() << endl;

    return str.str();
}

string marketStealVote::ToString(void) const
{
    stringstream str;

    str << "marketop=" << marketop << endl;
    str << "hHeight=" << nHeight << endl;
    str << "txid=" << txid.GetHex() << endl;
    str << "voteid=" << voteid.GetHex() << endl;

    return str.str();
}

