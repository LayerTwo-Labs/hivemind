// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <chainparams.h>
#include <consensus/params.h>
#include <hash.h>
#include <random.h>
#include <sidechain.h>
#include <uint256.h>
#include <util.h>
#include <ui_interface.h>
#include <init.h>

#include <stdint.h>

#include <boost/thread.hpp>

static const char DB_COIN = 'C';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

static const char DB_LAST_SIDECHAIN_DEPOSIT = 'x';
static const char DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE = 'w';

using namespace std;

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    char key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true)
{
}

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    return db.Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return db.Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    vector<uint256> vhashHeadBlocks;
    if (!db.Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    size_t batch_size = (size_t)gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
    int crash_simulate = gArgs.GetArg("-dbcrashratio", 0);
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, vector<uint256>{hashBlock, old_tip});

    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent())
                batch.Erase(entry);
            else
                batch.Write(entry, it->second.coin);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
        if (batch.SizeEstimate() > batch_size) {
            LogPrint(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            db.WriteBatch(batch);
            batch.Clear();
            if (crash_simulate) {
                static FastRandomContext rng;
                if (rng.randrange(crash_simulate) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogPrint(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = db.WriteBatch(batch);
    LogPrint(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CDBWrapper&>(db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}

bool CBlockTreeDB::WriteBatchSync(const vector<pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (vector<pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const vector<pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (vector<pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteFlag(const string &name, bool fValue) {
    return Write(make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const string &name, bool &fValue) {
    char ch;
    if (!Read(make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(const Consensus::Params& consensusParams, function<CBlockIndex*(const uint256&, const uint256&)> insertBlockIndex)
{
    unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(make_pair(DB_BLOCK_INDEX, uint256()));

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.GetBlockHash(), diskindex.hashMainBlock);
                pindexNew->pprev          = insertBlockIndex(diskindex.hashPrev, uint256());
                pindexNew->nHeight        = diskindex.nHeight;
                pindexNew->nFile          = diskindex.nFile;
                pindexNew->nDataPos       = diskindex.nDataPos;
                pindexNew->nUndoPos       = diskindex.nUndoPos;
                pindexNew->nVersion       = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime          = diskindex.nTime;
                pindexNew->hashMainBlock  = diskindex.hashMainBlock;
                pindexNew->hashWithdrawalBundle    = diskindex.hashWithdrawalBundle;
                pindexNew->nStatus        = diskindex.nStatus;
                pindexNew->nTx            = diskindex.nTx;

                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    return true;
}

CSidechainTreeDB::CSidechainTreeDB(size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(GetDataDir() / "blocks" / "sidechain", nCacheSize, fMemory, fWipe) { }

bool CSidechainTreeDB::WriteSidechainIndex(const vector<pair<uint256, const SidechainObj *> > &list)
{
    CDBBatch batch(*this);
    for (vector<pair<uint256, const SidechainObj *> >::const_iterator it=list.begin(); it!=list.end(); it++) {
        const uint256 &objid = it->first;
        const SidechainObj *obj = it->second;
        pair<char, uint256> key = make_pair(obj->sidechainop, objid);

        if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_OP) {
            const SidechainWithdrawal *ptr = (const SidechainWithdrawal *) obj;
            batch.Write(key, *ptr);
        }
        else
        if (obj->sidechainop == DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP) {
            const SidechainWithdrawalBundle *ptr = (const SidechainWithdrawalBundle *) obj;
            batch.Write(key, *ptr);

            // Also index the WithdrawalBundle by the WithdrawalBundle transaction hash
            uint256 hashWithdrawalBundle = ptr->tx.GetHash();
            pair<char, uint256> keyTx = make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, hashWithdrawalBundle);
            batch.Write(keyTx, *ptr);

            // Update DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE
            batch.Write(DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE, hashWithdrawalBundle);

            LogPrintf("%s: Writing new WithdrawalBundle and updating DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE to: %s",
                    __func__, hashWithdrawalBundle.ToString());
        }
        else
        if (obj->sidechainop == DB_SIDECHAIN_DEPOSIT_OP) {
            const SidechainDeposit *ptr = (const SidechainDeposit *) obj;
            batch.Write(key, *ptr);

            // Also index the deposit by the non amount hash
            uint256 hashNonAmount = ptr->GetID();
            batch.Write(make_pair(DB_SIDECHAIN_DEPOSIT_OP, hashNonAmount), *ptr);

            // Update DB_LAST_SIDECHAIN_DEPOSIT
            batch.Write(DB_LAST_SIDECHAIN_DEPOSIT, hashNonAmount);
        }
    }

    return WriteBatch(batch, true);
}

bool CSidechainTreeDB::WriteWithdrawalUpdate(const vector<SidechainWithdrawal>& vWithdrawal)
{
    CDBBatch batch(*this);

    for (const SidechainWithdrawal& wt : vWithdrawal)
    {
        pair<char, uint256> key = make_pair(wt.sidechainop, wt.GetID());
        batch.Write(key, wt);
    }

    return WriteBatch(batch, true);
}

bool CSidechainTreeDB::WriteWithdrawalBundleUpdate(const SidechainWithdrawalBundle& withdrawalBundle)
{
    CDBBatch batch(*this);

    pair<char, uint256> key = make_pair(withdrawalBundle.sidechainop, withdrawalBundle.GetID());
    batch.Write(key, withdrawalBundle);

    // Also index the WithdrawalBundle by the WithdrawalBundle transaction hash
    uint256 hashWithdrawalBundle = withdrawalBundle.tx.GetHash();
    pair<char, uint256> keyTx = make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, hashWithdrawalBundle);
    batch.Write(keyTx, withdrawalBundle);

    // Also write withdrawal status updates if WithdrawalBundle status changes
    vector<SidechainWithdrawal> vUpdate;
    for (const uint256& id: withdrawalBundle.vWithdrawalID) {
        SidechainWithdrawal withdrawal;
        if (!GetWithdrawal(id, withdrawal)) {
            LogPrintf("%s: Failed to read withdrawal of WithdrawalBundle from LDB!\n", __func__);
            return false;
        }
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_FAILED) {
            withdrawal.status = WITHDRAWAL_UNSPENT;
            vUpdate.push_back(withdrawal);
        }
        else
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_SPENT) {
            withdrawal.status = WITHDRAWAL_SPENT;
            vUpdate.push_back(withdrawal);
        }
        else
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_CREATED) {
            withdrawal.status = WITHDRAWAL_IN_BUNDLE;
            vUpdate.push_back(withdrawal);
        }
    }

    if (!WriteWithdrawalUpdate(vUpdate)) {
        LogPrintf("%s: Failed to write withdrawal update!\n", __func__);
        return false;
    }

    return WriteBatch(batch, true);
}

bool CSidechainTreeDB::WriteLastWithdrawalBundleHash(const uint256& hash)
{
    return Write(DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE, hash);
}

bool CSidechainTreeDB::GetWithdrawal(const uint256& objid, SidechainWithdrawal& withdrawal)
{
    if (ReadSidechain(make_pair(DB_SIDECHAIN_WITHDRAWAL_OP, objid), withdrawal))
        return true;

    return false;
}

bool CSidechainTreeDB::GetWithdrawalBundle(const uint256& objid, SidechainWithdrawalBundle& withdrawalBundle)
{
    if (ReadSidechain(make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, objid), withdrawalBundle))
        return true;

    return false;
}

bool CSidechainTreeDB::GetDeposit(const uint256& objid, SidechainDeposit& deposit)
{
    if (ReadSidechain(make_pair(DB_SIDECHAIN_DEPOSIT_OP, objid), deposit))
        return true;

    return false;
}

vector<SidechainWithdrawal> CSidechainTreeDB::GetWithdrawals(const uint8_t& nSidechain)
{
    const char sidechainop = DB_SIDECHAIN_WITHDRAWAL_OP;
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(sidechainop, nSidechain), uint256()));

    vector<SidechainWithdrawal> vWT;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        SidechainWithdrawal wt;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetSidechainValue(wt))
                vWT.push_back(wt);
        }

        pcursor->Next();
    }

    return vWT;
}

vector<SidechainWithdrawalBundle> CSidechainTreeDB::GetWithdrawalBundles(const uint8_t& nSidechain)
{
    const char sidechainop = DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP;
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(sidechainop, nSidechain), uint256()));

    vector<SidechainWithdrawalBundle> vWithdrawalBundle;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        SidechainWithdrawalBundle withdrawalBundle;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetSidechainValue(withdrawalBundle)) {
                // Only return the WithdrawalBundle(s) indexed by ID
                if (key.second == withdrawalBundle.GetID())
                    vWithdrawalBundle.push_back(withdrawalBundle);
            }
        }

        pcursor->Next();
    }
    return vWithdrawalBundle;
}

vector<SidechainDeposit> CSidechainTreeDB::GetDeposits(const uint8_t& nSidechain)
{
    const char sidechainop = DB_SIDECHAIN_DEPOSIT_OP;
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(sidechainop, nSidechain), uint256()));

    vector<SidechainDeposit> vDeposit;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        SidechainDeposit deposit;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetSidechainValue(deposit))
                // Only return the deposits(s) indexed by ID
                if (key.second == deposit.GetID())
                    vDeposit.push_back(deposit);
        }

        pcursor->Next();
    }
    return vDeposit;
}

bool CSidechainTreeDB::HaveDeposits()
{
    const char sidechainop = DB_SIDECHAIN_DEPOSIT_OP;
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(sidechainop, DB_SIDECHAIN_DEPOSIT_OP), uint256()));

    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    if (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        pair<char, uint256> key;
        SidechainDeposit d;
        if (pcursor->GetKey(key) && key.first == sidechainop) {
            if (pcursor->GetSidechainValue(d))
                return true;
        }
    }
    return false;
}

bool CSidechainTreeDB::HaveDepositNonAmount(const uint256& hashNonAmount)
{
    SidechainDeposit deposit;
    if (ReadSidechain(make_pair(DB_SIDECHAIN_DEPOSIT_OP, hashNonAmount),
                deposit))
        return true;

    return false;
}

bool CSidechainTreeDB::GetLastDeposit(SidechainDeposit& deposit)
{
    // Look up the last deposit non amount hash
    uint256 objid;
    if (!Read(DB_LAST_SIDECHAIN_DEPOSIT, objid))
        return false;

    // Read the last deposit
    if (ReadSidechain(make_pair(DB_SIDECHAIN_DEPOSIT_OP, objid), deposit))
        return true;

    return false;
}

bool CSidechainTreeDB::GetLastWithdrawalBundleHash(uint256& hash)
{
    // Look up the last deposit non amount hash
    if (!Read(DB_LAST_SIDECHAIN_WITHDRAWAL_BUNDLE, hash))
        return false;

    return true;
}

bool CSidechainTreeDB::HaveWithdrawalBundle(const uint256& hashWithdrawalBundle) const
{
    SidechainWithdrawalBundle withdrawalBundle;
    if (ReadSidechain(make_pair(DB_SIDECHAIN_WITHDRAWAL_BUNDLE_OP, hashWithdrawalBundle), withdrawalBundle))
        return true;

    return false;
}

namespace {

//! Legacy class to deserialize pre-pertxout database entries without reindex.
class CCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    vector<CTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! empty constructor
    CCoins() : fCoinBase(false), vout(0), nHeight(0) { }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        // version
        int nVersionDummy;
        ::Unserialize(s, VARINT(nVersionDummy));
        // header code
        ::Unserialize(s, VARINT(nCode));
        fCoinBase = nCode & 1;
        vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 2) != 0;
        vAvail[1] = (nCode & 4) != 0;
        unsigned int nMaskCode = (nCode / 8) + ((nCode & 6) != 0 ? 0 : 1);
        // spentness bitmask
        while (nMaskCode > 0) {
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail);
            for (unsigned int p = 0; p < 8; p++) {
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }
            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CTxOut());
        for (unsigned int i = 0; i < vAvail.size(); i++) {
            if (vAvail[i])
                ::Unserialize(s, REF(CTxOutCompressor(vout[i])));
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
    }
};

}

/** Upgrade the database from older formats.
 *
 * Currently implemented: from the per-tx utxo model (0.8..0.14.x) to per-txout.
 */
bool CCoinsViewDB::Upgrade() {
    unique_ptr<CDBIterator> pcursor(db.NewIterator());
    pcursor->Seek(make_pair(DB_COINS, uint256()));
    if (!pcursor->Valid()) {
        return true;
    }

    int64_t count = 0;
    LogPrintf("Upgrading utxo-set database...\n");
    LogPrintf("[0%%]...");
    uiInterface.ShowProgress(_("Upgrading UTXO database"), 0, true);
    size_t batch_size = 1 << 24;
    CDBBatch batch(db);
    int reportDone = 0;
    pair<unsigned char, uint256> key;
    pair<unsigned char, uint256> prev_key = {DB_COINS, uint256()};
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        if (ShutdownRequested()) {
            break;
        }
        if (pcursor->GetKey(key) && key.first == DB_COINS) {
            if (count++ % 256 == 0) {
                uint32_t high = 0x100 * *key.second.begin() + *(key.second.begin() + 1);
                int percentageDone = (int)(high * 100.0 / 65536.0 + 0.5);
                uiInterface.ShowProgress(_("Upgrading UTXO database"), percentageDone, true);
                if (reportDone < percentageDone/10) {
                    // report max. every 10% step
                    LogPrintf("[%d%%]...", percentageDone);
                    reportDone = percentageDone/10;
                }
            }
            CCoins old_coins;
            if (!pcursor->GetValue(old_coins)) {
                return error("%s: cannot parse CCoins record", __func__);
            }
            COutPoint outpoint(key.second, 0);
            for (size_t i = 0; i < old_coins.vout.size(); ++i) {
                if (!old_coins.vout[i].IsNull() && !old_coins.vout[i].scriptPubKey.IsUnspendable()) {
                    Coin newcoin(move(old_coins.vout[i]), old_coins.nHeight, old_coins.fCoinBase);
                    outpoint.n = i;
                    CoinEntry entry(&outpoint);
                    batch.Write(entry, newcoin);
                }
            }
            batch.Erase(key);
            if (batch.SizeEstimate() > batch_size) {
                db.WriteBatch(batch);
                batch.Clear();
                db.CompactRange(prev_key, key);
                prev_key = key;
            }
            pcursor->Next();
        } else {
            break;
        }
    }
    db.WriteBatch(batch);
    db.CompactRange({DB_COINS, uint256()}, key);
    uiInterface.ShowProgress("", 100, false);
    LogPrintf("[%s].\n", ShutdownRequested() ? "CANCELLED" : "DONE");
    return !ShutdownRequested();
}

/* Hivemind market database */

CMarketTreeDB::CMarketTreeDB(size_t nCacheSize, bool fMemory, bool fWipe)
  : CDBWrapper(GetDataDir() / "blocks" / "market", nCacheSize, fMemory, fWipe) {
}

bool CMarketTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(make_pair('f', nFile), info);
}

bool CMarketTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write('R', '1');
    else
        return Erase('R');
}

bool CMarketTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists('R');
    return true;
}

bool CMarketTreeDB::ReadLastBlockFile(int &nFile) {
    return Read('l', nFile);
}

bool CMarketTreeDB::WriteBatchSync(const vector<pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (vector<pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(make_pair('f', it->first), *it->second);
    }
    batch.Write('l', nLastFile);
    return WriteBatch(batch, true);
}

bool CMarketTreeDB::WriteMarketIndex(const vector<pair<uint256, const marketObj *> >&vect)
{
    CDBBatch batch(*this);

    vector<pair<uint256,const marketObj *> >::const_iterator it;
    for (it=vect.begin(); it != vect.end(); it++) {
        const uint256 &objid = it->first;
        const marketObj *obj = it->second;
        pair<char,uint256> key = make_pair(obj->marketop, objid);

        if (obj->marketop == 'B') {
           const marketBranch *ptr = (const marketBranch *) obj;
           pair<marketBranch,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
        }
        else
        if (obj->marketop == 'D') {
           const marketDecision *ptr = (const marketDecision *) obj;
           pair<marketDecision,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           batch.Write(make_pair(make_pair('d',ptr->branchid),objid), value);
        }
        else
        if (obj->marketop == 'L') {
           const marketStealVote *ptr = (const marketStealVote *) obj;
           pair<marketStealVote,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           batch.Write(make_pair(make_pair(make_pair('l',ptr->branchid),ptr->height),objid), value);
        }
        else
        if (obj->marketop == 'M') {
           const marketMarket *ptr = (const marketMarket *) obj;
           pair<marketMarket,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           for(size_t i=0; i < ptr->decisionIDs.size(); i++)
               batch.Write(make_pair(make_pair('m',ptr->decisionIDs[i]),objid), value);
        }
        else
        if (obj->marketop == 'O') {
           const marketOutcome *ptr = (const marketOutcome *) obj;
           pair<marketOutcome,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           batch.Write(make_pair(make_pair('o',ptr->branchid),objid), value);
        }
        else
        if (obj->marketop == 'R') {
           const marketRevealVote *ptr = (const marketRevealVote *) obj;
           pair<marketRevealVote,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           batch.Write(make_pair(make_pair(make_pair('r',ptr->branchid),ptr->height),objid), value);
        }
        else
        if (obj->marketop == 'S') {
           const marketSealedVote *ptr = (const marketSealedVote *) obj;
           pair<marketSealedVote,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           batch.Write(make_pair(make_pair(make_pair('s',ptr->branchid),ptr->height),objid), value);
        }
        else
        if (obj->marketop == 'T') {
           const marketTrade *ptr = (const marketTrade *) obj;
           pair<marketTrade,uint256> value = make_pair(*ptr, obj->txid);
           batch.Write(key, value);
           batch.Write(make_pair(make_pair('t',ptr->marketid),objid), value);
        }
    }
    return WriteBatch(batch);
}

bool CMarketTreeDB::WriteFlag(const string &name, bool fValue) {
    return Write(make_pair('F', name), fValue ? '1' : '0');
}

bool CMarketTreeDB::ReadFlag(const string &name, bool &fValue) {
    char ch;
    if (!Read(make_pair('F', name), ch))
       return false;
    fValue = ch == '1';
    return true;
}

bool CMarketTreeDB::GetBranch(const uint256 &objid, marketBranch& branch)
{
    if (ReadSidechain(make_pair('B', objid), branch))
        return true;

    return false;
}

bool CMarketTreeDB::GetDecision(const uint256 &objid, marketDecision& decision)
{
    if (ReadSidechain(make_pair('D', objid), decision))
        return true;

    return false;
}

bool CMarketTreeDB::GetMarket(const uint256 &objid, marketMarket& market)
{
    if (ReadSidechain(make_pair('M', objid), market))
        return true;

    return false;
}

bool CMarketTreeDB::GetOutcome(const uint256 &objid, marketOutcome& outcome)
{
    if (ReadSidechain(make_pair('O', objid), outcome))
        return true;

    return false;
}

bool CMarketTreeDB::GetRevealVote(const uint256 &objid, marketRevealVote& vote)
{
    if (ReadSidechain(make_pair('R', objid), vote))
        return true;

    return false;
}

bool CMarketTreeDB::GetSealedVote(const uint256 &objid, marketSealedVote& vote)
{
    if (ReadSidechain(make_pair('S', objid), vote))
        return true;

    return false;
}

bool CMarketTreeDB::GetStealVote(const uint256 &objid, marketStealVote& vote)
{
    if (ReadSidechain(make_pair('L', objid), vote))
        return true;

    return false;
}

bool CMarketTreeDB::GetTrade(const uint256 &objid, marketTrade& trade)
{
    if (ReadSidechain(make_pair('T', objid), trade))
        return true;

    return false;
}

vector<marketBranch>
CMarketTreeDB::GetBranches(void)
{
    const char op = 'B';
    ostringstream ss;
    ::Serialize(ss, make_pair(op, uint256()));

    vector<marketBranch> vBranch;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        marketBranch branch;
        if (pcursor->GetKey(key) && key.first == op) {
            if (pcursor->GetSidechainValue(branch))
                vBranch.push_back(branch);
        }

        pcursor->Next();
    }
    return vBranch;
}

vector<marketDecision>
CMarketTreeDB::GetDecisions(const uint256& id /* branch id */)
{
    const char op = 'd';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketDecision> vDecision;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        marketDecision decision;
        if (pcursor->GetKey(key) && key.first == op && key.second == id) {
            if (pcursor->GetSidechainValue(decision))
                vDecision.push_back(decision);
        }

        pcursor->Next();
    }
    return vDecision;
}

vector<marketMarket>
CMarketTreeDB::GetMarkets(const uint256& id /* branch id */)
{
    const char op = 'm';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketMarket> vMarket;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        marketMarket market;
        if (pcursor->GetKey(key) && key.first == op && key.second == id) {
            if (pcursor->GetSidechainValue(market))
                vMarket.push_back(market);
        }

        pcursor->Next();
    }
    return vMarket;
}

vector<marketOutcome>
CMarketTreeDB::GetOutcomes(const uint256& id /* branchid */)
{
    const char op = 'o';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketOutcome> vOutcome;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        marketOutcome outcome;
        if (pcursor->GetKey(key) && key.first == op && key.second == id) {
            if (pcursor->GetSidechainValue(outcome))
                vOutcome.push_back(outcome);
        }

        pcursor->Next();
    }
    return vOutcome;
}

vector<marketRevealVote>
CMarketTreeDB::GetRevealVotes(const uint256 & /* branchid */ id, uint32_t height)
{
    const char op = 'r';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketRevealVote> vVote;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<pair<char, uint256>, uint32_t> key;
        marketRevealVote vote;
        if (pcursor->GetKey(key) && key.first.first == op &&
                key.first.second == id && key.second == height) {
            vVote.push_back(vote);
        }

        pcursor->Next();
    }

    return vVote;
}

vector<marketSealedVote>
CMarketTreeDB::GetSealedVotes(const uint256 & /* branchid */ id, uint32_t height)
{
    const char op = 's';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketSealedVote> vVote;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<pair<char, uint256>, uint32_t> key;
        marketSealedVote vote;
        if (pcursor->GetKey(key) && key.first.first == op
                && key.first.second == id && key.second == height) {
            vVote.push_back(vote);
        }

        pcursor->Next();
    }

    return vVote;
}

vector<marketStealVote>
CMarketTreeDB::GetStealVotes(const uint256 & /* branchid */ id, uint32_t height)
{
    const char op = 'l';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketStealVote> vVote;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<pair<char, uint256>, uint32_t> key;
        marketStealVote vote;
        if (pcursor->GetKey(key) && key.first.first == op
                && key.first.second == id && key.second == height) {
            vVote.push_back(vote);
        }

        pcursor->Next();
    }

    return vVote;
}

vector<marketTrade>
CMarketTreeDB::GetTrades(const uint256 & /* marketid */ id)
{
    const char op = 't';
    ostringstream ss;
    ::Serialize(ss, make_pair(make_pair(op, id), uint256()));

    vector<marketTrade> vTrade;

    unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(ss.str());
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();

        pair<char, uint256> key;
        marketTrade trade;
        if (pcursor->GetKey(key) && key.first == op && key.second == id) {
            if (pcursor->GetSidechainValue(trade))
                vTrade.push_back(trade);
        }

        pcursor->Next();
    }
    return vTrade;
}
