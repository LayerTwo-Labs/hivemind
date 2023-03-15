// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/markettablemodel.h>

#include <qt/clientmodel.h>

#include <sidechain.h>
#include <txdb.h>
#include <validation.h>

#include <sstream>

Q_DECLARE_METATYPE(MarketTableObject)

MarketTableModel::MarketTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
}

int MarketTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int MarketTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 2;
}

QVariant MarketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return false;

    int row = index.row();
    int col = index.column();

    // Double check that the data pointed at by the index still exists, it is
    // possible for a Withdrawalto be removed from the model when a block is connected.
    if (row >= model.size())
        return QVariant();

    if (!model.at(row).canConvert<MarketTableObject>())
        return QVariant();

    MarketTableObject object = model.at(row).value<MarketTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Market details
        if (col == 1) {
            return object.details;
        }
        break;
    }
    case Qt::DecorationRole:
    {
        // Graph
        //if (col == 0) {
        //    MarketGraphWidget graphWidget;
        //    return graphWidget.getTableGraphPixmap(QString::fromStdString(market->title), market);
        //}
    }
    case Qt::SizeHintRole:
    {
        // Graph
        if (col == 0) {
            return QSize(480, 360);
        }
    }
    case Qt::TextAlignmentRole:
    {
        // Graph
        if (col == 0) {
            return int(Qt::AlignHCenter | Qt::AlignVCenter);
        }
        // Market details
        if (col == 1) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }
    case MarketIDRole:
        return QString::fromStdString(object.id.ToString());
    }
    return QVariant();
}

QVariant MarketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Chart");
            case 1:
                return QString("Market Info");
            }
        }
    }
    return QVariant();
}

void MarketTableModel::UpdateModel()
{
    beginResetModel();
    model.clear();
    endResetModel();

    // TODO
    uint256 branchid = uint256S("0f894a25c5e0318ee148fe54600ebbf50782f0a1df1eb2aab06321a8ccec270d");

    // Collect decisions for branch
    std::vector<marketDecision> vDecision;
    vDecision = pmarkettree->GetDecisions(branchid);

    if (vDecision.empty())
        return;

    // Collect all markets for all decisions
    std::vector<marketMarket> vMarket;
    for (const marketDecision& d : vDecision) {
        std::vector<marketMarket> vDecisionMarket;
        vDecisionMarket = pmarkettree->GetMarkets(d.GetHash());
        for (const marketMarket& m : vDecisionMarket)
            vMarket.push_back(m);
    }
    vDecision = pmarkettree->GetDecisions(branchid);


    std::vector<MarketTableObject> vTableObject;
    for (const marketMarket& m : vMarket) {

        std::stringstream sstream;
        sstream << "Title: " << m.title << std::endl;
        sstream << "Description: " << m.description << std::endl;
        sstream << "Tags: " << m.tags << std::endl;
        sstream << "Market ID: " << m.GetHash().GetHex() << std::endl;

        MarketTableObject object;
        object.id = m.GetHash();
        object.details = QString::fromStdString(sstream.str());

        vTableObject.push_back(object);
    }

    beginInsertRows(QModelIndex(), model.size(), model.size() + vTableObject.size() - 1);
    for (const MarketTableObject& o : vTableObject)
        model.append(QVariant::fromValue(o));
    endInsertRows();
}


void MarketTableModel::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model)
    {
        connect(model, SIGNAL(numBlocksChanged(int, QDateTime, double, bool)),
                this, SLOT(UpdateModel()));

        UpdateModel();
    }
}

