// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MARKET_TABLEMODEL_H
#define MARKET_TABLEMODEL_H

#include <amount.h>
#include <uint256.h>

#include <QAbstractTableModel>
#include <QList>
#include <QString>

class ClientModel;

struct MarketTableObject
{
    QString details;
    uint256 id;
};

class MarketTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit MarketTableModel(QObject *parent = 0);

    enum RoleIndex {
        /** Market ID */
        MarketIDRole = Qt::UserRole,
    };

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    void setClientModel(ClientModel *model);

public Q_SLOTS:
    void UpdateModel();

private:
    QList<QVariant> model;

    ClientModel *clientModel;
};

#endif // MARKET_TABLEMODEL_H
