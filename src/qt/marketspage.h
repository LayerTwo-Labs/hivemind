// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MARKETSPAGE_H
#define MARKETSPAGE_H

#include <QWidget>

namespace Ui {
class MarketsPage;
}

class ClientModel;
class MarketTableModel;

class MarketsPage : public QWidget
{
    Q_OBJECT

public:
    explicit MarketsPage(QWidget *parent = nullptr);
    ~MarketsPage();

    void setClientModel(ClientModel *model);

private:
    Ui::MarketsPage *ui;

    MarketTableModel* marketModel = nullptr;

private Q_SLOTS:
};

#endif // MARKETSPAGE_H
