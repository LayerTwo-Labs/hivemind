// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/marketspage.h>
#include <qt/forms/ui_marketspage.h>

MarketsPage::MarketsPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MarketsPage)
{
    ui->setupUi(this);
}

MarketsPage::~MarketsPage()
{
    delete ui;
}
