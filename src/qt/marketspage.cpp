// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/marketspage.h>
#include <qt/forms/ui_marketspage.h>

#include <qt/markettablemodel.h>

#include <QScrollBar>

MarketsPage::MarketsPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MarketsPage)
{
    ui->setupUi(this);

    ui->tableView->horizontalHeader()->setStretchLastSection(true);

#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
    ui->tableView->verticalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->tableView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    // Hide vertical header
    ui->tableView->verticalHeader()->setVisible(false);
    // Hide Horizontal header
    ui->tableView->horizontalHeader()->setVisible(false);
    // Left align the horizontal header text
    ui->tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    // Set horizontal scroll speed to per 3 pixels
    ui->tableView->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    // Select entire row
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    // Select only one row
    ui->tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    // Disable word wrap
    ui->tableView->setWordWrap(false);

    marketModel = new MarketTableModel(this);
    ui->tableView->setModel(marketModel);
}

MarketsPage::~MarketsPage()
{
    delete ui;
}

void MarketsPage::setClientModel(ClientModel *model)
{
    marketModel->setClientModel(model);
}
