#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <iostream>
#include <string>
#include "CipherManager.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    CipherManager cipher;

private slots:
    void handle_cipher();
    void handle_decipher();
    void open_file_unciphered();
    void open_file_ciphered();
    void handle_file_cipher();
    void handle_file_decipher();
    void handle_F_cal();
    void handle_E_cal();
    void handle_IP_cal();
    void handle_XOR_cal();
};

#endif // MAINWINDOW_H
