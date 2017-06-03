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

    void handle_cipher_aes();
    void handle_decipher_aes();
    void open_file_ciphered_aes();
    void open_file_unciphered_aes();
    void handle_file_cipher_aes();
    void handle_file_decipher_aes();
    void handle_SubB_cal();
    void handle_MixCol_cal();
    void handle_Shift_cal();
    void handle_Addrkey_cal();

};

#endif // MAINWINDOW_H
