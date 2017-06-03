#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QFileDialog"
#include "QString"
#include "Qtconcurrent/QtConcurrentRun"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->cipher_btn, SIGNAL(released()), this, SLOT(handle_cipher()));
    connect(ui->decipher_btn, SIGNAL(released()), this, SLOT(handle_decipher()));
    connect(ui->file_select_btn, SIGNAL(released()), this, SLOT(open_file_unciphered()));
    connect(ui->file_select_btn_2, SIGNAL(released()), this, SLOT(open_file_ciphered()));
    connect(ui->cipher_btn_2, SIGNAL(released()),this, SLOT(handle_file_cipher()));
    connect(ui->decipher_btn_2, SIGNAL(released()),this, SLOT(handle_file_decipher()));
    connect(ui->IP_Btn, SIGNAL(released()), this, SLOT(handle_IP_cal()));
    connect(ui->F_Btn, SIGNAL(released()), this, SLOT(handle_F_cal()));
    connect(ui->E_Btn, SIGNAL(released()), this, SLOT(handle_E_cal()));
    connect(ui->XOR_Btn, SIGNAL(released()), this, SLOT(handle_XOR_cal()));

    connect(ui->cipher_btn_aes, SIGNAL(released()), this, SLOT(handle_cipher_aes()));
    connect(ui->decipher_btn_aes,SIGNAL(released()), this, SLOT(handle_decipher_aes()));
    connect(ui->uncipher_file_select_btn_aes, SIGNAL(released()), this, SLOT(open_file_unciphered_aes()));
    connect(ui->ciphered_file_select_btn_aes, SIGNAL(released()), this, SLOT(open_file_ciphered_aes()));
    connect(ui->cipher_file_btn_aes, SIGNAL(released()), this, SLOT(handle_file_cipher_aes()));
    connect(ui->decipher_file_btn_aes, SIGNAL(released()), this, SLOT(handle_file_decipher_aes()));
    connect(ui->sb_btn,SIGNAL(released()),this, SLOT(handle_SubB_cal()));
    connect(ui->sr_btn,SIGNAL(released()),this, SLOT(handle_Shift_cal()));
    connect(ui->mc_btn,SIGNAL(released()),this, SLOT(handle_MixCol_cal()));
    connect(ui->ark_btn,SIGNAL(released()),this, SLOT(handle_Addrkey_cal()));
}

void MainWindow::handle_cipher() {
    ui->tip_label->setText("");
    std::string digitals(ui->uncipher_text->text().toUtf8().constData());
    if (digitals.size() != 16) {
        QString s = QStringLiteral("明文必须是16个的16进制字符");
        ui->tip_label->setText(s);
        ui->ciphered_text->setText("");
        return;
    }
    if (!cipher.is_legal(digitals)) {
        QString s = QStringLiteral("请在明文框中输入正确的16进制字符");
        ui->tip_label->setText(s);
        ui->ciphered_text->setText("");
        return;
    }

    std::string key(ui->key->text().toUtf8().constData());
    if (!cipher.is_legal(key)) {
        QString s = QStringLiteral("请在密钥框输入正确的16进制字符");
        ui->tip_label->setText(s);
        ui->ciphered_text->setText("");
        return;
    }
    if (key.size() != 16) {
        QString s = QStringLiteral("密钥不足64bit，将自动用0填充空位");
        ui->tip_label->setText(s);
    }
    std::string ciphered_data(cipher.cipherDigitalByDES(digitals, key));
    std::string K_info = cipher.getKInfo();
    std::string Mid_info = cipher.getMidInfo();

    ui->ciphered_text->setText(QString::fromStdString(ciphered_data));
    ui->K_info->setText(QString::fromStdString(K_info));
    ui->Mid_info->setText(QString::fromStdString(Mid_info));
}

void MainWindow::handle_decipher() {
    ui->tip_label->setText("");
    std::string digitals(ui->ciphered_text->text().toUtf8().constData());
    if (digitals.size() != 16) {
        QString s = QStringLiteral("密文必须是16个的16进制字符");
        ui->tip_label->setText(s);
        ui->uncipher_text->setText("");
        return;
    }
    if (!cipher.is_legal(digitals)) {
        QString s = QStringLiteral("请在密文框中输入正确的16进制字符");
        ui->tip_label->setText(s);
        ui->uncipher_text->setText("");
        return;
    }

    std::string key(ui->key->text().toUtf8().constData());
    if (!cipher.is_legal(key)) {
        QString s = QStringLiteral("请在密钥框输入正确的16进制字符");
        ui->tip_label->setText(s);
        ui->uncipher_text->setText("");
        return;
    }
    if (key.size() != 16) {
        QString s = QStringLiteral("密钥不足64bit，将自动用0填充空位");
        ui->tip_label->setText(s);
    }
    std::string ciphered_data(cipher.decipherDigitalByDES(digitals, key));
    std::string K_info = cipher.getKInfo();
    std::string Mid_info = cipher.getMidInfo();

    ui->uncipher_text->setText(QString::fromStdString(ciphered_data));
    ui->K_info->setText(QString::fromStdString(K_info));
    ui->Mid_info->setText(QString::fromStdString(Mid_info));
}

void MainWindow::open_file_unciphered() {
    QString path = QFileDialog::getOpenFileName(this, "Open", ".", "*.*");
    ui->uncipher_text_2->setText(path);
    ui->ciphered_text_2->setText(path + ".des");
}

void MainWindow::open_file_ciphered() {
    QString path = QFileDialog::getOpenFileName(this, "Open", ".", "*.des");
    ui->ciphered_text_2->setText(path);
    QString substr = path.left(path.length()-4);
    ui->uncipher_text_2->setText(substr);
}

void MainWindow::handle_file_cipher() {
    ui->tip_label_2->setText("正在加密……");
    QString path_in = ui->uncipher_text_2->text();
    QString path_out = ui->ciphered_text_2->text();
    QString key = ui->key_2->text();

    //QtConcurrent::run(cipher.cipherFileByDES, path_in.toStdString(), path_out.toStdString(), key.toStdString());
    //int errno = QFuture::result();
    int errno = cipher.cipherFileByDES(path_in.toStdString(), path_out.toStdString(), key.toStdString());
    if (errno == 1) {
        QString s = QStringLiteral("请输入正确的待加密文件路径");
        ui->tip_label_2->setText(s);
        return;
    }
    else if (errno == 2) {
        QString s = QStringLiteral("请输入正确的输出路径");
        return;
    }
    if (key.size() != 16) {
        QString s = QStringLiteral("加密成功！密钥不足64bit，将自动用0填充空位");
        ui->tip_label_2->setText(s);
        return;
    }
    QString s = QStringLiteral("加密成功");
    ui->tip_label_2->setText(s);
}

void MainWindow::handle_file_decipher() {
    ui->tip_label_2->setText("正在解密……");
    QString path_out = ui->uncipher_text_2->text();
    QString path_in = ui->ciphered_text_2->text();
    QString key = ui->key_2->text();

    int errno = cipher.decipherFileByDES(path_in.toStdString(), path_out.toStdString(), key.toStdString());
    if (errno == 1) {
        QString s = QStringLiteral("请输入正确的待解密文件路径");
        ui->tip_label_2->setText(s);
        return;
    }
    else if (errno == 2) {
        QString s = QStringLiteral("请输入正确的输出路径");
        ui->tip_label_2->setText(s);
        return;
    }
    else if (errno == 3) {
        QString s = QStringLiteral("文件损坏");
        ui->tip_label_2->setText(s);
        return;
    }
    if (key.size() != 16) {
        QString s = QStringLiteral("解密成功！密钥不足64bit，将自动用0填充空位");
        ui->tip_label_2->setText(s);
        return;
    }
    QString s = QStringLiteral("解密成功");
    ui->tip_label_2->setText(s);
}

void MainWindow::handle_IP_cal() {
    ui->IP_Output->setText("");
    std::string ip(ui->IP_Input->text().toUtf8().constData());
    if (ip.size() != 16) {
        QString s = QStringLiteral("请输入16个16进制字符");
        ui->IP_Output->setText(s);
        return;
    }
    if (!cipher.is_legal(ip)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->IP_Output->setText(s);
        return;
    }
    ui->IP_Output->setText(QString::fromStdString(cipher.calIPByDES(ip)));
}

void MainWindow::handle_F_cal() {
    ui->F_Output->setText("");
    std::string r(ui->F_R_Input->text().toUtf8().constData());
    std::string k(ui->F_K_Input->text().toUtf8().constData());
    if (r.size() != 8 || k.size() != 12) {
        QString s = QStringLiteral("请输入正确长度的R和K");
        ui->F_Output->setText(s);
        return;
    }
    if (!cipher.is_legal(r) || !cipher.is_legal(k)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->F_Output->setText(s);
        return;
    }
    ui->F_Output->setText(QString::fromStdString(cipher.calFByDES(r, k)));
}

void MainWindow::handle_E_cal() {
    ui->E_Output->setText("");
    std::string r(ui->E_Input->text().toUtf8().constData());
    if (r.size() != 8) {
        QString s = QStringLiteral("请输入正确长度的R");
        ui->E_Output->setText(s);
        return;
    }
    if (!cipher.is_legal(r)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->E_Output->setText(s);
        return;
    }
    ui->E_Output->setText(QString::fromStdString(cipher.calEByDES(r)));
}

void MainWindow::handle_XOR_cal() {
    ui->XOR_Output->setText("");
    std::string l(ui->XOR_L->text().toUtf8().constData());
    std::string r(ui->XOR_R->text().toUtf8().constData());
    if (l.size() != r.size()) {
        QString s = QStringLiteral("请输入相同长度的数");
        ui->XOR_Output->setText(s);
        return;
    }
    if (!cipher.is_legal(l) || !cipher.is_legal(r)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->XOR_Output->setText(s);
        return;
    }
    ui->XOR_Output->setText(QString::fromStdString(cipher.calXor(l,r)));
}

void MainWindow::handle_cipher_aes() {
    ui->tip_label_aes->setText("");
    std::string digitals(ui->uncipher_text_aes->text().toUtf8().constData());
    if (digitals.size() != 32) {
        QString s = QStringLiteral("明文必须是32个的16进制字符");
        ui->tip_label_aes->setText(s);
        ui->ciphered_text_aes->setText("");
        return;
    }
    if (!cipher.is_legal(digitals)) {
        QString s = QStringLiteral("请在明文框中输入正确的16进制字符");
        ui->tip_label_aes->setText(s);
        ui->ciphered_text_aes->setText("");
        return;
    }

    std::string key(ui->key_aes->text().toUtf8().constData());
    if (!cipher.is_legal(key)) {
        QString s = QStringLiteral("请在密钥框输入正确的16进制字符");
        ui->tip_label_aes->setText(s);
        ui->ciphered_text_aes->setText("");
        return;
    }
    if (key.size() != 32) {
        QString s = QStringLiteral("密钥不足128bit，请输入正确长度的密钥");
        ui->tip_label_aes->setText(s);
        ui->ciphered_text_aes->setText("");
        return;
    }
    std::string ciphered_data(cipher.cipherDigitalByAES(digitals, key));
    std::string K_info(cipher.getKInfoAES());
    std::string Mid_info(cipher.getMidInfoAES());

    ui->ciphered_text_aes->setText(QString::fromStdString(ciphered_data));
    ui->K_info_aes->setText(QString::fromStdString(K_info));
    ui->Mid_info_aes->setText(QString::fromStdString(Mid_info));
}

void MainWindow::handle_decipher_aes() {
    ui->tip_label_aes->setText("");
    std::string digitals(ui->ciphered_text_aes->text().toUtf8().constData());
    if (digitals.size() != 32) {
        QString s = QStringLiteral("密文必须是32个的16进制字符");
        ui->tip_label_aes->setText(s);
        ui->uncipher_text_aes->setText("");
        return;
    }
    if (!cipher.is_legal(digitals)) {
        QString s = QStringLiteral("请在密文框中输入正确的16进制字符");
        ui->tip_label_aes->setText(s);
        ui->uncipher_text_aes->setText("");
        return;
    }

    std::string key(ui->key_aes->text().toUtf8().constData());
    if (!cipher.is_legal(key)) {
        QString s = QStringLiteral("请在密钥框输入正确的16进制字符");
        ui->tip_label_aes->setText(s);
        ui->uncipher_text_aes->setText("");
        return;
    }
    if (key.size() != 32) {
        QString s = QStringLiteral("密钥不足128bit，请输入正确长度的密钥");
        ui->tip_label_aes->setText(s);
        ui->uncipher_text_aes->setText("");
        return;
    }
    std::string uncipher_data(cipher.decipherDigitalByAES(digitals, key));
    std::string K_info(cipher.getKInfoAES());
    std::string Mid_info(cipher.getMidInfoAES());

    ui->uncipher_text_aes->setText(QString::fromStdString(uncipher_data));
    ui->K_info_aes->setText(QString::fromStdString(K_info));
    ui->Mid_info_aes->setText(QString::fromStdString(Mid_info));
}

void MainWindow::open_file_ciphered_aes() {
    QString path = QFileDialog::getOpenFileName(this, "Open", ".", "*.aes");
    ui->ciphered_file_path->setText(path);
    QString substr = path.left(path.length()-4);
    ui->uncipher_file_path->setText(substr);
}

void MainWindow::open_file_unciphered_aes() {
    QString path = QFileDialog::getOpenFileName(this, "Open", ".", "*.*");
    ui->uncipher_file_path->setText(path);
    ui->ciphered_file_path->setText(path + ".aes");
}

void MainWindow::handle_file_cipher_aes() {
    ui->tip_file_label_aes->setText("正在加密……");
    QString path_in = ui->uncipher_file_path->text();
    QString path_out = ui->ciphered_file_path->text();
    QString key = ui->key_file->text();

    if (key.size() != 32) {
        QString s = QStringLiteral("密钥不足128bit，请输入正确长度的密钥");
        ui->tip_file_label_aes->setText(s);
        return;
    }
    //QtConcurrent::run(cipher.cipherFileByDES, path_in.toStdString(), path_out.toStdString(), key.toStdString());
    //int errno = QFuture::result();
    int errno = cipher.cipherFileByAES(path_in.toStdString(), path_out.toStdString(), key.toStdString());
    if (errno == 1) {
        QString s = QStringLiteral("请输入正确的待加密文件路径");
        ui->tip_file_label_aes->setText(s);
        return;
    }
    else if (errno == 2) {
        QString s = QStringLiteral("请输入正确的输出路径");
        ui->tip_file_label_aes->setText(s);
        return;
    }

    QString s = QStringLiteral("加密成功");
    ui->tip_file_label_aes->setText(s);
}

void MainWindow::handle_file_decipher_aes() {
    ui->tip_file_label_aes->setText("111");
    QString path_out = ui->uncipher_file_path->text();
    QString path_in = ui->ciphered_file_path->text();
    QString key = ui->key_file->text();

    if (key.size() != 32) {
        QString s = QStringLiteral("密钥不足128bit，请输入正确长度的密钥");
        ui->tip_file_label_aes->setText(s);
        return;
    }
    //QtConcurrent::run(cipher.cipherFileByDES, path_in.toStdString(), path_out.toStdString(), key.toStdString());
    //int errno = QFuture::result();
    int errno = cipher.decipherFileByAES(path_in.toStdString(), path_out.toStdString(), key.toStdString());
    if (errno == 1) {
        QString s = QStringLiteral("请输入正确的待解密文件路径");
        ui->tip_file_label_aes->setText(s);
        return;
    }
    else if (errno == 2) {
        QString s = QStringLiteral("请输入正确的输出路径");
        ui->tip_file_label_aes->setText(s);
        return;
    }
    else if (errno == 3) {
        QString s = QStringLiteral("文件损坏");
        ui->tip_file_label_aes->setText(s);
        return;
    }

    QString s = QStringLiteral("解密成功");
    ui->tip_file_label_aes->setText(s);
}

void MainWindow::handle_SubB_cal(){
    ui->subbytes_output->setText("");
    std::string sb(ui->subbytes_input->text().toUtf8().constData());
    if (sb.size() != 32) {
        QString s = QStringLiteral("请输入32个16进制字符");
        ui->subbytes_output->setText(s);
        return;
    }
    if (!cipher.is_legal(sb)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->subbytes_output->setText(s);
        return;
    }
    ui->subbytes_output->setText(QString::fromStdString(cipher.calSubByAES(sb)));
}

void MainWindow::handle_MixCol_cal() {
    ui->mixcol_output->setText("");
    std::string mix(ui->mixcol_input->text().toUtf8().constData());
    if (mix.size() != 32) {
        QString s = QStringLiteral("请输入32个16进制字符");
        ui->mixcol_output->setText(s);
        return;
    }
    if (!cipher.is_legal(mix)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->mixcol_output->setText(s);
        return;
    }
    ui->mixcol_output->setText(QString::fromStdString(cipher.calMixColByAes(mix)));
}

void MainWindow::handle_Shift_cal() {
    ui->shiftrows_output->setText("");
    std::string sr(ui->shiftrows_input->text().toUtf8().constData());
    if (sr.size() != 32) {
        QString s = QStringLiteral("请输入32个16进制字符");
        ui->shiftrows_output->setText(s);
        return;
    }
    if (!cipher.is_legal(sr)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->shiftrows_output->setText(s);
        return;
    }
    ui->shiftrows_output->setText(QString::fromStdString(cipher.calShiftRowByAES(sr)));
}

void MainWindow::handle_Addrkey_cal() {
    ui->addroundkey_output->setText("");
    std::string ar(ui->addroundkey_input->text().toUtf8().constData());
    std::string key(ui->addroundkey_key_input->text().toUtf8().constData());
    std::string r(ui->addroundkey_round_input->text().toUtf8().constData());
    if (ar.size() != 32 || key.size() != 32) {
        QString s = QStringLiteral("请输入32个16进制字符");
        ui->addroundkey_output->setText(s);
        return;
    }
    if (!cipher.is_legal(ar) || !cipher.is_legal(key)) {
        QString s = QStringLiteral("请输入正确的16进制字符");
        ui->addroundkey_output->setText(s);
        return;
    }
    int round = std::stoi(r);
    if (round > 10 || round < 0) {
        QString s = QStringLiteral("请输入正确的Round（0-10）");
        ui->addroundkey_output->setText(s);
        return;
    }
    ui->addroundkey_output->setText(QString::fromStdString(cipher.calAddRKeyByAes(ar,key,r)));
}

MainWindow::~MainWindow()
{
    delete ui;
}
