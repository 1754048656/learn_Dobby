//
// Created by Zhenxi on 2021/4/23.
//

#include "AESUtils.h"
#include <string>
#include <fstream>



AESUtils::AESUtils(unsigned char* key)
{

    memcpy(Sbox, sBox, 256);
    memcpy(InvSbox, invsBox, 256);
    KeyExpansion(key, w);
}



unsigned char* AESUtils::Cipher(unsigned char* input)
{
    unsigned char state[4][4];
    int i,r,c;

    for(r=0; r<4; r++)
    {
        for(c=0; c<4 ;c++)
        {
            state[r][c] = input[c*4+r];
        }
    }

    AddRoundKey(state,w[0]);

    for(i=1; i<=10; i++)
    {
        SubBytes(state);
        ShiftRows(state);
        if(i!=10)MixColumns(state);
        AddRoundKey(state,w[i]);
    }

    for(r=0; r<4; r++)
    {
        for(c=0; c<4 ;c++)
        {
            input[c*4+r] = state[r][c];
        }
    }

    return input;
}

unsigned char* AESUtils::InvCipher(unsigned char* input)
{
    unsigned char state[4][4];
    int i,r,c;

    for(r=0; r<4; r++)
    {
        for(c=0; c<4 ;c++)
        {
            state[r][c] = input[c*4+r];
        }
    }

    AddRoundKey(state, w[10]);
    for(i=9; i>=0; i--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w[i]);
        if(i)
        {
            InvMixColumns(state);
        }
    }

    for(r=0; r<4; r++)
    {
        for(c=0; c<4 ;c++)
        {
            input[c*4+r] = state[r][c];
        }
    }

    return input;
}

void* AESUtils::Cipher(void* input, int length)
{
    unsigned char* in = (unsigned char*) input;
    int i;
    if(!length)        // 如果是0则当做字符串处理
    {
        while(*(in+length++));
        in = (unsigned char*) input;
    }
    for(i=0; i<length; i+=16)
    {
        Cipher(in+i);
    }
    return input;
}

void* AESUtils::InvCipher(void* input, int length)
{
    unsigned char* in = (unsigned char*) input;
    int i;
    for(i=0; i<length; i+=16)
    {
        InvCipher(in+i);
    }
    return input;
}

void AESUtils::KeyExpansion(unsigned char* key, unsigned char w[][4][4])
{
    int i,j,r,c;
    unsigned char rc[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    for(r=0; r<4; r++)
    {
        for(c=0; c<4; c++)
        {
            w[0][r][c] = key[r+c*4];
        }
    }
    for(i=1; i<=10; i++)
    {
        for(j=0; j<4; j++)
        {
            unsigned char t[4];
            for(r=0; r<4; r++)
            {
                t[r] = j ? w[i][r][j-1] : w[i-1][r][3];
            }
            if(j == 0)
            {
                unsigned char temp = t[0];
                for(r=0; r<3; r++)
                {
                    t[r] = Sbox[t[(r+1)%4]];
                }
                t[3] = Sbox[temp];
                t[0] ^= rc[i-1];
            }
            for(r=0; r<4; r++)
            {
                w[i][r][j] = w[i-1][r][j] ^ t[r];
            }
        }
    }
}

unsigned char AESUtils::FFmul(unsigned char a, unsigned char b)
{
    unsigned char bw[4];
    unsigned char res=0;
    int i;
    bw[0] = b;
    for(i=1; i<4; i++)
    {
        bw[i] = bw[i-1]<<1;
        if(bw[i-1]&0x80)
        {
            bw[i]^=0x1b;
        }
    }
    for(i=0; i<4; i++)
    {
        if((a>>i)&0x01)
        {
            res ^= bw[i];
        }
    }
    return res;
}

void AESUtils::SubBytes(unsigned char state[][4])
{
    int r,c;
    for(r=0; r<4; r++)
    {
        for(c=0; c<4; c++)
        {
            state[r][c] = Sbox[state[r][c]];
        }
    }
}

void AESUtils::ShiftRows(unsigned char state[][4])
{
    unsigned char t[4];
    int r,c;
    for(r=1; r<4; r++)
    {
        for(c=0; c<4; c++)
        {
            t[c] = state[r][(c+r)%4];
        }
        for(c=0; c<4; c++)
        {
            state[r][c] = t[c];
        }
    }
}

void AESUtils::MixColumns(unsigned char state[][4])
{
    unsigned char t[4];
    int r,c;
    for(c=0; c< 4; c++)
    {
        for(r=0; r<4; r++)
        {
            t[r] = state[r][c];
        }
        for(r=0; r<4; r++)
        {
            state[r][c] = FFmul(0x02, t[r])
                          ^ FFmul(0x03, t[(r+1)%4])
                          ^ FFmul(0x01, t[(r+2)%4])
                          ^ FFmul(0x01, t[(r+3)%4]);
        }
    }
}

void AESUtils::AddRoundKey(unsigned char state[][4], unsigned char k[][4])
{
    int r,c;
    for(c=0; c<4; c++)
    {
        for(r=0; r<4; r++)
        {
            state[r][c] ^= k[r][c];
        }
    }
}

void AESUtils::InvSubBytes(unsigned char state[][4])
{
    int r,c;
    for(r=0; r<4; r++)
    {
        for(c=0; c<4; c++)
        {
            state[r][c] = InvSbox[state[r][c]];
        }
    }
}

void AESUtils::InvShiftRows(unsigned char state[][4])
{
    unsigned char t[4];
    int r,c;
    for(r=1; r<4; r++)
    {
        for(c=0; c<4; c++)
        {
            t[c] = state[r][(c-r+4)%4];
        }
        for(c=0; c<4; c++)
        {
            state[r][c] = t[c];
        }
    }
}

void AESUtils::InvMixColumns(unsigned char state[][4])
{
    unsigned char t[4];
    int r,c;
    for(c=0; c< 4; c++)
    {
        for(r=0; r<4; r++)
        {
            t[r] = state[r][c];
        }
        for(r=0; r<4; r++)
        {
            state[r][c] = FFmul(0x0e, t[r])
                          ^ FFmul(0x0b, t[(r+1)%4])
                          ^ FFmul(0x0d, t[(r+2)%4])
                          ^ FFmul(0x09, t[(r+3)%4]);
        }
    }
}


void AESUtils::Byte2Hex(const unsigned char* src, int len, char* dest) {
    for (int i=0; i<len; ++i) {
        sprintf(dest + i * 2,  "%02X", src[i]);
    }
}

void AESUtils::Hex2Byte(const char* src, int len, unsigned char* dest) {
    int length = len / 2;
    for (int i=0; i<length; ++i) {
        dest[i] = Char2Int(src[i * 2]) * 16 + Char2Int(src[i * 2 + 1]);
    }
}

int AESUtils::Char2Int(char c) {
    if ('0' <= c && c <= '9') {
        return (c - '0');
    }
    else if ('a' <= c && c<= 'f') {
        return (c - 'a' + 10);
    }
    else if ('A' <= c && c<= 'F') {
        return (c - 'A' + 10);
    }
    return -1;
}

string AESUtils::EncryptString(string strInfor) {
    int nLength = strInfor.length();
    int spaceLength = 16 - (nLength % 16);
    unsigned char* pBuffer = new unsigned char[nLength + spaceLength];
    memset(pBuffer, '\0', nLength + spaceLength);
    memcpy(pBuffer, strInfor.c_str(), nLength);
    Cipher(pBuffer, nLength + spaceLength);

    // 这里需要把得到的字符数组转换成十六进制字符串
    char* pOut = new char[2 * (nLength + spaceLength)];
    memset(pOut, '\0', 2 * (nLength + spaceLength));
    Byte2Hex(pBuffer, nLength + spaceLength, pOut);

    string retValue(pOut);
    delete[] pBuffer;
    delete[] pOut;
    return retValue;
}

string AESUtils::DecryptString(string strMessage) {
    int nLength = strMessage.length() / 2;
    unsigned char* pBuffer = new unsigned char[nLength];
    memset(pBuffer, '\0', nLength);
    Hex2Byte(strMessage.c_str(), strMessage.length(), pBuffer);

    InvCipher(pBuffer, nLength);
    string retValue((char*)pBuffer);
    delete[] pBuffer;
    return retValue;
}

void AESUtils::EncryptTxtFile(const char* inputFileName, const char* outputFileName) {
    ifstream ifs;

    // Open file:
    ifs.open(inputFileName);
    if (!ifs) {
        LOG(ERROR) << " AesEncryptor::EncryptTxtFile() - Open input file failed!  " ;
        return ;
    }

    // Read config data:
    string strInfor;
    string strLine;
    while (!ifs.eof()) {
        char temp[1024];
        memset(temp, '\0', 1024);
        ifs.read(temp, 1000);
        strInfor += temp;
    }
    ifs.close();

    // Encrypt
    strLine = EncryptString(strInfor);

    // Writefile
    ofstream ofs;
    ofs.open(outputFileName);
    if (!ofs) {
        LOG(ERROR) << ("AesEncryptor::EncryptTxtFile() - Open output file failed!");
        return ;
    }
    ofs << strLine;
    ofs.close();
}

void AESUtils::DecryptTxtFile(const char* inputFile, const char* outputFile) {
    ifstream ifs;

    // Open file:
    ifs.open(inputFile);
    if (!ifs) {
        LOG(ERROR) <<  ("AesEncryptor::DecryptTxtFile() - Open input file failed!");
        return ;
    }

    // Read config data:
    string strInfor;
    string strLine;
    while (!ifs.eof()) {
        char temp[1024];
        memset(temp, '\0', 1024);
        ifs.read(temp, 1000);
        strInfor += temp;
    }
    ifs.close();

    // Encrypt
    strLine = DecryptString(strInfor);

    // Writefile
    ofstream ofs;
    ofs.open(outputFile);
    if (!ofs) {
        LOG(ERROR) <<("AesEncryptor::DecryptTxtFile() - Open output file failed!");
        return ;
    }
    ofs << strLine;
    ofs.close();
}