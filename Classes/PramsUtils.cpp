//
// Created by xuxd on 2018/6/21.
//

#include <sys/time.h>
#include "PramsUtils.h"
#include "../crypt/AES.h"
#include "../crypt/HMAC_SHA1.h"
#include "../crypt/Mod5.hpp"
#include "../crypt/Xor.h"
#include "../Base.h"
#include "../crypt/Base64.hpp"

/**
 * 获取当前时间戳
 * @return
 */
long PramsUtils::getCurrentTime() {
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

string PramsUtils::byteToHexStr(unsigned char byte_arr[], int arr_len) {
    string hexstr;
    for (int i=0;i<arr_len;i++)
    {
        char hex1;
        char hex2;
        int value=byte_arr[i]; //直接将unsigned char赋值给整型的值，强制转换
        int v1=value/16;
        int v2=value % 16;

        //将商转成字母
        if (v1>=0&&v1<=9)
            hex1=(char)(48+v1);
        else
            hex1=(char)(55+v1);

        //将余数转成字母
        if (v2>=0&&v2<=9)
            hex2=(char)(48+v2);
        else
            hex2=(char)(55+v2);

        //将字母连接成串
        hexstr=hexstr+hex1+hex2;
    }
    return hexstr;
}

string PramsUtils::getPreAuthBusinessParams(string model , string system , string version, string isSdkLogin , string networkType ,
                                            string onlineType ,string operatorType , string timeStamp , string bussinessType ,string rl,string pipl ,bool supportYZSdk, string extendParams , string secret){

//    string authType = "2" ; //2:校验cookie 3:校验IP和cookie
    //model= ;
    const unsigned char param0[] =  {14,14,16,10,90,82} ;
    string paramStr0 = Xor::getXorStr(param0 , sizeof(param0));
    //&system= ;
    const unsigned char param1[] =  {69,18,13,28,66,10,31,28} ;
    string paramStr1 = Xor::getXorStr(param1 , sizeof(param1));
    //&version= ;
    const unsigned char param2[] =  {69,23,17,29,69,6,29,79,125} ;
    string paramStr2 = Xor::getXorStr(param2 , sizeof(param2));
    //&isSdkLogin= ;
    const unsigned char param3[] =  {69,8,7,60,82,4,62,78,39,74,74,83} ;
    string paramStr3 = Xor::getXorStr(param3 , sizeof(param3));
    //&networkType= ;
    const unsigned char param4[] =  {69,15,17,27,65,0,0,74,20,90,84,11,83} ;
    string paramStr4 = Xor::getXorStr(param4 , sizeof(param4));
    //&onlineType= ;
    const unsigned char param5[] =  {69,14,26,3,95,1,23,117,57,83,65,83} ;
    string paramStr5 = Xor::getXorStr(param5 , sizeof(param5));

    //&timeStamp= ;
    const unsigned char param6[] =  {69,21,29,2,83,60,6,64,45,83,25} ;
    string paramStr6 = Xor::getXorStr(param6 , sizeof(param6));
    //&bt= ;
    const unsigned char param7[] =  {69,3,0,82} ;
    string paramStr7 = Xor::getXorStr(param7 , sizeof(param7));
    // 2:校验cookie 3:校验IP和cookie
    //&authType=2
    const unsigned char param8[] =  {69,0,1,27,94,59,11,81,37,30,22} ;
    string paramStr8 = Xor::getXorStr(param8, sizeof(param8));
    //&rl=    ;
    const unsigned char param9[] =  {69,19,24,82} ;
    string paramStr9 = Xor::getXorStr(param9, sizeof(param9));
    //&pipl=  ;
    const unsigned char param10[] =  {69,17,29,31,90,82} ;
    string paramStr10 = Xor::getXorStr(param10, sizeof(param10));
    //&operatorType=
    const unsigned char param11[] =  {69,14,4,10,68,14,6,78,50,119,93,30,11,78};
    string paramStr11 = Xor::getXorStr(param11, sizeof(param11));

    string paramStr = paramStr0 + model
                      + paramStr1 + system
                      + paramStr2 + version
                      + paramStr3 + isSdkLogin
                      + paramStr4 + networkType
                      + paramStr5 + onlineType
                      + paramStr6 + timeStamp
                      + paramStr7 + bussinessType
                      + paramStr8
                      + paramStr9 + rl
                      + paramStr10 + pipl
                      + paramStr11 + operatorType;

    if(supportYZSdk){
        //&resultCodeType=2
        const unsigned char resultCode[] = {69,19,17,28,67,3,6,98,47,71,65,58,23,3,14,81,11} ;
        string paramStr12 = Xor::getXorStr(resultCode, sizeof(resultCode));
        paramStr += paramStr12;
    }
    if(!extendParams.empty()){
        paramStr += extendParams;
    }
    //LOGI(" ps params--------》 paramStr ： %s " , paramStr.c_str());
    //AES加密
    int out_len = 0 ;
    unsigned char * out = AES::encrypt((unsigned char *)paramStr.c_str() ,paramStr.length() , out_len ,(unsigned char *)secret.c_str());
    string result = PramsUtils::byteToHexStr(out ,out_len );

    SFree(out);
    return result;

}


string PramsUtils::getPreCodeBusinessParamsByJs(string model , string system , string version, string isSdkLogin , string networkType ,
                                            string onlineType ,string operatorType , string timeStamp , string rl,string pipl ,string extendParams , string secret){
    //model= ;
    const unsigned char param0[] =  {14,14,16,10,90,82} ;
    string paramStr0 = Xor::getXorStr(param0 , sizeof(param0));
    //&system= ;
    const unsigned char param1[] =  {69,18,13,28,66,10,31,28} ;
    string paramStr1 = Xor::getXorStr(param1 , sizeof(param1));
    //&version= ;
    const unsigned char param2[] =  {69,23,17,29,69,6,29,79,125} ;
    string paramStr2 = Xor::getXorStr(param2 , sizeof(param2));
    //&isSdkLogin= ;
    const unsigned char param3[] =  {69,8,7,60,82,4,62,78,39,74,74,83} ;
    string paramStr3 = Xor::getXorStr(param3 , sizeof(param3));
    //&networkType= ;
    const unsigned char param4[] =  {69,15,17,27,65,0,0,74,20,90,84,11,83} ;
    string paramStr4 = Xor::getXorStr(param4 , sizeof(param4));
    //&onlineType= ;
    const unsigned char param5[] =  {69,14,26,3,95,1,23,117,57,83,65,83} ;
    string paramStr5 = Xor::getXorStr(param5 , sizeof(param5));
    //&timeStamp= ;
    const unsigned char param6[] =  {69,21,29,2,83,60,6,64,45,83,25} ;
    string paramStr6 = Xor::getXorStr(param6 , sizeof(param6));
    //&rl=    ;
    const unsigned char param9[] =  {69,19,24,82} ;
    string paramStr9 = Xor::getXorStr(param9, sizeof(param9));
    //&pipl=  ;
    const unsigned char param10[] =  {69,17,29,31,90,82} ;
    string paramStr10 = Xor::getXorStr(param10, sizeof(param10));
    //&operatorType=
    const unsigned char param11[] =  {69,14,4,10,68,14,6,78,50,119,93,30,11,78};
    string paramStr11 = Xor::getXorStr(param11, sizeof(param11));

    string paramStr = paramStr0 + model
                      + paramStr1 + system
                      + paramStr2 + version
                      + paramStr3 + isSdkLogin
                      + paramStr4 + networkType
                      + paramStr5 + onlineType
                      + paramStr6 + timeStamp
                      + paramStr9 + rl
                      + paramStr10 + pipl
                      + paramStr11 + operatorType;

    if(!extendParams.empty()){
        paramStr += extendParams;
    }
   //LOGI(" getPreCodeBusinessParamsByJs ps params--------》 paramStr ： %s " , paramStr.c_str());
    //AES加密
    int out_len = 0 ;
    unsigned char * out = AES::encrypt((unsigned char *)paramStr.c_str() ,paramStr.length() , out_len ,(unsigned char *)secret.c_str());
    string result = PramsUtils::byteToHexStr(out ,out_len );

    SFree(out);
    return result;

}

string PramsUtils::getPreMobileBusinessParams(string model , string system , string version, string isSdkLogin , string networkType ,
                             string onlineType , string timeStamp , string bussinessType , string rl,string pipl,string extendParams , string secret){
    //model= ;
    const unsigned char param0[] =  {14,14,16,10,90,82} ;
    string paramStr0 = Xor::getXorStr(param0 , sizeof(param0));
    //&system= ;
    const unsigned char param1[] =  {69,18,13,28,66,10,31,28} ;
    string paramStr1 = Xor::getXorStr(param1 , sizeof(param1));
    //&version= ;
    const unsigned char param2[] =  {69,23,17,29,69,6,29,79,125} ;
    string paramStr2 = Xor::getXorStr(param2 , sizeof(param2));
    //&isSdkLogin= ;
    const unsigned char param3[] =  {69,8,7,60,82,4,62,78,39,74,74,83} ;
    string paramStr3 = Xor::getXorStr(param3 , sizeof(param3));
    //&networkType= ;
    const unsigned char param4[] =  {69,15,17,27,65,0,0,74,20,90,84,11,83} ;
    string paramStr4 = Xor::getXorStr(param4 , sizeof(param4));
    //&onlineType= ;
    const unsigned char param5[] =  {69,14,26,3,95,1,23,117,57,83,65,83} ;
    string paramStr5 = Xor::getXorStr(param5 , sizeof(param5));
    //&timeStamp= ;
    const unsigned char param6[] =  {69,21,29,2,83,60,6,64,45,83,25} ;
    string paramStr6 = Xor::getXorStr(param6 , sizeof(param6));
    //&bussinessType= ;
    const unsigned char param7[] =  {69,3,1,28,69,6,28,68,51,80,112,23,30,22,86} ;
    string paramStr7 = Xor::getXorStr(param7 , sizeof(param7));
    // 2:校验cookie 3:校验IP和cookie
    //&authType=2
    const unsigned char param8[] =  {69,0,1,27,94,59,11,81,37,30,22} ;
    string paramStr8 = Xor::getXorStr(param8, sizeof(param8));
    //&rl=    ;
    const unsigned char param9[] =  {69,19,24,82} ;
    string paramStr9 = Xor::getXorStr(param9, sizeof(param9));
    //&pipl=  ;
    const unsigned char param10[] =  {69,17,29,31,90,82} ;
    string paramStr10 = Xor::getXorStr(param10, sizeof(param10));


    string paramStr = paramStr0 + model
                      + paramStr1 + system
                      + paramStr2 + version
                      + paramStr3 + isSdkLogin
                      + paramStr4 + networkType
                      + paramStr5 + onlineType
                      + paramStr6 + timeStamp
                      + paramStr7 + bussinessType
                      + paramStr8
                      + paramStr9 + rl
                      + paramStr10 + pipl;

    if(!extendParams.empty()){
        paramStr += extendParams;
    }

    //AES加密
    int out_len = 0 ;
    unsigned char * out = AES::encrypt((unsigned char *)paramStr.c_str() ,paramStr.length() , out_len ,(unsigned char *)secret.c_str());
    string result = PramsUtils::byteToHexStr(out ,out_len );
    SFree(out);
    return result;

}


string PramsUtils::getPreAuthSign(string c , string ce , string tp, string pk , string ps ,string f ,string version , string signSecretHex){
    //签名原串
    string srcStr = c + ce + f + pk + ps + tp + version ;

    // TODO HMAC_SHA1 签名加密算法
    BYTE digest[20] ;
    CHMAC_SHA1 hmac_sha1 ;
    hmac_sha1.HMAC_SHA1((unsigned char * )srcStr.c_str(), srcStr.length(), (unsigned char * )signSecretHex.c_str(),signSecretHex.length(), digest) ;

    int len = sizeof(digest);
    string m_strSerialNumber = byteToHexStr(digest,len);
    return m_strSerialNumber;
}


string PramsUtils::getPreMobileSign(string c , string ce , string mp, string py , string ms ,string f , string v, string signSecretHex){
    //签名原串
    string srcStr = c + ce + f + mp + ms + py + v;

    // HMAC_SHA1 签名加密算法
    BYTE digest[20] ;
    CHMAC_SHA1 hmac_sha1 ;
    hmac_sha1.HMAC_SHA1((unsigned char * )srcStr.c_str(), srcStr.length(), (unsigned char * )signSecretHex.c_str(),signSecretHex.length(), digest) ;

    int len = sizeof(digest);
    string m_strSerialNumber = byteToHexStr(digest,len);
    return m_strSerialNumber;
}



string PramsUtils::getUxFinalParams(string params) {
    //cs2f6c7tfr4k5f3r ;
    const unsigned char param0[] =  {0,18,70,9,0,12,69,85,38,81,16,5,91,21,88,30} ;//ux aes密钥,XOR处理
    string paramStrKey = Xor::getXorStr(param0 , sizeof(param0));
    int out_len = 0;
    unsigned char * out = AES::encrypt4ux((unsigned char *)params.c_str() ,params.length() ,out_len , (unsigned char *)paramStrKey.c_str());
    string finalParams = Base64::base64_encode(out,out_len) ;
    SFree(out);
    return finalParams;
}



/**
 * 生成len位字符的随机码
 * @param str
 * @param len
 * @return
 */
string PramsUtils::generateRandomCode(char * str, int len) {
    const char CCH[] = "_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    srand((unsigned) time(NULL));
    for (int i = 0; i < len; ++i) {
        //int x = rand() % (sizeof(CCH) - 1); //这个方法不好, 因为许多随机数发生器的低位比特并不随机,
        //RAND MAX 在ANSI 里#define 在<stdlib.h>
        //RAND MAX 是个常数, 它告诉你C 库函数rand() 的固定范围。
        //不可以设RAND MAX 为其它的值, 也没有办法要求rand() 返回其它范围的值。
        int x = rand() / (RAND_MAX / (sizeof(CCH) - 1));
        str[i] = CCH[x];
    }
    return str;
}

/**
 * 获取16位字符的nonce
 */
string PramsUtils::genNonce(bool verifyResult ) {

    const int RAND_CHAR_SIZE = 10;
    char str[RAND_CHAR_SIZE + 1] = {0} ;
    string randomCode = PramsUtils::generateRandomCode(str, RAND_CHAR_SIZE);
    Mod5 md5 ;
    unsigned char * dest = md5.generateMod5((unsigned char *)randomCode.c_str(),randomCode.length());
    int i;
    char nonce[16] = {0};
    for (i = 0; i < 8; i++) {
        sprintf(nonce, "%s%02x", nonce, dest[i]);
    }
    SFree(dest);
    if(verifyResult){
        //如果sdk的activity处于栈定，则生成的随机16位的nonce的第14位和第三位的值一致，否则不同，平台根据会校验
        nonce[13] = nonce[2];
    }else {
        if(nonce[13] == nonce[2]){
            int a ;
            a = (int)nonce[2];
            a = a + (a=='f' ? -1 : 1);
            nonce[13] = a;
        }
    }
    return nonce;
}

void PramsUtils::hexStrToByte(const char *hex_str, int length, unsigned char *result) {
    char h, l;
    for(int i = 0; i < length/2; i++)
    {
        if(*hex_str < 58)
        {
            h = *hex_str - 48;
        }
        else if(*hex_str < 71)
        {
            h = *hex_str - 55;
        }
        else
        {
            h = *hex_str - 87;
        }
        hex_str++;
        if(*hex_str < 58)
        {
            l = *hex_str - 48;
        }
        else if(*hex_str < 71)
        {
            l = *hex_str - 55;
        }
        else
        {
            l = *hex_str - 87;
        }
        hex_str++;
        *result++ = h<<4|l;
    }

}

