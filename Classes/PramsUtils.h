//
// Created by xuxd on 2018/6/21.
//

#ifndef NDKDEMO_PRAMSUTILS_H
#define NDKDEMO_PRAMSUTILS_H

#define SFree(p)     if (p != nullptr) {\
free(p);\
p = nullptr;\
}

#include <sstream>
using namespace std;

class PramsUtils {
public :
    static long getCurrentTime();
    static string byteToHexStr(unsigned char byte_arr[], int arr_len);

    static string getPreAuthBusinessParams(string model , string system ,
                                           string version, string isSdkLogin , string networkType , string onlineType , string operatorType ,
                                           string timeStamp ,string bussinessType ,string rl,string pipl ,bool supportYZSdk,  string extendParams ,string secret);
    static string getPreCodeBusinessParamsByJs(string model , string system , string version, string isSdkLogin , string networkType ,
                                            string onlineType ,string operatorType , string timeStamp , string rl,string pipl ,string extendParams , string secret);

    static string getPreMobileBusinessParams(string model , string system ,
                                             string version, string isSdkLogin , string networkType , string onlineType ,
                                             string timeStamp ,string bussinessType ,string rl,string pipl, string extendParams ,string secret);

    static string getPreAuthSign(string c , string ce , string tp, string pk , string ps ,string f ,string av, string signSecretHex);

    static string getPreMobileSign(string c , string ce , string mp, string py , string ms ,string f , string v,string signSecretHex);

    static string generateRandomCode(char * str, int len);

    static string getUxFinalParams(string basic_string);

    static string genNonce(bool verifyResult);

    static void hexStrToByte(const char *hex_str, int length, unsigned char *result);
};


#endif //NDKDEMO_PRAMSUTILS_H
