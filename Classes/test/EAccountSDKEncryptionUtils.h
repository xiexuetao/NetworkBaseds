//
//  EAccountSDKEncryptionUtils.h
//  EAccountSDKEncDeCryptUtil
//
//  Created by Dsy on 2021/4/30.
//

#import <Foundation/Foundation.h>
#include "EAccountSDKXor.hpp"
#include "EAccountSDKPramsUtils.hpp"
#include "EAccountSDKCommLib.hpp"

NS_ASSUME_NONNULL_BEGIN

@interface EAccountSDKEncryptionUtils : NSObject

#pragma mark - 对称

+ (NSString *)symmetry_encrypt:(NSString *)str key:(NSString *)key;

+ (NSString *)symmetry_decrypt:(NSString *)str key:(NSString *)key;

+ (NSString *)symmetry_cppLogEncrypt:(NSString *)str key:(NSString *)key;

+ (NSString *)symmetry_cppEncrypt:(NSString *)str key:(NSString *)key;

+ (NSString *)symmetry_cppDecrypt:(NSString *)str key:(NSString *)key;

#pragma mark - 非对称

+ (NSString *)asymmetric_encrypt:(NSString *)str key:(NSString *)key;

+ (NSString *)asymmetric_decrypt:(NSString *)str key:(NSString *)key;

#pragma mark - 摘要

+ (NSString *)abstract_hamc_hashWithStr:(NSString *)str key:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
