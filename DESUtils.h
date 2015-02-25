//
//  DESUtils.h
//  testdes
//
//  Created by ArthurChen on 15/1/27.
//  Copyright (c) 2015年 ArthurChen. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface DESUtils : NSObject

+(NSString *)decryptUseDES:(NSString *)cipherText key:(NSString *)key;
+(NSString *)encryptUseDES:(NSString *)plainText key:(NSString *)key;

@end


@interface NSString (DESUtils)

- (NSString *)URLEncodedString;
- (NSString *)URLDecodedString;
- (NSString *)encodedURLString;
- (NSString *)decodedURLString;

@end

/*!
 A Simple Tool about strings.
 */

@interface StringUtility : NSObject

/*!
 convert hex strings to byte.
 e.g. "C1AB" to {0xC1, 0xAB}
 @param hexString the hexString,the length of it should be even.
 @result returns the corresponding data of the hexString.
 */
+ (NSData *)getDataFromHexString:(const char*)hexString;

/*!
 convert bytes to hex strings.
 e.g. {0xC1, 0xAB} to "C1AB"
 @param bytes the data start pointer
 @param length the length of the data
 @result returns the corresponding hexString of the data.
 */
+ (NSString *)getHexStringFromBytes:(const char*)bytes length:(int)length;

//普通字符串转换为十六进制的。
+ (NSString *)hexStringFromString:(NSString *)string;

// 十六进制转换为普通字符串的。
+ (NSString *)stringFromHexString:(NSString *)hexString;

@end

@interface Base64 : NSObject

+(int)char2Int:(char)c;
+(NSData *)decode:(NSString *)data;
+(NSString *)encode:(NSData *)data;

@end