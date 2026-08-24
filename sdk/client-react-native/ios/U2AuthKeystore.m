// Objective-C bridge shim — required to export the Swift module to the RN bridge.
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(U2AuthKeystore, NSObject)

RCT_EXTERN_METHOD(ensureKeyPair:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sign:(NSString *)base64Data
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
