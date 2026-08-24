// Objective-C bridge shim — required to export the Swift module to the RN bridge.
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(U2AuthPush, NSObject)

RCT_EXTERN_METHOD(getToken:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
