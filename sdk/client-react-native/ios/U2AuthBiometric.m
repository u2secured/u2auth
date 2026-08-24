// Objective-C bridge shim — required to export the Swift module to the RN bridge.
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(U2AuthBiometric, NSObject)

RCT_EXTERN_METHOD(authenticate:(NSString *)reason
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

@end
