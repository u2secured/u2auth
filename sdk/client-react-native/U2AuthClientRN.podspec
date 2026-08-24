require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "U2AuthClientRN"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = "https://u2secured.com"
  s.license      = package["license"]
  s.authors      = { "U2 Secured" => "dev@u2secured.com" }

  s.platforms    = { :ios => "14.0" }
  s.source       = { :git => "", :tag => "#{s.version}" }
  # Include the Objective-C bridge shims (*.m) alongside the Swift sources.
  # The .m files carry the RCT_EXTERN_MODULE / RCT_EXTERN_METHOD macros that
  # register the @objc Swift classes with the React Native bridge — without
  # them the native modules compile but never register, so JS calls resolve to
  # null at runtime. Glob {h,m,mm,swift} (the canonical RN podspec pattern).
  s.source_files = "ios/**/*.{h,m,mm,swift}"

  s.dependency "React-Core"

  # Secure Enclave / LocalAuthentication are system frameworks — no extra deps.
  s.frameworks = "LocalAuthentication", "Security"

  s.swift_version = "5.9"
end
