Multi-party ECDSA tests on mobile platforms (iOS)
=====================================

The purpose of this wiki page is to provide all necessary info on running tests and benches of multi-party ECDSA on mobile platforms (iOS, Android, even Raspberry P) **directly from Rust** using [**Dinghy**](https://github.com/snipsco/dinghy) plugin for simplified cross-compilation. This tutorial can be applied to any host OS in theory, but on practice there is no [Dinghy](https://github.com/snipsco/dinghy) on Windows :( **so Ubuntu and Mac OS X only**. Both have user folder so it will be marked as `%UserFolder%` which is for Ubuntu `/home/<your-username>/` and `/Users/<your-username>/` for Mac OS X

Prerequisites
--

* [**Dinghy**](https://github.com/snipsco/dinghy) - start by installing [Dinghy](https://github.com/snipsco/dinghy). You can do it either by trying your luck with older version of extension(0.2.16 at the moment) that can be installed by typing in terminal

        cargo install cargo-dinghy

    **_but it's recommended to replace `cargo-dinghy` binary with latest_** either prebuilt one form [releases](https://github.com/snipsco/dinghy/releases) page or the one built yourself. Directly adding binary to `%UserFolder%/.cargo/bin` can work, but **_is not recommended_** due to the cargo install step you may discover other outdated dependencies **like outdated OpenSSL (v 0.9.8) on MAC OS X** that needs to be updated via `brew` like in [this tutorial](https://medium.com/@katopz/how-to-upgrade-openssl-8d005554401)

* [**GMP**](https://gmplib.org/) (The GNU Multiple Precision Arithmetic Library)

    You will need to have architecture specific version of GMP for your device's platform. You can use [this prebuilt binary](./bin/gmp_ios.zip) for iOS on  Mac OSX. It's a static library that has following architectures:
  
  * `arm64` - for 64bit mobile processors starting for Apple A7 (ARMv8 instruction set)
  * `armv7` - for earlier 32bit mobile processors (not very usable on older devices due to low performance)
  * `x86_64` - for 64bit host processors to run on iOS device simulators
  
  But it's **_strongly recommended to build GMP on your system yourself_**. Otherwise you will have to install prebuilt binaries to your `lib` folder at `\<root>⁩\⁨usr⁩\local⁩\lib⁩` and [gmp.h](./bin/gmp_ios.zip) to your `include` folder at `\<root>⁩\⁨usr⁩\local⁩\include⁩` and something may not go wright:)

      make mostlyclean
      make clean
      make distclean
      make maintainer-clean

      ./configure CC="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang" CPP="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -E" CPPFLAGS="-target arm64-apple-darwin -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/ -miphoneos-version-min=7.0" --host=aarch64-apple-darwin --disable-assembly --enable-static --disable-shared

      make
      make install

  Note that `make check` is omitted, since anyway it's not implemented for mobile architectures.

  When rebuilding GMP for another architecture, **_you will need to do deep clean between builds_**, don't spare cleaning commands, like in example before `./configure` :D, otherwise you may end-up with inconsistent build.

  Also note in `./configure` example different spelling of architecture parameters for `CPPFLAGS="-target arm64-apple-darwin` and `--host=aarch64-apple-darwin` for 64bit. You will find list of connected devices and supported architectures using commands below
  
      cargo dinghy all-devices
      cargo dinghy all-platforms

  To avoid rebuilding GMP for other architectures every time you need another one, you can merge them into one library using `lipo` tool, like in the example below. Just after each build capture `libgmp.a` file, add some prefix (or suffix:) denoting the architecture in the name, put them in the same folder, and merge them using command like in example below (Mac OS X example)
  
      lipo -create libgmp_arm64.a libgmp_x86_64.a -output libgmp.a
  
  Then put the resulting file back to `\<root>⁩\⁨usr⁩\local⁩\lib`. On Ubuntu for Android it may be a bit different. For example you will have to use `libtool` instead of `lipo` like in [this info](https://stackoverflow.com/questions/3821916/how-to-merge-two-ar-static-libraries-into-one).

* **Signing profiles (iOS only)**

  For iOS you will need signing profiles, since only way to run some code on iOS is to put it in the app and sign. Please refer to [Dinghy iOS tutorial](https://github.com/snipsco/dinghy/blob/master/docs/ios.md). **TL;DR** - you will have to **run dummy app on device from XCode _with app bundle ID ending with `.Dinghy`_ using manual signing.**

  **Please note** that tutorial is a bit dated, like for example you **may still need Apple Developer Account**, since in free accounts automatic profiles that XCode generates for 6 days for you when you pick automatic signing - unfortunately seem not to work with Dinghy on versions of XCode >8.0. It's **_probably_** because Dinghy signs the app that is used to run Rust in manual mode.

Running Tests and Benchmarks
--

* Tests

      cargo dinghy -d 'YourDeviceName' --platform auto-ios-aarch64 -vvv test

* Benches

      cargo dinghy -d 'YourDeviceName' --platform auto-ios-aarch64 -vvv bench 

Yes!) If you performed all the steps for required prerequisites correctly - it becomes as simple as that:) Running your usual Rust commands just turns into adding `dinghy -d 'YourDeviceName' --platform auto-ios-<architecture> -vvv` in between. Note that `-vvv` argument turns on verbose output and number of `v` denotes verbosity level - it may give you a lot of useful info for troubleshooting.

Troubleshooting
--

TODO: section will be expanded based on feedback.