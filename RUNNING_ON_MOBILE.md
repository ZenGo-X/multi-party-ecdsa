Multi-party ECDSA tests on mobile platforms (iOS)
=====================================

The purpose of this wiki page is to provide all necessary info on running tests and benches of multi-party ECDSA on mobile platforms (iOS, Android, even Raspberry P) **directly from Rust** using [**Dinghy**](https://github.com/snipsco/dinghy) plugin for simplified cross-compilation. This tutorial can be applied to any host OS in theory, but on practice there is no [Dinghy](https://github.com/snipsco/dinghy) on Windows :( **so Ubuntu and Mac OS X only**. Both have user folder so it will be marked as `%UserFolder%` which is for Ubuntu `/home/<your-username>/` and `/Users/<your-username>/` for Mac OS X

Prerequisites
--

* [**Dinghy**](https://github.com/snipsco/dinghy) - start by installing [Dinghy](https://github.com/snipsco/dinghy). You can do it either by trying your luck with older version of extension(0.2.16 at the moment) that can be installed by typing in terminal

        cargo install cargo-dinghy

    **_but it's recommended to replace `cargo-dinghy` binary with latest_** either prebuilt one form [releases](https://github.com/snipsco/dinghy/releases) page or the one built yourself. Directly adding binary to `%UserFolder%/.cargo/bin` can work, but **_is not recommended_** because during cargo install step you may discover other outdated dependencies **like outdated OpenSSL (v 0.9.8) on MAC OS X** that needs to be updated via `brew` like in [this tutorial](https://medium.com/@katopz/how-to-upgrade-openssl-8d005554401)

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

* Set lib type in `Cargo.toml` to 
  ```toml
  crate-type = ["staticlib", "rlib"]
  ```

* Tests

      cargo dinghy -d 'YourDeviceName' --platform auto-ios-aarch64 -vvv test

* Benches

      cargo dinghy -d 'YourDeviceName' --platform auto-ios-aarch64 -vvv bench

Yes!) If you performed all the steps for required prerequisites correctly - it becomes as simple as that:)

Results
--

As you may see from [log highlights](./doc/bench_logs_highlights.rtf) Mac Mini host with **2.5-3GHz dual-core 64-bit Intel Core i5-3210M** CPU is on average **_just 3x faster_** then iPhone 6S with **1.85 GHz dual-core 64-bit ARMv8-A "Twister"** CPU.

**Log highlights** for comparison on running **on phone (iPhone 6S A1633)**
```
Last login: Wed Feb 20 22:29:28 on ttys004
macmini31:multi-party-ecdsa vl$ cargo dinghy -d 'iPhone John' --platform auto-ios-aarch64 bench
INFO  cargo_dinghy > Targeting platform 'auto-ios-aarch64' and device '91b2f0d3359d4df4ea35b3cd30d54550daa56b22'
   
Compiling multi-party-ecdsa v0.1.0 (/Users/vl/repo/multi-party-ecdsa)

running 9 tests
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_keygen_t1_n2 ... ok
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_keygen_t2_n3 ... ok
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_mta ... ok
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_keygen_t2_n4 ... ok
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_sign_n5_t2_ttag4 ... ok
test protocols::two_party_ecdsa::lindell_2017::test::tests::test_d_log_proof_party_two_party_one ... ok
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_sign_n8_t4_ttag6 ... test protocols::multi_party_ecdsa::gg_2018::test::tests::test_sign_n8_t4_ttag6 has been running for over 60 seconds
test protocols::two_party_ecdsa::lindell_2017::test::tests::test_full_key_gen ... ok
test protocols::two_party_ecdsa::lindell_2017::test::tests::test_two_party_sign ... ok
test protocols::multi_party_ecdsa::gg_2018::test::tests::test_sign_n8_t4_ttag6 ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

Benchmarking keygen:  
keygen                  time:   [31.155 s 31.889 s 32.171 s]

Benchmarking keygen t=1 n=2:  
keygen t=1 n=2          time:   [2.6533 s 2.8052 s 3.3143 s]

Benchmarking keygen t=2 n=3:  
keygen t=2 n=3          time:   [4.4918 s 5.1433 s 5.4888 s]

Benchmarking keygen t=5 n=8:  
keygen t=5 n=8          time:   [25.638 s 26.298 s 26.932 s]
```

and **host (Mac Mini A1347 Late 2012 MD387LL/A 16GB RAM)**

```
macmini31:multi-party-ecdsa vl$ cargo bench
Compiling multi-party-ecdsa v0.1.0 (/Users/vl/repo/multi-party-ecdsa)
Finished release [optimized] target(s) in 38.42s
Running target/release/deps/multi_party_ecdsa-5e00dae7db842f11

keygen                  time:   [4.0675 s 4.0988 s 4.1749 s] 

keygen t=1 n=2          time:   [816.58 ms 1.0185 s 1.2034 s]

keygen t=2 n=3          time:   [1.4682 s 1.5835 s 1.8026 s] 
Found 1 outliers among 5 measurements (20.00%)
  1 (20.00%) high severe

keygen t=5 n=8          time:   [9.1888 s 9.5256 s 9.9273 s] 
Found 1 outliers among 5 measurements (20.00%)
  1 (20.00%) low mild
```

You may want to check [full logs](./doc/bench_logs_full.rtf) for your own discretion.

So running your usual Rust commands just turns into adding `dinghy -d 'YourDeviceName' --platform auto-ios-<architecture> -vvv` in between. Note that `-vvv` argument turns on verbose output and number of `v` denotes verbosity level - it may give you a lot of useful info for :point_down:

Troubleshooting
--

* **Dependency conflicts**

  During compilation and/or linking both for desktop and mobile, _especially when you are new to Rust_, you may encounter errors caused by so called [cargo dependency hell](https://www.google.com/search?q=rust+dependency+hell) similar to [this](https://stackoverflow.com/questions/54281527/rust-compile-error-on-macos-related-to-gmp). Example errors may be something like:

  * related to `curv`

           error[E0277]: the trait bound `curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof: serde::Serialize` is not satisfied
           --> src/protocols/multi_party_ecdsa/gg_2018/mta.rs:34:5

  * related to `rust-gmp` and **GMP**

          expected struct `gmp::mpz::Mpz`, found another struct `gmp::mpz::Mpz`

    Solution to this type of problems is to download all dependencies like `zk-paillier`, `curv`, `rust-gmp`, `centipede`, `bulletproof`, compile, build, test them and reference via local `path = '<your_local_path_here>'`. For example

    ```toml
    #instead of
    #zk-paillier = { git = "https://github.com/KZen-networks/zk-paillier"}
    #reference local copy
    zk-paillier = { path = "<your_local_path_here>/KZen-networks/zk-paillier"}
    ```

    And you may need to re-reference same dependencies of dependencies inside their `Cargo.toml` files (for example `zk-paillier` references `curv` too)

* **Empty iOS device list**
  
  You may encounter  
  
      INFO  dinghy_lib::ios > Failed while looking for ios simulators. It this is not expected, you need to make sure `xcrun simctl list --json` works.
  
  and `cargo dinghy all-devices` returns nothing to you regarding iOS devices that are shown in XCode.
  So try to run `xcrun simctl list --json`. If you will get 
  
      xcrun: error: unable to find utility "simctl", not a developer tool or in PATH

  try [this info](https://stackoverflow.com/questions/29108172/xcrun-unable-to-find-simctl). The one [particularly useful](https://stackoverflow.com/a/53204124/763989) is

      xcode-select -s /Applications/Xcode.app

* **SIGKILL**

      error: process didn't exit successfully: `/Users/vl/repo/kzen/multi-party-ecdsa/target/release/deps/multi_party_ecdsa-593e51428b40de24` (signal: 4, SIGILL: illegal instruction)

  This one is very weird, and is connected to instance of **GMP** installed on your machine. To resolve this you may need to go to `\<root>⁩\⁨usr⁩\local⁩\lib` and move your `libgmp.dylib` and `libgmp.10.dylib` to some other temp new folder. **But be prepared to move them back !!!**, once you may need to bench/test for **x86_64 host** with

  ```toml
  crate-type = ["lib"]
  ```

  in your `Cargo.toml`