## [0.32.2](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.32.1...v0.32.2) (2026-10-22)

### Bug Fixes

* **images:** raise Go and klauspost/compress in opentofu-runner for two HIGH advisories ([bff1744](https://github.com/hegemony-sh/hegemony-step-plugins/commit/bff1744da6cee1e30976d159ac630a039f3598da))

## [0.32.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.32.0...v0.32.1) (2026-10-22)

### Bug Fixes

* **images:** raise Go and klauspost/compress in opentofu-runner for two HIGH advisories ([f525dd9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f525dd9bbffc5b2e34d2d39dcb1217ce99217698))

## [0.32.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.31.2...v0.32.0) (2026-10-18)

### Features

* **sdk,steps:** trust the run organization's CAs in TLS checks ([8445846](https://github.com/hegemony-sh/hegemony-step-plugins/commit/844584672fad0c85928c35258784bd0938ea6606))

### Bug Fixes

* **steps:** send plain HTTP when the organization's CA list is unavailable ([ce0ca33](https://github.com/hegemony-sh/hegemony-step-plugins/commit/ce0ca338212af0227e3a92f419cfa76cefbf1fcf))

## [0.31.2](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.31.1...v0.31.2) (2026-10-16)

### Bug Fixes

* **netcli:** say why each device failed in collect_evidence's error ([940259f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/940259f5b831dc980f937843366c80c7a702dcc5))

## [0.31.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.31.0...v0.31.1) (2026-10-16)

### Bug Fixes

* **transports:** name a refused login in timing mode ([b821f0d](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b821f0d2493378546a80eb5a63e5f29d1dac9c1a))

## [0.31.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.30.0...v0.31.0) (2026-10-14)

### Features

* **http:** let other handlers send through http.request's client ([3ef263f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3ef263f0e0882521e84b3184bb0cf4a316120812))
* **netbox:** add NetBox steps: request, ipam allocate/release, render_config ([8a723e0](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8a723e01ff57bb80c0ac04d08723d127fafd368e))

### Bug Fixes

* **http:** find a refused TLS handshake behind httpcore's from None ([7cde73b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7cde73b7ac68ee713282453645c510659116e64f))
* **netbox:** check NetBox's match count, and refuse a get of a whole list ([6422010](https://github.com/hegemony-sh/hegemony-step-plugins/commit/64220107d625d8d1116bbc50569a13354ac03036))
* **netbox:** honour Retry-After dates and zero, keep render keys unique ([6bd9b9c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6bd9b9cebb06c4e243707dc20b2af417c946848d))
* **netbox:** read every match before acting, check bulk Data when saved ([640559e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/640559ed983766bad3eb0cfc93eeb0f6460cd620))
* **netbox:** refuse null bulk Data, a countless list, and a TLS retry ([cf304cb](https://github.com/hegemony-sh/hegemony-step-plugins/commit/cf304cb52a57c4c629a11cc9815633e543801acb))
* **netbox:** refuse to act on matches that shifted while they were paged ([b30403f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b30403faa3fad68dd046717ddfcbdbaa6b6da87b))

## [0.30.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.29.1...v0.30.0) (2026-10-14)

### Features

* **inventory:** add inventory.sync, a step that syncs an inventory provider ([bbcd360](https://github.com/hegemony-sh/hegemony-step-plugins/commit/bbcd3603855bac12e3cb33cc31a9323b9c73d224))

### Bug Fixes

* **inventory:** agree on unexpected errors, document the overlap case ([925e158](https://github.com/hegemony-sh/hegemony-step-plugins/commit/925e1583c58883e6301b5fc9acc4a932a37abc3e))
* **inventory:** one host-error table, and a host TimeoutError is unexpected ([609f36d](https://github.com/hegemony-sh/hegemony-step-plugins/commit/609f36d3a0e4692151bb5c2fb5477c659ccccea8))
* **inventory:** wait through the whole window and report only time spent waiting ([35a1265](https://github.com/hegemony-sh/hegemony-step-plugins/commit/35a1265b8c4d6280099df77e491f0905314c7799))

## [0.29.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.29.0...v0.29.1) (2026-10-14)

### Bug Fixes

* **flow:** pass a template field mapping whatever it renders to ([31b31fd](https://github.com/hegemony-sh/hegemony-step-plugins/commit/31b31fd33ed8a525f4bb61731970072316fd54e5))

## [0.29.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.28.1...v0.29.0) (2026-10-13)

### Features

* **transports:** report the SSH algorithms each hop agreed on ([6417bd5](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6417bd57994d7a724587e62e338c1bee40e029c0))

### Bug Fixes

* **sdk:** treat RFC 5647's AES-GCM names as ciphers with integrity built in ([43c02cf](https://github.com/hegemony-sh/hegemony-step-plugins/commit/43c02cf6ec1af9611912579c94fac5804e7aeeca))

## [0.28.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.28.0...v0.28.1) (2026-10-10)

### Bug Fixes

* **images:** raise golang.org/x/net to v0.60.0 in the OpenTofu runner ([e82c6a3](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e82c6a3b17415e73b994bf1302b19b7f326c8164))

## [0.28.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.27.1...v0.28.0) (2026-10-10)

### Features

* **sdk:** add HostKeyVerifier, the host's SSH host-key trust for transports ([35caf80](https://github.com/hegemony-sh/hegemony-step-plugins/commit/35caf80af9c8584a3125bfb6dd99030dbe75d353))
* **transports:** check SSH host keys on both hops through the host's verifier ([fac188c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/fac188c2d5dd4a64d3c0acb6941370739fa99ef4))
* **transports:** refuse to connect without a host-key verifier ([0ff376b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/0ff376bd5a8e1d09bb8f5f33017d5b95df5fa52c))

## [0.27.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.27.0...v0.27.1) (2026-10-10)

### Bug Fixes

* **container:** let any image user write the files to harvest ([6fece30](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6fece301e2e054095bd322cbd3609b9ca7046eb8))

## [0.27.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.26.2...v0.27.0) (2026-10-09)

### Features

* **container:** build on the organization's cached copies of the base images ([54b4e88](https://github.com/hegemony-sh/hegemony-step-plugins/commit/54b4e883c2a39ce7c3b628b2a05f97a883eec999))
* **tf,ansible:** put image_digest in tf.plan, tf.apply and ansible.playbook metrics ([80c9c7a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/80c9c7a5a3df42ab370142d85490f9f893b1034b))

### Bug Fixes

* **container:** run the image by the digest its own pull reported ([0981367](https://github.com/hegemony-sh/hegemony-step-plugins/commit/09813674aa196fc23c117f2cd55982a216b5582a))
* **container:** serve only the base images the target's stages use, for one platform ([de85d9a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/de85d9a4bd47adaf799e14ae42a55c4b6fa3543e)), closes [#56](https://github.com/hegemony-sh/hegemony-step-plugins/issues/56)
* **container:** split Dockerfile instructions on any whitespace, tabs included ([aa9c797](https://github.com/hegemony-sh/hegemony-step-plugins/commit/aa9c79724c7038c890fb12dc32fc79860092ecb6))

## [0.26.2](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.26.1...v0.26.2) (2026-10-09)

### Bug Fixes

* **images:** build tofu with Go 1.26.9 ([3f54618](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3f54618ea77a23e0503ff8ab65ce5f1b64cd49f7))

## [0.26.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.26.0...v0.26.1) (2026-10-09)

### Bug Fixes

* **images:** build tofu with Go 1.26.9 ([dd2074c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/dd2074ceeb58754c1c98534d133861594d200ebf))

## [0.26.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.25.0...v0.26.0) (2026-10-08)

### Features

* **container:** name the image digest every container step runs by in its log ([a73cdb0](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a73cdb019d498ce45202ceb8211fd3a2e190158b))

## [0.25.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.24.0...v0.25.0) (2026-10-08)

### Features

* **container:** run every container step by its image digest and record it ([c52e08c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c52e08c0ab2f1a5f0f9b1fcf6e319f03d8be9582))

## [0.24.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.23.0...v0.24.0) (2026-10-07)

### Features

* **sdk:** let a step end only a state hold a given step took ([84f7a35](https://github.com/hegemony-sh/hegemony-step-plugins/commit/84f7a350bfdc94afa199511e12d4716bca1e6001))

### Bug Fixes

* **tf:** end only the state hold the plan step's own lock took ([7e073a5](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7e073a5ed7222f47eb8dee912167913185b242db))

## [0.23.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.22.0...v0.23.0) (2026-10-07)

### ⚠ BREAKING CHANGES

* **shell:** refuse values in lines whose interpreter is a template
* **transports:** stop a config block at the first line the device rejects
* **iosxe:** compare IOS-XE versions as releases, not substrings
* **iosxe:** wait in the install step until a reloading device goes down
* **iosxe:** read upgrade step settings through their config models
* **flow:** read flow.run's settings through its model, so a rendered "false" stops waiting
* **container:** read a rendered cache_image as a boolean and a blank working_dir as /workspace
* **evidence:** fail evidence.compare when the precheck capture failed
* **evidence:** fail evidence.assert on a capture that failed
* **evidence:** fail evidence.assert ordering checks on values that are not numbers
* **container:** refuse templates in the command of a host-access step
* **shell:** keep template values out of PowerShell commands
* **shell:** refuse environment variable names that are not identifiers
* **shell:** refuse whitespace control in command templates

### Bug Fixes

* **ansible:** escape a leading [#jinja2](https://github.com/hegemony-sh/hegemony-step-plugins/issues/jinja2): header in values Ansible reads ([927ee41](https://github.com/hegemony-sh/hegemony-step-plugins/commit/927ee41b93d1bfbb416f84109f2b279a6dae138c))
* **ansible:** say when the target roles match no device ([e2243e1](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e2243e12b62c3fa63b78ce0dd924fd05d075b4c6))
* **container:** keep the output of a container stopped at its timeout ([bbe231a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/bbe231abc82a412cbaf36e87972136bf56002ff6))
* **container:** read a rendered cache_image as a boolean and a blank working_dir as /workspace ([14ed35f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/14ed35fb5d0c16cd894f19ec04016fa2712a26b9))
* **container:** refuse templates in the command of a host-access step ([1c5ad9a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/1c5ad9a105ac8f7818b3098f367c42ebb3736032))
* **evidence:** fail evidence.assert on a capture that failed ([eb81b53](https://github.com/hegemony-sh/hegemony-step-plugins/commit/eb81b5344ecc170e27c95e0b9dd30ae638d5c9f7))
* **evidence:** fail evidence.assert ordering checks on values that are not numbers ([e949b8c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e949b8c5b5e7e72c1a56e04cd09ff1f1568edd4d))
* **evidence:** fail evidence.compare when the precheck capture failed ([b30408c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b30408cac1447b3d108efe4103b8b838545909fc))
* **flow:** read flow.run's settings through its model, so a rendered "false" stops waiting ([856acea](https://github.com/hegemony-sh/hegemony-step-plugins/commit/856acea7b81fee583842b9567ae83128649021c5))
* **iosxe:** answer each install-mode question exactly once ([1b5af88](https://github.com/hegemony-sh/hegemony-step-plugins/commit/1b5af88c9c08e3e02c7d0d2865e0aabc6bf20afd))
* **iosxe:** compare IOS-XE versions as releases, not substrings ([d52d52e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/d52d52ec8a7714e0463b403ff8fcabda2f379202))
* **iosxe:** end each reload check by the end of Reload Wait ([1e69c47](https://github.com/hegemony-sh/hegemony-step-plugins/commit/1e69c47cfcee43231dfdd23dafebf168ca7b0fb4))
* **iosxe:** fetch a fresh repository download URL for each staged device ([059b51f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/059b51f5030e484abc02893aa0c908396d93c272))
* **iosxe:** read upgrade step settings through their config models ([74c0520](https://github.com/hegemony-sh/hegemony-step-plugins/commit/74c0520f34219bbd5dcaadf510472bcaefca66b6))
* **iosxe:** title verify's poll interval setting Poll Interval ([caf9433](https://github.com/hegemony-sh/hegemony-step-plugins/commit/caf9433e217a533f3b2fe2dad73d973a54819275))
* **iosxe:** undo the boot change when its save or read-back fails ([dcbdfbc](https://github.com/hegemony-sh/hegemony-step-plugins/commit/dcbdfbc511aba4af2d4b2bba61474a8f5f7facd8))
* **iosxe:** wait in the install step until a reloading device goes down ([32ad428](https://github.com/hegemony-sh/hegemony-step-plugins/commit/32ad4289f9147d14e56fe6f92bf1665d79a15cb7))
* **monitor:** default the HTTP Health port to 80 and declare ping_count ([e924313](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e924313906c4a10217d31be09bf4886e39149601))
* **netcli:** find a configuration session after leading blank lines ([cb65762](https://github.com/hegemony-sh/hegemony-step-plugins/commit/cb657623a8f48dbaa56d581668d511f1c14b1fa0))
* **netmiko:** answer a timing command's prompt only once ([3a82490](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3a82490de75cf61282f1a96325b0e12da3b48c2f))
* **probe:** await the host's egress check on the step's own event loop ([2c57f9f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/2c57f9f215551c6e2318419b999b9c88e883e240))
* **probe:** fail only the probe.http target whose request cannot be made ([7c8f2d9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7c8f2d9d6c3c10d978c928d4e420d3396f445de1))
* **probe:** let probe.wait_reachable's HTTP Health check request any path ([42af963](https://github.com/hegemony-sh/hegemony-step-plugins/commit/42af963803879bbb094ac2ff2d83adfcd92bb1ca))
* **probe:** refuse a probe.wait_reachable window as long as the wait ([7a36299](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7a36299ddee414069d670998b136ed52ccbbb684))
* **probe:** run the probe.http and probe.dns egress checks off the event loop ([a99e238](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a99e2386714db477d115ea5880f02e664b5eb301))
* **shell:** keep template values out of PowerShell commands ([38bc245](https://github.com/hegemony-sh/hegemony-step-plugins/commit/38bc2459d197c569ad61e5821c2adccc0ceab49d))
* **shell:** refuse environment variable names that are not identifiers ([197f30c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/197f30c88ff7250dbf9b29d8ededa91a56fc22ef))
* **shell:** refuse values in lines whose interpreter is a template ([51f4c65](https://github.com/hegemony-sh/hegemony-step-plugins/commit/51f4c6537e3f3e4d290b65650b1e6b061eed0d9a))
* **shell:** refuse whitespace control in command templates ([e01d3ea](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e01d3ea14719014aa0957c0863e457678e7add7d)), closes [#-](https://github.com/hegemony-sh/hegemony-step-plugins/issues/-)
* **tf:** end the run's hold on managed state when tf.plan fails ([f406789](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f406789669bdb59a0c0c1b647f2605afb64b1973))
* **tf:** let tf.apply succeed on a plan with no changes without a shared workspace ([dd74dc7](https://github.com/hegemony-sh/hegemony-step-plugins/commit/dd74dc79db70a45609cf15f702b570b1254203b6))
* **tf:** read tf.plan's plan modes as the plan does, and refuse refresh_only with replace ([71e37a4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/71e37a4c87e8cb15fdc04e95fe8d94f8956e4dbf))
* **transports:** answer a prompt that a channel read cut in two ([416492c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/416492c4e3832785a8efcc449305903934de54c5))
* **transports:** answer the questions of a copy to startup-config ([dbce1da](https://github.com/hegemony-sh/hegemony-step-plugins/commit/dbce1dae935b8934c5e6e3e7969dffb1aaee992c))
* **transports:** keep command and configuration text out of the logs ([8090c5e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8090c5e4cf67c0667572814b865661e9b791f477))
* **transports:** stop a config block at the first line the device rejects ([9de4ea7](https://github.com/hegemony-sh/hegemony-step-plugins/commit/9de4ea71f0981e2dca921d8fec49ab80bc969fa3))

## [0.22.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.21.0...v0.22.0) (2026-10-06)

### Features

* **sdk:** add secret store services for steps ([f0ad301](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f0ad301ff3240d29936e388e57b66a71c6b2e3fe))
* **secret:** add secret.write to store, swap or delete a secret ([08c5337](https://github.com/hegemony-sh/hegemony-step-plugins/commit/08c5337d7119254b3f7af2ee4b94cbf77e13d889))

### Bug Fixes

* **sdk:** default the secret store services to NotImplementedError ([e80f2be](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e80f2be21d57d31950f09391000bc836ed0291ce))
* **secret:** never remove a file written in a source file's place; full output on failure ([a2c4dc3](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a2c4dc3dc42cf2ed8d7935443954bea0bf8e208a))
* **secret:** settle a cancelled swap before the cancellation propagates ([42ebb54](https://github.com/hegemony-sh/hegemony-step-plugins/commit/42ebb544f8ee203345e78d3f130475a4cbf5a773))
* **secret:** settle failed secret writes from what the store holds ([9926c0f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/9926c0f6ddf2a487710195f1fe495f3c3e65e29f))

## [0.21.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.20.0...v0.21.0) (2026-10-06)

### Features

* **probe:** add probe.tls to inspect served TLS certificates ([a060ac2](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a060ac20f5a9c8205f87e1fcdd53934c17b3fc64))
* **probe:** check certificate revocation lists in probe.tls ([4f2a24c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/4f2a24cd50a0fba0035faaee09db4ed7d8c5821b))

### Bug Fixes

* **probe:** apply the Netscape certificate type in probe.tls offline checks ([bcd0970](https://github.com/hegemony-sh/hegemony-step-plugins/commit/bcd0970f2e6c1a379d09a5d91e26bd76c2b02df4))
* **probe:** bound each probe.tls revocation request by the attempt timeout ([52ce17a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/52ce17ad19fbb6112a1cbb065ae21949311ffc66))
* **probe:** bound the age of an OCSP response or CRL without a next update ([b8d3e72](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b8d3e72fff0d332749f6af35527f7f96db05eea1))
* **probe:** bound the offline chain search in probe.tls ([623e149](https://github.com/hegemony-sh/hegemony-step-plugins/commit/623e1493df605d4a028efe02fadb0b5f1723a2dd))
* **probe:** call probe.tls parallelism max_parallel_devices like every handler ([a3a61e6](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a3a61e6fba73817ca60794b72da09798123b9288))
* **probe:** keep a certificate probe.tls cannot read with its endpoint ([0ee9f11](https://github.com/hegemony-sh/hegemony-step-plugins/commit/0ee9f116d546d2d635b82b9e00a6dac123e62ac9))
* **probe:** keep an unreadable OCSP response or CRL to its own endpoint ([66f591a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/66f591a1df82e15ea924cee75b36b33fb89c080c))
* **probe:** limit what probe.tls downloads for revocation checks ([8c8653a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8c8653a4f2739781364f47a92a77c3e5442cf87a))
* **probe:** match OpenSSL in probe.tls offline checks and harden OCSP ([75f9dd2](https://github.com/hegemony-sh/hegemony-step-plugins/commit/75f9dd2d03aa70a873733eda9f09d00d49d0af1e))
* **probe:** match OpenSSL's CA and name-constraint rules in probe.tls offline checks ([fc130ba](https://github.com/hegemony-sh/hegemony-step-plugins/commit/fc130bab686b71653588eeb413d29f5f3bae5e20))
* **probe:** name probe.tls evidence after the server name too ([cb8012e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/cb8012ef87a6e9535b7e9715bd15f5c06bb33e19))
* **probe:** parse PEM text in linear time in probe.tls ([015083a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/015083ad7a9eac7ee2f0ff9938725dcd32afe9cd))
* **probe:** read probe.tls revocation responses uncompressed ([7a255ea](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7a255ea0e1be901dc5be1a3f6db7a7cd9cb410d6))
* **probe:** read the served chain in probe.tls before Python 3.13 ([1265bda](https://github.com/hegemony-sh/hegemony-step-plugins/commit/1265bdaa72130aef3fd91854bffc584c5d675c4a))
* **probe:** refuse TLS connections when no egress gate can check them ([5b43b86](https://github.com/hegemony-sh/hegemony-step-plugins/commit/5b43b86ffba348073a20931ed60bc12b58f7643d))
* **probe:** report no chain verdict for a certificate probe.tls did not verify ([6fc4b66](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6fc4b666e4cfb91211ec36b67a897ba7b8615a2e))

## [0.20.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.19.0...v0.20.0) (2026-10-06)

### Features

* **http:** add http.request to call HTTP APIs from a flow ([aa1de08](https://github.com/hegemony-sh/hegemony-step-plugins/commit/aa1de0899ecf54d1cffa62932d27935ac0bcc7dc))

### Bug Fixes

* **http:** bound decompression, refuse short secrets, tighten pagination ([a36bdf7](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a36bdf765aaf510e251c54066f11951f40e2bdb2))
* **http:** check the dialled host name and harden http.request responses ([7c1c8dc](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7c1c8dc0848c3ef7ffb7c103764b6a8d97070101))
* **http:** redact the whole body before cutting previews; redact numeric echoes ([be40c68](https://github.com/hegemony-sh/hegemony-step-plugins/commit/be40c68bf9242bd1343ab30b76fd73e6bdb38b82))
* **http:** refuse to send credentials to a plain http:// URL ([47ef0e4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/47ef0e4a05460e142aa7ba0a81a61be05f5592f8))
* **http:** refuse to send when no egress gate can check the request ([9299df4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/9299df4bfe55d725207192830dbe1496d067956f))

## [0.19.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.18.0...v0.19.0) (2026-10-06)

### ⚠ BREAKING CHANGES

* **steps:** run each step with its model's settings, and fit its own time limit

### Features

* **sdk:** read step settings through the model, and declare a step's own time limit ([2c98cb9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/2c98cb9ac25346c44d69e2e44dfe96794f5bc153))

### Bug Fixes

* **sdk:** check a value given under an old name, and keep verify's wait per device ([003f081](https://github.com/hegemony-sh/hegemony-step-plugins/commit/003f081721765462e75b9b4df6d81d2bda6fe27c))
* **steps:** run each step with its model's settings, and fit its own time limit ([b4f7c58](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b4f7c58a909e337bb2d236fdde247a7be2016527))

## [0.18.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.17.0...v0.18.0) (2026-10-06)

### ⚠ BREAKING CHANGES

* **tf:** tf.apply refuses a plan made by the previous version of
tf.plan, which recorded no digest. Plan again after upgrading.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Features

* **sdk:** let a step end its run's hold on a managed state ([91c4f3a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/91c4f3ab8aaa0849b50abaf5287ced3d20bf75ad))

### Bug Fixes

* **container:** cap live output ([fe2be08](https://github.com/hegemony-sh/hegemony-step-plugins/commit/fe2be0862eaec29af740a7b7d5d9f1fb31d83129))
* **container:** count the live log as emitted, and mark output dropped at the budget ([7bbce80](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7bbce8061a32afeac0959127f254b0b4daae7146))
* **container:** stop long output lines from hanging container.run ([a059c6b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a059c6be49e59cdd10f8ffe284b0c9fa137d77bf))
* **tf:** end the state hold when there is nothing to apply ([a0a025e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a0a025eb3da287d343283c52639a484f9c8174f3))
* **tf:** refuse to apply a plan file that changed after planning ([7eeaac7](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7eeaac738e32e102d1fdb82585c23fed247bb215))
* **tf:** take the plan's digest and readable forms from one private file ([6adbd29](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6adbd295075c1eb1c5ef5c6ecdd8a42a8fcf6db5))

## [0.17.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.16.0...v0.17.0) (2026-10-06)

### ⚠ BREAKING CHANGES

* **iosxe:** the install step no longer sets the boot variable to
packages.conf by itself. Flows that relied on the automatic boot rewrite
must enable fix_boot_config.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Bug Fixes

* **iosxe:** change the boot setting only when asked ([0c35d82](https://github.com/hegemony-sh/hegemony-step-plugins/commit/0c35d82c0366780ed34af0c5e3c48d22cd9dc7dc))
* **iosxe:** check every command's result ([3b8e1da](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3b8e1da5a5e76986e4b720c712ba33aae1c03e11))
* **iosxe:** fail the MD5 check unless the device confirms the hash ([93ab133](https://github.com/hegemony-sh/hegemony-step-plugins/commit/93ab1334b573e1db9428ded4ab9116cd60ee9fd0))
* **iosxe:** let cancelling a run close device sessions ([7a34c4d](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7a34c4db81d39a61fab0e5922323cf3319c777c5))
* **iosxe:** read the whole verify /md5 answer and check its file ([f66ee3e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f66ee3e2f27a17e272aba012063c23fff63ab1b6))
* **iosxe:** report a failed install as failed ([59c5f3e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/59c5f3e44779d87ce02e8fc00d1e78df51049288))
* **iosxe:** send bundle-mode boot changes in one session ([55d7978](https://github.com/hegemony-sh/hegemony-step-plugins/commit/55d79781bd4cf58f089350e76ef7a84c7eb45071))
* **iosxe:** undo a boot change that failed part-way ([f878813](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f878813e5760b9b8958ab9a2397cb2e78adccb30))

## [0.16.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.15.0...v0.16.0) (2026-10-06)

### ⚠ BREAKING CHANGES

* **probe:** a probe.connectivity step using DNS Resolve with an IP
address in Hostname to Resolve passed before and now fails. Set Hostname
to Resolve to a DNS name.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>
* **probe:** a probe.connectivity step or monitor.connectivity
monitor using DNS Resolve on an IP address target without Hostname to
Resolve passed before and now fails. Set Hostname to Resolve, or target
a device by its name.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Features

* **probe:** wait_reachable port, check type and proxy ([f9c3e69](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f9c3e69ab130f1328d56ddf286ebf1bb3926b65e))
* **sdk:** let max_parallel_from_config take a default ([a32375b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a32375bea39f554fea166569645a9ea1a28889e7))

### Bug Fixes

* **probe:** bracket IPv6 addresses in the HTTP health check ([6f82c55](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6f82c552843fa15599a2946d9df78cc03e2aaddf))
* **probe:** check targets in parallel ([695b44a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/695b44a1b68931fb6a530ba3435943a6516f0087))
* **probe:** declare wait_reachable's connect timeout ([8e270af](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8e270af8af42d230fac3168317de79ab68c6d254))
* **probe:** default the HTTP health port to 80 ([4bfd227](https://github.com/hegemony-sh/hegemony-step-plugins/commit/4bfd2275ee767bfc24f54fef92e37bdc7eb7c32d))
* **probe:** kill the ping child when icmp_ping is cancelled ([3ea3b09](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3ea3b096fece20061b65ee37dc42f69254ef6691))
* **probe:** measure wait_reachable stability per target ([f0c4e3f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f0c4e3ff209ac210512531297203c647db493aa6))
* **probe:** refuse a DNS check of an IP target without a host name ([c6d2369](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c6d2369a785689688cbd0911175fb1b26dd03f42))
* **probe:** refuse an IP address as the DNS check's host name ([99b468f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/99b468f01879775a03201d5f65f594f6b9b28660))
* **probe:** report an invalid SOCKS proxy setting as config_error ([8a422d7](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8a422d7e3e96d6ef1a015a68ed140a857312d701))

## [0.15.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.14.0...v0.15.0) (2026-10-05)

### ⚠ BREAKING CHANGES

* **evidence:** evidence.compare fails when a precheck item has no
postcheck pair or its postcheck capture failed; these used to be
skipped. On text, subset and superset now compare lines (subset used to
need identical text, and superset always failed).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Features

* **netcli:** per-command timeout ([a85fff6](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a85fff672100b5ab0ce6d3c50ca202ef0647a81f))

### Bug Fixes

* **evidence:** fail a comparison when items are missing ([dd200d4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/dd200d491582232da19758f5e652e05fad0ee4db))
* **evidence:** find command output by its full text ([75bc623](https://github.com/hegemony-sh/hegemony-step-plugins/commit/75bc623991e70dece95f7bef22356988f6710bd6))
* **evidence:** match old artifact names without surrounding whitespace ([c31ff40](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c31ff40231556770cf74dab014d4dd90b21ec2ee))
* **netcli:** collect_evidence targets roles only ([0ccc58d](https://github.com/hegemony-sh/hegemony-step-plugins/commit/0ccc58dd32f5e4506e525fab2b16e5570add4c87))
* **netcli:** let cancelling a run close device sessions ([c9d4206](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c9d4206611d968025f2d98a7f50f7b5325e0589b))
* **transports:** run config blocks as written and stop after a failure ([b65d1fb](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b65d1fbcbc8b2895f2432e516d88900771e8fbe8))
* **transports:** say a command was skipped because the run was cancelled ([61010d5](https://github.com/hegemony-sh/hegemony-step-plugins/commit/61010d5238b1cd3c1db1ca198ea592916f493da1))

### Performance Improvements

* **evidence:** fetch the run's artifacts once per step ([44a77fa](https://github.com/hegemony-sh/hegemony-step-plugins/commit/44a77fa761e5ab12dbca8cdb60d66d9a7bb5f5c0))

## [0.14.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.13.1...v0.14.0) (2026-10-05)

### ⚠ BREAKING CHANGES

* **monitor:** the monitor.start and monitor.stop step handlers no
longer exist. A flow that still has one of these steps is refused on
save as an unknown handler, and a run that reaches such a step fails it.
Use monitor.connectivity instead before upgrading.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>
* **flow:** the flow.git_sync step handler no longer exists. A flow
that still has a flow.git_sync step is refused on save as an unknown
handler, and a run that reaches such a step fails it. Remove those steps
before upgrading.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Features

* **flow:** remove the flow.git_sync step handler ([5652ee5](https://github.com/hegemony-sh/hegemony-step-plugins/commit/5652ee50b1e0ebf05db8c88e33087e2c73d0b9cf))
* **monitor:** remove the monitor.start and monitor.stop step handlers ([070765a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/070765a0349e6204c1bea70d33bf4d70d5b8b01b))

## [0.13.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.13.0...v0.13.1) (2026-10-05)

### Bug Fixes

* **images:** patch the ansible-runner image so its release scan passes ([4ab14d6](https://github.com/hegemony-sh/hegemony-step-plugins/commit/4ab14d642620beee9bec35fa2fe73112195a4346))

## [0.13.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.12.0...v0.13.0) (2026-10-05)

### ⚠ BREAKING CHANGES

* **ansible:** Ansible no longer templates extra variable values. Write
Ansible expressions in the playbook instead.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>
* **shell:** a shell.execute step whose commands insert a {{ }} value
without | quote now fails before contacting any host. Add | quote, or
pass the value under Environment Variables and read it as "$NAME". With
the default interpreter environment variables are exported, which needs a
POSIX login shell. The | quote filter ships with the platform release that
calls template_errors.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Features

* **sdk:** let a handler refuse unsafe templates before they are rendered ([2c6ec1a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/2c6ec1aa903891962b480917006edc9db2027838))

### Bug Fixes

* **ansible:** stage extra variables as data, not templates ([8ad452d](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8ad452df9b4ca1b1ee1fee436bc3e57703a81578))
* **probe:** put the DNS check's chosen resolver through the egress policy ([5ffa0b4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/5ffa0b4be6849136435e63989983e1885480ac9c))
* **probe:** refuse a chosen resolver when no egress gate can check it ([fad2b50](https://github.com/hegemony-sh/hegemony-step-plugins/commit/fad2b501c50a3ef74a3d888530647feb39900292))
* **shell:** check where a quoted value stands, with Jinja's parser ([85d7a63](https://github.com/hegemony-sh/hegemony-step-plugins/commit/85d7a63e7f2e719ff7fc671d0ac9be8634ac23b7))
* **shell:** refuse unquoted template values in commands, make env work ([a5d7795](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a5d7795d578a45c7e15024ac6b0365c3decf4161))

## [0.12.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.11.0...v0.12.0) (2026-10-05)

### ⚠ BREAKING CHANGES

* **netcli:** the netcli.poll_until step handler no longer exists. A flow
that still has a netcli.poll_until step is refused on save as an unknown
handler, and a run that reaches such a step fails it. Replace those steps
before upgrading.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01LhWmMf82Cr3rWPxzUR15EQ
Signed-off-by: Jakub Trávník <jakub.travnik@gmail.com>

### Features

* **netcli:** remove netcli.poll_until ([da5863d](https://github.com/hegemony-sh/hegemony-step-plugins/commit/da5863df607d7c8522c7e057f6c062b1fe82884d))

## [0.11.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.10.0...v0.11.0) (2026-10-05)

### Features

* **container:** build without the platform registry, or push to another registry ([609ce0e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/609ce0e1b674b77330388450e31c82917526bce5))
* **sdk:** let a build step build without the platform registry or push elsewhere ([67f2235](https://github.com/hegemony-sh/hegemony-step-plugins/commit/67f2235c712eacdf68702afca708117f1cb1a248))

### Bug Fixes

* **container:** drop pushed-elsewhere names as the build ends, lowercase hosts ([748c69b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/748c69b1c7e38ec7f5a26734b1979803bfe1e9f8))
* **container:** refuse the platform registry named with a default port ([6ad6126](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6ad61267fb6406d03fa168510811dedbc140c678))

## [0.10.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.9.2...v0.10.0) (2026-10-03)

### Features

* **container:** add container.build to build and push images ([d788fa5](https://github.com/hegemony-sh/hegemony-step-plugins/commit/d788fa5435d9f6d343481679464060eaca997d86))
* **sdk:** describe where a building step pushes its image ([6bf5d7f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6bf5d7fe6d26766104a31dd815f48401c8ffc3db))

### Bug Fixes

* **container:** pin the build's digest, read long output, scope cache mounts ([55c8503](https://github.com/hegemony-sh/hegemony-step-plugins/commit/55c8503c42e4bef6125839364e87db8c313b819e))
* **container:** read the build context folder however it is spelled ([eb4e876](https://github.com/hegemony-sh/hegemony-step-plugins/commit/eb4e876b2e5305abf75cc0d36706091ecfe042dc))

## [0.9.2](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.9.1...v0.9.2) (2026-10-02)

### Bug Fixes

* **container:** name the cache key tag sha256_<digest>, not sha256-<digest> ([770d7ab](https://github.com/hegemony-sh/hegemony-step-plugins/commit/770d7ab01853782d9b45f5e2e3563d0a868adccf))

## [0.9.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.9.0...v0.9.1) (2026-10-01)

### Bug Fixes

* **container:** never cache an image from a registry named without a dot ([bf66b0f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/bf66b0fcae649d3ee2351a5ca05328076bcbe7a0))

## [0.9.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.8.0...v0.9.0) (2026-10-01)

### Features

* **container:** cache pulled images in the platform registry ([c1770a7](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c1770a74c97b2a52154d2e822a6cbec24c55ba38))

### Bug Fixes

* **container:** pull the checked digest, keep denials out of the cache, bound the lookups ([66a9740](https://github.com/hegemony-sh/hegemony-step-plugins/commit/66a974053d54ad64ace5f08a784c482d4658faf3))
* **container:** write a registry port with an underscore in a copy's path ([8b75fbc](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8b75fbc00250d1ae6cac95130fb296cecff7a5a9))

## [0.8.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.7.1...v0.8.0) (2026-10-01)

### Features

* **container:** honour a per-step Docker config directory ([e3a9909](https://github.com/hegemony-sh/hegemony-step-plugins/commit/e3a9909324ca0af770d136feae557a97ccedfc74))

### Bug Fixes

* **container:** record a digest-qualified image reference as the digest ([25d277c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/25d277c5df10e6c68ce61d48b7f0c83499dd26c2))

## [0.7.1](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.7.0...v0.7.1) (2026-09-30)

### Bug Fixes

* **release:** commit the runner image tags and publish the images when the release is published ([acef84c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/acef84cedf776ef06c65215fb20fa4595adfc0a1))

## [0.7.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.6.0...v0.7.0) (2026-09-30)

### Features

* **ansible:** publish the default execution image with every release ([672bdca](https://github.com/hegemony-sh/hegemony-step-plugins/commit/672bdca4dace04782920f5d028356817c5f46696))
* **licensing:** review every image component and ship notices in ansible-runner ([850af50](https://github.com/hegemony-sh/hegemony-step-plugins/commit/850af508c8f5ada693291ce29dc58dee9ea0d2c3))
* **licensing:** ship the licence texts in every wheel ([c7e853f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c7e853f12b3b0493ac3fb7b1d677f6731235ec2c))
* **tf:** hold a managed state from a plan until its run applies ([b61fd60](https://github.com/hegemony-sh/hegemony-step-plugins/commit/b61fd60d1da1728688b6cadad4f63035deac508b))
* **tf:** let a cancelled plan or apply stop cleanly ([15f7c0a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/15f7c0a1e84d3e8127bfc7aaf03863faf77c3401))
* **tf:** publish opentofu-runner as the OpenTofu default and apply the plan's image by digest ([f33ddc4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f33ddc4cd491d6253c336264bdceda40ee7a1f66))

### Bug Fixes

* **ansible:** build the runner image on ansible-core 2.19.13 ([71616b1](https://github.com/hegemony-sh/hegemony-step-plugins/commit/71616b1046328b0fc864d0479a1bf5e66e6a5e8a))
* **container:** finish the graceful stop through a second cancellation ([ec29f9c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/ec29f9c933c39ce18dd94574dc3816ee1afa27ca))
* **images:** build opentofu-runner's tofu from source with fixed Go modules ([434e938](https://github.com/hegemony-sh/hegemony-step-plugins/commit/434e9389f09a2c2fb921bf73dab629ccf4b38068))
* **images:** ship the Go licence texts in opentofu-runner and name the runners' real licences ([c13cd1c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c13cd1cd6f6f9379eda59dc58d82bf1537a023a6))
* **licensing:** refuse image installs from a requirements file ([badfe90](https://github.com/hegemony-sh/hegemony-step-plugins/commit/badfe90e6c400994160acc895dadeeffebf13759))
* **runner:** pass on only the first stop request to the tool ([a9f9b57](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a9f9b57c067680d9e12cb6c39259b4baa1ba983b))
* **runner:** start nothing after a stop request that came while preparing ([a9ea9a6](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a9ea9a6ada52d52b7d2df95597026d315b2f2c6c))
* **tf:** let the kill at the deadline wait out the whole stop grace ([81d90e2](https://github.com/hegemony-sh/hegemony-step-plugins/commit/81d90e2daf92c1bf41df53a8b044d968b67e0001))

## [0.6.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.5.0...v0.6.0) (2026-09-28)

### Features

* ansible.playbook step with inventory from Hegemony ([f0028b8](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f0028b8669c63005324064a369d12dd7543baa9d))
* **ansible:** name the failed and unreachable hosts in the step error ([9667945](https://github.com/hegemony-sh/hegemony-step-plugins/commit/96679457a5b9a59029cba65773fc9595a40a7e56))
* managed state for tf.plan and tf.apply ([933eef5](https://github.com/hegemony-sh/hegemony-step-plugins/commit/933eef512180bdb8d825582ff11182f04a136751))
* reusable container runner for tool handlers ([3c26d1e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3c26d1e795532801ba1efb36d25f96e5f6f945f4))
* **sdk:** node_scoped_state for handlers whose run state is keyed by node id ([8e9c5fa](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8e9c5faf6313cb0e370a05b1af4d3e4f9fa0e7b0))
* tf.plan and tf.apply for OpenTofu and Terraform ([a5fc685](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a5fc685649d02de142e447716c0284528006f0d5))

### Bug Fixes

* **ansible:** device ansible_vars can no longer set connection variables ([8028af4](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8028af4fefb4d4decbc6e7e0dd9fac0e03fa35eb))
* **ansible:** leave forks unset by default, and indent multi-line diffs ([5d8fad9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/5d8fad90372ea5a0236b18224ca0b4450bce7b9b))
* **ansible:** never read missing results as "nothing changed" ([8d06010](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8d0601087b9dbdcef5a1005a894ef6d370a9ec87))
* **ansible:** pass device data and secrets to Ansible as data, never as templates ([6e9e722](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6e9e7223a523393423146f713e74b5dc152a3f0f))
* **ansible:** quote the jump host ProxyCommand and refuse unplain jump host fields ([9ec8885](https://github.com/hegemony-sh/hegemony-step-plugins/commit/9ec888528c9ac6087f7162075c359e3d11765058))
* **ansible:** refuse device addresses ssh could read as options ([714b459](https://github.com/hegemony-sh/hegemony-step-plugins/commit/714b4591eb9c4ba4dadc34e581043a05a914ee53))
* **ansible:** refuse IPv6 zones that are not interface names ([31c5b51](https://github.com/hegemony-sh/hegemony-step-plugins/commit/31c5b51af8ebfa653d0ff49c94d06d5f2ddde1e0))
* **ansible:** refuse role groups that merge with reserved or derived groups ([efa7de8](https://github.com/hegemony-sh/hegemony-step-plugins/commit/efa7de80fafb68864c4d2d06149083e9964909c5))
* **ansible:** run scope leaves out other roles' devices without credentials ([1c4270b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/1c4270b96cc36ab5e4f1da3062e24fe6940347c2))
* **ansible:** say how to get the default image when its pull fails ([c1f7a33](https://github.com/hegemony-sh/hegemony-step-plugins/commit/c1f7a335685a379a58c7828b5be2b09054b92792))
* **ansible:** stop overriding the repository's ansible.cfg beyond need ([13ef69b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/13ef69bb36c5761f86e64423c29a3c9d9ba975d1))
* **release:** check sibling pins with extras and any spelling of the name ([deb951b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/deb951bd6757e90ad182ccf94050638e937213a8))
* **release:** require an exact pin on every sibling wheel ([ad9b879](https://github.com/hegemony-sh/hegemony-step-plugins/commit/ad9b8794429ca4a528ef07a1d81052ce3edda87c))
* resolve secret fields as written, mount no step outputs in tool steps ([bd3f35b](https://github.com/hegemony-sh/hegemony-step-plugins/commit/bd3f35bd764c4e2d2ab485959fb2bce3ce36181b))
* **runner:** give the copy-out after a step's deadline 10 seconds, not 30 ([6482392](https://github.com/hegemony-sh/hegemony-step-plugins/commit/64823920e140696094a393537e01e700b514bfa2))
* **runner:** keep flow inputs out of /hegemony/context.json ([1ad5dd9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/1ad5dd96751ea9284f943ce2bf7015a83a69b1a9))
* **runner:** name the cause when a URL-shaped secret resolves to nothing ([7eccde2](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7eccde284ca4abcdf59a91a5aa156199a6f0b36b))
* **runner:** report results that could not be copied out of the container ([a4e6882](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a4e6882736bb6ad549d0ed8a1d70dc55919248d9))
* **runner:** stage job files under a private directory on the worker ([0092511](https://github.com/hegemony-sh/hegemony-step-plugins/commit/00925116ef2d0e7ce62297a3b71290f90a3ef60b))
* spell the tf.plan no-backend message as one string ([012380e](https://github.com/hegemony-sh/hegemony-step-plugins/commit/012380e99d350547af30895878203c7e589ca507))
* **tf,ansible:** stop the tool at the step's deadline inside the container ([5ce4ef6](https://github.com/hegemony-sh/hegemony-step-plugins/commit/5ce4ef6a5bd3b9d8b00ff35a8b98a7fb25cac15b))
* **tf:** check the plan step's output before applying it ([81be378](https://github.com/hegemony-sh/hegemony-step-plugins/commit/81be378ae6389e554905f6966204de66b560b7b4))
* **tf:** collect the JSON plan last so it cannot crowd out the plan text ([d939a12](https://github.com/hegemony-sh/hegemony-step-plugins/commit/d939a125ad7b76d77852b14b8c9caf0f3ec0c39a))
* **tf:** keep a state the tool could not save; name the real cause of a failed apply ([6cce2d9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/6cce2d9afdeefadece4e25aa2c802c008fff954d))
* **tf:** keep managed state access within the platform's 24 hours ([45dca4a](https://github.com/hegemony-sh/hegemony-step-plugins/commit/45dca4afdb91382c1bff258d12f5daa6627468fa))
* **tf:** let Targets and Replace name keyed resource instances ([198b6f0](https://github.com/hegemony-sh/hegemony-step-plugins/commit/198b6f00d268e5fe0f8118f423f8cb35f51f3f14))
* **tf:** list every count tf.plan reports and how variables are typed ([ca3683f](https://github.com/hegemony-sh/hegemony-step-plugins/commit/ca3683fce378cd13b0aee76562662277df329fb6))
* **tf:** name the lock holder when a plan or apply cannot take the lock ([a33e452](https://github.com/hegemony-sh/hegemony-step-plugins/commit/a33e4527751a37614e0c9b250e48dbffbcd5cf20))
* **tf:** pass secret variables to the tool exactly as they resolve ([3cc1dca](https://github.com/hegemony-sh/hegemony-step-plugins/commit/3cc1dca7d84cc9ea9b14a06c1daba9a297953353))
* **tf:** read a blank or padded lock timeout the same way everywhere ([567291c](https://github.com/hegemony-sh/hegemony-step-plugins/commit/567291c94f0e04812de453b9b89bc55ca1170b1e))
* **tf:** return the configuration's outputs when there is nothing to apply ([73043ea](https://github.com/hegemony-sh/hegemony-step-plugins/commit/73043eafd922b9aa8a19b0ecd4577ab37e54373b))
* **tf:** say when a result file could not be copied out of the container ([7ae5ab9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/7ae5ab9219ee3980a05735511cde2699c27aea3c))
* **tf:** state access lasts as long as the container; a plan without its exit code fails ([2f29443](https://github.com/hegemony-sh/hegemony-step-plugins/commit/2f29443e963621f33219cf2c219a617386629eed))

## [0.5.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.4.0...v0.5.0) (2026-09-25)

### ⚠ BREAKING CHANGES

* **sdk:** ContainerRuntime.docker_host is required and must name
the sandbox daemon; container.run refuses "", a bare unix:// and a tcp://
with no host instead of inheriting the worker's environment.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01FVnouGuBTDymAFUEF8gMUy

### Bug Fixes

* describe the sandbox daemon, not the host's, in container.run ([1358883](https://github.com/hegemony-sh/hegemony-step-plugins/commit/135888315bac4c173f7622cf8d42fd3b906ae2f1))
* **sdk:** refuse an empty docker_host instead of using the worker's Docker daemon ([db91891](https://github.com/hegemony-sh/hegemony-step-plugins/commit/db9189127bdfd634c673fe31c2d39d205faea68b))

## [0.4.0](https://github.com/hegemony-sh/hegemony-step-plugins/compare/v0.3.1...v0.4.0) (2026-09-23)

### ⚠ BREAKING CHANGES

* **sdk:** HandlerContext.phase and HandlerContext.kind are gone.
A handler that read them reads ctx.tags.get("phase", "") /
ctx.tags.get("kind", "") instead; a host that built the context with
those two keyword arguments passes tags= instead. Positional
construction of HandlerContext shifts by two fields.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011ztw52e4SE3cob8UUEXsRs

### Features

* **sdk:** carry the step's tags on HandlerContext ([f798b68](https://github.com/hegemony-sh/hegemony-step-plugins/commit/f798b6849231d50e8b4db2d959dc14b33c230e19))
* **sdk:** handlers read phase and kind from ctx.tags ([11770e9](https://github.com/hegemony-sh/hegemony-step-plugins/commit/11770e92ae18274615bd3937d030598a1d71aa11))

### Bug Fixes

* **sdk:** declare HandlerContext.tags last so positional callers keep their bindings ([8dd2540](https://github.com/hegemony-sh/hegemony-step-plugins/commit/8dd2540ed46fc3985644b003325b2a5806d65cca))

# Changelog

Generated by semantic-release on every release; do not edit by hand.
