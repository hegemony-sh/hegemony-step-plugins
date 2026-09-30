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
