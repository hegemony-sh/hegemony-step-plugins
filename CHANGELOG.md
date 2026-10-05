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
