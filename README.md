# ARTisan

**An ODEX / VDEX patcher for Android. Change the compiled code ART runs, without touching the signed APK.**

ARTisan automates the OAT-patching technique explained in the write-up
[[*Falling in Love with the Art of ART*]](https://spookhorror.gitbook.io/blogs/falling-in-love-with-the-art-of-art). Instead of
hand-editing bytes in a hex editor, you pick an APK and the app does the whole flow for you.

---

## What it does

When an app is installed, Android compiles its DEX bytecode into a device-local
compiled artifact (`.odex` + `.vdex`) that sits next to the app. ART decides whether
to trust that artifact by comparing a **CRC-32 checksum** stored inside it against the
checksum of the installed `base.apk`. If they match, ART runs the compiled native code.

ARTisan compiles a fresh OAT from a modified APK, then rewrites the ODEX/VDEX metadata
so those checksums line up with the *installed* app, so ART accepts and runs your
modified compiled code while the signed APK on disk stays completely untouched.

In short:

1. Read the installed target's per-`classesN.dex` CRC-32s.
2. Compile the modified APK with `dex2oat`, using a length-padded working path so no
   bytes shift later (the Sabanal trick).
3. Byte-patch the ODEX location + checksum and the VDEX checksum array to match the
   installed APK.
4. Fix ownership/permissions and drop the result into the app's `oat/<isa>/` folder.

The patch finds each field by **searching** for the known bytes rather than assuming a
fixed offset, so it survives OAT/VDEX format changes across ART versions.

---

## Requirements

- A **rooted** device (needs `dex2oat` and write access to the app's install dir).
- The target app must already be **installed** (ARTisan patches an installed package).
- Tested on Android 11 to 16 (arm64). Format is version-agnostic by design.

## Usage

1. Build & install ARTisan, or grab a release APK.
2. Modify your target APK however you like (e.g. `apktool`), producing `modified.apk`.
3. Open ARTisan, tap **Select APK & Compile**, and pick `modified.apk`.
4. Force-stop and relaunch the target app. ART loads the patched OAT.

The overflow menu (⋮) has a **Verbose logging** toggle for full step-by-step output in
`logcat` (tag `dex2oat-lab`).

---

## How it works (the deep dive)

The full mechanism, the ART trust chain, the AOSP source that enforces it, and a manual
byte-level walkthrough are documented here:
**
[[Falling in Love with the Art of ART]](https://spookhorror.gitbook.io/blogs/falling-in-love-with-the-art-of-art)**.

---

## A note on the code

I understand the runtime mechanism deeply; the Kotlin was written with heavy AI
assistance. If you spot a bug or a cleaner approach, a PR will get a faster fix than an
issue. Contributions are genuinely welcome.

---

## Responsible use

This is **dual-use research**, built to understand Android's runtime trust model. It was
developed and demonstrated on my own device against an open-source target
([RootBeer sample](https://github.com/scottyab/rootbeer)). Use it only on devices and
applications you own or are explicitly authorized to test.

The defensive takeaway is the important one: **on a rooted device, client-side signature
and integrity checks are not a real security boundary. Keep checks that matter
server-side.**

---

*by [@spookhorror](https://github.com/spookhorror)*
