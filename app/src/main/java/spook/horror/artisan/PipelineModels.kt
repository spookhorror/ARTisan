package spook.horror.artisan

/**
 * Data models for the dex2oat pipeline.
 *
 * [RunResult] is the public result surfaced to the UI; [PatchResult] and
 * [InstalledInfo] are internal intermediates used within the pipeline.
 */

/** Full outcome of one pipeline run, rendered by the UI as step cards. */
data class RunResult(
    val sourceApkPath: String,
    val targetPackage: String,
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

/** Result of one OAT- or VDEX-patch pass. */
internal data class PatchResult(
    val patchCount: Int,
    val applied: Boolean,
    val detail: String,
    val perDexDetails: List<String>,
)

/** Installed-app facts resolved from PackageManager for the picked package. */
internal data class InstalledInfo(
    val sourceDir: String,
    val uid: Int,
    val sharedLibraryFiles: List<String>,
)
