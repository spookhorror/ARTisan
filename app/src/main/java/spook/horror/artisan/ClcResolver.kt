package spook.horror.artisan

import java.io.File
import java.io.RandomAccessFile

/** Resolves the `--class-loader-context` (CLC) dex2oat must be invoked with. */
internal object ClcResolver {

    /** Fallback CLC when neither the installed OAT nor PackageManager give us one. */
    const val FALLBACK_CLC = "PCL[]"

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
    fun resolveClassLoaderContext(
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
    fun readClcFromOat(oatFile: File): String? {
        if (!oatFile.exists() || oatFile.length() < 4096) return null
        return try {
            val readSize = minOf(32 * 1024L, oatFile.length()).toInt()
            val bytes = ByteArray(readSize)
            RandomAccessFile(oatFile, "r").use { raf -> raf.readFully(bytes) }
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
}
