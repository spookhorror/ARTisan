package spook.horror.artisan

import android.content.Context
import java.io.File
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

/** APK / DEX inspection and staging helpers. */
internal object ApkTools {

    fun queryApkPackageName(context: Context, apkFile: File): String? = try {
        context.packageManager.getPackageArchiveInfo(apkFile.absolutePath, 0)?.packageName
    } catch (t: Throwable) {
        vlog(TAG, t.message.toString())
        null
    }

    /**
     * Returns installed app's sourceDir, uid (== gid for third-party apps), and its
     * resolved shared-library JAR paths (populated when the manifest declares
     * <uses-library> entries and those libraries are installed on the system).
     */
    fun resolveInstalledApplicationInfo(context: Context, packageName: String): InstalledInfo? = try {
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
     * Copies [src] APK to [dest], forcing every classesN.dex entry to be stored DEFLATED.
     * Everything else is copied through with its original compression method preserved.
     *
     * Why: dex2oat embeds the DEX into the VDEX only when it cannot memory-map the entry
     * straight from the APK — which is exactly when the entry is compressed. An input whose
     * DEX is Stored (uncompressed) yields a VDEX with an empty DexFile section, so the
     * modified bytecode is not self-contained. Compressing the DEX here guarantees a
     * self-contained VDEX regardless of how the input APK stored its DEX. The DEX CRC-32
     * (computed over the uncompressed data) does not change, so checksum patching still
     * works. This working copy is only fed to dex2oat, never installed or launched, so
     * recompressing other entries would be harmless too — we preserve them only to save work.
     */
    fun stageWorkingApkWithCompressedDex(src: File, dest: File): Boolean = try {
        val dexNameRegex = Regex("^classes\\d*\\.dex$")
        ZipFile(src).use { zin ->
            ZipOutputStream(dest.outputStream().buffered()).use { zout ->
                zout.setLevel(Deflater.BEST_SPEED)
                val entries = zin.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    val out = ZipEntry(e.name)
                    if (e.isDirectory) {
                        zout.putNextEntry(out)
                        zout.closeEntry()
                        continue
                    }
                    if (dexNameRegex.matches(e.name)) {
                        out.method = ZipEntry.DEFLATED
                    } else {
                        // Preserve original storage; STORED entries must carry size + crc.
                        out.method = e.method
                        if (e.method == ZipEntry.STORED) {
                            out.size = e.size
                            out.compressedSize = e.size
                            out.crc = e.crc
                        }
                    }
                    zout.putNextEntry(out)
                    zin.getInputStream(e).use { it.copyTo(zout) }
                    zout.closeEntry()
                }
            }
        }
        dest.exists() && dest.length() > 0
    } catch (t: Throwable) {
        vlog(TAG, "  recompress staging failed: ${t.message}")
        try { dest.delete() } catch (_: Throwable) {}
        false
    }

    fun computeDexCrc32(apkFile: File): Long = try {
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
        vlog(TAG, t.message.toString())
        -1L
    }

    /** Reads CRC32 for every `classesN.dex` entry directly from the APK's central directory. */
    fun computeAllDexCrcs(apkFile: File): Map<String, Long> {
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
            vlog(TAG, t.message.toString())
            out
        }
    }
}
