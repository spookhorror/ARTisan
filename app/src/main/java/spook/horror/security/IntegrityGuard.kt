//package spook.horror.security
//
//import android.content.Context
//import java.util.zip.Adler32
//import java.util.zip.ZipFile
//
///**
// * IntegrityGuard — the defensive payoff of understanding dex2oat.
// *
// * ART binds a compiled OAT/VDEX to its DEX through the DEX header's adler32
// * checksum. This class recomputes that checksum over the app's OWN classes.dex
// * and compares it to the value stored in the header. That is exactly the check
// * that makes on-disk OAT/DEX patching fall over on modern Android:
// *
// *   - patch the DEX but forget the checksum  -> mismatch, detected here + rejected by ART
// *   - patch the checksum to match            -> the APK signature (v1/v2/v3) now breaks
// *
// * So an app can cheaply notice "my executable code no longer matches what shipped",
// * which is the honest security use of this whole area.
// */
//object IntegrityGuard {
//
//    data class Result(
//        val dexPath: String,
//        val storedChecksum: Long,     // value written in the DEX header
//        val computedChecksum: Long,   // adler32 we recomputed over the body
//        val intact: Boolean,          // stored == computed
//        val classLoaderDexPaths: List<String>,
//        val detail: String,
//    )
//
//    fun verify(context: Context): Result {
//        val apkPath = context.applicationInfo.sourceDir
//        return try {
//            ZipFile(apkPath).use { zip ->
//                val entry = zip.getEntry("classes.dex")
//                    ?: return errored(apkPath, "no classes.dex entry in APK")
//
//                val bytes = zip.getInputStream(entry).use { it.readBytes() }
//                if (bytes.size < 12) return errored(apkPath, "classes.dex too small")
//
//                // Header: magic[8], checksum[4] (adler32, little-endian), signature[20], ...
//                val stored = u32le(bytes, 8)
//
//                // The DEX checksum is adler32 of everything AFTER the checksum field,
//                // i.e. from offset 12 to the end of the file.
//                val adler = Adler32()
//                adler.update(bytes, 12, bytes.size - 12)
//                val computed = adler.value
//
//                Result(
//                    dexPath = "$apkPath!classes.dex",
//                    storedChecksum = stored,
//                    computedChecksum = computed,
//                    intact = stored == computed,
//                    classLoaderDexPaths = loadedDexPaths(),
//                    detail = if (stored == computed)
//                        "DEX body matches its header checksum — code is as shipped."
//                    else
//                        "MISMATCH — the DEX body was altered without fixing the checksum.",
//                )
//            }
//        } catch (t: Throwable) {
//            errored(apkPath, t.message ?: "verify error")
//        }
//    }
//
//    /** Ask the running ClassLoader which dex containers it actually loaded us from. */
//    private fun loadedDexPaths(): List<String> = try {
//        val cl = IntegrityGuard::class.java.classLoader
//        // BaseDexClassLoader.toString() lists its DexPathList entries on Android.
//        cl?.toString()
//            ?.substringAfter("DexPathList[", "")
//            ?.substringBeforeLast("]")
//            ?.split(",")
//            ?.map { it.trim() }
//            ?.filter { it.isNotEmpty() }
//            ?: emptyList()
//    } catch (t: Throwable) {
//        emptyList()
//    }
//
//    private fun u32le(b: ByteArray, off: Int): Long =
//        (b[off].toLong() and 0xFF) or
//            ((b[off + 1].toLong() and 0xFF) shl 8) or
//            ((b[off + 2].toLong() and 0xFF) shl 16) or
//            ((b[off + 3].toLong() and 0xFF) shl 24)
//
//    private fun errored(apkPath: String, msg: String) =
//        Result("$apkPath!classes.dex", -1, -1, false, emptyList(), msg)
//}
