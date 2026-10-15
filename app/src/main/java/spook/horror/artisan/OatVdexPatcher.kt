package spook.horror.artisan

import android.util.Log
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileChannel

/**
 * In-place, memory-mapped patchers for the generated OAT (ODEX) and VDEX artifacts.
 *
 * Both map the target file with a MappedByteBuffer (off-heap) and edit only the small
 * regions that matter — the DEX location string + 4-byte checksums — so multi-hundred-MB
 * multidex artifacts are patched without loading them into the app heap.
 */
internal object OatVdexPatcher {

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
    fun patchOatMultiDex(
        oat: File,
        workingPath: String,
        targetPath: String,
        pickedApkCrcs: Map<String, Long>,
        installedApkCrcs: Map<String, Long>,
    ): PatchResult {
        if (workingPath.length != targetPath.length) {
            return PatchResult(0, false, "path lengths differ (${workingPath.length} vs ${targetPath.length}) — refusing to patch", emptyList())
        }
        val fileLen = oat.length()
        if (fileLen > Int.MAX_VALUE) {
            return PatchResult(0, false, "OAT too large to map (${fileLen} bytes > 2GB)", emptyList())
        }
        return try {
            vlog(TAG, "  [OAT patch] memory-mapping ${fileLen} bytes from ${oat.absolutePath}")
            // Map the OAT in place instead of reading it into the heap. The file can be
            // hundreds of MB for large multidex apps; loading it into a single byte array
            // would blow the app heap (OutOfMemoryError). A MappedByteBuffer lives off-heap
            // and we only touch small regions (the path string + 4-byte checksums).
            RandomAccessFile(oat, "rw").use { raf ->
                val size = fileLen.toInt()
                val buf = raf.channel.map(FileChannel.MapMode.READ_WRITE, 0, fileLen)
                val needle = workingPath.toByteArray(Charsets.US_ASCII)
                vlog(TAG, "  [OAT patch] searching for working path (${needle.size} bytes) in OAT")
                val targetBytes = targetPath.toByteArray(Charsets.US_ASCII)
                val details = mutableListOf<String>()
                val skipped = mutableListOf<String>()
                var searchFrom = 0

                var matchNum = 0
                while (true) {
                    val idx = indexOfBytes(buf, needle, searchFrom)
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
                    val sizeBefore = uint32LE(buf, idx - 4).toInt()
                    vlog(TAG, "  │   the 4 bytes BEFORE the path (the size field) = $sizeBefore")
                    vlog(TAG, "  │   raw size bytes @ 0x%x: %s".format(idx - 4, hex(buf, idx - 4, 4)))
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
                            if (idx + workingPath.length + suffixLen > size) {
                                vlog(TAG, "  └─ skip: suffix would run past end of file")
                                searchFrom = idx + 1; continue
                            }
                            val suffixStr = readAscii(buf, idx + workingPath.length, suffixLen)
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
                    vlog(TAG, "  │   path  BEFORE @ 0x%x: '%s'".format(idx, readAscii(buf, idx, fullLocationLen)))

                    // Overwrite the path prefix with the target path (same length, no shift).
                    for (k in targetBytes.indices) buf.put(idx + k, targetBytes[k])
                    vlog(TAG, "  │   path  AFTER  @ 0x%x: '%s'".format(idx, readAscii(buf, idx, fullLocationLen)))

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
                    val searchEnd = minOf(searchStart + 64, size)
                    if (pickedCrc != null && installedCrc != null) {
                        val pickedPattern = byteArrayOf(
                            (pickedCrc and 0xFF).toByte(),
                            ((pickedCrc shr 8) and 0xFF).toByte(),
                            ((pickedCrc shr 16) and 0xFF).toByte(),
                            ((pickedCrc shr 24) and 0xFF).toByte(),
                        )
                        val checksumOff = indexOfBytes(buf, pickedPattern, searchStart)
                        if (checksumOff in searchStart until searchEnd) {
                            vlog(TAG, "  │   checksum found @ 0x%x (searched picked CRC 0x%08x, gap=%d bytes after path)".format(checksumOff, pickedCrc, checksumOff - searchStart))
                            buf.put(checksumOff, (installedCrc and 0xFF).toByte())
                            buf.put(checksumOff + 1, ((installedCrc shr 8) and 0xFF).toByte())
                            buf.put(checksumOff + 2, ((installedCrc shr 16) and 0xFF).toByte())
                            buf.put(checksumOff + 3, ((installedCrc shr 24) and 0xFF).toByte())
                            vlog(TAG, "  │   checksum AFTER  @ 0x%x: %s (= 0x%08x  ← installed %s CRC)".format(checksumOff, hex(buf, checksumOff, 4), installedCrc, dexName))
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
                    buf.force() // flush the in-place edits to disk
                    val summary = "patched ${details.size} dex_file_location entries" +
                        if (skipped.isNotEmpty()) "; ${skipped.size} false-positives skipped" else ""
                    PatchResult(details.size, true, summary, details + skipped)
                }
            }
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString())
            PatchResult(0, false, "patch error: ${t.message}", emptyList())
        }
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
    fun patchVdexChecksums(
        vdex: File,
        pickedApkCrcs: Map<String, Long>,
        installedApkCrcs: Map<String, Long>,
    ): PatchResult {
        val fileLen = vdex.length()
        if (fileLen < 24) return PatchResult(0, false, "VDEX too small (${fileLen} bytes)", emptyList())
        if (fileLen > Int.MAX_VALUE) return PatchResult(0, false, "VDEX too large to map (${fileLen} bytes > 2GB)", emptyList())
        return try {
            vlog(TAG, "  [VDEX patch] memory-mapping ${fileLen} bytes from ${vdex.absolutePath}")
            RandomAccessFile(vdex, "rw").use { raf ->
                val buf = raf.channel.map(FileChannel.MapMode.READ_WRITE, 0, fileLen)
                val version = try {
                    readAscii(buf, 4, 3).trim().toInt()
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
                if (sortedNames.isEmpty()) return@use PatchResult(0, false, "no CRCs to patch", emptyList())
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
                val idx = indexOfBytes(buf, expected, 0)
                if (idx < 0) {
                    Log.e(TAG, "  [VDEX patch] pattern NOT FOUND — pipeline will fail")
                    return@use PatchResult(
                        0, false,
                        "VDEX v$version: picked APK's CRC sequence not found consecutively — did dex2oat compile the picked APK?",
                        emptyList(),
                    )
                }
                vlog(TAG, "  [VDEX patch] pattern found at offset 0x%x (%d) — this is where the checksums array lives".format(idx, idx))
                vlog(TAG, "  [VDEX patch] BEFORE (whole array): ${hex(buf, idx, sortedNames.size * 4)}")

                // Overwrite each 4-byte slot with the installed APK's CRC for the corresponding dex.
                val details = mutableListOf<String>()
                sortedNames.forEachIndexed { i, name ->
                    val crc = installedApkCrcs[name] ?: return@forEachIndexed
                    val off = idx + i * 4
                    vlog(TAG, "  ┌─ [VDEX] slot $i ($name) @ 0x%x".format(off))
                    vlog(TAG, "  │   BEFORE: %s (= 0x%08x  ← picked-APK CRC dex2oat wrote)".format(hex(buf, off, 4), uint32LE(buf, off)))
                    buf.put(off,     (crc and 0xFF).toByte())
                    buf.put(off + 1, ((crc shr 8) and 0xFF).toByte())
                    buf.put(off + 2, ((crc shr 16) and 0xFF).toByte())
                    buf.put(off + 3, ((crc shr 24) and 0xFF).toByte())
                    vlog(TAG, "  └─ AFTER : %s (= 0x%08x  ← installed-APK CRC, what ART expects)".format(hex(buf, off, 4), crc))
                    details.add("$name @ 0x%x, CRC 0x%08x".format(off, crc))
                }
                vlog(TAG, "  [VDEX patch] AFTER  (whole array): ${hex(buf, idx, sortedNames.size * 4)}")

                buf.force() // flush the in-place edits to disk
                PatchResult(
                    details.size, true,
                    "patched VDEX v$version — ${details.size} CRCs at offset 0x%x (detected)".format(idx),
                    details,
                )
            }
        } catch (t: Throwable) {
            vlog(TAG, t.message.toString())
            PatchResult(0, false, "VDEX patch error: ${t.message}", emptyList())
        }
    }
}
