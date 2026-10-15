package spook.horror.artisan

import java.nio.ByteBuffer

/**
 * Low-level byte helpers for locating and editing fields inside OAT/VDEX artifacts.
 *
 * Two flavours exist:
 *  - `ByteArray` versions, used for small in-memory buffers (e.g. the CLC scan).
 *  - `ByteBuffer` versions, used against a memory-mapped file so large OAT/VDEX
 *    files are edited in place, off-heap. Absolute get(i)/put(i,b) don't move the
 *    buffer position.
 *
 * `internal` + same package → the pipeline calls these unqualified.
 */

/** Little-endian uint32 read from a mapped buffer at [offset]. */
internal fun uint32LE(buf: ByteBuffer, offset: Int): Long =
    (buf.get(offset).toLong() and 0xFF) or
        ((buf.get(offset + 1).toLong() and 0xFF) shl 8) or
        ((buf.get(offset + 2).toLong() and 0xFF) shl 16) or
        ((buf.get(offset + 3).toLong() and 0xFF) shl 24)

/** Read [len] ASCII bytes from a mapped buffer at [off] as a String. */
internal fun readAscii(buf: ByteBuffer, off: Int, len: Int): String {
    val arr = ByteArray(len)
    for (i in 0 until len) arr[i] = buf.get(off + i)
    return String(arr, Charsets.US_ASCII)
}

/** Pretty-print [len] bytes at [off] as space-separated hex, for logs. */
internal fun hex(bytes: ByteArray, off: Int, len: Int): String {
    if (off < 0 || off >= bytes.size) return "<out of range>"
    val end = minOf(off + len, bytes.size)
    val sb = StringBuilder()
    for (i in off until end) sb.append("%02x ".format(bytes[i].toInt() and 0xFF))
    return sb.toString().trim()
}

/** Pretty-print [len] bytes at [off] of a mapped buffer as space-separated hex, for logs. */
internal fun hex(buf: ByteBuffer, off: Int, len: Int): String {
    val cap = buf.capacity()
    if (off < 0 || off >= cap) return "<out of range>"
    val end = minOf(off + len, cap)
    val sb = StringBuilder()
    for (i in off until end) sb.append("%02x ".format(buf.get(i).toInt() and 0xFF))
    return sb.toString().trim()
}

/** First offset >= [from] where [needle] occurs in [haystack], or -1. */
internal fun indexOfBytes(haystack: ByteArray, needle: ByteArray, from: Int = 0): Int {
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

/** First offset >= [from] where [needle] occurs in the mapped buffer [haystack], or -1. */
internal fun indexOfBytes(haystack: ByteBuffer, needle: ByteArray, from: Int): Int {
    val n = needle.size
    val cap = haystack.capacity()
    if (n == 0 || cap < n) return -1
    var i = maxOf(0, from)
    val last = cap - n
    outer@ while (i <= last) {
        var j = 0
        while (j < n) {
            if (haystack.get(i + j) != needle[j]) { i++; continue@outer }
            j++
        }
        return i
    }
    return -1
}
