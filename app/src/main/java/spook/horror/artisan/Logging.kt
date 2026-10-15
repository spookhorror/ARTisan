package spook.horror.artisan

import android.util.Log

/** Logcat tag shared across the pipeline. */
internal const val TAG = "dex2oat-lab"

/**
 * Gated INFO logger. Suppressed unless [Dex2OatRunner.verbose] is on; errors (Log.e)
 * always print. Top-level + `internal` so every file in the package logs the same way
 * without threading a logger through each object.
 */
internal fun vlog(tag: String, msg: String) {
    if (Dex2OatRunner.verbose) Log.i(tag, msg)
}
