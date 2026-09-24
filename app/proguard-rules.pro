# ARTisan R8 / ProGuard rules
#
# Compose, Material3, AndroidX and the Kotlin stdlib all ship their own
# consumer keep-rules, so nothing extra is needed for them.
#
# The patching pipeline (Dex2OatRunner) uses no reflection on app classes —
# only ProcessBuilder, java.util.zip and RandomAccessFile — so R8 can shrink
# freely. Add keeps here only if you later reference a class by name.
