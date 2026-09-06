//package spook.horror.security
//
///**
// * LicenseGate — a deliberately simple "protected" check, the classic target a
// * patcher flips. Kept trivial on purpose: the point of the lab is to observe how
// * dex2oat/OAT binding and IntegrityGuard interact with a method like this, not to
// * build real DRM (a single boolean is exactly what makes naive checks weak).
// */
//object LicenseGate {
//
//    /** A real app would verify a signed license/entitlement server-side. */
//    fun isPro(): Boolean = false
//
//    /**
//     * What a compiled OAT actually contains for isPro():
//     *   - dex2oat turns the DEX `const/4 v0, 0x0 ; return v0` into native code
//     *     (e.g. arm64 `mov w0, #0 ; ret`).
//     *   - The OAT patch technique rewrites those native bytes to `mov w0, #1`.
//     *   - On Android 9+ that only "sticks" if the vdex/oat checksums stay
//     *     consistent AND the method was AOT-compiled at all; otherwise ART runs
//     *     the DEX from the (signed) APK and the patch is ignored.
//     *
//     * Use oatdump (see tools/oat-lab.ps1) to see the generated native code for
//     * this method on your own build.
//     */
//    const val EXPLAINER: String = "isPro() compiles to a constant-return; that is the code an OAT patch targets."
//}
