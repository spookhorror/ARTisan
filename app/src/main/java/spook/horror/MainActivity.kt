package spook.horror

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import spook.horror.security.Dex2OatRunner
import spook.horror.ui.theme.Dex2oatTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            Dex2oatTheme {
                LabScaffold()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun LabScaffold() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var running by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<Dex2OatRunner.RunResult?>(null) }

    val pickApkLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        running = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { Dex2OatRunner.runOnApkUri(context, uri) }
            result = r
            running = false
        }
    }

    val onPick: () -> Unit = {
        result = null
        pickApkLauncher.launch(arrayOf("application/vnd.android.package-archive"))
    }

    var menuOpen by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    var verbose by remember { mutableStateOf(Dex2OatRunner.verbose) }

    if (showAbout) {
        AboutDialog(onDismiss = { showAbout = false })
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("ARTisan", fontWeight = FontWeight.Bold)
                        Text(
                            "ODEX / VDEX Patcher",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { menuOpen = true }) {
                        Text(
                            "⋮",
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                    }
                    DropdownMenu(
                        expanded = menuOpen,
                        onDismissRequest = { menuOpen = false },
                    ) {
                        DropdownMenuItem(
                            text = { Text("Verbose logging") },
                            trailingIcon = { Text(if (verbose) "On ✓" else "Off") },
                            onClick = {
                                verbose = !verbose
                                Dex2OatRunner.verbose = verbose
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("About") },
                            onClick = {
                                menuOpen = false
                                showAbout = true
                            },
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer,
                ),
            )
        },
    ) { innerPadding ->
        LabScreen(
            modifier = Modifier.padding(innerPadding),
            running = running,
            result = result,
            onPick = onPick,
        )
    }
}

@Composable
private fun AboutDialog(onDismiss: () -> Unit) {
    // ─── Fill in your details here ───────────────────────────────
    val authorName = "Varun Kumar/ spookhorror"
    val authorHandle = "@spookhorror"
    val blogUrl = "spookhorror.gitbook.io/"
    // ─────────────────────────────────────────────────────────────

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
        title = { Text("About ARTisan") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "A research lab for understanding how ART trusts compiled code — " +
                        "it compiles the OAT, patches its ODEX / VDEX checksums, and lets ART load it.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(2.dp))
                LabeledLine("Author", authorName)
                LabeledLine("Contact", authorHandle)
                LabeledLine("Write-up", blogUrl)
                Spacer(Modifier.height(2.dp))
                Text(
                    "For research and education on devices/apps you own or are authorized to test.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

@Composable
private fun LabScreen(
    modifier: Modifier = Modifier,
    running: Boolean,
    result: Dex2OatRunner.RunResult?,
    onPick: () -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Primary action lives up top — the first thing the user sees and can act on.
        HeroActionCard(running = running, hasResult = result != null, onPick = onPick)

        if (running) {
            RunningCard()
        }

        if (result != null) {
            ResultSection(result)
        } else if (!running) {
            // Idle: keep the explainer available but secondary, below the action.
            MechanismCard()
            CompatibilityCard()
        }
    }
}

@Composable
private fun HeroActionCard(running: Boolean, hasResult: Boolean, onPick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Column(Modifier.padding(20.dp)) {
            Text(
                "Compile & patch ODEX / VDEX",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "Pick an APK whose package is installed on this device. We compile a fresh OAT, " +
                    "patch its ODEX + VDEX checksums, and drop them into the app's own oat/<isa>/ folder.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = onPick,
                enabled = !running,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                ),
            ) {
                Text(
                    when {
                        running -> "Working…"
                        hasResult -> "Pick another APK"
                        else -> "Select APK & Compile"
                    },
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(
                "Requires root. Pick the base APK (must contain classes.dex).",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

@Composable
private fun ResultSection(r: Dex2OatRunner.RunResult) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OverallStatusCard(r)

        StepCard(
            stepNumber = 1,
            title = "Source + installed CRC32s captured",
            subtitle = "Every classesN.dex in the INSTALLED target has its own OatDexFileHeader entry — we patch each one",
            statusOk = r.originalDexCrc32 >= 0 && r.installedDexCrcs.isNotEmpty(),
        ) {
            LabeledLine("source (picked)", r.sourceApkPath)
            LabeledLine("source classes.dex CRC32", "0x%08x".format(r.originalDexCrc32))
            LabeledLine("installed target", r.targetInstallPath)
            Text(
                "installed CRC32s (${r.installedDexCrcs.size} dex files):",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            r.installedDexCrcs.entries.sortedBy { it.key.length }.forEach { (name, crc) ->
                LabeledLine("  $name", "0x%08x".format(crc))
            }
        }

        StepCard(
            stepNumber = 2,
            title = "Sabanal path padding",
            subtitle = "Working path padded with '1's so length matches target — byte-patch needs no offset relocation",
            statusOk = r.pathsLengthMatch,
        ) {
            LabeledLine("target install (${r.targetInstallPath.length} chars)", r.targetInstallPath)
            LabeledLine("working path (${r.workingDexPath.length} chars)", r.workingDexPath)
            StatusRow("lengths match", r.pathsLengthMatch)
        }

        StepCard(
            stepNumber = 3,
            title = "dex2oat invocation",
            subtitle = "Same command shape installd uses (only ISA differs by device)",
            statusOk = r.exitCode == 0 && r.outOatExists,
        ) {
            LabeledLine("instruction set", r.instructionSet)
            LabeledLine("class-loader-context", r.classLoaderContext ?: "-")
            Text(
                "  ↳ ${r.classLoaderContextSource}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))
            Text("command", style = MaterialTheme.typography.labelSmall)
            CodeBlock(r.command.joinToString(" \\\n  "))
            LabeledLine("exit code", r.exitCode.toString())
            if (r.stderr.isNotBlank()) {
                Text("stderr", style = MaterialTheme.typography.labelSmall)
                CodeBlock(r.stderr.trim())
            }
        }

        StepCard(
            stepNumber = 4,
            title = "OAT produced",
            subtitle = "dex2oat wrote the compiled OAT into this app's private files dir",
            statusOk = r.outOatExists,
        ) {
            LabeledLine("path", r.outOatPath)
            LabeledLine("size", if (r.outOatExists) "%,d bytes".format(r.outOatSizeBytes) else "absent")
            LabeledLine("detail", r.detail)
        }

        StepCard(
            stepNumber = 5,
            title = "ODEX byte-patch (multi-dex)",
            subtitle = "For EACH classesN.dex: dex_file_location_data → target install path, dex_file_location_checksum → installed target's classesN.dex CRC32 (validated against the installed APK)",
            statusOk = r.patchApplied && r.patchCount == r.installedDexCrcs.size,
        ) {
            LabeledLine("entries patched", "${r.patchCount} of ${r.installedDexCrcs.size} expected")
            StatusRow("all entries patched", r.patchCount == r.installedDexCrcs.size && r.patchApplied)
            Text(r.patchDetail, style = MaterialTheme.typography.bodySmall)
            if (r.patchPerDex.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                r.patchPerDex.forEach {
                    Text(
                        "  $it",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
            }
        }

        StepCard(
            stepNumber = 6,
            title = "VDEX byte-patch (dex_checksums array)",
            subtitle = "VDEX header carries its OWN CRC array, validated against the installed APK's DEX CRC — the same ground truth the ODEX is checked against. ART checks each independently, so you must patch both. Offset found by searching for the picked CRCs (version-agnostic; v027 stores them at 0x3c), 4 bytes per dex, natural order.",
            statusOk = r.vdexPatchApplied && r.vdexPatchCount == r.installedDexCrcs.size,
        ) {
            LabeledLine("entries patched", "${r.vdexPatchCount} of ${r.installedDexCrcs.size} expected")
            StatusRow("all entries patched", r.vdexPatchCount == r.installedDexCrcs.size && r.vdexPatchApplied)
            Text(r.vdexPatchDetail, style = MaterialTheme.typography.bodySmall)
            if (r.vdexPatchPerDex.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                r.vdexPatchPerDex.forEach {
                    Text(
                        "  $it",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
            }
        }

        StepCard(
            stepNumber = 7,
            title = "Permission fixups",
            subtitle = "chmod 644 + chown 1000:<targetUid> — matches installd output (uid 1000 = system, group = target app's own uid)",
            statusOk = r.permissionsApplied,
        ) {
            StatusRow("permissions applied", r.permissionsApplied)
            Text(r.permissionsDetail, style = MaterialTheme.typography.bodySmall)
        }

        StepCard(
            stepNumber = 8,
            title = "Move to install-dir oat/<isa>/",
            subtitle = "Copies odex+vdex into the target APK's real install dir (the final step). " +
                "Skipped when the target isn't installed, or when any earlier step failed.",
            statusOk = if (r.moveAttempted) r.moveApplied else true,
        ) {
            if (!r.moveAttempted) {
                Text(
                    r.moveDetail,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                LabeledLine("moved odex", r.movedOdexPath)
                LabeledLine("moved vdex", r.movedVdexPath)
                StatusRow("copied + relabeled", r.moveApplied)
                Text(r.moveDetail, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(6.dp))
                Text(
                    "⚠ Warning: on next launch of the target app, ART will try to load this OAT. " +
                        "For the OWN app this means the CURRENT running process still uses its old OAT; " +
                        "the replacement takes effect only on next restart. If patch/perms are wrong, ART rejects it and falls back to running the DEX.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}

@Composable
private fun OverallStatusCard(r: Dex2OatRunner.RunResult) {
    val allOk = r.outOatExists && r.exitCode == 0 && r.pathsLengthMatch && r.patchApplied && r.vdexPatchApplied && r.permissionsApplied
    val bg = if (allOk) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.errorContainer
    val fg = if (allOk) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onErrorContainer
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = bg),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(
                if (allOk) "Pipeline succeeded" else "Pipeline finished with issues",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = fg,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (allOk)
                    "%,d-byte OAT produced at %s, header patched, permissions applied. This matches installd's output shape."
                        .format(r.outOatSizeBytes, r.outOatPath)
                else
                    "See the step cards below for which stage failed and why.",
                style = MaterialTheme.typography.bodySmall,
                color = fg,
            )
        }
    }
}

@Composable
private fun RunningCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(24.dp),
                strokeWidth = 3.dp,
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    "dex2oat is compiling…",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    "Typically takes 5–15 seconds for a mid-size APK. All 8 cores hot.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun MechanismCard() {
    SectionCard(title = "How it works") {
        Text(
            "Eight steps, executed as root, reproducing installd's OAT-replacement flow:",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(8.dp))
        BulletLine("1", "Read picked APK → get package name → look up installed app's sourceDir via PackageManager, read every classesN.dex CRC32 from the installed APK")
        BulletLine("2", "Copy APK to /data/tmp/<pad>/base.apk where <pad> = '1' × N so total path length equals installed sourceDir length")
        BulletLine("3", "Run dex2oat --dex-file=<padded> --oat-file=<filesDir>/oat/<isa>/base.odex --class-loader-context=PCL[] --instruction-set=<isa>")
        BulletLine("4", "Multi-dex ODEX patch: for EACH classesN.dex, swap dex_file_location_data → installed sourceDir and dex_file_location_checksum → installed classesN.dex CRC32")
        BulletLine("5", "VDEX patch: locate the dex_checksums array by searching for the picked CRC32s (version-agnostic — no hardcoded offset) and overwrite with the installed CRC32s — ART validates the VDEX against the installed APK too, independently of the ODEX")
        BulletLine("6", "chmod 644 + chown 1000:<targetUid> on odex & vdex — matches installd output (group = target app's uid)")
        BulletLine("7", "Copy odex+vdex to <installed-sourceDir>/oat/<isa>/, chmod/chown, and restorecon -R for SELinux labels")
        BulletLine("8", "(Not shown) target app's next launch — ART loads the patched OAT")
        Spacer(Modifier.height(8.dp))
        Text(
            "The picked APK must correspond to a currently-INSTALLED app. Effect is visible after the target app is restarted (its currently-running process still holds the old OAT).",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun CompatibilityCard() {
    SectionCard(title = "Android version compatibility") {
        CompatRow("Android 11 (API 30)", "works cleanly — dex2oat via ART APEX")
        CompatRow("Android 12 / 12L (31–32)", "works cleanly")
        CompatRow("Android 13 (33)", "works cleanly")
        CompatRow("Android 14 (34)", "works with root; sepolicy on some vendor builds may block dex2oat — Magisk sepatch usually lifts this")
        CompatRow("Android 15 (35)", "same story as 14")
        CompatRow("Android 16 (36)", "same story as 14")
        Spacer(Modifier.height(6.dp))
        Text(
            "OAT header format changes across versions but our byte-patch is version-agnostic — " +
                "it finds each entry by the ASCII path bytes and validates it via the uint32 size " +
                "prefix, and the VDEX patch searches for the CRC array instead of hardcoding an offset, " +
                "so any OAT/VDEX version works.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun StepCard(
    stepNumber: Int,
    title: String,
    subtitle: String,
    statusOk: Boolean,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                StepBadge(stepNumber, statusOk)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) { content() }
        }
    }
}

@Composable
private fun StepBadge(n: Int, ok: Boolean) {
    val bg = if (ok) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.errorContainer
    val fg = if (ok) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onErrorContainer
    Box(
        modifier = Modifier
            .size(32.dp)
            .background(bg, shape = RoundedCornerShape(8.dp)),
        contentAlignment = Alignment.Center,
    ) {
        Text(n.toString(), color = fg, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun BulletLine(marker: String, text: String) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(
            marker,
            modifier = Modifier.width(20.dp),
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(text, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun CompatRow(version: String, note: String) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(
            version,
            modifier = Modifier.width(150.dp),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Medium,
        )
        Text(note, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun LabeledLine(label: String, value: String) {
    Column(Modifier.padding(vertical = 2.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            lineHeight = 16.sp,
        )
    }
}

@Composable
private fun StatusRow(label: String, ok: Boolean) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 2.dp)) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .background(
                    if (ok) Color(0xFF3DDC84) else MaterialTheme.colorScheme.error,
                    shape = RoundedCornerShape(5.dp),
                ),
        )
        Spacer(Modifier.width(8.dp))
        Text(label, style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.width(6.dp))
        Text(
            if (ok) "✓" else "✗",
            fontWeight = FontWeight.Bold,
            color = if (ok) Color(0xFF3DDC84) else MaterialTheme.colorScheme.error,
        )
    }
}

@Composable
private fun CodeBlock(text: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(6.dp),
            )
            .padding(8.dp),
    ) {
        Box(modifier = Modifier.horizontalScroll(rememberScrollState())) {
            Text(
                text = text,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                lineHeight = 15.sp,
            )
        }
    }
}
