from ..ANSI_COLORS import ANSI; C = ANSI()
from ..MODULES import IMPORT; M = IMPORT()


# ---------------- Smali Patch ----------------
def Smali_Patch(smali_folders, CoreX_Hook, isCoreX):

    target_files = [
        "SignatureCheck.smali",
        "LicenseClientV3.smali",
        "LicenseClient.smali",
        "Application.smali",
        "VMRunner.smali",
        "StartupLauncher.smali"
    ]

    patterns = []

    if not (isCoreX and not CoreX_Hook):
        patterns.extend(
            [
                (
                    r'invoke-static \{[^\}]*\}, Lcom/pairip/SignatureCheck;->verifyIntegrity\(Landroid/content/Context;\)V',
                    r'#',
                    "VerifyIntegrity"
                ),
                (
                    r'(\.method [^(]*verifyIntegrity\(Landroid/content/Context;\)V\s+.locals \d+)[\s\S]*?(\s+return-void\n.end method)',
                    r'\1\2',
                    "VerifyIntegrity"
                ),
                (
                    r'(\.method [^(]*verifySignatureMatches\(Ljava/lang/String;\)Z\s+.locals \d+\s+)[\s\S]*?(\s+return ([pv]\d+)\n.end method)',
                    r'\1const/4 \3, 0x1\2',
                    "verifySignatureMatches"
                ),
                (
                    r'(\.method [^(]*connectToLicensingService\(\)V\s+.locals \d+)[\s\S]*?(\s+return-void\n.end method)',
                    r'\1\2',
                    "connectToLicensingService"
                ),
                (
                    r'(\.method [^(]*initializeLicenseCheck\(\)V\s+.locals \d+)[\s\S]*?(\s+return-void\n.end method)',
                    r'\1\2',
                    "initializeLicenseCheck"
                ),
                (
                    r'(\.method [^(]*processResponse\(ILandroid/os/Bundle;\)V\s+.locals \d+)[\s\S]*?(\s+return-void\n.end method)',
                    r'\1\2',
                    "processResponse"
                )
            ]
        )

    # ---------------- Remove loadLibrary("pairipcore") from clinit (always) ----------------
    print(f"\n{C.INFO}{C.C} Searching for {C.OG}loadLibrary(\"pairipcore\"){C.C} in VMRunner clinit to remove...")

    patterns.append(
        (
            r'\n\s*const-string v\d+, "pairipcore"\n\s*invoke-static \{v\d+\}, Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V',
            r'',
            'CoreX_Hook RemovePairipcore'
        )
    )

    # ---------------- Bypass StartupLauncher.launch() so <clinit> completes ----------------
    # StartupLauncher.launch() is called from MyApplication.<clinit>() — a STATIC initializer.
    # Static initializers run before Application.<init>(), so if launch() crashes
    # (UnsatisfiedLinkError on executeVM because libpairipcore is not loaded),
    # Application.<init>() never runs, callobjects() never fires, and no dictionary is dumped.
    # Fix: make launch() return-void immediately so <clinit> completes safely.
    patterns.append(
        (
            r'(\.method public static declared-synchronized launch\(\)V\s+)\.locals \d+[\s\S]*?(\n\.end method)',
            r'\1.locals 0\n\n    return-void\2',
            'StartupLauncher launch() bypass'
        )
    )

    # ---------------- loadLibrary ➢ '_Pairip_CoreX' ----------------
    if CoreX_Hook or isCoreX:

        patterns.append(
            (
                r'(\.method [^<]*<clinit>\(\)V\s+.locals \d+\n)',
                r'\1\tconst-string v0, "_Pairip_CoreX"\n\tinvoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n',
                f'CoreX_Hook ➸❥ {C.OG}"lib_Pairip_CoreX.so"'
            )
        )

    Smali_Files = []
    for smali_folder in smali_folders:
        for root, _, files in M.os.walk(smali_folder):
            for file in files:
                if file in target_files:
                    Smali_Files.append(M.os.path.join(root, file))

    vmrunner_path = next((f for f in Smali_Files if f.endswith("VMRunner.smali")), None)
    startup_path = next((f for f in Smali_Files if f.endswith("StartupLauncher.smali")), None)

    if vmrunner_path:
        print(f"\n{C.S} Found {C.E} {C.G}VMRunner.smali {C.OG}➸❥ {C.Y}{vmrunner_path}")
    else:
        print(f"\n{C.WARN} VMRunner.smali NOT FOUND in any smali folder  ✘")

    if startup_path:
        print(f"\n{C.S} Found {C.E} {C.G}StartupLauncher.smali {C.OG}➸❥ {C.Y}{startup_path}")
    else:
        print(f"\n{C.WARN} StartupLauncher.smali NOT FOUND in any smali folder  ✘")

    for pattern, replacement, description in patterns:
        for Smali_File in Smali_Files:
            try:
                if description.startswith("CoreX_Hook") and not Smali_File.endswith("VMRunner.smali"):
                    continue
                if description == 'StartupLauncher launch() bypass' and not Smali_File.endswith("StartupLauncher.smali"):
                    continue

                content = open(Smali_File, 'r', encoding='utf-8', errors='ignore').read()
                new_content = M.re.sub(pattern, replacement, content)

                if new_content != content:
                    print(f"\n{C.S} Patch {C.E} {C.G}{description} {C.OG}➸❥ {C.Y}{M.os.path.basename(Smali_File)}")
                    print(f"{C.G}    |\n    └── {C.CC}Pattern {C.OG}➸❥ {C.P}{pattern}")
                    open(Smali_File, 'w', encoding='utf-8', errors='ignore').write(new_content)

                    if description == 'CoreX_Hook RemovePairipcore':
                        print(f"{C.G}    |\n    └── {C.CC}Result  {C.OG}➸❥ {C.G}loadLibrary(\"pairipcore\") REMOVED from clinit  ✔")
                    elif description == 'StartupLauncher launch() bypass':
                        print(f"{C.G}    |\n    └── {C.CC}Result  {C.OG}➸❥ {C.G}StartupLauncher.launch() bypassed — <clinit> will complete safely  ✔")

            except Exception as e:
                pass

    if vmrunner_path:
        try:
            final = open(vmrunner_path, 'r', encoding='utf-8', errors='ignore').read()
            if '"pairipcore"' in final:
                print(f"\n{C.WARN} VERIFY  {C.OG}➸❥ {C.R}\"pairipcore\" still present in VMRunner.smali  ✘")
            else:
                print(f"\n{C.S} VERIFY  {C.E} {C.G}\"pairipcore\" successfully removed from VMRunner.smali  ✔")
        except Exception:
            pass

    if startup_path:
        try:
            final = open(startup_path, 'r', encoding='utf-8', errors='ignore').read()
            if 'return-void\n.end method' in final and '.locals 0' in final:
                print(f"\n{C.S} VERIFY  {C.E} {C.G}StartupLauncher.launch() is now a no-op  ✔")
            else:
                print(f"\n{C.WARN} VERIFY  {C.OG}➸❥ {C.R}StartupLauncher.launch() was NOT bypassed  ✘")
        except Exception:
            pass

    print(f"\n{C.CC}{'_' * 61}\n")
