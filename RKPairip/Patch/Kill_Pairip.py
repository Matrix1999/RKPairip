from ..ANSI_COLORS import ANSI; C = ANSI()
from ..MODULES import IMPORT; M = IMPORT()

from RKPairip.Patch.Manifest_Patch import Decode_Manifest, Encode_Manifest, Fix_Manifest

C_Line = f"{C.CC}{'_' * 61}"


# ---------------- Find user's real Application class ----------------
def Find_Real_App_Class(smali_folders):
    """Locate com/pairip/application/Application.smali across ALL smali folders
    and read its `.super` line to recover the user's real Application class."""

    rel = M.os.path.join("com", "pairip", "application", "Application.smali")
    super_pat = M.re.compile(r'\.super\s+L([^;\s]+);')

    for folder in smali_folders:
        candidate = M.os.path.join(folder, rel)
        if M.os.path.isfile(candidate):
            try:
                content = open(candidate, 'r', encoding='utf-8', errors='ignore').read()
            except Exception:
                continue
            m = super_pat.search(content)
            if m:
                cls = m.group(1).replace('/', '.')
                # Sanity: don't return android.app.Application — that means it's already neutered
                if cls and cls != 'android.app.Application':
                    return cls

    # Fallback: walk every smali folder for any file at com/pairip/application/Application.smali
    for folder in smali_folders:
        for root, dirs, files in M.os.walk(folder):
            if 'Application.smali' in files and root.endswith(M.os.path.join('com', 'pairip', 'application')):
                fp = M.os.path.join(root, 'Application.smali')
                try:
                    content = open(fp, 'r', encoding='utf-8', errors='ignore').read()
                except Exception:
                    continue
                m = super_pat.search(content)
                if m:
                    cls = m.group(1).replace('/', '.')
                    if cls and cls != 'android.app.Application':
                        return cls

    return None


# ---------------- Detect Pairip VMRunner method protection ----------------
def Detect_VMRunner(smali_folders):
    """Detect Pairip VMRunner-style method protection.

    VMRunner replaces method bodies with reflection trampolines and stores the
    target Method objects in junk holder classes that contain ONLY:
        .field public static <name>:Ljava/lang/reflect/Method;
    declarations and NO `<clinit>` (libpairipcore populates them at runtime).

    If we strip pairip on such an APK, every protected method NPEs on
    Method.invoke(...). Refuse early with a clear message.

    Returns (count, samples) — count of holder classes detected, up to 5 sample paths.
    """

    field_pat = M.re.compile(r'^\.field\s+public\s+static\s+\w+\s*:\s*Ljava/lang/reflect/Method;\s*$', M.re.M)
    clinit_pat = M.re.compile(r'\.method\s+static\s+constructor\s+<clinit>\(\)V')

    holder_count = 0
    samples = []

    for smali_folder in smali_folders:
        for root, _, files in M.os.walk(smali_folder):
            for f in files:
                if not f.endswith('.smali'):
                    continue
                fp = M.os.path.join(root, f)
                try:
                    content = open(fp, 'r', encoding='utf-8', errors='ignore').read()
                except Exception:
                    continue

                method_fields = field_pat.findall(content)
                if len(method_fields) < 2:
                    continue
                # Must have NO <clinit> (i.e. fields are populated externally)
                if clinit_pat.search(content):
                    continue

                holder_count += 1
                if len(samples) < 5:
                    rel = M.os.path.relpath(fp, smali_folder)
                    samples.append(f"{rel} ({len(method_fields)} Method fields)")

    return holder_count, samples


# ---------------- Strip com/pairip/* + residual references ----------------
def Strip_Pairip_Smali(smali_folders):

    print(
        f"{C_Line}\n\n"
        f"\n{C.X}{C.C} Kill Pairip {C.OG}➸❥ {C.G}Removing com/pairip/* smali tree\n"
    )

    deleted_dirs = 0
    for smali_folder in smali_folders:
        path = M.os.path.join(smali_folder, "com", "pairip")
        if M.os.path.isdir(path):
            M.shutil.rmtree(path)
            print(f"{C.G}  |\n  └──── {C.CC}Deleted ~{C.G}$ {C.Y}{M.os.path.relpath(path)} {C.G} ✔")
            deleted_dirs += 1

    # Strip residual invoke-* to com/pairip/* and field refs that may exist outside that folder.
    pairip_invoke = M.re.compile(r'[ \t]*invoke-[^\s]+\s*\{[^\}]*\},\s*Lcom/pairip/[^\s\n]+\n')
    pairip_static = M.re.compile(r'[ \t]*sget-object\s+[vp]\d+,\s*Lcom/pairip/[^\s\n]+\n')

    cleaned_files = 0
    for smali_folder in smali_folders:
        for root, _, files in M.os.walk(smali_folder):
            for fname in files:
                if not fname.endswith('.smali'):
                    continue
                fp = M.os.path.join(root, fname)
                try:
                    content = open(fp, 'r', encoding='utf-8', errors='ignore').read()
                except Exception:
                    continue
                if 'Lcom/pairip/' not in content:
                    continue
                new_content = pairip_invoke.sub('', content)
                new_content = pairip_static.sub('', new_content)
                if new_content != content:
                    open(fp, 'w', encoding='utf-8', errors='ignore').write(new_content)
                    cleaned_files += 1

    print(
        f"\n{C.S} Folders Deleted {C.E} {C.OG}➸❥ {C.PN}{deleted_dirs} {C.G} ✔"
        f"\n{C.S} Smali Cleaned  {C.E} {C.OG}➸❥ {C.PN}{cleaned_files} {C.G} ✔\n"
        f"\n{C_Line}\n"
    )


# ---------------- Kill Pairip in Manifest ----------------
def Kill_Pairip_Manifest(decompile_dir, manifest_path, d_manifest_path, isAPKTool, App_Name, Super_Value):

    print(
        f"\n{C.X}{C.C} Kill Pairip {C.OG}➸❥ {C.G}Rewriting AndroidManifest.xml\n"
    )

    if isAPKTool:
        Decode_Manifest(manifest_path, d_manifest_path)
        target = d_manifest_path
    else:
        target = manifest_path

    # Strip Pairip license / vending / split meta-data + receivers
    Fix_Manifest(target)

    # Replace android:name="com.pairip.application.Application" -> user's real Application
    content = open(target, 'r', encoding='utf-8', errors='ignore').read()

    if App_Name and App_Name in content and Super_Value and App_Name != Super_Value:
        new_content = content.replace(App_Name, Super_Value)
        open(target, 'w', encoding='utf-8', errors='ignore').write(new_content)

        print(
            f"\n{C.S} Replaced {C.E} {C.P}'{C.G}{App_Name}{C.P}' {C.OG}➸❥ {C.P}'{C.C}{Super_Value}{C.P}' {C.G} ✔\n"
        )
    else:
        print(f"\n{C.WARN} Could not swap Application class — App_Name={App_Name} Super={Super_Value}\n")

    if isAPKTool:
        Encode_Manifest(decompile_dir, manifest_path, d_manifest_path)


# ---------------- Strip libpairipcore.so from native lib folders ----------------
def Strip_Pairip_Native(decompile_dir, isAPKTool):

    print(
        f"\n{C.X}{C.C} Kill Pairip {C.OG}➸❥ {C.G}Removing libpairipcore.so from lib/*\n"
    )

    # APKTool: <decompile_dir>/lib/<arch>/
    # APKEditor: <decompile_dir>/root/lib/<arch>/
    lib_roots = [
        M.os.path.join(decompile_dir, 'lib'),
        M.os.path.join(decompile_dir, 'root', 'lib'),
    ]

    targets = ('libpairipcore.so',)

    removed = 0
    for lib_root in lib_roots:
        if not M.os.path.isdir(lib_root):
            continue
        for arch in M.os.listdir(lib_root):
            arch_dir = M.os.path.join(lib_root, arch)
            if not M.os.path.isdir(arch_dir):
                continue
            for fname in M.os.listdir(arch_dir):
                if fname in targets:
                    fp = M.os.path.join(arch_dir, fname)
                    try:
                        M.os.remove(fp)
                        print(f"{C.G}  |\n  └──── {C.CC}Deleted ~{C.G}$ {C.Y}lib/{arch}/{fname} {C.G} ✔")
                        removed += 1
                    except Exception as e:
                        print(f"{C.WARN} Could not delete {fp}: {e}")

    if removed == 0:
        print(f"{C.INFO} {C.G}No libpairipcore.so found in lib/* (already absent).")

    print(f"\n{C.S} Native libs removed {C.E} {C.OG}➸❥ {C.PN}{removed} {C.G} ✔\n")


# ---------------- Public entry ----------------
def Kill_Pairip_Run(decompile_dir, manifest_path, d_manifest_path, isAPKTool, smali_folders, App_Name, Super_Value):
    """Total Pairip removal: manifest swap + smali strip + native lib strip. No VM, no .mtd, no virtual app."""

    Kill_Pairip_Manifest(decompile_dir, manifest_path, d_manifest_path, isAPKTool, App_Name, Super_Value)

    Strip_Pairip_Smali(smali_folders)

    Strip_Pairip_Native(decompile_dir, isAPKTool)
