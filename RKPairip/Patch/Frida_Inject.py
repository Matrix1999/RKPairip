from ..ANSI_COLORS import ANSI; C = ANSI()
from ..MODULES import IMPORT; M = IMPORT()

from RKPairip.Patch.Manifest_Patch import Decode_Manifest, Encode_Manifest

C_Line = f"{C.CC}{'_' * 61}"

# Frida-gadget release we pin against. Bump when frida ships a new release.
GADGET_VERSION = "16.5.9"
GADGET_BASE = f"https://github.com/frida/frida/releases/download/{GADGET_VERSION}"

# Map APK arch dir -> frida release artifact name
GADGET_FILES = {
    "arm64-v8a":   f"frida-gadget-{GADGET_VERSION}-android-arm64.so.xz",
    "armeabi-v7a": f"frida-gadget-{GADGET_VERSION}-android-arm.so.xz",
    "x86":         f"frida-gadget-{GADGET_VERSION}-android-x86.so.xz",
    "x86_64":      f"frida-gadget-{GADGET_VERSION}-android-x86_64.so.xz",
}

# Gadget config: load script from sibling .so file inside lib/<arch>/.
# Path is relative to the config file, so this resolves at runtime regardless
# of where Android extracts the libs (or whether it extracts them at all).
GADGET_CONFIG = (
    b'{"interaction":{"type":"script",'
    b'"path":"libpairip_hook.script.so",'
    b'"on_change":"reload"}}\n'
)


# ---------------- Cache + download gadget ----------------
def _cache_dir():
    home = M.os.path.expanduser("~")
    p = M.os.path.join(home, ".RKPairip", "gadgets", GADGET_VERSION)
    M.os.makedirs(p, exist_ok=True)
    return p


def Get_Gadget(arch):
    """Return path to a decompressed gadget .so for arch.
    Downloads + decompresses on first use, caches under ~/.RKPairip/gadgets/."""

    if arch not in GADGET_FILES:
        return None

    cache = _cache_dir()
    so_path = M.os.path.join(cache, f"libfrida-gadget-{arch}.so")

    if M.os.path.isfile(so_path) and M.os.path.getsize(so_path) > 1_000_000:
        return so_path

    import urllib.request, lzma
    url = f"{GADGET_BASE}/{GADGET_FILES[arch]}"
    print(f"   {C.X}{C.C} Downloading {C.G}{arch}{C.OG} gadget {C.G}( {GADGET_VERSION} ){C.CC} ...")

    xz_path = so_path + ".xz"
    try:
        urllib.request.urlretrieve(url, xz_path)
    except Exception as e:
        print(f"   {C.ERROR} download failed: {e}")
        return None

    try:
        with open(xz_path, 'rb') as f:
            data = lzma.decompress(f.read())
        with open(so_path, 'wb') as f:
            f.write(data)
    finally:
        try: M.os.remove(xz_path)
        except OSError: pass

    return so_path


# ---------------- Bundled hook script ----------------
def _hook_script_bytes():
    here = M.os.path.dirname(M.os.path.dirname(M.os.path.abspath(__file__)))
    p = M.os.path.join(here, 'Hooks', 'pairip_bypass.js')
    with open(p, 'rb') as f:
        return f.read()


# ---------------- lib/ root for active layout ----------------
def _lib_root(decompile_dir, isAPKTool):
    if isAPKTool:
        return M.os.path.join(decompile_dir, "lib")
    return M.os.path.join(decompile_dir, "root", "lib")


# ---------------- Drop gadget + config + script into every lib/<arch>/ ----------------
def Drop_Gadgets(decompile_dir, isAPKTool):

    print(
        f"{C_Line}\n\n"
        f"\n{C.X}{C.C} Frida Gadget {C.OG}➸❥ {C.G}Embedding into lib/*\n"
    )

    lib_root = _lib_root(decompile_dir, isAPKTool)
    if not M.os.path.isdir(lib_root):
        print(f"   {C.ERROR} No lib/ directory at {lib_root}")
        return 0

    arches = sorted(d for d in M.os.listdir(lib_root)
                    if M.os.path.isdir(M.os.path.join(lib_root, d)))
    if not arches:
        print(f"   {C.ERROR} No native arches under lib/")
        return 0

    script = _hook_script_bytes()
    dropped = 0

    for arch in arches:
        if arch not in GADGET_FILES:
            print(f"   {C.X}{C.C} Skipping unsupported arch: {C.Y}{arch}")
            continue

        gadget_src = Get_Gadget(arch)
        if not gadget_src:
            print(f"   {C.ERROR} Could not obtain gadget for {arch} — skipping")
            continue

        arch_dir   = M.os.path.join(lib_root, arch)
        gadget_dst = M.os.path.join(arch_dir, "libfrida-gadget.so")
        config_dst = M.os.path.join(arch_dir, "libfrida-gadget.config.so")
        script_dst = M.os.path.join(arch_dir, "libpairip_hook.script.so")

        M.shutil.copyfile(gadget_src, gadget_dst)
        with open(config_dst, 'wb') as f: f.write(GADGET_CONFIG)
        with open(script_dst, 'wb') as f: f.write(script)

        size_mb = M.os.path.getsize(gadget_dst) / (1024 * 1024)
        print(f"   {C.X}{C.C} {arch:<14}{C.OG}➸❥ {C.G}gadget ({size_mb:.1f} MB) + config + hook  ✔")
        dropped += 1

    return dropped


# ---------------- Inject System.loadLibrary("frida-gadget") into <clinit> ----------------
def Inject_LoadLibrary(smali_folders, real_app_class, lib_name="frida-gadget"):
    """Insert `System.loadLibrary("frida-gadget")` at the very start of the user's
    real Application <clinit>.

    Class load order in pairip-wrapped apps:
      1. ClassLoader loads `com.pairip.application.Application`
      2. → must first load its parent (the user's real Application)
      3. → user's Application <clinit> runs HERE  ← we inject here
      4. → pairip's Application <clinit> runs
      5. → Android calls pairip's `attachBaseContext` which calls verifyIntegrity

    This is the earliest hook point reachable from smali alone — Java.perform
    finishes synchronously inside step 3 before step 5 runs."""

    print(
        f"{C_Line}\n\n"
        f"\n{C.X}{C.C} Frida Gadget {C.OG}➸❥ {C.G}Injecting loadLibrary into "
        f"{C.Y}{real_app_class}{C.G}.<clinit>\n"
    )

    rel = real_app_class.replace('.', '/') + '.smali'
    target = None
    for folder in smali_folders:
        cand = M.os.path.join(folder, rel.replace('/', M.os.sep))
        if M.os.path.isfile(cand):
            target = cand
            break

    if not target:
        print(f"   {C.ERROR} Could not find {rel} in any smali folder")
        return False

    content = open(target, 'r', encoding='utf-8').read()

    inj = (
        '    const-string v0, "' + lib_name + '"\n\n'
        '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n\n'
    )

    clinit_pat = M.re.compile(
        r'(\.method\s+static\s+constructor\s+<clinit>\(\)V\s*\n)'
        r'(\s*\.locals\s+)(\d+)(\s*\n)',
        M.re.M
    )

    m = clinit_pat.search(content)
    if m:
        locals_n = max(int(m.group(3)), 1)
        new = (
            content[:m.start()]
            + m.group(1)
            + f"{m.group(2)}{locals_n}{m.group(4)}"
            + inj
            + content[m.end():]
        )
        print(f"   {C.X}{C.C} Existing <clinit> patched (locals={locals_n}).")
    else:
        new_clinit = (
            '\n# direct methods (RKPairip-injected)\n'
            '.method static constructor <clinit>()V\n'
            '    .locals 1\n\n'
            f'{inj}'
            '    return-void\n'
            '.end method\n'
        )
        super_pat = M.re.compile(r'(\.super\s+L[^;\s]+;\s*\n(?:\.source\s+"[^"]*"\s*\n)?)')
        sm = super_pat.search(content)
        if sm:
            new = content[:sm.end()] + new_clinit + content[sm.end():]
            print(f"   {C.X}{C.C} Synthesized fresh <clinit> after .super.")
        else:
            new = content + new_clinit
            print(f"   {C.X}{C.C} Appended fresh <clinit> at EOF (fallback).")

    with open(target, 'w', encoding='utf-8') as f:
        f.write(new)

    print(f"   {C.X}{C.C} {target.split(M.os.sep)[-1]} {C.OG}➸❥ {C.G}patched  ✔")
    return True


# ---------------- Force extractNativeLibs="true" in <application> ----------------
def Force_ExtractNativeLibs(decompile_dir, manifest_path, d_manifest_path, isAPKTool):
    """Force `android:extractNativeLibs="true"` so native libs land on disk and
    frida-gadget can read its config/script as filesystem files."""

    if isAPKTool:
        if not M.os.path.isfile(d_manifest_path):
            Decode_Manifest(manifest_path, d_manifest_path)
        path = d_manifest_path
    else:
        path = manifest_path  # APKEditor: plain XML

    if not M.os.path.isfile(path):
        return

    text = open(path, 'r', encoding='utf-8').read()
    changed = False

    if 'android:extractNativeLibs="false"' in text:
        text = text.replace('android:extractNativeLibs="false"',
                            'android:extractNativeLibs="true"', 1)
        changed = True
    elif 'android:extractNativeLibs' not in text:
        text2 = M.re.sub(r'(<application\b)',
                         r'\1 android:extractNativeLibs="true"',
                         text, count=1)
        if text2 != text:
            text = text2
            changed = True

    if changed:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f"   {C.X}{C.C} Manifest {C.OG}➸❥ {C.G}android:extractNativeLibs=\"true\"  ✔")
        if isAPKTool:
            Encode_Manifest(decompile_dir, manifest_path, d_manifest_path)


# ---------------- Top-level orchestrator for -g mode ----------------
def Frida_Inject_Run(decompile_dir, manifest_path, d_manifest_path,
                     isAPKTool, smali_folders, real_app_class):

    Force_ExtractNativeLibs(decompile_dir, manifest_path, d_manifest_path, isAPKTool)

    dropped = Drop_Gadgets(decompile_dir, isAPKTool)
    if dropped == 0:
        raise RuntimeError("No frida-gadget binaries were embedded — aborting.")

    if not Inject_LoadLibrary(smali_folders, real_app_class):
        raise RuntimeError("Failed to inject System.loadLibrary into Application <clinit>.")
