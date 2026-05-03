from ..ANSI_COLORS import ANSI; C = ANSI()
from ..MODULES import IMPORT; M = IMPORT()

from RKPairip.Patch.Manifest_Patch import Decode_Manifest, Encode_Manifest
from RKPairip.Patch.Sig_Extract import Extract_Original_Cert

C_Line = f"{C.CC}{'_' * 61}"

# Pinned frida-gadget release. Bump when frida ships a new one.
GADGET_VERSION = "16.5.9"
GADGET_BASE = f"https://github.com/frida/frida/releases/download/{GADGET_VERSION}"
GADGET_FILES = {
    "arm64-v8a":   f"frida-gadget-{GADGET_VERSION}-android-arm64.so.xz",
    "armeabi-v7a": f"frida-gadget-{GADGET_VERSION}-android-arm.so.xz",
    "x86":         f"frida-gadget-{GADGET_VERSION}-android-x86.so.xz",
    "x86_64":      f"frida-gadget-{GADGET_VERSION}-android-x86_64.so.xz",
}

GADGET_CONFIG = (
    b'{"interaction":{"type":"script",'
    b'"path":"libpairip_hook.script.so",'
    b'"on_change":"reload"}}\n'
)

# Gadget filename rename — pairip's anti-frida scanner greps /proc/self/maps
# for "frida". By landing the gadget under an innocuous name we evade the
# string-based scan. The frida runtime works fine under any filename.
GADGET_LIB_NAME = "RKMod-runtime"   # loadLibrary("<this>") → libRKMod-runtime.so


# ============================================================
# Gadget download / cache
# ============================================================
def _cache_dir():
    home = M.os.path.expanduser("~")
    p = M.os.path.join(home, ".RKPairip", "gadgets", GADGET_VERSION)
    M.os.makedirs(p, exist_ok=True)
    return p


def Get_Gadget(arch):
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
        with open(xz_path, 'rb') as f:
            raw = lzma.decompress(f.read())
        with open(so_path, 'wb') as f:
            f.write(raw)
    except Exception as e:
        print(f"   {C.ERROR} download failed for {arch}: {e}")
        return None
    finally:
        try: M.os.remove(xz_path)
        except OSError: pass
    return so_path


# ============================================================
# Build per-APK customized hook script
# ============================================================
def _customized_hook_script(orig_cert_der):
    """Read the bundled JS template, bake the original cert DER (base64) in,
    return as bytes ready to drop into lib/<arch>/."""

    here = M.os.path.dirname(M.os.path.dirname(M.os.path.abspath(__file__)))
    tpl_path = M.os.path.join(here, 'Hooks', 'pairip_bypass.js')
    with open(tpl_path, 'r', encoding='utf-8') as f:
        template = f.read()

    cert_b64 = M.base64.b64encode(orig_cert_der).decode('ascii')
    if '__ORIGINAL_CERT_B64__' not in template:
        raise RuntimeError("pairip_bypass.js template missing __ORIGINAL_CERT_B64__ placeholder")
    return template.replace('__ORIGINAL_CERT_B64__', cert_b64).encode('utf-8')


# ============================================================
# lib/ root
# ============================================================
def _lib_root(decompile_dir, isAPKTool):
    if isAPKTool:
        return M.os.path.join(decompile_dir, "lib")
    return M.os.path.join(decompile_dir, "root", "lib")


# ============================================================
# Drop gadget + config + customized script
# ============================================================
def Drop_Gadgets(decompile_dir, isAPKTool, hook_script_bytes):
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

    dropped = 0
    for arch in arches:
        if arch not in GADGET_FILES:
            print(f"   {C.X}{C.C} Skipping unsupported arch: {C.Y}{arch}")
            continue
        gadget_src = Get_Gadget(arch)
        if not gadget_src:
            print(f"   {C.ERROR} Could not obtain gadget for {arch}")
            continue

        arch_dir   = M.os.path.join(lib_root, arch)
        gadget_dst = M.os.path.join(arch_dir, f"lib{GADGET_LIB_NAME}.so")
        config_dst = M.os.path.join(arch_dir, f"lib{GADGET_LIB_NAME}.config.so")
        script_dst = M.os.path.join(arch_dir, "libpairip_hook.script.so")

        M.shutil.copyfile(gadget_src, gadget_dst)
        with open(config_dst, 'wb') as f: f.write(GADGET_CONFIG)
        with open(script_dst, 'wb') as f: f.write(hook_script_bytes)

        size_mb = M.os.path.getsize(gadget_dst) / (1024 * 1024)
        print(f"   {C.X}{C.C} {arch:<14}{C.OG}➸❥ {C.G}gadget ({size_mb:.1f} MB) + config + hook  ✔")
        dropped += 1

    return dropped


# ============================================================
# Manifest helpers — find appComponentFactory + force extract
# ============================================================
def _read_manifest_text(decompile_dir, manifest_path, d_manifest_path, isAPKTool):
    if isAPKTool:
        if not M.os.path.isfile(d_manifest_path):
            Decode_Manifest(manifest_path, d_manifest_path)
        path = d_manifest_path
    else:
        path = manifest_path
    return path, open(path, 'r', encoding='utf-8').read()


def _write_manifest_text(decompile_dir, manifest_path, d_manifest_path, isAPKTool, text):
    path = d_manifest_path if isAPKTool else manifest_path
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    if isAPKTool:
        Encode_Manifest(decompile_dir, manifest_path, d_manifest_path)


def Get_AppComponentFactory(decompile_dir, manifest_path, d_manifest_path, isAPKTool):
    """Return the FQCN of the manifest's <application android:appComponentFactory>,
    or None if not set."""

    _, text = _read_manifest_text(decompile_dir, manifest_path, d_manifest_path, isAPKTool)
    m = M.re.search(r'android:appComponentFactory="([^"]+)"', text)
    return m.group(1) if m else None


def Force_ExtractNativeLibs(decompile_dir, manifest_path, d_manifest_path, isAPKTool):
    """Set android:extractNativeLibs="true" so the gadget can read its config
    and script from the on-disk native lib dir."""

    path, text = _read_manifest_text(decompile_dir, manifest_path, d_manifest_path, isAPKTool)
    if 'android:extractNativeLibs="false"' in text:
        text = text.replace('android:extractNativeLibs="false"',
                            'android:extractNativeLibs="true"', 1)
    elif 'android:extractNativeLibs' not in text:
        new = M.re.sub(r'(<application\b)',
                       r'\1 android:extractNativeLibs="true"',
                       text, count=1)
        if new == text:
            return
        text = new
    else:
        return  # already true

    _write_manifest_text(decompile_dir, manifest_path, d_manifest_path, isAPKTool, text)
    print(f"   {C.X}{C.C} Manifest {C.OG}➸❥ {C.G}android:extractNativeLibs=\"true\"  ✔")


# ============================================================
# Inject loadLibrary into the appComponentFactory class <clinit>
# ============================================================
def Inject_LoadLibrary_AppFactory(smali_folders, factory_class,
                                  lib_name=GADGET_LIB_NAME):
    """Insert `System.loadLibrary("<lib_name>")` at the very top of the
    appComponentFactory's <clinit>, wrapped in a Throwable try/catch so
    any failure can't propagate ExceptionInInitializerError.

    AppComponentFactory is the FIRST application class Android loads
    (LoadedApk.createAppFactory, called before Application is even
    instantiated). In Pairip-protected apps, this is the class whose
    <clinit> calls com.pairip.StartupLauncher.launch — the call that
    triggers VMRunner. By prepending loadLibrary HERE, the gadget loads
    and Java.perform installs all hooks BEFORE pairip's first
    VMRunner.invoke runs."""

    print(
        f"{C_Line}\n\n"
        f"\n{C.X}{C.C} Frida Gadget {C.OG}➸❥ {C.G}Injecting loadLibrary into "
        f"{C.Y}{factory_class}{C.G}.<clinit>\n"
    )

    rel = factory_class.replace('.', '/').replace('/', M.os.sep) + '.smali'
    target = None
    for folder in smali_folders:
        cand = M.os.path.join(folder, rel)
        if M.os.path.isfile(cand):
            target = cand
            break
    if not target:
        print(f"   {C.ERROR} Could not find {rel} in any smali folder")
        return False

    content = open(target, 'r', encoding='utf-8').read()
    # Wrap loadLibrary in try/Throwable so a failure can never propagate
    # an ExceptionInInitializerError from <clinit> and kill the process.
    inj = (
        '    :try_rkpairip_start\n'
        '    const-string v0, "' + lib_name + '"\n\n'
        '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n\n'
        '    :try_rkpairip_end\n'
        '    .catch Ljava/lang/Throwable; {:try_rkpairip_start .. :try_rkpairip_end} :catch_rkpairip\n'
        '    goto :rkpairip_done\n\n'
        '    :catch_rkpairip\n'
        '    move-exception v0\n\n'
        '    :rkpairip_done\n\n'
    )

    clinit_pat = M.re.compile(
        r'(\.method\s+static\s+constructor\s+<clinit>\(\)V\s*\n)'
        r'(\s*\.locals\s+)(\d+)(\s*\n)',
        M.re.M
    )
    m = clinit_pat.search(content)
    if m:
        locals_n = max(int(m.group(3)), 1)
        new = (content[:m.start()]
               + m.group(1)
               + f"{m.group(2)}{locals_n}{m.group(4)}"
               + inj
               + content[m.end():])
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
        new = (content[:sm.end()] + new_clinit + content[sm.end():]) if sm \
              else (content + new_clinit)
        print(f"   {C.X}{C.C} Synthesized fresh <clinit>.")

    with open(target, 'w', encoding='utf-8') as f:
        f.write(new)
    print(f"   {C.X}{C.C} {target.split(M.os.sep)[-1]} {C.OG}➸❥ {C.G}patched  ✔")
    return True


# ============================================================
# Top-level orchestrator
# ============================================================
def Frida_Inject_Run(apk_path, decompile_dir, manifest_path, d_manifest_path,
                     isAPKTool, smali_folders, real_app_class):

    # 1. Extract original signing cert from the input APK's V2/V3 block.
    print(
        f"{C_Line}\n\n"
        f"\n{C.X}{C.C} Frida Gadget {C.OG}➸❥ {C.G}Extracting original signing cert from APK\n"
    )
    orig_der = Extract_Original_Cert(apk_path)
    if not orig_der:
        raise RuntimeError("Could not extract a signing certificate from the APK. "
                           "Is it actually signed?")
    sha256 = M.hashlib.sha256(orig_der).hexdigest()
    print(f"   {C.X}{C.C} Original cert: {C.G}{len(orig_der)} bytes "
          f"{C.OG}➸ {C.Y}SHA-256: {sha256}")

    # 2. Build per-APK customized hook script.
    hook_bytes = _customized_hook_script(orig_der)
    print(f"   {C.X}{C.C} Hook script {C.OG}➸❥ {C.G}cert baked in "
          f"({len(hook_bytes)} bytes)  ✔")

    # 3. Force extractNativeLibs=true so the gadget can read its config from disk.
    Force_ExtractNativeLibs(decompile_dir, manifest_path, d_manifest_path, isAPKTool)

    # 4. Drop gadget + config + script into every supported lib/<arch>/.
    dropped = Drop_Gadgets(decompile_dir, isAPKTool, hook_bytes)
    if dropped == 0:
        raise RuntimeError("No frida-gadget binaries were embedded.")

    # 5. Inject loadLibrary into the manifest's appComponentFactory <clinit>
    #    (earliest possible Java code). Fall back to the user Application
    #    class if no factory is declared.
    factory = Get_AppComponentFactory(decompile_dir, manifest_path,
                                      d_manifest_path, isAPKTool)
    if factory:
        print(f"\n   {C.X}{C.C} appComponentFactory: {C.Y}{factory}")
        target_class = factory
    else:
        print(f"\n   {C.X}{C.C} No appComponentFactory in manifest — "
              f"falling back to {C.Y}{real_app_class}")
        target_class = real_app_class

    if not Inject_LoadLibrary_AppFactory(smali_folders, target_class):
        raise RuntimeError(f"Failed to inject loadLibrary into {target_class} <clinit>.")
