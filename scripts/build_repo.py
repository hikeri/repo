#!/usr/bin/env python3
"""Конвертирует apps/<appId>/ в метаданные fdroidserver и скачивает APK."""
import os, re, sys, shutil
from pathlib import Path
import requests, yaml
from PIL import Image
from pyaxmlparser import APK

API = "https://api.github.com"
APPS_DIR, METADATA_DIR, REPO_DIR = Path("apps"), Path("metadata"), Path("repo")
S = requests.Session()
S.headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
S.headers["Accept"] = "application/vnd.github+json"

ANTI_MAP = {  # имя файла -> канонический AntiFeature из fdroidserver
    "ads": "Ads", "disabled-algorithm": "DisabledAlgorithm",
    "known-vulnerability": "KnownVuln", "non-free-addons": "NonFreeAdd",
    "non-free-assets": "NonFreeAssets", "non-free-dependencies": "NonFreeDep",
    "non-free-network": "NonFreeNet", "no-sources": "NoSourceSince",
    "tethered-network": "TetheredNet", "tracking": "Tracking",
}
ANTI_LABELS = {  # человекочитаемые подписи для описания
    "Ads": "Advertising", "DisabledAlgorithm": "Signed using an unsafe algorithm",
    "KnownVuln": "Known security vulnerability", "NonFreeAdd": "Non-Free Addons",
    "NonFreeAssets": "Non-Free Assets", "NonFreeDep": "Non-Free Dependencies",
    "NonFreeNet": "Non-Free Network Services", "NoSourceSince": "No Source Since",
    "TetheredNet": "Tethered Network Services", "Tracking": "Tracking",
}
LANG_ALIASES = {"ru": "ru-RU", "pt": "pt-BR", "zh": "zh-CN", "no": "nb"}
SHOT_RE = re.compile(r"^(\d+)(?:\.([a-z]{2}(?:[-_][A-Za-z]{2})?))?\.(jpe?g|png)$", re.I)
LANG_SUFFIX = re.compile(r"^[a-z]{2}(_[A-Z]{2}|-[A-Za-z]{2})?$")


def norm_lang(code):
    code = code.replace("_", "-")
    if len(code) == 2 and code in LANG_ALIASES:
        return LANG_ALIASES[code]
    if "-" in code:  # ru-ru -> ru-RU
        l, r = code.split("-", 1)
        return f"{l}-{r.upper()}"
    return code


def split_lang(stem):
    """'description.ru' -> ('description', 'ru'); 'description' -> (..., None)"""
    if "." in stem:
        base, _, lang = stem.rpartition(".")
        if LANG_SUFFIX.match(lang):
            return base, norm_lang(lang)
    return stem, None


def parse_app(d: Path):
    """Читает всю структуру папки приложения."""
    text, shots, icons, banners = {}, [], {}, {}   # text: lang -> {имя: содержимое}
    for f in sorted(d.iterdir()):
        if f.is_dir():
            continue
        m = SHOT_RE.match(f.name)
        if m:                                       # 1.jpg, 2.ru.png, ...
            num, lang, ext = m.groups()
            lang = norm_lang(lang) if lang else "en-US"
            # сортировка: по номеру, jpg перед png при равном номере
            shots.append({"lang": lang, "num": int(num),
                         "png_last": ext.lower() == "png", "path": f})
            continue
        stem, ext = f.stem, f.suffix.lstrip(".").lower()
        if ext not in ("jpg", "jpeg", "png"):
            name, lang = split_lang(stem)
            lang = lang or "en-US"
            text.setdefault(lang, {})[name] = f.read_text(encoding="utf-8").strip()
        elif stem == "app_icon":
            name, lang = split_lang(stem)
            lang = lang or "en-US"
            cur = icons.get(lang)
            # jpg предпочтительнее (по вашему правилу), png приоритет ниже
            if cur is None or (cur[0] == "png" and ext in ("jpg", "jpeg")):
                icons[lang] = (ext, f)
        elif stem == "horizontal_banner":
            name, lang = split_lang(stem)
            lang = lang or "en-US"
            cur = banners.get(lang)
            if cur is None or (cur[0] == "png" and ext in ("jpg", "jpeg")):
                banners[lang] = (ext, f)
    return text, sorted(shots, key=lambda s: (s["lang"], s["num"], s["png_last"])), icons, banners


def gh(url):
    r = S.get(url, timeout=120)
    r.raise_for_status()
    return r.json()


def save_img_as_png(src: Path, dst: Path):
    dst.parent.mkdir(parents=True, exist_ok=True)
    Image.open(src).convert("RGBA" if src.suffix == ".png" else "RGB").save(dst, "PNG")


def process_app(d: Path):
    appid = d.name
    text, shots, icons, banners = parse_app(d)
    main = text.get("en-US", {})
    github_url = main.get("github_url")
    if not github_url:
        print(f"[SKIP] {appid}: нет github_url"); return

    m = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", github_url)
    if not m:
        print(f"[SKIP] {appid}: не удалось распарсить github_url"); return
    owner, proj = m.groups()

    # --- лицензия из GitHub API ---
    info = gh(f"{API}/repos/{owner}/{proj}")
    license_id = (info.get("license") or {}).get("spdx_id") or "Unknown"
    if license_id == "NOASSERTION":
        license_id = "Unknown"

    # --- последние 3 релиза, в которых есть APK ---
    rels = gh(f"{API}/repos/{owner}/{proj}/releases?per_page=30")
    rels = [r for r in rels
            if any(a["name"].lower().endswith(".apk") for a in r["assets"])]
    rels = rels[:3]
    if not rels:
        print(f"[SKIP] {appid}: нет релизов с APK"); return

    # --- скачиваем APK ---
    seen_vc, stable_vc = set(), 0
    for rel in rels:
        tag = rel["tag_name"]
        for asset in rel["assets"]:
            if not asset["name"].lower().endswith(".apk"):
                continue
            tmp = REPO_DIR / f"{appid}_{asset['name']}"
            tmp.parent.mkdir(parents=True, exist_ok=True)
            if not tmp.exists():
                with S.get(asset["browser_download_url"], stream=True, timeout=600) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as fh:
                        for chunk in r.iter_content(1 << 20):
                            fh.write(chunk)
            apk = APK(str(tmp))
            pkg, vc = apk.package, int(apk.version_code)
            if vc in seen_vc:                 # одинаковый APK в нескольких релизах
                tmp.unlink(); continue
            seen_vc.add(vc)
            final = REPO_DIR / f"{pkg}_{vc}.apk"
            shutil.move(tmp, final)
            if not rel["prerelease"]:          # рекомендуемая версия = стабильная
                stable_vc = max(stable_vc, vc)
            # --- changelog из тела релиза ---
            for lang, data in text.items():
                cl = METADATA_DIR / appid / lang / "changelogs" / f"{vc}.txt"
                cl.parent.mkdir(parents=True, exist_ok=True)
                title = f"Version {rel.get('name') or tag}"
                if rel["prerelease"]:
                    title += " (pre-release)"
                cl.write_text(title + "\n\n" + (rel.get("body") or "").strip(),
                              encoding="utf-8")
    if stable_vc == 0:
        stable_vc = max(seen_vc)               # стабильных нет — берём максимум

    # --- метаданные ---
    for lang, data in text.items():
        loc = METADATA_DIR / appid / lang
        loc.mkdir(parents=True, exist_ok=True)
        desc = data.get("description", "")
        lines = desc.split("\n")
        (loc / "short_description.txt").write_text(
            lines[0].strip()[:80], encoding="utf-8")
        full = "\n".join(lines[1:]).strip()

        antifeatures, reasons = [], []
        for fname, afeat in ANTI_MAP.items():
            if fname in data:
                antifeatures.append(afeat)
                reasons.append((afeat, data[fname]))
        if reasons:
            full += "\n\n<b>Anti-features:</b>\n" + "\n".join(
                f"• <b>{ANTI_LABELS[a]}</b>: {r}" for a, r in reasons)
        if full:
            (loc / "full_description.txt").write_text(full, encoding="utf-8")

        # графика
        imgs = loc / "images"
        if lang in icons:
            save_img_as_png(icons[lang][1], imgs / "icon.png")
        if lang in banners:
            save_img_as_png(banners[lang][1], imgs / "featureGraphic.png")
        shot_dir = imgs / "phoneScreenshots"
        i = 0
        for shot in [s for s in shots if s["lang"] == lang]:
            i += 1
            shot_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy(shot["path"], shot_dir / f"{i}{shot['path'].suffix.lower()}")

    cats = [c.strip() for c in main.get("categories", "").split(",") if c.strip()]
    meta = {
        "License": license_id,
        "SourceCode": github_url,
        "IssueTracker": github_url.rstrip("/") + "/issues",
        "Categories": cats,
        "CurrentVersionCode": stable_vc,
    }
    if antifeatures:
        meta["AntiFeatures"] = sorted(set(antifeatures))
    if main.get("website"):
        meta["WebSite"] = main["website"]
    (METADATA_DIR / f"{appid}.yml").write_text(
        yaml.safe_dump(meta, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"[OK] {appid}: {len(seen_vc)} APK, recommended VC={stable_vc}")


if __name__ == "__main__":
    if not APPS_DIR.exists():
        sys.exit("Папка apps/ не найдена")
    REPO_DIR.mkdir(exist_ok=True)
    for app_dir in sorted(APPS_DIR.iterdir()):
        if app_dir.is_dir():
            try:
                process_app(app_dir)
            except Exception as e:
                print(f"[ERR] {app_dir.name}: {e}")
