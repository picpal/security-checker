"""CycloneDX SBOM 생성 (cdxgen) — gradle/maven 전이 의존성 해석의 핵심.

락파일 없는 gradle 도 cdxgen 이 빌드도구를 호출해 전체 의존 그래프를 BOM 으로 만든다.
그 BOM 을 trivy sbom 으로 스캔하면 fs 정적 파싱이 놓치는 전이 CVE 를 잡는다(recall).

ensure_bom 은 "대상 경로 + 의존성 매니페스트 내용" 해시 캐시 + 프로세스 내 락으로
동시 어댑터가 cdxgen 을 한 번만 실행하게 한다. 매니페스트가 바뀌면 캐시 경로가 바뀌어
BOM 이 반드시 재생성된다(2026-09-09 실측 결함: 경로만으로 키를 잡아 의존성을 올려도
옛 BOM 이 영원히 재사용됐다 — 원칙 1 정확도 우선 위반).

내용 해시로도 못 잡는 잔여 경로가 있다: 동적 버전(`2.+`, `latest.release`, 범위 표기),
SNAPSHOT, 원격 parent pom — 매니페스트가 그대로여도 해석 결과가 달라진다.
dynamic_versions 가 이를 매니페스트에서 탐지하고, 걸리면 CLI 가 캐시를 우회한다
(`refresh=True`). 사용자는 `--no-bom-cache` 로 언제든 강제 우회할 수 있다.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import subprocess
import tempfile
import threading
import xml.etree.ElementTree as ET
from fnmatch import fnmatch
from pathlib import Path
from typing import NamedTuple

from .exclude import DEFAULT_EXCLUDES, path_excluded

# BOM 의 입력 = 의존성을 선언하는 파일. gradle 은 build/settings 외에 `apply from` 으로
# 끌어쓰는 dependencies.gradle 류도 의존성을 선언하므로 *.gradle 전체를 본다
# (cli.py::_SRC_GLOBS 와 같은 표기). *.lockfile 은 gradle 의존성 잠금(gradle.lockfile,
# buildscript-gradle.lockfile), *.versions.toml 은 버전 카탈로그.
_MANIFEST_GLOBS = (
    "pom.xml",
    "*.gradle", "*.gradle.kts",
    "gradle.properties",
    "*.versions.toml",
    "*.lockfile",
)


def _is_manifest(name: str) -> bool:
    return any(fnmatch(name, g) for g in _MANIFEST_GLOBS)


def iter_manifests(target, *, excludes=DEFAULT_EXCLUDES):
    """대상 안의 의존성 매니페스트를 결정적 순서로 나열.

    exclude.py 의 기본 제외를 디렉토리 단계에서 가지치기한다 — node_modules/build/.git
    안의 pom.xml 이 캐시 키를 오염시키면 빌드마다 키가 흔들려 캐시가 무의미해진다.
    """
    root = Path(target)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(d for d in dirnames if not path_excluded(str(rel / d), excludes))
        for name in sorted(filenames):
            if _is_manifest(name):
                yield Path(dirpath) / name


def _effective_gav(pom_root) -> tuple[str, str, str]:
    """pom 의 실효 좌표. groupId/version 은 생략 시 자기 <parent> 에서 상속된다
    (artifactId 는 상속되지 않는다). 못 구한 필드는 빈 문자열."""
    parent = _child(pom_root, "parent")
    def field(name):
        own = _child_text(pom_root, name)
        if own or parent is None:
            return own
        return _child_text(parent, name)
    return (field("groupId"), _child_text(pom_root, "artifactId"), field("version"))


def _local_parent_pom(pom: Path) -> Path | None:
    """pom 이 실제로 읽는 로컬 parent 파일. 원격(`<relativePath/>` 명시)이거나 없으면 None."""
    try:
        data = pom.read_bytes()
    except OSError:
        return None
    if b"<parent" not in data:
        return None
    try:
        node = _child(ET.fromstring(data), "parent")
    except Exception:
        return None
    if node is None:
        return None
    rp = _child(node, "relativePath")
    if rp is not None and not (rp.text or "").strip():
        return None  # 빈 relativePath = 항상 원격
    cand = pom.parent / ((rp.text or "").strip() if rp is not None else "../pom.xml")
    if cand.is_dir():
        cand = cand / "pom.xml"
    if not cand.is_file():
        return None
    # 파일이 있어도 좌표가 다르면 maven 은 그 파일을 무시하고 원격에서 받는다(P1-B).
    # 후보가 생략한 groupId/version 은 **자기 <parent> 에서 상속**되므로 실효 좌표로 대조한다
    # (R3 P1-2). 실효 좌표를 못 구하면 로컬이라 단정하지 않는다(fail-closed).
    try:
        cand_root = ET.fromstring(cand.read_bytes())
    except Exception:
        return None
    actual = _effective_gav(cand_root)
    declared = (_child_text(node, "groupId"), _child_text(node, "artifactId"),
                _child_text(node, "version"))
    if not all(actual) or actual != declared:
        return None
    return cand


_SETTINGS = ("settings.gradle", "settings.gradle.kts")


def _gradle_build_root(root: Path, max_up: int = 8) -> Path | None:
    """대상이 gradle 서브프로젝트면 그 빌드 루트(settings.gradle 를 가진 상위)를 준다.

    gradle 은 서브프로젝트를 평가할 때 루트의 ext·gradle.properties·버전 카탈로그를
    실제로 읽는다. 그 파일들이 지문·심볼 밖에 있으면 (1) 루트 변경이 캐시를 무효화하지
    못하고 (2) 보간이 미해석으로 남아 매 스캔 우회한다.
    """
    root = root.resolve()
    if any((root / s).is_file() for s in _SETTINGS):
        return None  # 이미 빌드 루트
    for anc in list(root.parents)[:max_up]:
        if any((anc / s).is_file() for s in _SETTINGS):
            return anc
        if (anc / ".git").is_dir():
            break  # 저장소 경계를 넘지 않는다
    return None


def collect_manifests(target, *, excludes=DEFAULT_EXCLUDES) -> list[Path]:
    """지문·탐지가 보는 매니페스트 집합.

    대상 안의 매니페스트 + **빌드가 실제로 읽는 파일**(대상 밖일 수 있다):
    maven 은 로컬 parent pom 체인, gradle 은 빌드 루트의 스크립트·프로퍼티·카탈로그.
    모듈 하나만 스캔해도 `../pom.xml` 이나 루트 `build.gradle` 이 바뀌면 캐시가
    무효화돼야 하기 때문이다(codex P1-1). 순서는 표시 경로 기준 정렬로 결정적이다.
    """
    root = Path(target)
    found = list(iter_manifests(root, excludes=excludes))
    seen = {p.resolve() for p in found}

    build_root = _gradle_build_root(root)
    if build_root is not None:
        # 빌드 루트 **하위 전체**. 직속 파일만 넣으면 apply from 으로 읽는 중첩 스크립트나
        # buildSrc/convention 플러그인·중첩 카탈로그가 지문 밖에 남는다(P1-D). 형제 모듈까지
        # 들어가 과잉 무효화가 되지만, 방향이 안전한 쪽이고 루트를 스캔할 때와 같은 집합이다.
        for p in iter_manifests(build_root, excludes=excludes):
            if p.resolve() not in seen:
                seen.add(p.resolve())
                found.append(p)
    queue = [p for p in found if p.name == "pom.xml"]
    while queue:
        parent = _local_parent_pom(queue.pop(0))
        if parent is not None and parent.resolve() not in seen:
            seen.add(parent.resolve())
            found.append(parent)
            queue.append(parent)
    return sorted(found, key=lambda p: _manifest_key(p, root))


def _manifest_key(path: Path, root: Path) -> str:
    """지문에 쓰는 표시 경로. 대상 밖 parent 는 '../pom.xml' 처럼 관계로 표기한다."""
    return os.path.relpath(path, root)


def manifest_fingerprint(target, *, excludes=DEFAULT_EXCLUDES) -> str:
    """의존성 매니페스트의 (상대경로, 내용) 해시. 캐시 키(식별자)용 — 보안 해시 아님.

    mtime 은 쓰지 않는다: git checkout/clone 이 mtime 을 바꿔 내용이 같아도 캐시가
    매번 무효화된다(재생성 비용이 커서 캐시가 사실상 사라짐).
    """
    root = Path(target)
    h = hashlib.sha1(usedforsecurity=False)
    for p in collect_manifests(root, excludes=excludes):
        h.update(_manifest_key(p, root).encode())  # 매니페스트 추가/삭제/이동도 반영
        h.update(b"\0")
        try:
            h.update(hashlib.sha1(p.read_bytes(), usedforsecurity=False).digest())
        except OSError:
            h.update(b"<unreadable>")
        h.update(b"\n")
    return h.hexdigest()[:16]


def bom_cache_path(target, *, excludes=DEFAULT_EXCLUDES) -> Path:
    """대상 경로 해시 / 매니페스트 내용 해시 / bom.json.

    경로 해시로 서로 다른 대상을 분리하고, 매니페스트 해시로 의존성 변경을 감지한다.
    바뀌면 새 경로(재생성), 그대로면 같은 경로(캐시 유지).
    """
    t = Path(target).resolve()
    h = hashlib.sha1(str(t).encode(), usedforsecurity=False).hexdigest()[:16]
    return (Path(tempfile.gettempdir()) / "secscan-bom" / h
            / manifest_fingerprint(t, excludes=excludes) / "bom.json")


class DynamicVersion(NamedTuple):
    """정적 해석으로 "고정"이라고 확정할 수 없는 선언 1건.

    kind 는 왜 확정 못 했는지다 — dynamic(해석된 동적 버전) / unresolved(미해석 보간·
    프로퍼티) / ambiguous(후보 충돌) / unparsable(파싱 실패) / external-script(따라갈 수
    없는 applied script). 전부 "캐시를 믿을 수 없다"는 같은 결론으로 간다.
    """
    file: str        # 대상 기준 상대경로
    coordinate: str  # "group:artifact" 또는 프로퍼티 키·스크립트 경로
    version: str
    kind: str = "dynamic"


KIND_LABELS = {
    "dynamic": "동적 버전", "unresolved": "해석 불가", "ambiguous": "후보 모호",
    "unparsable": "파싱 실패", "external-script": "외부 스크립트",
}


# maven 레거시 키워드는 "정확히 일치"할 때만 동적이다 — "4.3.30.RELEASE"(스프링 구 표기)는
# 고정 버전이라 부분 일치로 잡으면 대량 FP 가 난다.
_VERSION_KEYWORDS = frozenset({"LATEST", "RELEASE"})
# gradle 좌표 문자열 'group:artifact:version' (가장 흔한 선언 형태).
# 버전 자리에 `${property('x')}` 처럼 따옴표·괄호가 든 보간이 올 수 있어 ${...} 덩어리를
# 먼저 삼킨다 — 안 그러면 `${property(` 로 잘려 보간으로도 동적으로도 안 보인다(P1-A).
_GRADLE_COORD = re.compile(
    r"""(["'])([\w.\-]+):([\w.\-]+):((?:\$\{[^{}]*\}|[^"'\s])+)\1""")
_TOML_KEY = re.compile(r"""^\s*([\w.\-]+)\s*=""")
# gradle 보간: $name 또는 ${expr}
_INTERP = re.compile(r"""\$\{([^{}]+)\}|\$([A-Za-z_]\w*)""")
# 빌드 스크립트의 문자열 할당: def/val/var/ext. 접두는 선택. (따옴표 값만 — 코드 값은 무시)
_GRADLE_ASSIGN = re.compile(
    r"""(?:^|[\s{;(])(?:def|val|var)?\s*(?:ext\s*\.\s*)?([A-Za-z_][\w.]*)\s*=\s*["']([^"']+)["']""",
    re.M)
_GRADLE_EXT_INDEX = re.compile(
    r"""ext\s*\[\s*["']([^"']+)["']\s*\]\s*=\s*["']([^"']+)["']""")
# apply from: 'x.gradle' / apply(from = "x.gradle")
_APPLY_FROM = re.compile(r"""apply\s*\(?\s*from\s*[:=]\s*["']([^"']+)["']""")
_ROOT_VARS = re.compile(r"""\$\{?(?:rootProject\.projectDir|rootProject\.rootDir|rootDir|projectDir|project\.rootDir)\}?/?""")


def _strip_interp(p: str) -> str:
    """apply from 경로의 $rootDir 류 접두를 걷어낸다(상대 경로로 되돌리기 위함)."""
    return _ROOT_VARS.sub("", p).lstrip("/")
_QUOTED = re.compile(r"""["']([^"']+)["']""")


def is_dynamic_version(version) -> bool:
    """해석 시점마다 다른 아티팩트로 풀릴 수 있는 버전 표기인가."""
    s = str(version or "").strip()
    if not s:
        return False
    if "SNAPSHOT" in s.upper():
        return True
    if s in _VERSION_KEYWORDS:
        return True
    if s.endswith("+"):                       # 2.+ / 1.2.+ / +
        return True
    if s.lower().startswith("latest."):       # latest.release / latest.integration
        return True
    if s[0] in ("[", "(", "]") and "," in s:  # 범위. "[1.0]" 은 한 버전 고정이라 제외
        return True
    return False


def _tag(node) -> str:
    return node.tag.rsplit("}", 1)[-1] if isinstance(node.tag, str) else ""


def _child(node, name: str):
    for c in node:
        if _tag(c) == name:
            return c
    return None


def _child_text(node, name: str) -> str:
    c = _child(node, name)
    return (c.text or "").strip() if c is not None else ""


def _dynamic_reason(value, lookup, depth: int = 4):  # -> (표현, kind) | None
    """동적이면 근거 버전 표현, 아니면 None. **해석 못 하면 동적으로 본다(fail-closed).**

    보고 값은 풀렸으면 해석된 값(`2.+`), 못 풀었으면 원래 표현(`${lib.version}`) —
    사용자가 왜 우회했는지 바로 읽을 수 있다.

    lookup(name) 은 후보 값들의 집합, 또는 None(미해석)을 준다. 빈 집합은 "지문 안에서
    해석되는 참조"라 값은 몰라도 원격 변동 요인이 아니라는 뜻이다. 정확도 우선(원칙 1):
    해석 못 한 표현을 고정으로 단정하면 옛 그래프로 스캔하게 된다(codex P1-2·P1-3).
    """
    v = str(value or "").strip()
    if not v:
        return None
    if is_dynamic_version(v):
        return v, "dynamic"
    tokens = [a or b for a, b in _INTERP.findall(v)]
    if not tokens:
        return None
    if depth <= 0:
        return v, "unresolved"
    for t in tokens:
        candidates = lookup(t.strip())
        if candidates is None:
            return v, "unresolved"  # 어디에도 정의가 없다
        if len({str(c).strip() for c in candidates}) > 1:
            # 후보가 갈린다(상호배타 maven profile, 모듈마다 다른 ext…). 활성화 규칙은
            # 정적으로 확정할 수 없으니 모호 → 우회(P1-C).
            return v, "ambiguous"
        for c in candidates:
            reason = _dynamic_reason(c, lookup, depth - 1)
            if reason is not None:
                return reason
    return None


def _pom_properties(pom: Path) -> dict:
    """자기 <properties> + 로컬 parent 체인의 <properties>(자식 우선). 값은 후보 집합.

    profile 안의 <properties> 도 포함한다 — 프로파일이 정의한 버전을 미해석으로 두면
    멀티모듈 프로젝트가 통째로 캐시를 잃는다.
    """
    props: dict[str, set] = {}
    cur, depth = pom, 10
    while cur is not None and depth:
        try:
            root = ET.fromstring(cur.read_bytes())
        except Exception:
            break
        here: dict[str, set] = {}
        for pnode in root.iter():
            if _tag(pnode) != "properties":
                continue
            for c in pnode:
                here.setdefault(_tag(c), set()).add((c.text or "").strip())
        for k, vals in here.items():
            props.setdefault(k, vals)  # 가까운 pom 이 이긴다(자식 > 부모)
        cur, depth = _local_parent_pom(cur), depth - 1
    return props


# maven 내장 프로퍼티 중 "프로젝트 자기 버전"을 가리키는 것들. 리액터 안에서 풀리므로
# 원격 변동 요인이 아니다(멀티모듈의 표준 표기 — 잡으면 대량 FP).
_SELF_VERSION_PROPS = frozenset({
    "project.version", "pom.version", "version", "project.parent.version",
    "pom.parent.version", "revision", "sha1", "changelist",
})


def _maven_lookup(props: dict):
    def lookup(name: str):
        if name in props:
            return props[name]
        if name in _SELF_VERSION_PROPS:
            return set()
        return None
    return lookup


def _maven_dynamic(path: Path, rel: str, fingerprinted: set):
    root = ET.parse(path).getroot()
    lookup = _maven_lookup(_pom_properties(path))

    for node in root.iter():
        kind = _tag(node)
        if kind == "parent":
            # 억제 조건은 "로컬에 있다"가 아니라 **지문에 실제로 들어갔다** 이다.
            # 지문에 없는 parent 가 바뀌면 캐시 키가 안 움직인다(codex P1-1).
            local = _local_parent_pom(path)
            if local is not None and local.resolve() in fingerprinted:
                continue
        elif kind != "dependency":
            continue
        version = _child_text(node, "version")
        if not version:
            continue  # 버전 미기재 = BOM/parent 관리형. 선언이 없으니 판단 대상이 아니다
        reason = _dynamic_reason(version, lookup)
        if reason is not None:
            coord = f"{_child_text(node, 'groupId')}:{_child_text(node, 'artifactId')}"
            yield DynamicVersion(rel, coord, reason[0], reason[1])


def _gradle_symbols(manifests) -> dict:
    """빌드 스크립트 전체 + gradle.properties 의 "이름 → 값 후보" 표.

    멀티모듈에서는 루트가 정의하고 모듈이 쓰므로 대상 전체를 한 번에 모은다.
    """
    symbols: dict[str, set] = {}
    for p in manifests:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if p.name == "gradle.properties":
            for line in text.splitlines():
                line = line.strip()
                if line and line[0] not in "#!" and "=" in line:
                    k, _, v = line.partition("=")
                    symbols.setdefault(k.strip(), set()).add(v.strip())
        elif fnmatch(p.name, "*.gradle") or fnmatch(p.name, "*.gradle.kts"):
            for name, value in _GRADLE_ASSIGN.findall(text):
                symbols.setdefault(name, set()).add(value)
            for name, value in _GRADLE_EXT_INDEX.findall(text):
                symbols.setdefault(name, set()).add(value)
    return symbols


_GRADLE_PREFIXES = ("rootProject.ext.", "project.ext.", "rootProject.", "project.", "ext.")


def _gradle_lookup(symbols: dict, has_catalog: bool, local: dict | None = None):
    def lookup(expr: str):
        name = expr.strip()
        if name.endswith(".get()"):
            name = name[: -len(".get()")]
        for pre in _GRADLE_PREFIXES:
            if name.startswith(pre):
                name = name[len(pre):]
                break
        # libs.* 는 버전 카탈로그 참조 — 카탈로그 파일이 지문에 있고, 동적 항목이면
        # 카탈로그 스캔(_toml_dynamic)이 따로 잡는다. 미해석으로 볼 이유가 없다.
        if has_catalog and (name == "libs" or name.startswith("libs.")):
            return set()
        if local and name in local:
            return local[name]  # 자기 스크립트의 정의가 이긴다
        return symbols.get(name)
    return lookup


def _gradle_dynamic(path: Path, rel: str, symbols: dict, has_catalog: bool, followed: set,
                    build_root: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    local: dict[str, set] = {}
    for name, value in _GRADLE_ASSIGN.findall(text):
        local.setdefault(name, set()).add(value)
    for name, value in _GRADLE_EXT_INDEX.findall(text):
        local.setdefault(name, set()).add(value)
    lookup = _gradle_lookup(symbols, has_catalog, local)

    for _q, group, artifact, version in _GRADLE_COORD.findall(text):
        reason = _dynamic_reason(version, lookup)
        if reason is not None:
            yield DynamicVersion(rel, f"{group}:{artifact}", reason[0], reason[1])

    # 따라가지 못한 applied script = 그 안의 선언을 통째로 못 본다는 뜻이다.
    for target in _APPLY_FROM.findall(text):
        if "://" in target:
            yield DynamicVersion(rel, f"apply from {target}", "원격 스크립트", "external-script")
            continue
        # `$rootDir/...` 은 스크립트 위치가 아니라 **빌드 루트** 기준이다. 이걸 틀리면
        # 지문에 이미 있는 스크립트가 external-script 로 몰려 매 스캔 재생성된다(R3 P2).
        base = build_root if _ROOT_VARS.search(target) else path.parent
        cand = (base / _strip_interp(target)).resolve()
        if cand not in followed:
            yield DynamicVersion(rel, f"apply from {target}", "지문 밖", "external-script")


def _toml_dynamic(path: Path, rel: str):
    """gradle 버전 카탈로그(*.versions.toml) — 키 = 값 줄의 따옴표 값을 본다."""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0]
        key = _TOML_KEY.match(line)
        if not key:
            continue
        for value in _QUOTED.findall(line):
            if is_dynamic_version(value):
                yield DynamicVersion(rel, key.group(1), value)


def _properties_dynamic(path: Path, rel: str):
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line[0] in "#!" or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # `version=` 은 gradle 관례상 프로젝트 자기 버전 — 의존성이 아니다.
        if key.lower() == "version":
            continue
        if is_dynamic_version(value):
            yield DynamicVersion(rel, key, value)


def _manifest_dynamic(path: Path, rel: str, fingerprinted: set, symbols: dict, has_catalog: bool,
                      build_root: Path):
    name = path.name
    if name == "pom.xml":
        return _maven_dynamic(path, rel, fingerprinted)
    if fnmatch(name, "*.gradle") or fnmatch(name, "*.gradle.kts"):
        return _gradle_dynamic(path, rel, symbols, has_catalog, fingerprinted, build_root)
    if fnmatch(name, "*.versions.toml"):
        return _toml_dynamic(path, rel)
    if name == "gradle.properties":
        return _properties_dynamic(path, rel)
    return ()  # *.lockfile 은 해석 결과(고정 버전) 기록이라 볼 것이 없다


def dynamic_versions(target, *, excludes=DEFAULT_EXCLUDES) -> list[DynamicVersion]:
    """매니페스트에서 동적 버전·SNAPSHOT·원격 parent 선언을 찾는다.

    걸리면 매니페스트 지문이 같아도 BOM 을 새로 만들어야 한다. 파일 하나가 깨져도
    나머지는 계속 본다(부분 실패는 정상, 원칙 5).
    """
    root = Path(target)
    manifests = collect_manifests(root, excludes=excludes)
    fingerprinted = {p.resolve() for p in manifests}
    has_catalog = any(fnmatch(p.name, "*.versions.toml") for p in manifests)
    symbols = _gradle_symbols(manifests)
    build_root = (_gradle_build_root(root) or root).resolve()

    out: list[DynamicVersion] = []
    for p in manifests:
        key = _manifest_key(p, root)
        try:
            out.extend(_manifest_dynamic(p, key, fingerprinted, symbols, has_catalog, build_root))
        except Exception as e:
            # 파싱 실패는 "고정"이 아니라 "모른다" — 조용히 넘기면 스테일이 된다(원칙 5).
            out.append(DynamicVersion(key, type(e).__name__, "해석 실패", "unparsable"))
    return out


def _cdxgen_runner(argv, timeout):
    env = {**os.environ, "FETCH_LICENSE": "false"}
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)


def generate_sbom(target, out_path, *, run=_cdxgen_runner, timeout: float = 900.0):
    """cdxgen 으로 BOM 생성. 성공+파일존재면 경로, 아니면 None.

    임시 파일에 쓰고 성공했을 때만 원자적으로 교체한다 — 재생성(refresh)이 실패했는데
    같은 경로에 옛 BOM 이 남아 있으면 그걸 "성공"으로 오인하기 때문(스테일 재발).
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f"{out.name}.{os.getpid()}.tmp")
    argv = ["cdxgen", "-t", "java", "-o", str(tmp), str(target)]
    try:
        run(argv, timeout)
    except Exception:
        tmp.unlink(missing_ok=True)
        return None
    if tmp.exists() and tmp.stat().st_size > 0:
        os.replace(tmp, out)
        return out
    tmp.unlink(missing_ok=True)
    return None


_locks_guard = threading.Lock()
_locks: dict[str, threading.Lock] = {}


# BOM 캐시 수명. 정적 분석이 **원리적으로** 못 보는 변화(원격 아티팩트 재배포, -P/-D 로
# 주입되는 버전, 코드가 계산하는 좌표…)에 대한 하한선이다. 매니페스트 내용 해시가 1차
# 방어이고, 이건 "그래도 하루 지난 BOM 은 다시 만든다"는 마지막 안전망.
DEFAULT_BOM_MAX_AGE_S = 24 * 3600


def ensure_bom(target, *, timeout: float = 900.0, run=_cdxgen_runner, refresh: bool = False,
               max_age_s: float | None = DEFAULT_BOM_MAX_AGE_S, now=time.time):
    """BOM 을 한 번만 생성(경로+매니페스트 해시 캐시 + 락). 매니페스트가 그대로면 재사용.

    refresh=True 면 캐시 적중을 무시하고 다시 해석한다(동적 버전/SNAPSHOT 처럼 매니페스트가
    그대로여도 그래프가 달라지는 경우, 또는 `--no-bom-cache`). 결과는 같은 캐시 경로에
    기록돼 다음 스캔이 그대로 이득을 본다.

    max_age_s 를 넘긴 캐시도 다시 만든다(None 이면 수명 무제한). 여기서 쓰는 mtime 은
    **우리가 만든 캐시 파일의 생성 시각**이라 캐시 키에서 mtime 을 금지한 이유(git 이
    소스 mtime 을 바꾼다)와 무관하다.
    """
    path = bom_cache_path(target)
    with _locks_guard:
        lock = _locks.setdefault(str(path), threading.Lock())
    with lock:
        if not refresh and path.exists() and path.stat().st_size > 0:
            fresh = max_age_s is None or (now() - path.stat().st_mtime) <= max_age_s
            if fresh:
                return path
        return generate_sbom(target, path, run=run, timeout=timeout)
