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


def manifest_fingerprint(target, *, excludes=DEFAULT_EXCLUDES) -> str:
    """의존성 매니페스트의 (상대경로, 내용) 해시. 캐시 키(식별자)용 — 보안 해시 아님.

    mtime 은 쓰지 않는다: git checkout/clone 이 mtime 을 바꿔 내용이 같아도 캐시가
    매번 무효화된다(재생성 비용이 커서 캐시가 사실상 사라짐).
    """
    root = Path(target)
    h = hashlib.sha1(usedforsecurity=False)
    for p in iter_manifests(root, excludes=excludes):
        h.update(str(p.relative_to(root)).encode())  # 매니페스트 추가/삭제/이동도 반영
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
    """매니페스트가 그대로여도 해석 결과가 달라질 수 있는 의존성 선언 1건."""
    file: str        # 대상 기준 상대경로
    coordinate: str  # "group:artifact" 또는 프로퍼티 키
    version: str


# maven 레거시 키워드는 "정확히 일치"할 때만 동적이다 — "4.3.30.RELEASE"(스프링 구 표기)는
# 고정 버전이라 부분 일치로 잡으면 대량 FP 가 난다.
_VERSION_KEYWORDS = frozenset({"LATEST", "RELEASE"})
# gradle 좌표 문자열 'group:artifact:version' (가장 흔한 선언 형태).
_GRADLE_COORD = re.compile(r"""["']([\w.\-]+):([\w.\-]+):([^"'\s]+)["']""")
_TOML_KEY = re.compile(r"""^\s*([\w.\-]+)\s*=""")
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


def _resolve_property(value: str, props: dict, depth: int = 3) -> str:
    """`${commons.version}` 을 <properties> 로 한 단계씩 푼다(못 풀면 빈 문자열)."""
    while depth and value.startswith("${") and value.endswith("}"):
        value = props.get(value[2:-1], "")
        depth -= 1
    return value


def _maven_dynamic(path: Path, rel: str):
    root = ET.parse(path).getroot()
    props = {}
    for pnode in root.findall("./{*}properties"):
        for c in pnode:
            props[_tag(c)] = (c.text or "").strip()

    for node in root.iter():
        kind = _tag(node)
        if kind == "parent":
            # 로컬 parent 는 이미 지문에 들어 있다(멀티모듈 집합체). 원격 parent 만 동적 소스.
            # `<relativePath/>` 를 빈 값으로 명시하면 항상 원격, 없으면 기본값 ../pom.xml.
            rp = _child(node, "relativePath")
            if not (rp is not None and not (rp.text or "").strip()):
                cand = path.parent / ((rp.text or "").strip() if rp is not None else "../pom.xml")
                if cand.is_file() or (cand / "pom.xml").is_file():
                    continue
        elif kind != "dependency":
            continue
        version = _resolve_property(_child_text(node, "version"), props)
        if is_dynamic_version(version):
            coord = f"{_child_text(node, 'groupId')}:{_child_text(node, 'artifactId')}"
            yield DynamicVersion(rel, coord, version)


def _gradle_dynamic(path: Path, rel: str):
    for group, artifact, version in _GRADLE_COORD.findall(path.read_text(encoding="utf-8", errors="replace")):
        if is_dynamic_version(version):
            yield DynamicVersion(rel, f"{group}:{artifact}", version)


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


def _manifest_dynamic(path: Path, rel: str):
    name = path.name
    if name == "pom.xml":
        return _maven_dynamic(path, rel)
    if fnmatch(name, "*.gradle") or fnmatch(name, "*.gradle.kts"):
        return _gradle_dynamic(path, rel)
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
    out: list[DynamicVersion] = []
    for p in iter_manifests(root, excludes=excludes):
        try:
            out.extend(_manifest_dynamic(p, str(p.relative_to(root))))
        except Exception:
            continue
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


def ensure_bom(target, *, timeout: float = 900.0, run=_cdxgen_runner, refresh: bool = False):
    """BOM 을 한 번만 생성(경로+매니페스트 해시 캐시 + 락). 매니페스트가 그대로면 재사용.

    refresh=True 면 캐시 적중을 무시하고 다시 해석한다(동적 버전/SNAPSHOT 처럼 매니페스트가
    그대로여도 그래프가 달라지는 경우, 또는 `--no-bom-cache`). 결과는 같은 캐시 경로에
    기록돼 다음 스캔이 그대로 이득을 본다.
    """
    path = bom_cache_path(target)
    with _locks_guard:
        lock = _locks.setdefault(str(path), threading.Lock())
    with lock:
        if not refresh and path.exists() and path.stat().st_size > 0:
            return path
        return generate_sbom(target, path, run=run, timeout=timeout)
