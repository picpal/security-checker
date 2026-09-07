"""FR-4: report 패키지 불변식 회귀.

(a) 자동 억제 금지(spec §7 "억제 자동화" 대응, PROGRESS.md 보고서 워크북 절) — report 패키지
    어떤 모듈도 `secscan.suppress` 를 import 하지 않는다. ast 로 import 문 자체를 걷어 모듈명에
    "suppress" 가 없는지 보고(alias 우회 포함), 소스 텍스트에도 `secscan.suppress`·
    `from ..suppress`·`from .suppress` 문자열이 없는지 이중으로 단언한다.
(b) scan 의 exit code 불변(report 실패에도 게이트 판정은 유지)은 tests/test_cli.py 의
    test_main_scan_report_failure_does_not_swallow_exit_code(FR-2)가 담당한다 — 여기서 중복
    테스트를 만들지 않는다.
"""
import ast
from pathlib import Path

REPORT_DIR = Path("secscan/report")
REPORT_FILES = sorted(REPORT_DIR.glob("*.py"))


def _imported_names(tree: ast.Module) -> list[str]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level  # 상대 import 는 level(점 개수)로 상위 패키지를 표시
            module = node.module or ""
            names.append(prefix + module)
            for alias in node.names:
                names.append(f"{prefix}{module}.{alias.name}" if module else f"{prefix}{alias.name}")
    return names


def test_report_package_glob_finds_modules():
    # ast 검사 자체가 무의미해지지 않도록 — glob 이 실제로 파일을 찾는지 먼저 확인.
    assert {p.name for p in REPORT_FILES} >= {"cli.py", "paths.py", "result_check.py", "workbook.py"}


def test_no_report_module_imports_suppress():
    for path in REPORT_FILES:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for name in _imported_names(tree):
            assert "suppress" not in name, f"{path}: import 에 suppress 포함 — {name}"
        assert "secscan.suppress" not in source, path
        assert "from ..suppress" not in source, path
        assert "from .suppress" not in source, path
