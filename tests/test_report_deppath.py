"""CycloneDX 의존 그래프 → 직접/전이 경로 문자열(spec §5.3)."""
from pathlib import Path

from secscan.models import Component, Finding
from secscan.report.deppath import MAX_HOPS, NO_BOM, NOT_IN_BOM, DepGraph, deppaths_for

BOM = Path("fixtures/report/work-note-bom.cdx.json")


def test_transitive_chain_from_fixture():
    g = DepGraph.from_path(BOM)
    assert g.path_for("org.apache.tomcat.embed:tomcat-embed-core", "10.1.55") == "전이 ← spring-boot-starter-tomcat ← spring-boot-starter-web"
    assert g.path_for("org.apache.logging.log4j:log4j-api", "2.24.3") == (
        "전이 ← log4j-to-slf4j ← spring-boot-starter-logging ← spring-boot-starter ← mybatis-spring-boot-starter")


def test_direct_missing_and_version_mismatch():
    g = DepGraph.from_path(BOM)
    assert g.path_for("org.flywaydb:flyway-core", "11.7.2") == "직접"
    assert g.path_for("x:y", "1") == NOT_IN_BOM
    assert g.path_for("org.apache.tomcat.embed:tomcat-embed-core", "10.1.99").startswith("전이(버전 상이: 10.1.55) ← ")


def test_missing_bom_file_and_truncation():
    assert DepGraph.from_path(Path("nope/bom.json")) is None
    chain = {"bom-ref": "root", "components": [], "dependencies": []}
    refs = [f"pkg:maven/g/a{i}@1?type=jar" for i in range(7)]
    bom = {"metadata": {"component": {"bom-ref": "pkg:maven/g/root@1?type=jar"}},
           "components": [{"bom-ref": r, "group": "g", "name": f"a{i}", "version": "1"} for i, r in enumerate(refs)],
           "dependencies": [{"ref": "pkg:maven/g/root@1?type=jar", "dependsOn": [refs[0]]}]
                           + [{"ref": refs[i], "dependsOn": [refs[i + 1]]} for i in range(6)]}
    s = DepGraph(bom).path_for("g:a6", "1")
    assert s == "전이 ← a5 ← a4 ← a3 ← a2 ← …" and s.count("←") == MAX_HOPS + 1
    unreachable = {"metadata": {"component": {"bom-ref": "r"}}, "components": [{"bom-ref": "z", "group": "g", "name": "z", "version": "1"}], "dependencies": []}
    assert DepGraph(unreachable).path_for("g:z", "1") == "BOM 에 있음(경로 미상)"


def test_deppaths_for_findings_only_sca_and_none_graph():
    sca = Finding(category="sca", severity="high", title="t", tool="trivy", rule_id="CVE-1",
                  component=Component("maven", "org.flywaydb:flyway-core", "11.7.2"))
    sast = Finding(category="sast", severity="low", title="t", tool="semgrep", rule_id="r")
    g = DepGraph.from_path(BOM)
    assert deppaths_for([sca, sast], g) == {sca.id: "직접"}
    assert deppaths_for([sca, sast], None) == {sca.id: NO_BOM}
