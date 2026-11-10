from pathlib import Path

ROOT = Path(__file__).parent.parent
MANIFEST = (ROOT / "k8s-example.yaml.tpl").read_text()


def test_manifest_runs_the_same_clamd_script_as_compose():
    script = (ROOT / "clamd-start.sh").read_text()
    for line in script.splitlines():
        assert " " * 14 + line + "\n" in MANIFEST


def test_every_container_is_non_root_and_read_only():
    containers = MANIFEST.count("- name: clamd") + MANIFEST.count("- name: app")
    assert containers == 2
    assert MANIFEST.count("runAsNonRoot: true") == containers
    assert MANIFEST.count("readOnlyRootFilesystem: true") == containers
    assert MANIFEST.count("allowPrivilegeEscalation: false") == containers
    assert MANIFEST.count('capabilities: { drop: ["ALL"] }') == containers
