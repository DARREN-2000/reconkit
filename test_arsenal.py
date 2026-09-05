"""Socket-free tests for the reconkit arsenal catalog + launcher."""

import shutil
from pathlib import Path

from reconkit.core import arsenal as A


def test_catalog_shape():
    s = A.summary()
    assert s["total"] >= 200
    assert len(s["categories"]) == 19
    names = [t["name"] for t in A.CATALOG]
    assert len(names) == len(set(names))
    required = ("name", "category", "phase", "desc", "bins", "install", "license", "url")
    assert all(all(k in t for k in required) for t in A.CATALOG)
    assert all(t["phase"] in (0, 1, 2, 3, 4, 5, 6, 7) for t in A.CATALOG)
    assert all(t["license"] in (A.FOSS, A.FREEMIUM, A.COMMERCIAL, A.REF) for t in A.CATALOG)
    assert all(isinstance(t["bins"], list) for t in A.CATALOG)


def test_lookup():
    assert A.by_name("nmap") is not None
    assert A.by_name("NMAP") is not None
    msf = A.by_name("msfconsole")
    assert msf is not None and msf["name"] == "metasploit"
    assert A.by_name("definitely-not-a-tool") is None


def test_filters():
    web = A.filter_tools(category="web-app")
    assert len(web) > 0 and all(t["category"] == "web-app" for t in web)
    p4 = A.filter_tools(phase=4)
    assert len(p4) > 0 and all(t["phase"] == 4 for t in p4)
    foss = A.filter_tools(license=A.FOSS)
    assert len(foss) > 0 and all(t["license"] == A.FOSS for t in foss)


def test_detection():
    res = A.check()
    assert all(k in res for k in ("installed", "missing", "libraries", "references", "summary"))
    assert all(isinstance(x, tuple) and len(x) == 2 for x in res["installed"])
    assert "angr" in res["libraries"]
    assert "kali" in res["references"]


def test_authorization_gate():
    r_refuse = A.run_tool("nmap", [], authorized=False)
    assert r_refuse["data"]["ok"] is False
    assert "authorization" in r_refuse["summary"].lower()
    
    r_unknown = A.run_tool("nope", [], authorized=True)
    assert r_unknown["data"]["ok"] is False
    assert "unknown" in r_unknown["summary"].lower()
    
    r_lib = A.run_tool("angr", [], authorized=True)
    assert r_lib["data"]["ok"] is False


def test_authorized_execution():
    if shutil.which("strings"):
        repo_root = Path(__file__).resolve().parent
        target_file = repo_root / "reconkit" / "__init__.py"
        r_ok = A.run_tool("strings", [str(target_file)], authorized=True)
        assert r_ok["data"]["ok"] is True
        assert r_ok["data"]["returncode"] == 0
