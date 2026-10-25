"""Reproduce Helm config validation failures without deploying anything.

Usage: python3 reproduce.py /absolute/path/to/project /absolute/path/to/helm
Requires an already built target/debug/uk-server and openssl.
All certificates and credentials below are disposable test material.
"""

from pathlib import Path
import re
import subprocess
import sys
import tempfile

repo = Path(sys.argv[1]).resolve()
helm = sys.argv[2]
rendered = subprocess.check_output(
    [helm, "template", "audit", str(repo / "deploy/helm/uncrowned-king"),
     "--set", "server.existingSecret=audit-creds",
     "--set", "server.existingTlsSecret=audit-tls"], text=True)


def scalar(name):
    match = re.search(r"^  " + re.escape(name) + r": \|\n((?:    .*\n|\n)*)", rendered, re.M)
    return "\n".join(line[4:] if line.startswith("    ") else line
                     for line in match.group(1).splitlines()) + "\n"


with tempfile.TemporaryDirectory(prefix="uk-helm-audit-") as directory:
    root = Path(directory)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
         "-days", "1", "-subj", "/CN=localhost"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    policy = root / "policy.toml"
    policy.write_text(scalar("policy.toml"))
    for name in ["key.pem", "cert.pem", "policy.toml"]:
        (root / name).chmod(0o600)
    server = (scalar("server.toml")
              .replace("/etc/uncrowned-king/policy/policy.toml", str(policy))
              .replace("/etc/uncrowned-king/tls/tls.crt", str(root / "cert.pem"))
              .replace("/etc/uncrowned-king/tls/tls.key", str(root / "key.pem")))
    server += ('\n[[credentials]]\nkey_id = "audit"\n'
               'secret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"\n')
    integer_only = re.sub(r"(?<== )\d+\.\d+e\+\d+", lambda m: str(int(float(m[0]))), server)
    cases = [("as-rendered", server), ("integer-only", integer_only),
             ("integer-and-limit", integer_only.replace("67108864", "16777216"))]
    for label, body in cases:
        config = root / (label + ".toml")
        config.write_text(body)
        config.chmod(0o600)
        result = subprocess.run(
            [str(repo / "target/debug/uk-server"), "--config", str(config), "config-check"],
            capture_output=True, text=True)
        print(label, "exit", result.returncode)
        print(result.stdout + result.stderr)
