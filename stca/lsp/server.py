"""STCA LSP Server — real-time squiggles in editors (VS Code, Neovim, JetBrains)."""
from __future__ import annotations
import argparse, json, sys, threading
from pathlib import Path
from typing import Dict, List, Optional

class LSPServer:
    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path.cwd()
        self.workspace_files: Dict[str, str] = {}
        self.debounce_timers: Dict[str, threading.Timer] = {}
        self.debounce_ms = 500

    def run(self):
        while True:
            try:
                message = self._read_message()
                if message is None: break
                self._handle_message(message)
            except KeyboardInterrupt: break
            except Exception as e:
                sys.stderr.write(f"LSP error: {e}\n")

    def _read_message(self):
        headers: Dict[str, str] = {}
        while True:
            line = sys.stdin.readline()
            if not line: return None
            line = line.strip()
            if not line: break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        content_length = int(headers.get("content-length", 0))
        if content_length == 0: return None
        body = sys.stdin.read(content_length)
        try: return json.loads(body)
        except: return None

    def _send_message(self, message: dict):
        body = json.dumps(message)
        sys.stdout.write(f"Content-Length: {len(body)}\r\n\r\n")
        sys.stdout.write(body)
        sys.stdout.flush()

    def _handle_message(self, message: dict):
        method = message.get("method")
        id_ = message.get("id")
        params = message.get("params", {})
        if method == "initialize":
            self._send_message({"jsonrpc": "2.0", "id": id_, "result": {
                "capabilities": {"textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": False}},
                                 "hoverProvider": True, "codeActionProvider": True},
                "serverInfo": {"name": "stca-lsp", "version": "1.0.0"}}})
        elif method == "initialized": pass
        elif method == "shutdown": self._send_message({"jsonrpc": "2.0", "id": id_, "result": None})
        elif method == "exit": sys.exit(0)
        elif method == "textDocument/didOpen":
            doc = params.get("textDocument", {})
            self.workspace_files[doc.get("uri", "")] = doc.get("text", "")
            self._schedule_analysis(doc.get("uri", ""))
        elif method == "textDocument/didChange":
            doc = params.get("textDocument", {})
            changes = params.get("contentChanges", [])
            if changes: self.workspace_files[doc.get("uri", "")] = changes[0].get("text", "")
            self._schedule_analysis(doc.get("uri", ""))
        elif method == "textDocument/didSave":
            self._schedule_analysis(params.get("textDocument", {}).get("uri", ""), force=True)
        elif method == "textDocument/hover":
            self._send_message({"jsonrpc": "2.0", "id": id_, "result": {"contents": "STCA: hover info"}})
        elif method == "textDocument/codeAction":
            self._send_message({"jsonrpc": "2.0", "id": id_, "result": []})

    def _schedule_analysis(self, uri: str, force: bool = False):
        if uri in self.debounce_timers: self.debounce_timers[uri].cancel()
        timer = threading.Timer(self.debounce_ms / 1000.0, lambda: self._analyze_and_publish(uri))
        timer.daemon = True
        timer.start()
        self.debounce_timers[uri] = timer

    def _analyze_and_publish(self, uri: str):
        text = self.workspace_files.get(uri, "")
        if not text: return
        path = Path(uri[7:] if uri.startswith("file://") else uri)
        findings = self._analyze_text(path, text)
        diagnostics = [self._finding_to_diagnostic(f) for f in findings]
        self._send_message({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                            "params": {"uri": uri, "diagnostics": diagnostics}})

    def _analyze_text(self, path: Path, text: str) -> List[dict]:
        import tempfile
        suffix = path.suffix or ".py"
        findings: List[dict] = []
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, dir=str(self.repo_root)) as tmp:
            tmp.write(text)
            tmp_path = Path(tmp.name)
        try:
            if suffix == ".py":
                from ..nullness import NullnessAnalyzer
                for issue in NullnessAnalyzer().analyze_file(tmp_path, self.repo_root):
                    findings.append({"rule_id": "nullness", "file": str(path), "line": issue.line,
                                     "message": issue.reason, "severity": "warning", "fix": ""})
            elif suffix in (".js", ".jsx", ".ts", ".tsx"):
                from ..js_pattern_scanner import scan_js_patterns
                for hit in scan_js_patterns(tmp_path, self.repo_root):
                    findings.append({"rule_id": hit.rule_id, "file": hit.file, "line": hit.line,
                                     "message": hit.message, "severity": hit.severity, "fix": hit.fix})
            # v2.9: Wire all v2 scanners for real-time LSP feedback
            from ..multi_lang import scan_crypto_multi, scan_auth_multi, scan_idor_multi, scan_concurrency_multi
            from ..code_quality import analyze_code_quality
            for scanner in [scan_crypto_multi, scan_auth_multi, scan_idor_multi, scan_concurrency_multi]:
                try:
                    for lf in scanner(tmp_path, self.repo_root):
                        findings.append({"rule_id": lf.rule_id, "file": str(path), "line": lf.line,
                                         "message": lf.description, "severity": lf.severity, "fix": lf.fix})
                except: pass
            try:
                for issue in analyze_code_quality(tmp_path, self.repo_root):
                    findings.append({"rule_id": issue.rule_id, "file": str(path), "line": issue.line,
                                     "message": issue.description, "severity": issue.severity, "fix": issue.fix})
            except: pass
            # Tree-sitter AST
            try:
                from ..tree_sitter_analyzer import analyze_with_ast
                for issue in analyze_with_ast(tmp_path, self.repo_root):
                    findings.append({"rule_id": issue.rule_id, "file": str(path), "line": issue.line,
                                     "message": issue.description, "severity": issue.severity, "fix": issue.fix})
            except: pass
        except: pass
        finally: tmp_path.unlink(missing_ok=True)
        return findings

    def _finding_to_diagnostic(self, finding: dict) -> dict:
        sev_map = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 3}
        return {"range": {"start": {"line": max(0, finding.get("line", 1) - 1), "character": 0},
                          "end": {"line": max(0, finding.get("line", 1) - 1), "character": 80}},
                "severity": sev_map.get(finding.get("severity", "medium").lower(), 2),
                "code": finding.get("rule_id", ""), "source": "stca", "message": finding.get("message", "")}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=None)
    args = parser.parse_args()
    server = LSPServer(Path(args.repo_root) if args.repo_root else None)
    server.run()

if __name__ == "__main__":
    main()
