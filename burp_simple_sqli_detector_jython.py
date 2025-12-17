# -*- coding: utf-8 -*-
#
# Simple SQLi Detector - Burp Extension (Jython 2.7)
# STRICT RULES:
# - Do NOT change detection logic / payloads / heuristics.
# - Only adapt for Burp integration, UI, threading, queue, and requested UX additions.
#
# NOTE (ASCII ONLY):
# - This file avoids non-ASCII symbols to prevent Jython encoding errors.
from burp import IBurpExtender, ITab, IContextMenuFactory, IProxyListener
from java.lang import Runnable
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JTable, JScrollPane, JTextPane,
    JRadioButton, ButtonGroup, JMenuItem, JSplitPane, JCheckBox, SwingUtilities,
    JPopupMenu
)
from javax.swing.table import DefaultTableModel
from javax.swing.text import StyleConstants
from java.awt import BorderLayout, Dimension, Color
from java.awt.event import ActionListener, MouseAdapter
from java.util.concurrent import (
    Executors, LinkedBlockingQueue, ExecutorCompletionService, TimeUnit, Callable, TimeoutException
)
from collections import OrderedDict
import uuid
import re
import json
import threading
try:
    from urlparse import urlparse, urlunparse
except Exception:
    urlparse = None
    urlunparse = None
# ----------------------------
# Cancellation Exception
# ----------------------------
class StopNowException(Exception):
    pass
# =====================================================================================
# ORIGINAL SCRIPT PORT (logic preserved; only transport + logging adapted)
# =====================================================================================
class CurlParser(object):
    __slots__ = ('curl_cmd', 'method', 'url', 'headers', 'cookies', 'body', 'extra_flags')
    def __init__(self, curl_cmd):
        self.curl_cmd = (curl_cmd or "").strip()
        self.method = "GET"
        self.url = ""
        self.headers = []
        self.cookies = []
        self.body = None
        self.extra_flags = []
    def parse(self):
        if not self.curl_cmd:
            return self._empty_result()
        if not self.curl_cmd.lstrip().startswith('curl'):
            return self._parse_raw_request()
        cmd = self.curl_cmd.replace('\\\n', ' ').replace('\\\r\n', ' ')
        tokens = self._tokenize(cmd)
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == 'curl':
                i += 1
                continue
            if tok in ('-X', '--request'):
                i += 1
                if i < len(tokens):
                    self.method = tokens[i]
                i += 1
                continue
            if tok in ('-H', '--header'):
                i += 1
                if i < len(tokens):
                    h = tokens[i]
                    if not h.lower().startswith("content-length:"):
                        self.headers.append(h)
                i += 1
                continue
            if tok in ('-b', '--cookie'):
                i += 1
                if i < len(tokens):
                    self.cookies.append(tokens[i])
                i += 1
                continue
            if tok in ('-d', '--data', '--data-raw', '--data-binary'):
                i += 1
                if i < len(tokens):
                    self.body = tokens[i]
                i += 1
                continue
            if tok in ('--path-as-is', '-k', '--insecure', '-s', '--silent',
                      '--compressed', '-L', '--location'):
                self.extra_flags.append(tok)
                i += 1
                continue
            if tok in ('-i', '--include'):
                i += 1
                continue
            if not tok.startswith('-'):
                self.url = tok
            i += 1
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'cookies': self.cookies,
            'body': self.body,
            'extra_flags': self.extra_flags
        }
    def _parse_raw_request(self):
        lines = self.curl_cmd.split('\n')
        if not lines:
            return self._empty_result()
        parts = lines[0].strip().split(' ')
        if len(parts) < 2:
            return self._empty_result()
        self.method = parts[0].strip()
        path = parts[1].strip()
        host = None
        cookie_header = None
        body_start = len(lines)
        for i, line in enumerate(lines[1:], 1):
            line = line.rstrip('\r').strip('\n')
            if not line.strip():
                body_start = i + 1
                break
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip()
                value = value.strip()
                if key.lower() == 'host':
                    host = value
                elif key.lower() == 'cookie':
                    cookie_header = value
                else:
                    if key.lower() != 'content-length':
                        self.headers.append("%s: %s" % (key, value))
        if host:
            if path.startswith("http://") or path.startswith("https://"):
                self.url = path
            else:
                # original behavior: default https
                self.url = "https://%s%s" % (host, path)
        else:
            self.url = path
        if cookie_header:
            self.cookies.append(cookie_header)
        if body_start < len(lines):
            b = '\n'.join(lines[body_start:]).strip()
            self.body = b if b else None
        self.extra_flags.append('-k')
        return {
            'method': self.method,
            'url': self.url,
            'headers': self.headers,
            'cookies': self.cookies,
            'body': self.body,
            'extra_flags': self.extra_flags
        }
    def _empty_result(self):
        return {'method': 'GET', 'url': '', 'headers': [], 'cookies': [], 'body': None, 'extra_flags': []}
    def _tokenize(self, cmd):
        tokens = []
        current = []
        i = 0
        cmd_len = len(cmd)
        while i < cmd_len:
            c = cmd[i]
            if c in ' \t\n\r' and not current:
                i += 1
                continue
            if cmd[i:i+2] == "$'":
                if current:
                    tokens.append(''.join(current))
                    current = []
                j = i + 2
                while j < cmd_len:
                    if cmd[j] == "'":
                        tokens.append(cmd[i:j+1])
                        i = j + 1
                        break
                    if cmd[j] == '\\' and j + 1 < cmd_len:
                        j += 2
                    else:
                        j += 1
                else:
                    i = j
                continue
            if c == "'" and not current:
                j = i + 1
                while j < cmd_len and cmd[j] != "'":
                    j += 1
                tokens.append(cmd[i+1:j])
                i = j + 1
                continue
            if c == '"' and not current:
                j = i + 1
                while j < cmd_len:
                    if cmd[j] == '"':
                        break
                    if cmd[j] == '\\' and j + 1 < cmd_len:
                        j += 2
                    else:
                        j += 1
                tokens.append(cmd[i+1:j])
                i = j + 1
                continue
            if c in ' \t\n\r':
                if current:
                    tokens.append(''.join(current))
                    current = []
                i += 1
                continue
            current.append(c)
            i += 1
        if current:
            tokens.append(''.join(current))
        return tokens
class SQLiDetector(object):
    __slots__ = (
        'debug', 'max_workers', 'mode', 'cookie_only', 'full_mode', 'force_json', 'timeout_sec',
        '_transport', '_log', '_should_stop'
    )
    def __init__(self, transport, logger, should_stop,
                 debug=False, max_workers=10, mode='single',
                 cookie_only=False, full_mode=False, force_json=False, timeout_sec=30):
        self.debug = debug
        self.max_workers = max_workers
        self.mode = mode # 'single', 'faster', 'fastest'
        self.cookie_only = cookie_only
        self.full_mode = full_mode
        self.force_json = force_json
        self.timeout_sec = timeout_sec
        self._transport = transport
        self._log = logger
        self._should_stop = should_stop
    def _check_stop(self):
        if self._should_stop():
            raise StopNowException("Stopped by user")
    # -------- HTTP transport (Burp adapter returns status or None) --------
    def execute_request(self, method, url, headers_list, cookies_list, body, extra_flags):
        self._check_stop()
        if self.debug:
            self._log("[DEBUG] %s %s\n" % (method, (url or "")[:160]))
        executor = Executors.newSingleThreadExecutor()
        callable_task = _TransportCallable(self._transport, method, url, headers_list, cookies_list, body, extra_flags)
        future = executor.submit(callable_task)
        try:
            st = future.get(self.timeout_sec, TimeUnit.SECONDS)
            if self.debug:
                self._log("[DEBUG] Status: %s\n" % str(st))
            return st
        except TimeoutException:
            if self.debug:
                self._log("[DEBUG] Timeout after %d sec\n" % self.timeout_sec)
            return None
        except StopNowException:
            raise
        except Exception as e:
            if self.debug:
                self._log("[DEBUG] Error: %s\n" % str(e))
            return None
        finally:
            try:
                future.cancel(True)
            except:
                pass
            try:
                executor.shutdownNow()
            except:
                pass
    # -------- content-type / JSON detection --------
    def is_json_body(self, headers, body):
        if not body:
            return False
        b = body.strip()
        if self.force_json:
            try:
                json.loads(b)
                return True
            except Exception:
                return False
        ct = None
        for h in headers:
            if h.lower().startswith("content-type:"):
                ct = h.split(":", 1)[1].strip().lower()
                break
        if ct and "application/json" in ct:
            return True
        if b.startswith("{") or b.startswith("["):
            try:
                json.loads(b)
                return True
            except Exception:
                return False
        return False
    def _normalize_json_suffix(self, suffix):
        if suffix == "%27":
            return "'"
        if suffix == "%27%27":
            return "''"
        return suffix
    # -------- param extraction --------
    def extract_params(self, url, body, headers):
        get_params = {}
        post_params = {}
        json_paths = []
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, _, value = param.partition('=')
                    get_params.setdefault(key, []).append(value)
                else:
                    get_params.setdefault(param, []).append('')
        is_json = self.is_json_body(headers, body)
        if body:
            if is_json:
                try:
                    data = json.loads(body, object_pairs_hook=OrderedDict)
                    json_paths = self._extract_json_paths(data)
                except Exception:
                    json_paths = []
                    is_json = False
            if (not is_json) and ('=' in body) and (not body.strip().startswith('{')):
                for param in body.split('&'):
                    if '=' in param:
                        key, _, value = param.partition('=')
                        post_params.setdefault(key, []).append(value)
                    else:
                        post_params.setdefault(param, []).append('')
        return get_params, post_params, json_paths, is_json
    def extract_cookie_params(self, cookies):
        cookie_params = {}
        for cookie in cookies:
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    cookie_params.setdefault(key, []).append(value)
        return cookie_params
    # -------- JSON paths --------
    def _extract_json_paths(self, data, prefix=""):
        paths = []
        if isinstance(data, dict):
            for k, v in data.items():
                p = ("%s.%s" % (prefix, k)) if prefix else k
                paths.extend(self._extract_json_paths(v, p))
        elif isinstance(data, list):
            for i, v in enumerate(data):
                p = ("%s[%d]" % (prefix, i)) if prefix else ("[%d]" % i)
                paths.extend(self._extract_json_paths(v, p))
        else:
            if (isinstance(data, str) or isinstance(data, unicode)) and prefix:
                paths.append(prefix)
        return paths
    def _parse_json_path(self, path):
        tokens = []
        buf = ''
        i = 0
        n = len(path)
        while i < n:
            c = path[i]
            if c == '.':
                if buf:
                    tokens.append(buf)
                    buf = ''
                i += 1
                continue
            if c == '[':
                if buf:
                    tokens.append(buf)
                    buf = ''
                j = path.find(']', i + 1)
                if j == -1:
                    break
                idx_str = path[i + 1:j]
                try:
                    tokens.append(int(idx_str))
                except Exception:
                    tokens.append(idx_str)
                i = j + 1
                continue
            buf += c
            i += 1
        if buf:
            tokens.append(buf)
        return tokens
    def _mutate_json_at_path(self, data, tokens, suffix):
        if not tokens:
            if isinstance(data, basestring):
                return data + suffix
            return data
        head = tokens[0]
        tail = tokens[1:]
        if isinstance(head, int) and isinstance(data, list):
            new_list = list(data)
            if 0 <= head < len(new_list):
                new_list[head] = self._mutate_json_at_path(new_list[head], tail, suffix)
            return new_list
        if isinstance(head, basestring) and isinstance(data, dict):
            new_obj = type(data)(data)
            if head in new_obj:
                new_obj[head] = self._mutate_json_at_path(new_obj[head], tail, suffix)
            return new_obj
        return data
    # -------- mutations --------
    def mutate_url_param(self, url, param_name, param_idx, suffix):
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        parts = []
        current_idx = {}
        for param in (parsed.query.split('&') if parsed.query else []):
            if '=' in param:
                key, _, value = param.partition('=')
                idx = current_idx.get(key, 0)
                if key == param_name and idx == param_idx:
                    value += suffix
                current_idx[key] = idx + 1
                parts.append("%s=%s" % (key, value))
            else:
                parts.append(param)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, '&'.join(parts), parsed.fragment
        ))
    def mutate_body_param(self, body, param_name, param_idx, suffix, json_enabled):
        if not body:
            return body
        if json_enabled and body.strip().startswith(('{', '[')):
            try:
                data = json.loads(body, object_pairs_hook=OrderedDict)
                js_suffix = self._normalize_json_suffix(suffix)
                path_tokens = self._parse_json_path(param_name)
                mutated = self._mutate_json_at_path(data, path_tokens, js_suffix)
                return json.dumps(mutated, ensure_ascii=False, separators=(',', ':'))
            except Exception:
                return body
        parts = []
        current_idx = {}
        for param in body.split('&'):
            if '=' in param:
                key, _, value = param.partition('=')
                idx = current_idx.get(key, 0)
                if key == param_name and idx == param_idx:
                    value += suffix
                current_idx[key] = idx + 1
                parts.append("%s=%s" % (key, value))
            else:
                parts.append(param)
        return '&'.join(parts)
    def mutate_cookie_param(self, cookies, param_name, param_idx, suffix):
        mutated = []
        current_idx = {}
        for cookie in cookies:
            parts = []
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    idx = current_idx.get(key, 0)
                    if key == param_name and idx == param_idx:
                        value += suffix
                    current_idx[key] = idx + 1
                    parts.append("%s=%s" % (key, value))
                else:
                    parts.append(part)
            mutated.append('; '.join(parts))
        return mutated
    def _get_header(self, headers, name):
        ln = name.lower()
        for i, h in enumerate(headers):
            if ':' not in h:
                continue
            k, _, v = h.partition(':')
            if k.strip().lower() == ln:
                return i, v.strip()
        return None
    def _set_header(self, headers, name, value):
        out = list(headers)
        found = False
        ln = name.lower()
        for i, h in enumerate(out):
            if ':' not in h:
                continue
            k, _, _ = h.partition(':')
            if k.strip().lower() == ln:
                out[i] = "%s: %s" % (name, value)
                found = True
                break
        if not found:
            out.append("%s: %s" % (name, value))
        return out
    # -------- modes (logic preserved) --------
    def scan_faster(self, base_cmd):
        self._check_stop()
        self._log("Mode: FASTER (batch test with single-recursive fallback)\n")
        json_enabled = self.is_json_body(base_cmd['headers'], base_cmd.get('body'))
        mut_url = self._mutate_all_url_params(base_cmd['url'], '%27')
        mut_body = self._mutate_all_body(base_cmd.get('body'), '%27', json_enabled)
        mut_cookies = self._mutate_all_cookies(base_cmd.get('cookies', []), "'") if base_cmd.get('cookies') else None
        status = self.execute_request(
            base_cmd['method'],
            mut_url,
            base_cmd['headers'],
            mut_cookies or base_cmd.get('cookies', []),
            mut_body,
            base_cmd['extra_flags']
        )
        if status == 500:
            self._log(" -> Got 500, switching to single-recursive mode\n")
            return self.scan_single_recursive(base_cmd)
        else:
            self._log(" -> Got %s, skipping\n" % str(status))
            return []
    def scan_fastest(self, base_cmd):
        self._check_stop()
        self._log("Mode: FASTEST (batch test with double-quote verification)\n")
        json_enabled = self.is_json_body(base_cmd['headers'], base_cmd.get('body'))
        mut_url1 = self._mutate_all_url_params(base_cmd['url'], '%27')
        mut_body1 = self._mutate_all_body(base_cmd.get('body'), '%27', json_enabled)
        mut_cookies1 = self._mutate_all_cookies(base_cmd.get('cookies', []), "'") if base_cmd.get('cookies') else None
        status1 = self.execute_request(
            base_cmd['method'],
            mut_url1,
            base_cmd['headers'],
            mut_cookies1 or base_cmd.get('cookies', []),
            mut_body1,
            base_cmd['extra_flags']
        )
        if status1 != 500:
            self._log(" -> Got %s, skipping\n" % str(status1))
            return []
        self._log(" -> Got 500 with single quote\n")
        mut_url2 = self._mutate_all_url_params(base_cmd['url'], '%27%27')
        mut_body2 = self._mutate_all_body(base_cmd.get('body'), '%27%27', json_enabled)
        mut_cookies2 = self._mutate_all_cookies(base_cmd.get('cookies', []), "''") if base_cmd.get('cookies') else None
        status2 = self.execute_request(
            base_cmd['method'],
            mut_url2,
            base_cmd['headers'],
            mut_cookies2 or base_cmd.get('cookies', []),
            mut_body2,
            base_cmd['extra_flags']
        )
        if status2 != 500:
            self._log(" -> Got %s with double quote, fallback to identify probable input\n" % str(status2))
            return self.scan_single_recursive(base_cmd)
        else:
            self._log(" -> Still 500 with double quote, skipping\n")
            return []
    def _mutate_all_url_params(self, url, suffix):
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        parsed = urlparse(clean_url)
        if not parsed.query:
            return url
        parts = []
        for param in parsed.query.split('&'):
            if '=' in param:
                key, _, value = param.partition('=')
                parts.append("%s=%s%s" % (key, value, suffix))
            else:
                parts.append(param)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, '&'.join(parts), parsed.fragment
        ))
    def _mutate_all_body(self, body, suffix, json_enabled):
        if body is None:
            return None
        if json_enabled and body.strip().startswith(('{', '[')):
            try:
                data = json.loads(body, object_pairs_hook=OrderedDict)
                js_suffix = self._normalize_json_suffix(suffix)
                mutated = self._mutate_json_recursive(data, js_suffix)
                return json.dumps(mutated, ensure_ascii=False, separators=(',', ':'))
            except Exception:
                return body
        if '=' in body:
            parts = []
            for param in body.split('&'):
                if '=' in param:
                    key, _, value = param.partition('=')
                    parts.append("%s=%s%s" % (key, value, suffix))
                else:
                    parts.append(param)
            return '&'.join(parts)
        return body
    def _mutate_json_recursive(self, data, suffix):
        if isinstance(data, dict):
            out = type(data)()
            for k, v in data.items():
                out[k] = self._mutate_json_recursive(v, suffix)
            return out
        if isinstance(data, list):
            return [self._mutate_json_recursive(v, suffix) for v in data]
        if isinstance(data, basestring):
            return data + suffix
        return data
    def _mutate_all_cookies(self, cookies, suffix):
        mutated = []
        for cookie in cookies:
            parts = []
            for part in cookie.split(';'):
                part = part.strip()
                if '=' in part:
                    key, _, value = part.partition('=')
                    parts.append("%s=%s%s" % (key, value, suffix))
                else:
                    parts.append(part)
            mutated.append('; '.join(parts))
        return mutated
    # -------- singleRecursive (logic preserved; termination fixed to not hang worker) --------
    def scan_single_recursive(self, base_cmd):
        self._check_stop()
        headers = base_cmd['headers']
        json_enabled = self.is_json_body(headers, base_cmd.get('body'))
        # Requested behavior: if --json is enabled, ONLY test JSON parameters and ONLY for POST.
        # This is scope/selection only; detection logic stays unchanged.
        if self.force_json:
            if (base_cmd.get('method') or "").upper() != "POST":
                self._log("ForceJSON: request is not POST; skipping (JSON-only mode)\n")
                return []
        get_params, post_params, json_paths, is_json = self.extract_params(
            base_cmd['url'], base_cmd.get('body'), headers
        )
        if self.force_json:
            if not is_json:
                self._log("ForceJSON: no valid JSON body detected; skipping\n")
                return []
        cookie_params = self.extract_cookie_params(base_cmd.get('cookies', [])) if base_cmd.get('cookies') else {}
        # Normal behavior flags
        do_params = (not self.cookie_only)
        do_cookies = (self.cookie_only or self.full_mode)
        do_headers = self.full_mode
        # ForceJSON overrides scope: JSON-only (no cookies/headers, no GET/POST-form params)
        json_only = True if self.force_json else False
        if json_only:
            do_params = True
            do_cookies = False
            do_headers = False
        get_count = sum([len(v) for v in get_params.values()])
        post_count = sum([len(v) for v in post_params.values()])
        json_count = len(json_paths) if is_json else 0
        cookie_count = sum([len(v) for v in cookie_params.values()])
        if json_only:
            self._log("ForceJSON: Found %d JSON string-leaf parameter(s)\n" % json_count)
        else:
            if self.cookie_only:
                self._log("Found %d COOKIE parameter(s) (cookie-only mode)\n" % cookie_count)
            else:
                if is_json:
                    self._log("Found %d GET, %d JSON string-leaf parameter(s)\n" % (get_count, json_count))
                else:
                    self._log("Found %d GET, %d POST, %d COOKIE parameter(s)\n" % (get_count, post_count, cookie_count))
        tasks = []
        if do_params:
            if json_only:
                # JSON-only mode: ONLY JSON string-leaf paths
                if is_json:
                    for path in json_paths:
                        tasks.append((base_cmd, path, 0, 'JSON', json_enabled))
            else:
                for param_name, values in get_params.items():
                    for idx in range(len(values)):
                        tasks.append((base_cmd, param_name, idx, 'GET', json_enabled))
                if is_json:
                    for path in json_paths:
                        tasks.append((base_cmd, path, 0, 'JSON', json_enabled))
                else:
                    for param_name, values in post_params.items():
                        for idx in range(len(values)):
                            tasks.append((base_cmd, param_name, idx, 'POST', json_enabled))
        if do_cookies:
            for param_name, values in cookie_params.items():
                for idx in range(len(values)):
                    tasks.append((base_cmd, param_name, idx, 'COOKIE', json_enabled))
        if do_headers:
            base_headers = list(base_cmd['headers'])
            if self._get_header(base_headers, "User-Agent") is None:
                base_headers = self._set_header(base_headers, "User-Agent", "Mozilla/5.0")
            if self._get_header(base_headers, "Referer") is None:
                try:
                    p = urlparse(base_cmd['url'])
                    base_headers = self._set_header(base_headers, "Referer", "%s://%s/" % (p.scheme, p.netloc))
                except Exception:
                    base_headers = self._set_header(base_headers, "Referer", "https://example.com/")
            if self._get_header(base_headers, "X-Forwarded-For") is None:
                base_headers = self._set_header(base_headers, "X-Forwarded-For", "127.0.1")
            base_cmd2 = dict(base_cmd)
            base_cmd2['headers'] = base_headers
            tasks.append((base_cmd2, "User-Agent", 0, "HEADER", json_enabled))
            tasks.append((base_cmd2, "Referer", 0, "HEADER", json_enabled))
            tasks.append((base_cmd2, "X-Forwarded-For", 0, "HEADER", json_enabled))
        if not tasks:
            self._log("Nothing to test with selected flags.\n")
            return []
        self._check_stop()
        # IMPORTANT: avoid long awaitTermination that can freeze the worker if any thread is stuck.
        pool = Executors.newFixedThreadPool(int(self.max_workers))
        ecs = ExecutorCompletionService(pool)
        findings = []
        try:
            for t in tasks:
                ecs.submit(_DetectorCallable(self, t))
            for _ in range(len(tasks)):
                self._check_stop()
                f = ecs.take()
                try:
                    res = f.get(60, TimeUnit.SECONDS)
                except TimeoutException:
                    self._log(" [WARN] Parameter test timeout\n")
                    continue
                except Exception as e:
                    self._log(" [ERROR] Parameter test error: %s\n" % str(e))
                    continue
                if res:
                    findings.append(res)
            return findings
        except StopNowException:
            try:
                pool.shutdownNow()
            except Exception:
                pass
            raise
        finally:
            # Best-effort shutdown WITHOUT waiting forever.
            try:
                pool.shutdownNow()
            except Exception:
                pass
            try:
                pool.shutdown()
            except Exception:
                pass
            try:
                pool.awaitTermination(1, TimeUnit.SECONDS)
            except Exception:
                pass
    # -------- per-input test (logic preserved; adds per-parameter output to UI) --------
    def test_parameter(self, base_cmd, param_name, param_idx, param_type, json_enabled):
        self._check_stop()
        self._log(" Testing %s: %s[%d]\n" % (param_type, param_name, param_idx))
        baseline_status = self.execute_request(
            base_cmd['method'],
            base_cmd['url'],
            base_cmd['headers'],
            base_cmd.get('cookies', []),
            base_cmd.get('body'),
            base_cmd['extra_flags']
        )
        if baseline_status is None:
            return None
        if param_type == 'JSON':
            s1, s2 = "%27", "%27%27"
        elif param_type in ('COOKIE', 'HEADER'):
            s1, s2 = "'", "''"
        else:
            s1, s2 = "%27", "%27%27"
        def run_mutation(suffix):
            self._check_stop()
            if param_type == 'GET':
                mut_url = self.mutate_url_param(base_cmd['url'], param_name, param_idx, suffix)
                mut_body = base_cmd.get('body')
                mut_cookies = base_cmd.get('cookies', [])
                mut_headers = base_cmd.get('headers', [])
            elif param_type == 'POST':
                mut_url = base_cmd['url']
                mut_body = self.mutate_body_param(base_cmd.get('body') or "", param_name, param_idx, suffix, False)
                mut_cookies = base_cmd.get('cookies', [])
                mut_headers = base_cmd.get('headers', [])
            elif param_type == 'JSON':
                mut_url = base_cmd['url']
                mut_body = self.mutate_body_param(base_cmd.get('body') or "", param_name, param_idx, suffix, True)
                mut_cookies = base_cmd.get('cookies', [])
                mut_headers = base_cmd.get('headers', [])
            elif param_type == 'COOKIE':
                mut_url = base_cmd['url']
                mut_body = base_cmd.get('body')
                mut_cookies = self.mutate_cookie_param(base_cmd.get('cookies', []), param_name, param_idx, suffix)
                mut_headers = base_cmd.get('headers', [])
            else: # HEADER
                mut_url = base_cmd['url']
                mut_body = base_cmd.get('body')
                mut_cookies = base_cmd.get('cookies', [])
                found = self._get_header(base_cmd.get('headers', []), param_name)
                current_val = found[1] if found else ""
                mut_headers = self._set_header(base_cmd.get('headers', []), param_name, current_val + suffix)
            st = self.execute_request(
                base_cmd['method'],
                mut_url,
                mut_headers,
                mut_cookies,
                mut_body,
                base_cmd['extra_flags']
            )
            cmd_str = "curl -X %s" % base_cmd['method']
            for h in mut_headers:
                cmd_str += " -H '%s'" % h
            if mut_cookies:
                for c in mut_cookies:
                    cmd_str += " -b '%s'" % c
            if mut_body:
                cmd_str += " --data-raw '%s'" % mut_body
            cmd_str += " '%s'" % mut_url
            return st, cmd_str
        quote_status, quote_cmd = run_mutation(s1)
        if quote_status is None or quote_status != 500:
            return None
        dquote_status, dquote_cmd = run_mutation(s2)
        if dquote_status is None or dquote_status == 500:
            return None
        if param_type == 'JSON':
            label = param_name
        else:
            label = "%s[%d]" % (param_name, param_idx)
        return {
            'param': label,
            'type': param_type,
            'baseline': baseline_status,
            'quote': quote_status,
            'dquote': dquote_status,
            'quote_cmd': quote_cmd,
            'dquote_cmd': dquote_cmd,
            'url': base_cmd['url']
        }
    # -------- dispatch --------
    def scan(self, content):
        self._check_stop()
        parser = CurlParser(content)
        base_cmd = parser.parse()
        if not base_cmd['url']:
            self._log("Error: No URL found in request\n")
            return []
        self._log("\nTarget: %s %s\n" % (base_cmd['method'], base_cmd['url']))
        if self.mode == 'faster':
            return self.scan_faster(base_cmd)
        elif self.mode == 'fastest':
            return self.scan_fastest(base_cmd)
        else:
            return self.scan_single_recursive(base_cmd)
class _DetectorCallable(Callable):
    def __init__(self, detector, args_tuple):
        self.detector = detector
        self.args = args_tuple
    def call(self):
        return self.detector.test_parameter(*self.args)
class _TransportCallable(Callable):
    def __init__(self, transport, method, url, headers_list, cookies_list, body, extra_flags):
        self.transport = transport
        self.method = method
        self.url = url
        self.headers_list = headers_list
        self.cookies_list = cookies_list
        self.body = body
        self.extra_flags = extra_flags
    def call(self):
        return self.transport.send(self.method, self.url, self.headers_list, self.cookies_list, self.body, self.extra_flags)
# =====================================================================================
# Burp Transport Adapter (build request bytes + return status code)
# =====================================================================================
class BurpHttpTransport(object):
    def __init__(self, callbacks, helpers, should_stop):
        self.callbacks = callbacks
        self.helpers = helpers
        self._should_stop = should_stop
    def _check_stop(self):
        if self._should_stop():
            raise StopNowException("Stopped by user")
    def send(self, method, url, headers_list, cookies_list, body, extra_flags):
        self._check_stop()
        clean_url = url[2:-1] if url.startswith("$'") and url.endswith("'") else url
        p = urlparse(clean_url)
        scheme = (p.scheme or "https").lower()
        host = p.hostname or p.netloc
        if not host:
            return None
        port = p.port
        if port is None:
            port = 443 if scheme == "https" else 80
        use_https = True if scheme == "https" else False
        path = p.path if p.path else "/"
        if p.query:
            path = path + "?" + p.query
        headers_dict = {}
        for h in headers_list:
            if ':' in h:
                k, _, v = h.partition(':')
                headers_dict[k.strip()] = v.strip()
        cookies_dict = {}
        for cookie_str in (cookies_list or []):
            for part in cookie_str.split(';'):
                part = part.strip()
                if '=' in part:
                    k, _, v = part.partition('=')
                    cookies_dict[k.strip()] = v.strip()
        req_headers = []
        req_headers.append("%s %s HTTP/1.1" % (method, path))
        req_headers.append("Host: %s" % host)
        for k in headers_dict:
            lk = k.lower()
            if lk == "host" or lk == "content-length":
                continue
            req_headers.append("%s: %s" % (k, headers_dict[k]))
        if cookies_dict:
            cookie_parts = []
            for ck in cookies_dict:
                cookie_parts.append("%s=%s" % (ck, cookies_dict[ck]))
            req_headers.append("Cookie: " + "; ".join(cookie_parts))
        if body is None:
            body_bytes = None
        else:
            try:
                body_bytes = self.helpers.stringToBytes(body)
            except Exception:
                body_bytes = body
        try:
            req_bytes = self.helpers.buildHttpMessage(req_headers, body_bytes)
        except Exception:
            raw = "\r\n".join(req_headers) + "\r\n\r\n" + (body or "")
            req_bytes = self.helpers.stringToBytes(raw)
        try:
            protocol = "https" if use_https else "http"
            svc = self.helpers.buildHttpService(host, port, protocol)
            resp = self.callbacks.makeHttpRequest(svc, req_bytes)
            if resp is None:
                return None
            resp_bytes = resp.getResponse()
            if resp_bytes is None:
                return None
            ri = self.helpers.analyzeResponse(resp_bytes)
            self._check_stop()
            return ri.getStatusCode()
        except StopNowException:
            raise
        except Exception:
            return None
# =====================================================================================
# Burp Extension UI + Queue/Worker + Job lookup + Send-to tools
# =====================================================================================
class Job(object):
    def __init__(self, message):
        self.id = str(uuid.uuid4())[:8]
        self.message = message
def display_hit_name(ftype, raw_param):
    if not raw_param:
        return "Unknown"
    if ftype == "JSON":
        leaf = raw_param.rsplit(".", 1)[-1]
        leaf = re.sub(r"\[\d+\]", "", leaf)
        return leaf or raw_param
    if ftype in ("GET", "POST", "COOKIE") and ("[" in raw_param) and raw_param.endswith("]"):
        return raw_param.split("[", 1)[0]
    return raw_param
class EnqueueListener(ActionListener):
    def __init__(self, extender, message):
        self.ext = extender
        self.msg = message
    def actionPerformed(self, event):
        self.ext.enqueue_one(self.msg)
class PopupMouseListener(MouseAdapter):
    def __init__(self, ext, popup, kind):
        self.ext = ext
        self.popup = popup
        self.kind = kind # "jobs" or "request"
    def mousePressed(self, e):
        self._maybe_show(e)
    def mouseReleased(self, e):
        self._maybe_show(e)
    def _maybe_show(self, e):
        try:
            if not e.isPopupTrigger():
                return
        except Exception:
            return
        try:
            if self.kind == "jobs":
                jid = self.ext._jobid_from_jobs_table_event(e)
                self.ext._popup_jobid = jid
            else:
                try:
                    self.ext._popup_jobid = (self.ext.jobid_search_field.getText() or "").strip()
                except Exception:
                    self.ext._popup_jobid = None
            self.popup.show(e.getComponent(), e.getX(), e.getY())
        except Exception:
            pass
class SendPopupToRepeaterListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext.send_job_to_repeater(self.ext._popup_jobid)
class SendPopupToIntruderListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext.send_job_to_intruder(self.ext._popup_jobid)
class SendPopupToComparerListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext.send_job_to_comparer(self.ext._popup_jobid)
class PopupShowRequestListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        jid = self.ext._popup_jobid
        if jid:
            self.ext._ui_set_jobid_search(jid)
            self.ext.show_request_for_jobid(jid)
class ProxyListener(IProxyListener):
    def __init__(self, ext):
        self.ext = ext
    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            return
        if not self.ext.auto_mode_cb.isSelected():
            return
        try:
            info = message.getMessageInfo()
            req_info = self.ext.helpers.analyzeRequest(info)
            method = req_info.getMethod()
            # Skip preflight OPTIONS requests
            if method == "OPTIONS":
                return
            url = req_info.getUrl()
            if self.ext.callbacks.isInScope(url):
                self.ext.enqueue_one(info)
        except Exception:
            pass
class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Simple SQLi Detector")
        # Queue + single worker
        self.job_queue = LinkedBlockingQueue()
        self.worker_pool = Executors.newFixedThreadPool(1)
        self.stop_event = threading.Event()
        self.current_job_id = None
        self.current_lock = threading.Lock()
        # re-entrancy guard (STRICT: one click -> one job, no dedupe; prevent accidental double-fire)
        self._enqueue_guard_lock = threading.Lock()
        self._enqueue_in_progress = False
        # JobID -> original initiating request text (lookup/search)
        self.job_requests = {}
        # JobID -> original initiating request bytes (for sendToRepeater/Intruder/Comparer)
        self.job_request_bytes = {}
        # JobID -> (host, port, use_https)
        self.job_services = {}
        # current popup jobid context
        self._popup_jobid = None
        # Log actions for rerender
        self.log_actions = []
        self.rerender_pending = False
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerProxyListener(ProxyListener(self))
        # Start worker (must not die)
        self.worker_pool.submit(Worker(self))
    # ---------------- UI ----------------
    def _build_ui(self):
        self.main = JPanel(BorderLayout())
        top = JPanel()
        self.threads_field = JTextField("5", 4)
        self.timeout_field = JTextField("30", 4)
        self.force_json_cb = JCheckBox("json", False)
        self.mode_sr = JRadioButton("singleRecursive", True)
        self.mode_faster = JRadioButton("faster(less-reliable)", False)
        self.mode_fastest = JRadioButton("fastest(least-reliable)", False)
        bg = ButtonGroup()
        bg.add(self.mode_sr)
        bg.add(self.mode_faster)
        bg.add(self.mode_fastest)
        self.scope_default = JRadioButton("params-only", False)
        self.scope_cookie = JRadioButton("cookie-only", False)
        self.scope_full = JRadioButton("full", True)
        sbg = ButtonGroup()
        sbg.add(self.scope_default)
        sbg.add(self.scope_cookie)
        sbg.add(self.scope_full)
        self.auto_mode_cb = JCheckBox("Auto Mode", True)
        self.filter_hits_cb = JCheckBox("Show Hits Only       ", False)
        self.filter_hits_cb.addActionListener(FilterListener(self))
        self.btn_clear_jobs = JButton("Clear jobs")
        self.btn_clear_results = JButton("Clear results")
        self.btn_clear_jobs.addActionListener(ClearJobsListener(self))
        self.btn_clear_results.addActionListener(ClearResultsListener(self))
        # JobID lookup bar (shows initiating request)
        self.jobid_search_field = JTextField("", 10)
        self.btn_show_request = JButton("Show request (JobID)")
        self.btn_show_request.addActionListener(ShowRequestListener(self))
        top.add(JLabel("Threads (-t)"))
        top.add(self.threads_field)
        top.add(JLabel("Timeout"))
        top.add(self.timeout_field)
        top.add(self.mode_sr)
        top.add(self.mode_faster)
        top.add(self.mode_fastest)
        top.add(self.scope_default)
        top.add(self.scope_cookie)
        top.add(self.scope_full)
        top.add(self.force_json_cb)
        top.add(self.auto_mode_cb)
        top.add(self.filter_hits_cb)
        top.add(JLabel("  Search by JobID"))
        top.add(self.jobid_search_field)
        top.add(self.btn_show_request)
        top.add(self.btn_clear_jobs)
        top.add(self.btn_clear_results)
        self.main.add(top, BorderLayout.NORTH)
        self.table_model = DefaultTableModel(
            ["JobID", "Host", "Method", "URL", "Mode", "Status", "Hits"], 0
        )
        self.jobs_table = JTable(self.table_model)
        table_scroll = JScrollPane(self.jobs_table)
        table_scroll.setPreferredSize(Dimension(850, 520))
        # Request viewer (top-right)
        self.request_pane = JTextPane()
        self.request_pane.setEditable(False)
        req_scroll = JScrollPane(self.request_pane)
        req_scroll.setPreferredSize(Dimension(650, 240))
        # Log output (bottom-right)
        self.results_pane = JTextPane()
        self.results_pane.setEditable(False)
        results_scroll = JScrollPane(self.results_pane)
        results_scroll.setPreferredSize(Dimension(650, 280))
        right_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, req_scroll, results_scroll)
        right_split.setResizeWeight(0.45)
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, table_scroll, right_split)
        split.setResizeWeight(0.6)
        self.main.add(split, BorderLayout.CENTER)
        # ---- Right-click popup: Jobs table ----
        self.jobs_popup = JPopupMenu()
        mi_show = JMenuItem("Show request (this JobID)")
        mi_show.addActionListener(PopupShowRequestListener(self))
        self.jobs_popup.add(mi_show)
        mi_rep = JMenuItem("Send to Repeater")
        mi_rep.addActionListener(SendPopupToRepeaterListener(self))
        self.jobs_popup.add(mi_rep)
        mi_int = JMenuItem("Send to Intruder")
        mi_int.addActionListener(SendPopupToIntruderListener(self))
        self.jobs_popup.add(mi_int)
        mi_cmp = JMenuItem("Send to Comparer")
        mi_cmp.addActionListener(SendPopupToComparerListener(self))
        self.jobs_popup.add(mi_cmp)
        self.jobs_table.addMouseListener(PopupMouseListener(self, self.jobs_popup, "jobs"))
        # ---- Right-click popup: Request viewer ----
        self.request_popup = JPopupMenu()
        mi_rep2 = JMenuItem("Send shown request to Repeater")
        mi_rep2.addActionListener(SendPopupToRepeaterListener(self))
        self.request_popup.add(mi_rep2)
        mi_int2 = JMenuItem("Send shown request to Intruder")
        mi_int2.addActionListener(SendPopupToIntruderListener(self))
        self.request_popup.add(mi_int2)
        mi_cmp2 = JMenuItem("Send to Comparer")
        mi_cmp2.addActionListener(SendPopupToComparerListener(self))
        self.request_popup.add(mi_cmp2)
        self.request_pane.addMouseListener(PopupMouseListener(self, self.request_popup, "request"))
    def getTabCaption(self):
        return "Simple SQLi Detector"
    def getUiComponent(self):
        return self.main
    # ---------------- Context Menu (Burp right-click on items) ----------------
    def createMenuItems(self, invocation):
        try:
            msgs = invocation.getSelectedMessages()
        except Exception:
            msgs = None
        if msgs is None:
            return []
        try:
            count = len(msgs)
        except Exception:
            try:
                count = msgs.length
            except Exception:
                return []
        if count != 1:
            return []
        msg = msgs[0]
        item = JMenuItem("Send to Simple SQLi Detector")
        item.addActionListener(EnqueueListener(self, msg))
        return [item]
    # STRICT: enqueue exactly one job per click, no dedupe; prevent accidental double-fire
    def enqueue_one(self, msg):
        with self._enqueue_guard_lock:
            if self._enqueue_in_progress:
                return
            self._enqueue_in_progress = True
        try:
            # Skip OPTIONS requests when manually sending
            req_info = self.helpers.analyzeRequest(msg)
            if req_info.getMethod() == "OPTIONS":
                return
            job = Job(msg)
            self.job_queue.offer(job)
            # Store the initiating request for later lookup + forwarding to tools
            try:
                req_bytes = msg.getRequest()
                self.job_request_bytes[job.id] = req_bytes
                self.job_requests[job.id] = self.helpers.bytesToString(req_bytes)
            except Exception:
                self.job_request_bytes[job.id] = None
                self.job_requests[job.id] = ""
            # Store service tuple for sending to Repeater/Intruder
            try:
                req_info2 = self.helpers.analyzeRequest(msg)
                url2 = req_info2.getUrl()
                host2 = url2.getHost()
                proto2 = (url2.getProtocol() or "").lower()
                use_https2 = True if proto2 == "https" else False
                port2 = url2.getPort()
                if port2 is None or int(port2) == -1:
                    port2 = 443 if use_https2 else 80
                self.job_services[job.id] = (host2, int(port2), use_https2)
            except Exception:
                self.job_services[job.id] = None
            url = req_info.getUrl()
            mode = self._get_mode()
            host = url.getHost()
            method = req_info.getMethod()
            self._ui_add_row(job.id, host, method, str(url), mode, "QUEUED", "0")
            self._log_line("[%s] QUEUED %s %s" % (job.id, method, str(url)))
        finally:
            with self._enqueue_guard_lock:
                self._enqueue_in_progress = False
    # ---------------- Controls ----------------
    def clear_jobs(self):
        # clear queued jobs (does not stop a running job)
        self._clear_queue_only()
        def do():
            self.table_model.setRowCount(0)
        SwingUtilities.invokeLater(do)
        try:
            self.job_requests.clear()
        except Exception:
            pass
        try:
            self.job_request_bytes.clear()
        except Exception:
            pass
        try:
            self.job_services.clear()
        except Exception:
            pass
        self._log_line("[*] Jobs cleared")
    def clear_results(self):
        self.log_actions = []
        def do():
            try:
                self.results_pane.setText("")
            except Exception:
                pass
            try:
                self.request_pane.setText("")
            except Exception:
                pass
        SwingUtilities.invokeLater(do)
    def _clear_queue_only(self):
        try:
            self.job_queue.clear()
        except Exception:
            pass
    # ---------------- UI helpers ----------------
    def _ui_add_row(self, jobid, host, method, url, mode, status, hits):
        def do():
            self.table_model.addRow([jobid, host, method, url, mode, status, hits])
        SwingUtilities.invokeLater(do)
    def _find_row_by_jobid(self, jobid):
        key = str(jobid)
        for r in range(self.table_model.getRowCount()):
            if str(self.table_model.getValueAt(r, 0)) == key:
                return r
        return None
    def _ui_set_cell(self, jobid, col_idx, value):
        def do():
            row = self._find_row_by_jobid(jobid)
            if row is not None:
                self.table_model.setValueAt(value, row, col_idx)
        SwingUtilities.invokeLater(do)
    def _ui_set_jobid_search(self, jobid):
        def do():
            try:
                self.jobid_search_field.setText(str(jobid))
            except Exception:
                pass
        SwingUtilities.invokeLater(do)
    def show_request_for_jobid(self, jobid_text):
        jobid = (jobid_text or "").strip()
        req = None
        try:
            req = self.job_requests.get(jobid, None)
        except Exception:
            req = None
        if req is None:
            self._log_line("[!] No stored request for JobID: %s" % jobid)
            return
        def do():
            try:
                self.request_pane.setText(req)
                self.request_pane.setCaretPosition(0)
            except Exception:
                pass
        SwingUtilities.invokeLater(do)
    def _log_line(self, text):
        self._log(text + "\n", None, 'normal')
    def _log_hit_reason(self, text):
        self._log(text + "\n", None, 'hit_reason')
    def _log_hit_param_red(self, prefix, param, suffix):
        self._log(prefix, None, 'hit_prefix')
        self._log(param, Color.RED, 'hit_param')
        self._log(suffix, None, 'hit_suffix')
    def _log(self, text, color=None, ltype='normal'):
        self.log_actions.append({'text': text, 'color': color, 'type': ltype})
        if not self.rerender_pending:
            self.rerender_pending = True
            SwingUtilities.invokeLater(RerenderRunnable(self))
    def _rerender_logs(self):
        if not self.rerender_pending:
            self.rerender_pending = True
            SwingUtilities.invokeLater(RerenderRunnable(self))
    def _do_rerender(self):
        def do():
            try:
                doc = self.results_pane.getStyledDocument()
                doc.remove(0, doc.getLength())
                show_only_hits = self.filter_hits_cb.isSelected()
                hit_types = ['hit_prefix', 'hit_param', 'hit_suffix', 'hit_reason']
                for action in self.log_actions:
                    if show_only_hits and action['type'] not in hit_types:
                        continue
                    color = action['color']
                    if color:
                        st = self.results_pane.addStyle("temp", None)
                        StyleConstants.setForeground(st, color)
                        doc.insertString(doc.getLength(), action['text'], st)
                    else:
                        doc.insertString(doc.getLength(), action['text'], None)
                self.results_pane.setCaretPosition(doc.getLength())
            except Exception:
                pass
            finally:
                self.rerender_pending = False
        SwingUtilities.invokeLater(do)
    # ---------------- Right-click helpers ----------------
    def _jobid_from_jobs_table_event(self, e):
        try:
            row = self.jobs_table.rowAtPoint(e.getPoint())
            if row is None or int(row) < 0:
                return None
            try:
                self.jobs_table.setRowSelectionInterval(int(row), int(row))
            except Exception:
                pass
            try:
                jid = self.table_model.getValueAt(int(row), 0)
                return str(jid)
            except Exception:
                return None
        except Exception:
            return None
    def _get_job_payload(self, jobid):
        jid = (jobid or "").strip()
        if not jid:
            return None, None
        reqb = None
        svc = None
        try:
            reqb = self.job_request_bytes.get(jid, None)
        except Exception:
            reqb = None
        try:
            svc = self.job_services.get(jid, None)
        except Exception:
            svc = None
        return reqb, svc
    def send_job_to_repeater(self, jobid):
        reqb, svc = self._get_job_payload(jobid)
        if reqb is None or svc is None:
            self._log_line("[!] Cannot send to Repeater: missing request/service for JobID: %s" % str(jobid))
            return
        host, port, use_https = svc
        try:
            self.callbacks.sendToRepeater(host, int(port), bool(use_https), reqb, "SQLiDet %s" % str(jobid))
            self._log_line("[*] Sent JobID %s to Repeater" % str(jobid))
        except Exception as e:
            self._log_line("[!] sendToRepeater failed for %s: %s" % (str(jobid), str(e)))
    def send_job_to_intruder(self, jobid):
        reqb, svc = self._get_job_payload(jobid)
        if reqb is None or svc is None:
            self._log_line("[!] Cannot send to Intruder: missing request/service for JobID: %s" % str(jobid))
            return
        host, port, use_https = svc
        try:
            self.callbacks.sendToIntruder(host, int(port), bool(use_https), reqb)
            self._log_line("[*] Sent JobID %s to Intruder" % str(jobid))
        except Exception:
            try:
                protocol = "https" if bool(use_https) else "http"
                http_svc = self.helpers.buildHttpService(host, int(port), protocol)
                self.callbacks.sendToIntruder(http_svc, reqb)
                self._log_line("[*] Sent JobID %s to Intruder" % str(jobid))
            except Exception as e2:
                self._log_line("[!] sendToIntruder failed for %s: %s" % (str(jobid), str(e2)))
    def send_job_to_comparer(self, jobid):
        reqb, _ = self._get_job_payload(jobid)
        if reqb is None:
            self._log_line("[!] Cannot send to Comparer: missing request for JobID: %s" % str(jobid))
            return
        try:
            self.callbacks.sendToComparer(reqb)
            self._log_line("[*] Sent JobID %s to Comparer" % str(jobid))
        except Exception as e:
            self._log_line("[!] sendToComparer failed for %s: %s" % (str(jobid), str(e)))
    # ---------------- Settings mapping (CLI flags) ----------------
    def _get_mode(self):
        if self.mode_fastest.isSelected():
            return "fastest"
        if self.mode_faster.isSelected():
            return "faster"
        return "single"
    def _get_scope(self):
        if self.scope_cookie.isSelected():
            return "cookie-only"
        if self.scope_full.isSelected():
            return "full"
        return "default"
    def _get_threads(self):
        try:
            t = int(self.threads_field.getText().strip())
            if t <= 0:
                return 1
            return t
        except Exception:
            return 1
    def _get_timeout(self):
        try:
            t = int(self.timeout_field.getText().strip())
            if t <= 0:
                return 30
            return t
        except Exception:
            return 30
    def _get_force_json(self):
        return True if self.force_json_cb.isSelected() else False
    def _should_stop(self):
        return self.stop_event.is_set()
class ClearJobsListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext.clear_jobs()
class ClearResultsListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext.clear_results()
class ShowRequestListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        try:
            jobid = self.ext.jobid_search_field.getText()
        except Exception:
            jobid = ""
        self.ext.show_request_for_jobid(jobid)
class FilterListener(ActionListener):
    def __init__(self, ext):
        self.ext = ext
    def actionPerformed(self, event):
        self.ext._rerender_logs()
class RerenderRunnable(Runnable):
    def __init__(self, ext):
        self.ext = ext
    def run(self):
        self.ext._do_rerender()
class Worker(Runnable):
    def __init__(self, ext):
        self.ext = ext
    def run(self):
        while True:
            try:
                job = self.ext.job_queue.take()
            except Exception as e:
                try:
                    self.ext._log_line("[WORKER] ERROR taking from queue: %s" % str(e))
                except Exception:
                    pass
                continue
            try:
                self.ext.stop_event.clear()
                with self.ext.current_lock:
                    self.ext.current_job_id = job.id
                self._safe_set_status(job.id, "RUNNING")
                try:
                    self.ext._log_line("[%s] RUNNING" % job.id)
                except Exception:
                    pass
                hits = 0
                try:
                    hits = self._run_job(job)
                    self._safe_set_done(job.id, hits)
                    try:
                        self.ext._log_line("[%s] DONE (hits=%d)" % (job.id, hits))
                    except Exception:
                        pass
                except Exception as e:
                    self._safe_set_error(job.id, hits)
                    try:
                        self.ext._log_line("[%s] ERROR: %s" % (job.id, str(e)))
                    except Exception:
                        pass
            finally:
                try:
                    with self.ext.current_lock:
                        self.ext.current_job_id = None
                except Exception:
                    pass
                try:
                    self.ext.stop_event.clear()
                except Exception:
                    pass
    def _safe_set_status(self, jobid, status):
        try:
            self.ext._ui_set_cell(jobid, 5, status)
        except Exception:
            pass
    def _safe_set_done(self, jobid, hits):
        try:
            self.ext._ui_set_cell(jobid, 5, "DONE")
        except Exception:
            pass
        try:
            self.ext._ui_set_cell(jobid, 6, str(hits))
        except Exception:
            pass
    def _safe_set_error(self, jobid, hits):
        try:
            self.ext._ui_set_cell(jobid, 5, "ERROR")
        except Exception:
            pass
        try:
            self.ext._ui_set_cell(jobid, 6, str(hits))
        except Exception:
            pass
    def _run_job(self, job):
        req_bytes = job.message.getRequest()
        req_text = self.ext.helpers.bytesToString(req_bytes)
        mode = self.ext._get_mode()
        threads = self.ext._get_threads()
        timeout = self.ext._get_timeout()
        force_json = self.ext._get_force_json()
        scope = self.ext._get_scope()
        cookie_only = True if scope == "cookie-only" else False
        full_mode = True if scope == "full" else False
        if force_json:
            mode = "single"
            cookie_only = False
            full_mode = False
            scope = "json-only"
            try:
                self.ext._ui_set_cell(job.id, 4, "single+json")
            except Exception:
                pass
            self.ext._log_line("[%s] ForceJSON enabled: forcing Mode=singleRecursive and Scope=JSON-only (POST JSON body only)" % job.id)
        try:
            req_info = self.ext.helpers.analyzeRequest(job.message)
            url = req_info.getUrl()
            method = req_info.getMethod()
            self.ext._log_line("[%s] Job start: %s %s" % (job.id, method, str(url)))
        except Exception:
            self.ext._log_line("[%s] Job start" % job.id)
        self.ext._log_line("[%s] Mode=%s | Threads=%d | Scope=%s | Timeout=%d | ForceJSON=%s" %
                           (job.id, mode, threads, scope, timeout, "yes" if force_json else "no"))
        transport = BurpHttpTransport(self.ext.callbacks, self.ext.helpers, self.ext._should_stop)
        detector = SQLiDetector(
            transport=transport,
            logger=lambda s: self.ext._log("[%s] %s" % (job.id, s)),
            should_stop=self.ext._should_stop,
            debug=False,
            max_workers=threads,
            mode=mode,
            cookie_only=cookie_only,
            full_mode=full_mode,
            force_json=force_json,
            timeout_sec=timeout
        )
        findings = detector.scan(req_text)
        hits = 0
        comment_lines = []
        for f in findings:
            hits += 1
            display_param = display_hit_name(f.get('type', ''), f.get('param', 'Unknown'))
            self.ext._log_hit_param_red(
                "[%s] [HIT] Parameter: " % job.id,
                display_param,
                "\n"
            )
            self.ext._log_hit_reason(
                "[%s] Reason: baseline=%s -> quote=500 -> doublequote!=500" %
                (job.id, str(f.get('baseline')))
            )
            def set_highlight():
                try:
                    job.message.setHighlight("red")
                except Exception:
                    pass
            SwingUtilities.invokeLater(set_highlight)
            mode_label = "singleRecursive" if mode == "single" else mode
            comment_lines.append(
                "[Simple SQLi Detector] Parameter: %s | Mode: %s | Reason: baseline -> 500 -> non-500" %
                (display_param, mode_label)
            )
        if hits > 0:
            def set_comment_and_sitemap():
                try:
                    job.message.setComment("\n".join(comment_lines))
                    self.ext.callbacks.addToSiteMap(job.message)
                except Exception:
                    pass
            SwingUtilities.invokeLater(set_comment_and_sitemap)
            try:
                self.ext._ui_set_jobid_search(job.id)
                self.ext.show_request_for_jobid(job.id)
            except Exception:
                pass
        else:
            self.ext._log_line("[%s] OK No SQLi signals detected (heuristic)" % job.id)
        self.ext._log_line("[%s] Job completion summary" % job.id)
        self.ext._log_line("[%s] Hits: %d" % (job.id, hits))
        return hits
