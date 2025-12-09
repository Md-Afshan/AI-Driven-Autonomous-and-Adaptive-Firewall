"""
FirewallController: Python wrapper to manage iptables blocklist.
This class uses subprocess.run to issue iptables commands. Requires root privileges.
"""
import subprocess
import shlex
import os

try:
    import iptc
    _HAS_IPTC = True
except Exception:
    _HAS_IPTC = False

class FirewallController:
    def __init__(self):
        try:
            if os.geteuid() != 0:
                raise PermissionError('FirewallController requires root privileges')
        except AttributeError:
            # os.geteuid() is not available on Windows; skip privilege check here.
            # Actual iptables operations will still fail if not run with proper privileges.
            pass

    def _run(self, cmd):
        # safe shell splitting fallback
        args = shlex.split(cmd)
        try:
            result = subprocess.run(args, capture_output=True, text=True)
            return result
        except FileNotFoundError as e:
            # iptables not available (e.g., running on Windows); warn and return a dummy
            print('iptables not found:', e)
            class _Res:
                returncode = 1
                stderr = str(e)
            return _Res()
        except Exception as e:
            print('Error running command', cmd, e)
            class _Res2:
                returncode = 1
                stderr = str(e)
            return _Res2()

    def add_block(self, ip):
        # Prefer python-iptables library if available
        if _HAS_IPTC:
            rule = iptc.Rule()
            rule.src = ip
            rule.target = iptc.Target(rule, "DROP")
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            chain.insert_rule(rule)
            return True
        # fallback to subprocess
        cmd = f"iptables -I INPUT -s {ip} -j DROP"
        res = self._run(cmd)
        if res.returncode != 0:
            print(f"Failed to add block {ip}: {res.stderr}")
            return False
        return True

    def remove_block(self, ip):
        if _HAS_IPTC:
            chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
            # remove any matching rules (best-effort)
            for rule in chain.rules:
                if rule.src == ip and rule.target.name == 'DROP':
                    chain.delete_rule(rule)
            return True
        cmd = f"iptables -D INPUT -s {ip} -j DROP"
        res = self._run(cmd)
        if res.returncode != 0:
            print(f"Failed to remove block {ip}: {res.stderr}")
            return False
        return True

    def flush(self):
        if _HAS_IPTC:
            table = iptc.Table(iptc.Table.FILTER)
            table.flush()
            return True
        cmd = "iptables -F"
        res = self._run(cmd)
        if res.returncode != 0:
            print(f"Failed to flush iptables: {res.stderr}")
            return False
        return True
