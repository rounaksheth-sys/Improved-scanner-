#!/usr/bin/env python3
"""
Improved TCP port scanner (beginner-friendly, concurrent).
Usage examples:
  py port_scan_improved.py 127.0.0.1 --start 1 --end 1024
  py port_scan_improved.py example.com --common
  py port_scan_improved.py 192.168.29.130 --ports 22,80,443,8080 --timeout 0.6 --workers 100 --output results.csv
Note: Scan only machines you own or have permission to test.
"""
import socket
import argparse
import concurrent.futures
import csv
import sys
import time

# ANSI color helpers (works in many terminals; Windows PowerShell/Terminal support)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 161, 389, 443, 445, 3389, 8080, 8443]

def parse_args():
    p = argparse.ArgumentParser(description="Improved concurrent TCP port scanner")
    p.add_argument("target", help="Target hostname or IP")
    p.add_argument("--start", type=int, default=1, help="Start port (default 1)")
    p.add_argument("--end", type=int, default=1024, help="End port (default 1024)")
    p.add_argument("--ports", type=str, help="Comma-separated specific ports, e.g. 22,80,443")
    p.add_argument("--common", action="store_true", help="Scan common ports only")
    p.add_argument("--timeout", type=float, default=0.5, help="Socket timeout seconds (default 0.5)")
    p.add_argument("--workers", type=int, default=100, help="Number of threads (default 100)")
    p.add_argument("--banner", action="store_true", help="Attempt to read service banner from open ports")
    p.add_argument("--output", type=str, help="Save results to CSV file")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    return p.parse_args()

def resolve_target(target):
    # Try IPv4 first, fall back to IPv6 name resolution if necessary
    try:
        ip = socket.gethostbyname(target)
        return ip, socket.AF_INET
    except socket.gaierror:
        # Attempt IPv6
        try:
            info = socket.getaddrinfo(target, None, socket.AF_INET6)
            if info:
                return info[0][4][0], socket.AF_INET6
        except Exception:
            pass
    raise Exception("Unable to resolve target")

def scan_port(target_ip, family, port, timeout, grab_banner=False):
    """Return a dict: {'port':port,'status':'OPEN'/'CLOSED'/'FILTERED','banner':str}"""
    # Create socket for IPv4 or IPv6
    try:
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        # connect_ex returns 0 on success, or errno on failure
        result = s.connect_ex((target_ip, port))
        if result == 0:
            banner = ""
            if grab_banner:
                try:
                    # Some services send banner immediately; otherwise this will timeout quickly
                    s.settimeout(0.8)
                    data = s.recv(1024)
                    banner = data.decode(errors="ignore").strip()
                except Exception:
                    banner = ""
            s.close()
            return {"port": port, "status": "OPEN", "banner": banner}
        else:
            s.close()
            # Distinguish between filtered (timeout) and actively refused errors is tricky with connect_ex;
            # But large errno values or timeouts are treated as closed/filtered. We'll mark as CLOSED for connect_ex != 0
            return {"port": port, "status": "CLOSED", "banner": ""}
    except socket.timeout:
        return {"port": port, "status": "FILTERED", "banner": ""}
    except Exception as e:
        return {"port": port, "status": "ERROR", "banner": str(e)}

def main():
    args = parse_args()
    # Resolve target
    try:
        target_ip, family = resolve_target(args.target)
    except Exception as e:
        print(RED + f"Error: {e}" + RESET)
        sys.exit(1)

    # Prepare list of ports to scan
    ports = []
    if args.ports:
        try:
            ports = sorted({int(p.strip()) for p in args.ports.split(",") if p.strip()})
        except ValueError:
            print(RED + "Invalid --ports value. Provide comma separated integers." + RESET)
            sys.exit(1)
    elif args.common:
        ports = COMMON_PORTS.copy()
    else:
        if args.start < 0 or args.end < 0 or args.start > args.end:
            print(RED + "Invalid port range." + RESET)
            sys.exit(1)
        ports = list(range(args.start, args.end + 1))

    # Colors
    use_color = not args.no_color

    print(f"Target: {args.target} -> {target_ip}")
    print(f"Ports to scan: {len(ports)} (workers={args.workers}, timeout={args.timeout}s)\n")

    results = []
    start_time = time.time()

    # ThreadPool for concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target_ip, family, port, args.timeout, args.banner): port
            for port in ports
        }
        try:
            for fut in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[fut]
                try:
                    res = fut.result()
                except Exception as exc:
                    res = {"port": port, "status": "ERROR", "banner": str(exc)}
                results.append(res)
                # Print immediately for demo
                status = res["status"]
                banner = res.get("banner", "") or ""
                if use_color:
                    if status == "OPEN":
                        tag = GREEN + "OPEN" + RESET
                    elif status == "FILTERED":
                        tag = YELLOW + "FILTERED" + RESET
                    elif status == "ERROR":
                        tag = RED + "ERROR" + RESET
                    else:
                        tag = RED + "CLOSED" + RESET
                else:
                    tag = status
                line = f"Port {res['port']:5d}: {tag}"
                if banner:
                    line += f"  => {banner[:120]}"
                print(line)
        except KeyboardInterrupt:
            print(RED + "\nScan interrupted by user." + RESET)
            executor.shutdown(wait=False)
            sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\nScan finished in {elapsed:.2f} seconds.")

    # Optionally save CSV
    if args.output:
        try:
            with open(args.output, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["port", "status", "banner"])
                for r in sorted(results, key=lambda x: x["port"]):
                    writer.writerow([r["port"], r["status"], r.get("banner","")])
            print(f"Results saved to {args.output}")
        except Exception as e:
            print(RED + f"Could not write file: {e}" + RESET)

if __name__ == "__main__":
    main()
