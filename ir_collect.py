#!/usr/bin/env python3
"""
ir_collect.py – Cross‑platform incident response collection tool.

This script gathers system information, running processes, network connections
and file hashes, then writes them into a timestamped directory under
`output/`. Optionally, it can compress the directory into a ZIP archive and
upload it to an Amazon S3 bucket.

Usage example:

    python ir_collect.py --targets "/var/log" "/home/user/Documents" --zip \
        --s3-bucket my-bucket --s3-prefix incidents/$(hostname)

Dependencies: psutil, boto3 (for S3 uploads).
"""

import argparse
import csv
import hashlib
import json
import os
import platform
import socket
import time
from datetime import datetime
from typing import List, Dict

import psutil

try:
    import boto3  # type: ignore
    from botocore.exceptions import BotoCoreError, NoCredentialsError
except ImportError:
    boto3 = None  # type: ignore


def collect_system_info() -> Dict[str, str]:
    """Gather basic system information."""
    return {
        'hostname': socket.gethostname(),
        'os': f"{platform.system()} {platform.release()}",
        'architecture': platform.machine(),
        'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        'uptime_seconds': str(int(time.time() - psutil.boot_time())),
    }


def collect_processes() -> List[Dict[str, str]]:
    """List running processes (PID, name, and command line)."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            info = proc.info
            processes.append({
                'pid': str(info['pid']),
                'name': info['name'] or '',
                'cmdline': ' '.join(info['cmdline']) if info['cmdline'] else '',
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes


def collect_connections() -> List[Dict[str, str]]:
    """List active network connections."""
    conns = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ''
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ''
            conns.append({
                'pid': str(conn.pid) if conn.pid else '',
                'local_address': laddr,
                'remote_address': raddr,
                'status': conn.status,
            })
        except Exception:
            continue
    return conns


def hash_files(targets: List[str], log_entries: List[str]) -> List[Dict[str, str]]:
    """Compute SHA‑256 hashes for files under target directories."""
    hashes = []
    for target in targets:
        if not os.path.exists(target):
            log_entries.append(f"Target path not found: {target}")
            continue
        for root, _, files in os.walk(target):
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    sha256 = hashlib.sha256()
                    with open(path, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            sha256.update(chunk)
                    hashes.append({
                        'file': path,
                        'sha256': sha256.hexdigest(),
                    })
                except (PermissionError, OSError) as e:
                    log_entries.append(f"Failed to hash {path}: {e}")
    return hashes


def write_json(data: dict, path: str) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def write_csv(rows: List[Dict[str, str]], path: str) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def compress_directory(src_dir: str, zip_path: str) -> None:
    import zipfile
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(src_dir):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, src_dir)
                zipf.write(full_path, arcname=rel_path)


def upload_to_s3(zip_path: str, bucket: str, prefix: str) -> None:
    if boto3 is None:
        print("boto3 is not installed; cannot upload to S3.")
        return
    s3 = boto3.client('s3')
    key = f"{prefix.rstrip('/')}/{os.path.basename(zip_path)}"
    try:
        s3.upload_file(zip_path, bucket, key)
        print(f"Uploaded {zip_path} to s3://{bucket}/{key}")
    except (BotoCoreError, NoCredentialsError) as e:
        print(f"Failed to upload to S3: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description='Incident response collection toolkit')
    parser.add_argument('--targets', nargs='+', required=True, help='Directories to hash')
    parser.add_argument('--zip', action='store_true', help='Compress output into ZIP')
    parser.add_argument('--s3-bucket', default=None, help='S3 bucket to upload the ZIP')
    parser.add_argument('--s3-prefix', default='', help='S3 prefix/key (e.g. folder)')
    args = parser.parse_args()

    # Create timestamped output directory
    timestamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    out_base = os.path.join('output', timestamp)
    os.makedirs(out_base, exist_ok=True)

    log_entries: List[str] = []

    # Collect data
    system_info = collect_system_info()
    processes = collect_processes()
    connections = collect_connections()
    hashes = hash_files(args.targets, log_entries)

    # Write outputs
    write_json(system_info, os.path.join(out_base, 'system_info.json'))
    write_json({'processes': processes}, os.path.join(out_base, 'processes.json'))
    write_json({'connections': connections}, os.path.join(out_base, 'connections.json'))
    write_csv(hashes, os.path.join(out_base, 'hashes.csv'))
    with open(os.path.join(out_base, 'log.txt'), 'w', encoding='utf-8') as log_file:
        for entry in log_entries:
            log_file.write(entry + '\n')

    print(f"Data written to {out_base}")

    # Compress and upload if requested
    if args.zip or args.s3_bucket:
        zip_name = f"{timestamp}.zip"
        zip_path = os.path.join('output', zip_name)
        compress_directory(out_base, zip_path)
        print(f"Created zip archive {zip_path}")
        if args.s3_bucket:
            upload_to_s3(zip_path, args.s3_bucket, args.s3_prefix or timestamp)


if __name__ == '__main__':
    main()