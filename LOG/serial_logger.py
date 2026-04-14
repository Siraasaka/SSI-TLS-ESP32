#!/usr/bin/env python3
"""
serial_logger.py — Robust serial logger for SSI-TLS / Baseline benchmarks
Filters empty lines and serial noise, captures only meaningful output.

Usage:
  python serial_logger.py COM14 115200 ssi_tls_client.csv
  python serial_logger.py COM7  115200 ssi_tls_server.csv
"""

import serial
import sys
import time
import re
from datetime import datetime

def main():
    if len(sys.argv) < 3:
        print("Usage: python serial_logger.py <PORT> <BAUD> [output.csv]")
        print("Example: python serial_logger.py COM14 115200 benchmark.csv")
        sys.exit(1)

    port = sys.argv[1]
    baud = int(sys.argv[2])
    csv_file = sys.argv[3] if len(sys.argv) > 3 else f"log_{port}_{int(time.time())}.csv"
    log_file = csv_file.replace('.csv', '_full.log')

    print(f"[Logger] Port: {port} @ {baud} baud")
    print(f"[Logger] CSV output: {csv_file}")
    print(f"[Logger] Full log: {log_file}")
    print(f"[Logger] Press Ctrl+C to stop\n")

    ser = serial.Serial(port, baud, timeout=1)
    time.sleep(2)  # Wait for ESP32 boot

    csv_f = open(csv_file, 'w')
    csv_f.write('round,time_ms\n')

    log_f = open(log_file, 'w')
    log_f.write(f'=== Serial Log: {port} @ {baud} baud ===\n')
    log_f.write(f'=== Started: {datetime.now()} ===\n\n')

    bench_pattern = re.compile(r'^(\d{1,4}),(\d{2,6})$')  # "123,3571"
    csv_count = 0
    line_count = 0
    last_progress = time.time()

    try:
        while True:
            raw = ser.readline()
            if not raw:
                continue

            try:
                line = raw.decode('utf-8', errors='ignore').strip()
            except:
                continue

            # Skip empty lines entirely
            if not line:
                continue

            line_count += 1

            # Write all non-empty lines to full log
            log_f.write(line + '\n')

            # Print to console
            print(line)

            # Check if it's a benchmark data line
            match = bench_pattern.match(line)
            if match:
                round_num = int(match.group(1))
                time_ms = int(match.group(2))
                # Validate: round 1-1000, time 100-30000ms
                if 1 <= round_num <= 1000 and 100 <= time_ms <= 30000:
                    csv_f.write(f'{round_num},{time_ms}\n')
                    csv_f.flush()
                    csv_count += 1

            # Periodic progress
            if time.time() - last_progress > 30:
                print(f"\n[Logger] Lines: {line_count}, CSV rows: {csv_count}\n")
                last_progress = time.time()

            # Check for completion
            if 'END CSV' in line or 'Done. Halting.' in line:
                print(f"\n[Logger] Benchmark complete! {csv_count} data points captured.")
                break

    except KeyboardInterrupt:
        print(f"\n[Logger] Stopped by user. {csv_count} data points captured.")

    finally:
        csv_f.close()
        log_f.write(f'\n=== Stopped: {datetime.now()} ===\n')
        log_f.close()
        ser.close()
        print(f"[Logger] Files saved: {csv_file}, {log_file}")

if __name__ == '__main__':
    main()
