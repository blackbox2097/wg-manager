"""
Gunicorn configuration for WireGuard Manager.

1 worker + 4 threads:
  - Background sampler thread starts exactly once (no duplicate writes to SQLite)
  - SQLite write contention is eliminated (single process)
  - I/O-bound workload benefits from threads, not processes
"""

import os

# ── Binding ──────────────────────────────────────────────────────────────────
bind    = f"0.0.0.0:{os.environ.get('WG_MANAGER_PORT', '5000')}"
backlog = 64

# ── Workers ───────────────────────────────────────────────────────────────────
workers = 1
threads = 4
worker_class = 'gthread'

# ── Timeouts ─────────────────────────────────────────────────────────────────
# wg-quick up/down can take a few seconds; 30s is safe
timeout       = 30
keepalive     = 5
graceful_timeout = 10

# ── Reliability ───────────────────────────────────────────────────────────────
# Recycle worker after N requests to prevent any slow memory growth
max_requests      = 1000
max_requests_jitter = 100

# ── Logging ───────────────────────────────────────────────────────────────────
accesslog = '-'   # stdout → captured by systemd journal
errorlog  = '-'
loglevel  = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s %(D)sµs'

# ── Process name ─────────────────────────────────────────────────────────────
proc_name = 'wg-manager'
