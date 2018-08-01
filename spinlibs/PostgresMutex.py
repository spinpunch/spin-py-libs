#!/usr/bin/env python

# Provide mutex locking for batch operations (e.g. cron jobs).
# This is implemented using PostgreSQL advisory locks.

from contextlib import contextmanager
from hashlib import sha256
from struct import unpack

# postgres requires the lock ID to be a 64-bit integer. Use first bits from SHA-256 hash.
def lock_name_hash(lock_name):
    # <Q means "little-endian signed long long"
    return unpack('<q', sha256(lock_name).digest()[:8])

@contextmanager
def acquire(db_engine, lock_name):
    """ Try to acquire a lock. Return True if we got it, False otherwise. """
    lock_id = lock_name_hash(lock_name)
    result = db_engine.execute('SELECT pg_try_advisory_lock(%s)', lock_id).fetchone()[0]
    yield result is True
    if result:
        db_engine.execute('SELECT pg_advisory_unlock(%s)', lock_id).fetchone()

def acquire_permanently(db_engine, lock_name):
    """ Try to acquire a lock, which will be held until this process exits. Return True if we got it, False otherwise. """
    lock_id = lock_name_hash(lock_name)
    result = db_engine.execute('SELECT pg_try_advisory_lock(%s)', lock_id).fetchone()[0]
    return result is True
