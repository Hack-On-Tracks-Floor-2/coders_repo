"""Root-level export for VOID Persistence Adapter.

Provides backward compatibility and direct import:
    from db_adapter import EventPersistence, SqliteEventPersistence
"""

from persistence.db_adapter import EventPersistence, SqliteEventPersistence

__all__ = ["EventPersistence", "SqliteEventPersistence"]
