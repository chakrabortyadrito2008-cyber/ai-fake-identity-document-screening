from database.db_manager import DatabaseManager
def migrate(database_path: str) -> None: DatabaseManager(database_path).initialize()
