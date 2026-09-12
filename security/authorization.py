from enum import Enum
class Role(str,Enum): ANALYST="analyst"; ADMIN="admin"
def allows(role: Role, action: str) -> bool: return role==Role.ADMIN or action in {"screen","read"}
