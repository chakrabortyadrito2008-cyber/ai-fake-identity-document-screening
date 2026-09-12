import time
from collections import defaultdict,deque
class RateLimiter:
    def __init__(self, limit:int, max_clients:int=10000): self.limit=limit; self.max_clients=max_clients; self.events=defaultdict(deque)
    def allow(self,key:str)->bool:
        now=time.monotonic()
        if key not in self.events and len(self.events)>=self.max_clients:
            stale=[client for client,events in self.events.items() if not events or events[-1]<now-60]
            for client in stale: self.events.pop(client,None)
            if len(self.events)>=self.max_clients:return False
        q=self.events[key]
        while q and q[0]<now-60:q.popleft()
        if len(q)>=self.limit:return False
        q.append(now);return True
