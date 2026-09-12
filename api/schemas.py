from pydantic import BaseModel, Field
class ScreenRequest(BaseModel): file_path:str=Field(min_length=1); identity_key:str|None=None
class BatchRequest(BaseModel): items:list[ScreenRequest]=Field(max_length=50)
