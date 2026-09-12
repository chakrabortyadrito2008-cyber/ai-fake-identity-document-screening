from fastapi.testclient import TestClient
from api.app import create_app

def test_health_endpoint(pipeline_root):
    response=TestClient(create_app(pipeline_root)).get('/health')
    assert response.status_code==200
    assert response.json()['ok'] is True
