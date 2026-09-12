def test_batch_schema():
    from api.schemas import BatchRequest
    assert BatchRequest(items=[]).items==[]
