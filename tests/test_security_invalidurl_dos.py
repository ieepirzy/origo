from origo.endpoints import _fetch_client_metadata_document


def test_fetch_client_metadata_document_rejects_control_character_url():
    """A client_id URL with an embedded control character (e.g. \r) can pass
    urlparse but raise http.client.InvalidURL/ValueError once urllib.request
    actually opens it. That must be treated the same as any other
    unreachable metadata document -- a None return, not a crash (DoS)."""
    result = _fetch_client_metadata_document("https://example.com/foo\r\nbar")
    assert result is None
