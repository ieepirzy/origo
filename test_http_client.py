from origo.endpoints import _fetch_client_metadata_document
try:
    _fetch_client_metadata_document("https://example.com/foo\r\nbar")
except Exception as e:
    print(f"Exception: {type(e).__name__}: {e}")
print("Finished!")
