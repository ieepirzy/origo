import urllib.parse
from origo.endpoints import _build_redirect

def test_build_redirect_surrogate_dos():
    # Attempting to encode a surrogate should raise ValueError, not UnicodeEncodeError
    try:
        _build_redirect("https://example.com/cb", {"state": "\ud800"})
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Invalid characters in parameters" in str(e)
    except Exception as e:
        assert False, f"Should have raised ValueError, raised {type(e).__name__} instead: {e}"
