from origo.endpoints import _form_action_source

def test_form_action_source_safe_csp():
    assert _form_action_source("https://example.com/callback") == "https://example.com"
    assert _form_action_source("myapp://callback") == "myapp://callback"
    assert _form_action_source("myapp:") == "myapp:"

def test_form_action_source_rejects_csp_delimiters():
    assert _form_action_source("https://example.com';frame-ancestors 'self'") == ""
    assert _form_action_source("https://example.com,frame-ancestors") == ""
    assert _form_action_source("https://example.com frame-ancestors") == ""
    assert _form_action_source("https://example.com;frame-ancestors") == ""

def test_form_action_source_rejects_non_ascii():
    assert _form_action_source("https://例え.テスト/cb") == ""
