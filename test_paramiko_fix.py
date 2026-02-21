
class AuthHandler:
    def __init__(self):
        self._table = {'a': 1}

    @property
    def _client_handler_table(self):
        return self._table

print("Original property:")
try:
    print(AuthHandler._client_handler_table)
except Exception as e:
    print(e)

print("Patching...")
try:
    if isinstance(AuthHandler._client_handler_table, property):
        _table = AuthHandler._client_handler_table.fget(AuthHandler())
        AuthHandler._client_handler_table = _table
except Exception as e:
    print("Patch error:", e)

print("After patch:")
try:
    print(AuthHandler._client_handler_table)
    print("Dict access:", AuthHandler._client_handler_table['a'])
except Exception as e:
    print(e)
