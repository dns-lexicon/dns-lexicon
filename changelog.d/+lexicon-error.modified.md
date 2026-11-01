Providers now raise `LexiconError` (or `AuthenticationError`) instead of a bare
`Exception`; existing `except Exception` handlers keep working
