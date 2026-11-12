Fixed
~~~~~

- Several endpoints registered under the same name, such as a
  :class:`~authlib.oauth2.rfc9068.JWTIntrospectionEndpoint` followed by an
  :class:`~authlib.oauth2.rfc7662.IntrospectionEndpoint`, share the wrapped
  request. When the first endpoint skipped to the next one with
  ``ContinueIteration``, the framework request was wrapped a second time.
  The Django integration cannot wrap an already wrapped request, so a plain
  token raised a server error. The request is now wrapped once, and the
  chained endpoints behave identically with the Flask and Django
  integrations.
