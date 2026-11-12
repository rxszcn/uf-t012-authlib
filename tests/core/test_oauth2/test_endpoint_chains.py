"""Chained endpoints registered under the same ``ENDPOINT_NAME``.

The framework integrations wrap the framework request into an
:class:`~authlib.oauth2.rfc6749.OAuth2Request` in different ways. The Django
one requires a raw framework request: wrapping an already wrapped request
again raises ``AttributeError``. The Flask one ignores its argument and reads
a global proxy. A third style wraps once and rejects a second wrap.

The authorization server must therefore wrap the request once and share it
with every endpoint of the chain, so the behavior is identical for the three
integration styles.
"""

import pytest

from authlib.common.errors import ContinueIteration
from authlib.oauth2.rfc6749 import AuthorizationServer
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint


class StubClient:
    client_id = "client-id"
    client_secret = "client-secret"

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_endpoint_auth_method(self, method, endpoint):
        return True


class StubPayload:
    def __init__(self, data):
        self.data = dict(data)
        self.datalist = {key: [value] for key, value in data.items()}

    @property
    def client_id(self):
        return self.data.get("client_id")


class StubOAuth2Request(OAuth2Request):
    """An OAuth2Request built from a raw framework request."""

    def __init__(self, request):
        super().__init__(
            method=request["method"],
            uri=request["uri"],
            headers=dict(request["headers"]),
        )
        self.payload = StubPayload(request["form"])
        self.framework_request = request

    @property
    def args(self):
        return {}

    @property
    def form(self):
        return self.payload.data


class RawRequest(dict):
    """A raw framework request, as Django or Flask would provide."""


class StrictServer(AuthorizationServer):
    """Django-style integration: the request can only be wrapped once.

    Re-wrapping an :class:`OAuth2Request` fails, like the Django integration
    which calls ``request.build_absolute_uri()``.
    """

    def create_oauth2_request(self, request):
        if isinstance(request, OAuth2Request):
            raise AttributeError(
                f"{type(request).__name__} has no 'build_absolute_uri'"
            )
        return StubOAuth2Request(request)

    def create_json_request(self, request):
        raise NotImplementedError


class ReentrantServer(AuthorizationServer):
    """Flask-style integration: the framework argument is ignored.

    The wrapped request is rebuilt from a global request proxy, so wrapping
    it again happens to work.
    """

    def __init__(self, current_request):
        super().__init__()
        self._current_request = current_request

    def create_oauth2_request(self, request):
        return StubOAuth2Request(self._current_request)

    def create_json_request(self, request):
        raise NotImplementedError


class OneWrapServer(AuthorizationServer):
    """An integration that wraps a request once and rejects a second wrap."""

    def create_oauth2_request(self, request):
        if isinstance(request, OAuth2Request):
            raise TypeError("The request is already an OAuth2Request.")
        return StubOAuth2Request(request)

    def create_json_request(self, request):
        raise NotImplementedError


class StubResponse:
    def __init__(self, status_code, body, headers):
        self.status_code = status_code
        self.body = body
        self.headers = headers


def make_server(mode, raw_request):
    if mode == "strict":
        server = StrictServer()
    elif mode == "reentrant":
        server = ReentrantServer(raw_request)
    elif mode == "one_wrap":
        server = OneWrapServer()
    else:  # pragma: no cover
        raise ValueError(mode)

    server.query_client = lambda client_id: StubClient()
    server.send_signal = lambda name, *args, **kwargs: None
    server.handle_response = lambda status, body, headers: StubResponse(
        status, body, headers
    )
    return server


class SkippingIntrospectionEndpoint(IntrospectionEndpoint):
    """An endpoint that never handles the token and passes it on."""

    handled = 0

    def check_permission(self, token, client, request):
        return True

    def query_token(self, token_string, token_type_hint):
        raise ContinueIteration()

    def introspect_token(self, token):
        self.__class__.handled += 1
        return {}


class PlainIntrospectionEndpoint(IntrospectionEndpoint):
    """The RFC 7662 endpoint of the chain, for opaque tokens."""

    def __init__(self, tokens=None, server=None):
        super().__init__(server=server)
        self.tokens = tokens or {}

    def check_permission(self, token, client, request):
        return True

    def query_token(self, token_string, token_type_hint):
        return self.tokens.get(token_string)

    def introspect_token(self, token):
        return {"active": True, "client_id": token.client_id}


class StoredToken:
    def __init__(self, client_id):
        self.client_id = client_id

    def is_expired(self):
        return False

    def is_revoked(self):
        return False

    def check_client(self, client):
        return self.client_id == client.client_id


class SkippingRevocationEndpoint(RevocationEndpoint):
    def query_token(self, token_string, token_type_hint):
        raise ContinueIteration()

    def revoke_token(self, token, request):
        raise AssertionError("the skipping endpoint must not revoke")


class PlainRevocationEndpoint(RevocationEndpoint):
    def __init__(self, tokens=None, server=None):
        super().__init__(server=server)
        self.tokens = tokens or {}
        self.revoked = []

    def query_token(self, token_string, token_type_hint):
        return self.tokens.get(token_string)

    def revoke_token(self, token, request):
        self.revoked.append(token)


def make_raw_request(form):
    return RawRequest(
        method="POST",
        uri="https://authorization-server.test/oauth/introspect",
        headers={"Authorization": "Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ="},
        form=form,
    )


@pytest.fixture(autouse=True)
def reset_handled():
    SkippingIntrospectionEndpoint.handled = 0
    yield
    SkippingIntrospectionEndpoint.handled = 0


@pytest.mark.parametrize("mode", ["strict", "reentrant", "one_wrap"])
def test_introspection_chain_uses_next_endpoint(mode):
    """A plain token skipped by the first endpoint is handled by the next."""
    raw_request = make_raw_request({"token": "plain-token"})
    server = make_server(mode, raw_request)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(
        PlainIntrospectionEndpoint({"plain-token": StoredToken("client-id")})
    )

    response = server.create_endpoint_response(
        "introspection", RawRequest(dict(raw_request))
    )

    assert response.status_code == 200
    assert response.body["active"] is True
    assert response.body["client_id"] == "client-id"
    assert SkippingIntrospectionEndpoint.handled == 0


@pytest.mark.parametrize("mode", ["strict", "reentrant", "one_wrap"])
def test_introspection_chain_unknown_token(mode):
    """The last endpoint answers ``active: false`` instead of raising."""
    raw_request = make_raw_request({"token": "unknown"})
    server = make_server(mode, raw_request)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint())

    response = server.create_endpoint_response(
        "introspection", RawRequest(dict(raw_request))
    )

    assert response.status_code == 200
    assert response.body == {"active": False}


@pytest.mark.parametrize("mode", ["strict", "reentrant", "one_wrap"])
def test_introspection_chain_three_endpoints(mode):
    """The request is wrapped once and shared by the whole chain."""
    raw_request = make_raw_request({"token": "plain-token"})
    server = make_server(mode, raw_request)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(
        PlainIntrospectionEndpoint({"plain-token": StoredToken("client-id")})
    )

    response = server.create_endpoint_response(
        "introspection", RawRequest(dict(raw_request))
    )

    assert response.status_code == 200
    assert response.body["active"] is True


@pytest.mark.parametrize("mode", ["strict", "reentrant", "one_wrap"])
def test_introspection_chain_oauth2_error(mode):
    """An OAuth2 error raised after a skip still produces an error response."""
    raw_request = make_raw_request({})
    server = make_server(mode, raw_request)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint())

    response = server.create_endpoint_response(
        "introspection", RawRequest(dict(raw_request))
    )

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"


@pytest.mark.parametrize("mode", ["strict", "reentrant", "one_wrap"])
def test_revocation_chain_uses_next_endpoint(mode):
    """The revocation chain shares the request between its endpoints too."""
    raw_request = make_raw_request({"token": "plain-token"})
    server = make_server(mode, raw_request)
    endpoint = PlainRevocationEndpoint({"plain-token": StoredToken("client-id")})
    server.register_endpoint(SkippingRevocationEndpoint)
    server.register_endpoint(endpoint)

    response = server.create_endpoint_response(
        "revocation", RawRequest(dict(raw_request))
    )

    assert response.status_code == 200
    assert response.body == {}
    assert len(endpoint.revoked) == 1


@pytest.mark.parametrize("mode", ["strict", "reentrant", "one_wrap"])
def test_single_endpoint_still_wraps_the_request(mode):
    """A lone endpoint behaves as before the fix."""
    raw_request = make_raw_request({"token": "plain-token"})
    server = make_server(mode, raw_request)
    server.register_endpoint(
        PlainIntrospectionEndpoint({"plain-token": StoredToken("client-id")})
    )

    response = server.create_endpoint_response(
        "introspection", RawRequest(dict(raw_request))
    )

    assert response.status_code == 200
    assert response.body["active"] is True


def test_wrapped_request_is_not_wrapped_again():
    """An OAuth2Request passed directly reaches the endpoint untouched."""
    raw_request = make_raw_request({"token": "plain-token"})
    server = make_server("strict", raw_request)
    server.register_endpoint(
        PlainIntrospectionEndpoint({"plain-token": StoredToken("client-id")})
    )

    response = server.create_endpoint_response(
        "introspection", StubOAuth2Request(dict(raw_request))
    )

    assert response.status_code == 200
    assert response.body["active"] is True


def test_continue_iteration_skips_to_the_end():
    """When every endpoint skips, the chain ends without re-wrapping the
    request. ``ContinueIteration`` is not an ``OAuth2Error``: it must be
    caught by its own clause."""
    raw_request = make_raw_request({"token": "plain-token"})
    server = make_server("strict", raw_request)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(SkippingIntrospectionEndpoint)

    assert (
        server.create_endpoint_response("introspection", RawRequest(dict(raw_request)))
        is None
    )
