import json

import pytest

from authlib.common.errors import ContinueIteration
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from .models import Client
from .models import OAuth2Token
from .oauth2_server import create_basic_auth

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def env():
    import os

    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
    yield
    os.environ.pop("AUTHLIB_INSECURE_TRANSPORT", None)


@pytest.fixture(autouse=True)
def client(user):
    client = Client(
        user=user,
        client_id="client-id",
        client_secret="client-secret",
        token_endpoint_auth_method="client_secret_basic",
        default_redirect_uri="https://client.test",
    )
    client.save()
    yield client
    client.delete()


@pytest.fixture
def auth_header():
    return create_basic_auth("client-id", "client-secret")


class SkippingIntrospectionEndpoint(IntrospectionEndpoint):
    """An endpoint that never handles the token and passes it on."""

    def check_permission(self, token, client, request):
        return True

    def query_token(self, token_string, token_type_hint):
        raise ContinueIteration()

    def introspect_token(self, token):
        raise AssertionError("the skipping endpoint must not answer")


class PlainIntrospectionEndpoint(IntrospectionEndpoint):
    def check_permission(self, token, client, request):
        return True

    def query_token(self, token_string, token_type_hint):
        try:
            return OAuth2Token.objects.get(access_token=token_string)
        except OAuth2Token.DoesNotExist:
            return None

    def introspect_token(self, token):
        return {
            "active": True,
            "client_id": token.client_id,
            "token_type": token.token_type,
            "scope": token.scope,
        }


class SkippingRevocationEndpoint(RevocationEndpoint):
    def query_token(self, token_string, token_type_hint):
        raise ContinueIteration()

    def revoke_token(self, token, request):
        raise AssertionError("the skipping endpoint must not revoke")


class PlainRevocationEndpoint(RevocationEndpoint):
    def query_token(self, token_string, token_type_hint):
        try:
            return OAuth2Token.objects.get(access_token=token_string)
        except OAuth2Token.DoesNotExist:
            return None

    def revoke_token(self, token, request):
        token.access_token_revoked_at = 1
        token.save()


def test_introspection_chain_plain_token(factory, server, auth_header, token):
    """The Django integration wraps the request once. A second wrap used to
    raise AttributeError when the first endpoint skipped to the next one."""
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint)

    request = factory.post(
        "/oauth/introspect",
        data={"token": token.access_token},
        HTTP_AUTHORIZATION=auth_header,
    )
    response = server.create_endpoint_response("introspection", request)

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["active"] is True
    assert data["client_id"] == "client-id"


def test_introspection_chain_unknown_token(factory, server, auth_header):
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint)

    request = factory.post(
        "/oauth/introspect",
        data={"token": "unknown-token"},
        HTTP_AUTHORIZATION=auth_header,
    )
    response = server.create_endpoint_response("introspection", request)

    assert response.status_code == 200
    assert json.loads(response.content) == {"active": False}


def test_introspection_chain_three_endpoints(factory, server, auth_header, token):
    """The same wrapped request is shared by the whole chain."""
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint)

    request = factory.post(
        "/oauth/introspect",
        data={"token": token.access_token},
        HTTP_AUTHORIZATION=auth_header,
    )
    response = server.create_endpoint_response("introspection", request)

    assert response.status_code == 200
    assert json.loads(response.content)["active"] is True


def test_introspection_chain_invalid_request_still_errors(factory, server, auth_header):
    """An OAuth2 error raised after a skip still gives an error response."""
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint)

    request = factory.post(
        "/oauth/introspect",
        data={},
        HTTP_AUTHORIZATION=auth_header,
    )
    response = server.create_endpoint_response("introspection", request)

    assert response.status_code == 400
    assert json.loads(response.content)["error"] == "invalid_request"


def test_revocation_chain_revokes_with_next_endpoint(
    factory, server, auth_header, token
):
    server.register_endpoint(SkippingRevocationEndpoint)
    server.register_endpoint(PlainRevocationEndpoint)

    request = factory.post(
        "/oauth/revoke",
        data={"token": token.access_token},
        HTTP_AUTHORIZATION=auth_header,
    )
    response = server.create_endpoint_response("revocation", request)

    assert response.status_code == 200
    token.refresh_from_db()
    assert token.is_revoked()
