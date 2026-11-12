"""Chained introspection and revocation endpoints with the Flask integration.

The Flask integration reads the request from a global proxy, so re-wrapping
the request happened to work before the framework-agnostic fix. These tests
pin the end-to-end behavior of the chain, including the case where the view
passes the framework request explicitly.
"""

import pytest
from flask import json
from flask import request as flask_request

from authlib.common.errors import ContinueIteration
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from .models import Token
from .models import db
from .oauth2_server import create_basic_header


class SkippingIntrospectionEndpoint(IntrospectionEndpoint):
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
        return db.session.query(Token).filter_by(access_token=token_string).first()

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
        return db.session.query(Token).filter_by(access_token=token_string).first()

    def revoke_token(self, token, request):
        token.access_token_revoked_at = 1
        db.session.commit()


@pytest.fixture(autouse=True)
def routes(app, server):
    server.register_endpoint(SkippingIntrospectionEndpoint)
    server.register_endpoint(PlainIntrospectionEndpoint)
    server.register_endpoint(SkippingRevocationEndpoint)
    server.register_endpoint(PlainRevocationEndpoint)

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        # Pass the framework request explicitly, like the Django views do.
        return server.create_endpoint_response("introspection", flask_request)

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return server.create_endpoint_response("revocation", flask_request)


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/callback"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


def test_introspection_chain_plain_token(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": token.access_token},
        headers=headers,
    )

    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data["active"] is True
    assert data["client_id"] == "client-id"


def test_introspection_chain_unknown_token(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/introspect",
        data={"token": "unknown-token"},
        headers=headers,
    )

    assert rv.status_code == 200
    assert json.loads(rv.data) == {"active": False}


def test_introspection_chain_invalid_request(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post("/oauth/introspect", data={}, headers=headers)

    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_revocation_chain_revokes_with_next_endpoint(test_client, token):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/revoke",
        data={"token": token.access_token},
        headers=headers,
    )

    assert rv.status_code == 200
    assert json.loads(rv.data) == {}
    db.session.refresh(token)
    assert token.is_revoked()
