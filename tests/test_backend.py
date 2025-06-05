import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from utils import create_jwt_token

from django_cognito_jwt import backend
from django_cognito_jwt.backend import AuthenticationFailed as NinjaAuthenticationFailed

USER_MODEL = get_user_model()


def test_authenticate_no_token(rf):
    request = rf.get("/")
    auth = backend.JSONWebTokenAuthentication()
    assert auth.authenticate(request) is None


def test_authenticate_valid(
    rf, monkeypatch, cognito_well_known_keys, jwk_private_key_one
):
    token = create_jwt_token(
        jwk_private_key_one,
        {
            "iss": "https://cognito-idp.eu-central-1.amazonaws.com/bla",
            "aud": settings.COGNITO_AUDIENCE,
            "sub": "username",
        },
    )

    def func(payload):
        return USER_MODEL(username=payload["sub"])

    monkeypatch.setattr(
        USER_MODEL.objects, "get_or_create_for_cognito", func, raising=False
    )

    request = rf.get("/", HTTP_AUTHORIZATION=b"bearer %s" % token.encode("utf8"))
    auth = backend.JSONWebTokenAuthentication()
    user, auth_token = auth.authenticate(request)
    assert user
    assert user.username == "username"
    assert auth_token == token.encode("utf8")


def test_authenticate_invalid(rf, cognito_well_known_keys, jwk_private_key_two):
    token = create_jwt_token(
        jwk_private_key_two,
        {
            "iss": "https://cognito-idp.eu-central-1.amazonaws.com/bla",
            "aud": settings.COGNITO_AUDIENCE,
            "sub": "username",
        },
    )

    request = rf.get("/", HTTP_AUTHORIZATION=b"bearer %s" % token.encode("utf8"))
    auth = backend.JSONWebTokenAuthentication()

    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_authenticate_error_segments(rf):
    request = rf.get("/", HTTP_AUTHORIZATION=b"bearer randomiets")
    auth = backend.JSONWebTokenAuthentication()

    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_authenticate_error_invalid_header(rf):
    request = rf.get("/", HTTP_AUTHORIZATION=b"bearer")
    auth = backend.JSONWebTokenAuthentication()

    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_authenticate_error_spaces(rf):
    request = rf.get("/", HTTP_AUTHORIZATION=b"bearer random iets")
    auth = backend.JSONWebTokenAuthentication()

    with pytest.raises(AuthenticationFailed):
        auth.authenticate(request)


def test_authenticate_error_response_code():
    client = Client()
    resp = client.get("/", HTTP_AUTHORIZATION=b"bearer random iets")

    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_ninja_authenticate_error_response_code():
    client = Client()
    resp = client.get("/", HTTP_AUTHORIZATION=b"bearer random iets")

    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_ninja_authenticate_valid(
    rf, monkeypatch, cognito_well_known_keys, jwk_private_key_one
):
    token = create_jwt_token(
        jwk_private_key_one,
        {
            "iss": "https://cognito-idp.eu-central-1.amazonaws.com/bla",
            "aud": settings.COGNITO_AUDIENCE,
            "sub": "username",
        },
    )

    def func(payload):
        return USER_MODEL(username=payload["sub"])

    monkeypatch.setattr(
        USER_MODEL.objects, "get_or_create_for_cognito", func, raising=False
    )

    request = rf.get("/ninja", HTTP_AUTHORIZATION=b"bearer %s" % token.encode("utf8"))
    auth = backend.NinjaJSONWebTokenAuthentication()
    user = auth.authenticate(request, token)
    assert user
    assert user.username == "username"


def test_ninja_authenticate_invalid(rf, cognito_well_known_keys, jwk_private_key_two):
    token = create_jwt_token(
        jwk_private_key_two,
        {
            "iss": "https://cognito-idp.eu-central-1.amazonaws.com/bla",
            "aud": settings.COGNITO_AUDIENCE,
            "sub": "username",
        },
    )

    request = rf.get("/ninja", HTTP_AUTHORIZATION=b"bearer %s" % token.encode("utf8"))
    auth = backend.NinjaJSONWebTokenAuthentication()

    with pytest.raises(NinjaAuthenticationFailed):
        auth.authenticate(request, token)
