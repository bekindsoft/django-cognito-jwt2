from django.urls import path
from ninja import NinjaAPI
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.response import Response

from django_cognito_jwt import (
    JSONWebTokenAuthentication,
    NinjaJSONWebTokenAuthentication,
)

api = NinjaAPI()


@api_view(http_method_names=["GET"])
@authentication_classes((JSONWebTokenAuthentication,))
def sample_view(request):
    return Response({"hello": "world"})


@api.get("/ninja", auth=NinjaJSONWebTokenAuthentication())
def sample_ninja_view(request):
    return {}


urlpatterns = [
    path("", sample_view, name="sample_view"),
    path("ninja/", api.urls, name="ninja_sample_view"),
]
