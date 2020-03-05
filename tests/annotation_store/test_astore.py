
import json
import pytest
import responses
import uuid

from django.conf import settings
from django.test.client import RequestFactory
from django.urls import reverse

from annotation_store.astore import AnnotationStore
from hx_lti_initializer.models import LTIResourceLinkConfig
from hx_lti_initializer.utils import retrieve_token


@pytest.mark.django_db
def test_get_store_cfg():
    path = reverse('annotation_store:api_root_prefix')
    request_factory = RequestFactory()

    delete_request = request_factory.delete(
            '{}/12345678?version=catchpy&context_id=ladeeda',
            content_type='application/json',
    )

    response = AnnotationStore.get_store_cfg_from_request(delete_request)
    assert isinstance(response, list)
    assert len(response) == 0

