from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import F, Q
from lti.contrib.django import DjangoToolProvider
from hx_lti_assignment.models import Assignment
from hx_lti_assignment.models import Assignment
from hx_lti_initializer.utils import retrieve_token

from .models import Annotation, AnnotationTags

import json
import requests
import datetime
import logging
import urllib

logger = logging.getLogger(__name__)

# attr names for annotation-store cfg in Assignment object
STORECFG_ATTRS = ['annotation_database_url', 'annotation_database_apikey',
        'annotation_database_secret_token']

class AnnotationStore(object):
    '''
    '''
    logger = logging.getLogger(__name__)


    # from hx_lti_initializer/utils.py
    @classmethod
    def get_store_cfg(cls, collection_id=None, context_id=None):
        if collection_id:
            try:
                cfg = Assignment.objects.get(
                        assignment_id=collection_id).values(*STORECFG_ATTRS)
                store_cfg = [cfg]
            except Assignment.DoesNotExist as e:
                cls.logger.error('assignment({}) not found'.format(collection_id))
                return []

        elif context_id:
            try:
                store_cfg = Assignment.objects \
                        .filter(course__course_id=context_id) \
                        .values(*STORECFG_ATTRS) \
                        .distinct(*STORECFG_ATTRS) \
                        .order_by(*STORECFG_ATTRS)
            except DatabaseError as e:
                cls.logger.error('assignment not found for context({}): {}' \
                        .format(collection_id, e))
                return []

        else:
            cls.logger.info('request for all distinct assignments possible!')
            try:
                store_cfg = Assignment.objects \
                        .values(*STORECFG_ATTRS) \
                        .distinct(*STORECFG_ATTRS) \
                        .order_by(*STORECFG_ATTRS)
            except DatabaseError as e:
                cls.logger.error('no assignments found in database!')
                return []

        # The list of database entries might not be unique (despite the *select distinct*) if any of
        # the URLs contain whitespace. The code below accounts for that possibility.
        k, cfg_by_url = ('annotation_database_url', {})
        for row in store_cfg:
            row[k] = row[k].strip()
            if row[k] and row[k] not in cfg_by_url:
                cfg_by_url[row[k]] = row
            else:
                cls.logger.debug(
                        ('CURSES CURSES CURSES CURSES! annotation_database_url'
                          ' with trailing spaces!!! ({})').format(row[k]))

        return cfg_by_url.values()


    @classmethod
    def get_store_cfg_from_request(cls, request):
        '''get annotation_store configs related to this request.

        'create' always get collection_id from the body of request;
        other requests follow this order:
            1. collection_id param in querystring
                 if collection_id present but can't find object, then error
            2. resource_link_id param in querystring
                 if resource_link_id present but can't find object, then error
            3. context_id param in querystring
                if context_id present but can't find object, then error
                here a search will be across assignments in a course
            4. no param found results in search for all possible store configs
               across the whole database!

        returns a list of dicts; list might be empty.
        [
            {
                'annotation_database_url': 'http://store1.com/catch/annotator',
                'annotation_database_apikey': 'key1',
                'annotation_database_secret_token': 'secret1',
            },
            {
                'annotation_database_url': 'http://store2.com/catch/annotator',
                'annotation_database_apikey': 'key2',
                'annotation_database_secret_token': 'secret2',
            },
        ]
        '''

        if request.method == 'POST':
            # get collection_id from json body
            # note that PUT for update is not reliable since the context_id
            # might be the thing that changed!
            body = json.loads(str(self.request.body, 'utf-8'))
            # try to read as if it's Webannotation
            try:
                collection_id = body['platform']['collection_id']
            except KeyError as e:
                # try to read as if it's Annotatorjs
                collection_id = body.get('collectionId', None)
            if collection_id:
                store_cfg = cls.get_store_cfg(collection_id=collection_id)
                return store_cfg

        else:  # other than create(POST), check querystring
            try:
                qs = urllib.parse.parse_qs(request.META['QUERY_STRING'])
            except KeyError as e:
                qs = {}

            # check querystring for context/collection
            collection_id = qs.get('collection_id', qs.get('collectionId', None))
            if collection_id:
                store_cfg = cls.get_store_cfg(collection_id=collection_id)
                return store_cfg

            resource_link_id = qs.get('resource_link_id', None)
            if resource_link_id:
                try:
                    rli = LTIResourceLinkConfig.objects.get(resource_link_id=resource_link_id)
                except LTIResourceLinkConfig.DoesNotExist as e:
                    self.logger.info('resource_link_id({}) not found from querystring'.format(resource_link_id))
                    resource_link_id = None
                else:
                    store_cfg = cls.get_store_cfg(collection_id=rli.collection_id)
                    return store_cfg

            context_id = qs.get('context_id', qs.get('contextId', None))
            if context_id:
                store_cfg = cls.get_store_cfg(context_id=context_id)
                return store_cfg

            # run out of places to find annotation backend cfg!
            # look for some other requirement that allow operation to be
            # done across all backend stores, e.g. if instructor then ok
            # to search over all courses for a user_id to, say, check
            # participation history.

            # at some point, give up.
            self.logger.info('unable to find annotation store for qs({})'.format(qs))
            return []


    @classmethod
    def search(cls, request):
        cfg = cls.get_store_cfg_from_request(request)

        if cfg:
            # select distinct(backend_store_cfg)

            # for each backend_store_cfg, issue a search request

            # what happens if one of the requests fail?
            # concatenate all results

            # what should return? just json? the response obj from backend
            # request? shoult it manipulate the response from backend?

            pass
        else:
            # is this an error? or should just return empty result?
            pass


    @classmethod
    def create(cls, request):
        cfg = cls.get_store_cfg_from_request(request)
        if len(cfg) != 1:
            # error? insufficient params in request
            return None

        # issue request to create



    @classmethod
    def update(cls, request):
        cfg = cls.get_store_cfg_from_request(request)
        if len(cfg) != 1:
            # error? insufficient params in request
            return None


    @classmethod
    def delete(cls, request):
        cfg = cls.get_store_cfg_from_request(request)
        if len(cfg) != 1:
            # error? insufficient params in request
            return None


    @classmethod
    def read(cls, request):
        cfg = cls.get_store_cfg_from_request(request)
        if len(cfg) != 1:
            # error? insufficient params in request
            return None


    @classmethod
    def lti_grade_passback(cls, score=1.0):
        pass




###########################################################
# Backend Classes


class StoreBackend(object):
    BACKEND_NAME = None
    ADMIN_GROUP_ID = '__admin__'
    ADMIN_GROUP_ENABLED = True if settings.ORGANIZATION == 'ATG' else False

    def __init__(self, request):
        self.request = request
        self.logger = logging.getLogger('{module}.{cls}'.format(module=__name__, cls=self.__class__.__name__))

    def root(self, annotation_id=None):
        return HttpResponse(json.dumps(dict(name=self.BACKEND_NAME)), content_type='application/json')

    def search(self):
        raise NotImplementedError

    def create(self, annotation_id):
        raise NotImplementedError

    def read(self, annotation_id):
        raise NotImplementedError

    def update(self, annotation_id):
        raise NotImplementedError

    def delete(self, annotation_id):
        raise NotImplementedError

    def _get_assignment(self, assignment_id):
        try:
            return get_object_or_404(Assignment, assignment_id=assignment_id)
        except Exception as e:
            self.logger.error("Error loading assignment object: %s" % assignment_id)
            raise e

    def _get_request_body(self):
        body = json.loads(str(self.request.body, 'utf-8'))
        if self.ADMIN_GROUP_ENABLED:
            return self._modify_permissions(body)
        return body

    def _modify_permissions(self, data):
        '''
        Given an annotation data object, update the "read" permissions so that
        course admins can view private annotations.

        Instead of adding the specific user IDs of course admins, a group identifier is used
        so that the IDs aren't hard-coded, which would require updating if the list of admins
        changes in the tool. It's expected that when the tool searchs the annotation database on
        behalf of a course admin, it will use the admin group identifier.

        Possible read permissions:
           - permissions.read = []                        # world-readable (public)
           - permissions.read = [user_id]                 # private (user only)
           - permissions.read = [user_id, ADMIN_GROUP_ID] # semi-private (user + admins only)

        '''
        permissions = {"read": [], "admin": [], "update": [], "delete": []}
        permissions.update(data.get('permissions', {}))
        self.logger.debug("_modify_permissions() before: %s" % str(permissions))

        # No change required when the annotation is world-readable
        if len(permissions['read']) == 0:
            return data

        has_parent = ('parent' in data and data['parent'] != '' and data['parent'] != '0')
        if has_parent:
            # Ensure that when a reply is created, it remains visible to the author of the parent
            # annotation, even if the reply has unchecked "Allow anyone to view this annotation" in
            # the annotator editor. Ideally, the annotator UI field should either be removed from the
            # annotator editor for replies, or work as expected. That is, when checked, only the annotation
            # author, reply author, and thread participants have read permission.
            permissions['read'] = []
        else:
            # Ensure that the annotation author's user_id is present in the read permissions.
            # This might not be the case if an admin changes a public annotation to private,
            # since annotator will set the admin's user_id, and not the author's user_id.
            if data['user']['id'] not in permissions['read']:
                permissions['read'].insert(0, data['user']['id'])

            # Ensure the annotation is readable by course admins.
            if self.ADMIN_GROUP_ID not in permissions['read']:
                permissions['read'].append(self.ADMIN_GROUP_ID)

        self.logger.debug("_modify_permissions() after: %s" % str(permissions))

        data['permissions'] = permissions
        return data

class CatchStoreBackend(StoreBackend):
    BACKEND_NAME = 'catch'

    def __init__(self, request):
        super(CatchStoreBackend, self).__init__(request)
        self.logger = logging.getLogger('{module}.{cls}'.format(module=__name__, cls=self.__class__.__name__))
        self.headers = {
            'x-annotator-auth-token': request.META.get('HTTP_X_ANNOTATOR_AUTH_TOKEN', '!!MISSING!!'),
            'content-type': 'application/json',
        }
        self.timeout = 5.0 # most actions should complete within this amount of time, other than search perhaps

    def root(self, annotation_id):
        self.logger.info(u"MethodType: %s" % self.request.method)
        if self.request.method == "GET":
            self.before_search()
            response = self.search()
            is_graded = self.request.LTI['launch_params'].get('lis_outcome_service_url', None) is not None
            if is_graded and self.after_search(response):
                self.lti_grade_passback(score=1)
                self.logger.info("Grade sent back for user %s" % self.request.LTI['hx_user_id'])  
            return response
        elif self.request.method == "POST":
            return self.create(annotation_id)
        elif self.request.method == "PUT":
            return self.update(annotation_id)
        elif self.request.method == "DELETE":
            return self.delete(annotation_id)
        return self.BACKEND_NAME

    def _get_database_url(self, path='/'):
        try:
            if self.request.method == "GET":
                assignment_id = self.request.GET.get('collectionId', self.request.GET.get('collection_id', None))
            else:
                body = self._get_request_body()
                assignment_id = body.get('collectionId', body.get('collection_id', None))
            if assignment_id:
                    assignment = self._get_assignment(assignment_id)
                    base_url = assignment.annotation_database_url
            else:
                base_url = str(ANNOTATION_DB_URL).strip()
        except:
            self.logger.info("Default annotation_database_url used as assignment could not be found.")
            base_url = str(ANNOTATION_DB_URL).strip()
        return '{base_url}{path}'.format(base_url=base_url, path=path)

    def _retrieve_annotator_token(self, user_id):
        return retrieve_token(user_id, ANNOTATION_DB_API_KEY, ANNOTATION_DB_SECRET_TOKEN)

    def _response_timeout(self):
        return HttpResponse(json.dumps({"error": "request timeout"}), status=500, content_type='application/json')

    def before_search(self):
        # Override the auth token when the user is a course administrator, so they can query annotations
        # that have set their read permissions to private (i.e. read: self-only).
        # Note: this only works if the "__admin__" group ID was added to the annotation read permissions
        # prior to saving it, otherwise this will have no effect.
        if self.ADMIN_GROUP_ENABLED and self.request.LTI['is_staff']:
            self.logger.info('updating auth token for admin')
            self.headers['x-annotator-auth-token'] = self._retrieve_annotator_token(user_id=self.ADMIN_GROUP_ID)

    def search(self):
        timeout = 10.0
        params = self.request.GET.urlencode()
        database_url = self._get_database_url('/search')
        self.logger.info('search request: url=%s headers=%s params=%s timeout=%s' % (database_url, self.headers, params, timeout))
        try:
            response = requests.get(database_url, headers=self.headers, params=params, timeout=timeout)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('search response status_code=%s content_length=%s' % (response.status_code, response.headers.get('content-length', 0)))
        return HttpResponse(response.content, status=response.status_code, content_type='application/json')

    def after_search(self, response):
        retrieved_self = self.request.LTI['launch_params'].get('user_id', '*') == self.request.GET.get('userid', '')
        return retrieved_self and int(json.loads(response.content)['total'] > 0)

    def create(self, annotation_id):
        body = self._get_request_body()
        database_url = self._get_database_url('/create')
        data = json.dumps(body)
        self.logger.info('create request: url=%s headers=%s data=%s' % (database_url, self.headers, data))
        try:
            response = requests.post(database_url, data=data, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                is_graded = self.request.LTI['launch_params'].get('lis_outcome_service_url', False)
                self.logger.debug('************** passgrade url({})'.format(is_graded))
                if is_graded:
                    self.lti_grade_passback(score=1)
                    self.logger.info("Grade sent back for user %s" % self.request.LTI['hx_user_id']) 
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('create response status_code=%s' % response.status_code)
        return HttpResponse(response.content, status=response.status_code, content_type='application/json')

    def update(self, annotation_id):
        body = self._get_request_body()
        database_url = self._get_database_url('/update/%s' % annotation_id)
        data = json.dumps(body)
        self.logger.info('update request: url=%s headers=%s data=%s' % (database_url, self.headers, data))
        try:
            response = requests.post(database_url, data=data, headers=self.headers, timeout=self.timeout)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('update response status_code=%s' % response.status_code)
        return HttpResponse(response.content, status=response.status_code, content_type='application/json')

    def delete(self, annotation_id):
        database_url = self._get_database_url('/delete/%s' % annotation_id)
        self.logger.info('delete request: url=%s headers=%s' % (database_url, self.headers))
        try:
            response = requests.delete(database_url, headers=self.headers, timeout=self.timeout)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('delete response status_code=%s' % response.status_code)
        return HttpResponse(response)

    def _get_tool_provider(self):
        try:
            lti_secret = settings.LTI_SECRET_DICT[self.request.LTI.get('hx_context_id')]
        except KeyError:
            lti_secret = settings.LTI_SECRET

        if 'launch_params' in self.request.LTI:
            params = self.request.LTI['launch_params']

            # the middleware includes an LTI dict with all lti params for
            # lti_grade_passback() -- an lti request that is not a lti-launch.
            # py-lti only understands lti params that come directly in the POST
            mutable_post = self.request.POST.copy()
            mutable_post.update(params)
            self.request.POST = mutable_post

            return DjangoToolProvider.from_django_request(
                lti_secret, request=self.request)
        return DjangoToolProvider.from_django_request(
            lti_secret, request=self.request)

    def lti_grade_passback(self, score=1.0):
        if score < 0 or score > 1.0 or isinstance(score, str):
            return
        tool_provider = self._get_tool_provider()
        if not tool_provider.is_outcome_service():
            self.logger.debug("LTI consumer does not expect a grade for the current user and assignment")
            return
        self.logger.info("Initiating LTI Grade Passback: score=%s" % score)
        try:
            outcome = tool_provider.post_replace_result(score)
            self.logger.info(vars(outcome))
            if outcome.is_success():
                self.logger.info(u"LTI grade request was successful. Description: %s" % outcome.description)
            else:
                self.logger.error(u"LTI grade request failed. Description: %s" % outcome.description)
            self.outcome = outcome
        except Exception as e:
            self.logger.error("LTI post_replace_result request failed: %s" % str(e))


class AppStoreBackend(StoreBackend):
    BACKEND_NAME = 'app'

    def __init__(self, request):
        super(AppStoreBackend, self).__init__(request)
        self.date_format = '%Y-%m-%dT%H:%M:%S %Z'
        self.max_limit = 1000

    def read(self, annotation_id):
        anno = get_object_or_404(Annotation, pk=annotation_id)
        result = self._serialize_annotation(anno)
        return HttpResponse(json.dumps(result), status=200, content_type='application/json')

    def search(self):
        user_id = self.request.LTI['hx_user_id']
        is_staff = self.request.LTI['is_staff']

        query_map = {
            'contextId':            'context_id',
            'collectionId':         'collection_id',
            'uri':                  'uri',
            'media':                'media',
            'userid':               'user_id',
            'username':             'user_name__icontains',
            'parentid':             'parent_id',
            'text':                 'text__icontains',
            'quote':                'quote__icontains',
            'tag':                  'tags__name__iexact',
            'dateCreatedOnOrAfter': 'created_at__gte',
            'dateCreatedOnOrBefore':'created_at__lte',
        }

        # Setup filters based on the search query
        filters = {}
        for param, filter_key in query_map.iteritems():
            if param not in self.request.GET or self.request.GET[param] == '':
                continue
            value = self.request.GET[param]
            if param.startswith('date'):
                filters[filter_key] = datetime.datetime.strptime(str(value), self.date_format)
            else:
                filters[filter_key] = value

        filter_conds = []
        if not is_staff:
            filter_conds.append(Q(is_private=False) | (Q(is_private=True) & Q(user_id=user_id)))

        # Create the queryset with the filters applied and get a count of the total size
        queryset = Annotation.objects.filter(*filter_conds, **filters)
        total = queryset.count()

        # Examine the user's requested limit and offset and check constraints
        limit = -1
        if 'limit' in self.request.GET and self.request.GET['limit'].isdigit():
            requested_limit = int(self.request.GET['limit'])
            limit = requested_limit if requested_limit <= self.max_limit else self.max_limit
        else:
            limit = self.max_limit

        offset = 0
        if 'offset' in self.request.GET and self.request.GET['offset'].isdigit():
            requested_offset = int(self.request.GET['offset'])
            offset = requested_offset if requested_offset < total else total

        # Slice the queryset and return the selected rows
        start, end = (offset, offset + limit if offset + limit < total else total)
        if limit < 0:
            queryset = queryset[start:]
        else:
            queryset = queryset[start:end]

        rows = [self._serialize_annotation(anno) for anno in queryset]
        result = {
            'total': total,
            'limit': limit,
            'offset': offset,
            'size': len(rows),
            'rows': rows,
        }

        return HttpResponse(json.dumps(result), status=200, content_type='application/json')

    def create(self, annotation_id):
        anno = self._create_or_update(anno=None)
        result = self._serialize_annotation(anno)
        return HttpResponse(json.dumps(result), status=200, content_type='application/json')

    def update(self, annotation_id):
        anno = self._create_or_update(anno=Annotation.objects.get(pk=annotation_id))
        result = self._serialize_annotation(anno)
        return HttpResponse(json.dumps(result), status=200, content_type='application/json')

    @transaction.atomic
    def delete(self, annotation_id):
        anno = Annotation.objects.get(pk=annotation_id)
        anno.is_deleted = True
        anno.save()

        if anno.parent_id:
            parent_anno = Annotation.objects.get(pk=anno.parent_id)
            parent_anno.total_comments = F('total_comments') - 1
            parent_anno.save()

        result = self._serialize_annotation(anno)
        return HttpResponse(json.dumps(result), status=200, content_type='application/json')

    @transaction.atomic
    def _create_or_update(self, anno=None):
        create = anno is None
        if create:
            anno = Annotation()

        body = self._get_request_body()
        anno.context_id = body['contextId']
        anno.collection_id = body['collectionId']
        anno.uri = body['uri']
        anno.media = body['media']
        anno.user_id = body['user']['id']
        anno.user_name = body['user']['name']
        anno.is_private = False if len(body.get('permissions', {}).get('read', [])) == 0 else True
        anno.text = body.get('text', '')
        anno.quote = body.get('quote', '')
        anno.json = json.dumps(body)

        if 'parent' in body and body['parent'] != '0':
            anno.parent_id = int(body['parent'])
        anno.save()

        if create and anno.parent_id:
            parent_anno = Annotation.objects.get(pk=int(body['parent']))
            parent_anno.total_comments = F('total_comments') + 1
            parent_anno.save()

        if not create:
            anno.tags.clear()
        for tag_name in body.get('tags', []):
            tag_object, created = AnnotationTags.objects.get_or_create(name=tag_name.strip())
            anno.tags.add(tag_object)

        return anno

    def _serialize_annotation(self, anno):
        data = json.loads(anno.json)
        data.update({
            "id": anno.pk,
            "deleted": anno.is_deleted,
            "created": anno.created_at.strftime(self.date_format),
            "updated": anno.updated_at.strftime(self.date_format),
        })
        if anno.parent_id is None:
            data['totalComments'] = anno.total_comments
        return data


class WebAnnotationStoreBackend(StoreBackend):
    BACKEND_NAME = 'catchpy'

    def __init__(self, request):
        super(WebAnnotationStoreBackend, self).__init__(request)
        self.logger = logging.getLogger('{module}.{cls}'.format(module=__name__, cls=self.__class__.__name__))
        self.headers = {
            'x-annotator-auth-token': request.META.get('HTTP_X_ANNOTATOR_AUTH_TOKEN', '!!MISSING!!'),
            'content-type': 'application/json',
        }
        self.timeout = 5.0 # most actions should complete within this amount of time, other than search perhaps

    def root(self, annotation_id):
        self.logger.info(u"MethodType: %s" % self.request.method)
        if self.request.method == "GET":
            self.before_search()
            response = self.search()
            is_graded = self.request.LTI['launch_params'].get('lis_outcome_service_url', False)
            if is_graded and self.after_search(response):
                self.lti_grade_passback(score=1)
            return response
        elif self.request.method == "POST":
            return self.create(annotation_id)
        elif self.request.method == "PUT":
            return self.update(annotation_id)
        elif self.request.method == "DELETE":
            return self.delete(annotation_id)
        return self.BACKEND_NAME

    def _get_database_url(self, path='/'):
        try:
            if self.request.method == "GET":
                assignment_id = self.request.GET.get('collectionId', self.request.GET.get('collection_id', None))
                self.logger.debug('^^^^^^^^^^^^^^^^^^^^^^^^ SEARCH assignment_id({})'.format(assignment_id))
            elif self.request.method == "DELETE":
                qs = urllib.parse.parse_qs(self.request.META['QUERY_STRING'])
                try:
                    assignment_id = qs.get('collectionId')[0]
                except (KeyError, IndexError) as e:
                    assignment_id = None

            else:
                body = self._get_request_body()
                # 02mar20 naomi: TODO pulling collection_id from wrong place,
                # this is a webannotation so body['platform']['collection_id']
                # related to https://github.com/lduarte1991/hxat/issues/116
                # 03mar20 naomi: if client tries to update the collection_id?
                # what is the supposed behavior for hxat?
                assignment_id = body.get('collectionId', body.get('collection_id', None))
                #assignment_id = body['platform']['collection_id']
            if assignment_id:
                    assignment = self._get_assignment(assignment_id)
                    base_url = assignment.annotation_database_url
            else:
                # 02mar20 naomi: if collection_id not present it is probably a
                # search throughout course. In this case, search should iterate
                # over all assignments and issue a search per assignment since,
                # potentially, each assignment can be in a different store.
                # _get_database_url() maybe returns a map of
                # (collection_id, database_url) pairs and its clients have to
                # deal with that.
                base_url = str(ANNOTATION_DB_URL).strip()
        except Exception as e:
            self.logger.info("Default annotation_database_url used as assignment could not be found.")
            self.logger.info("*************************************** {}".format(e))
            base_url = str(ANNOTATION_DB_URL).strip()
        return '{base_url}{path}'.format(base_url=base_url, path=path)

    def _retrieve_annotator_token(self, user_id):
        return retrieve_token(user_id, ANNOTATION_DB_API_KEY, ANNOTATION_DB_SECRET_TOKEN)

    def _response_timeout(self):
        return HttpResponse(json.dumps({"error": "request timeout"}), status=500, content_type='application/json')

    def before_search(self):
        # Override the auth token when the user is a course administrator, so they can query annotations
        # that have set their read permissions to private (i.e. read: self-only).
        # Note: this only works if the "__admin__" group ID was added to the annotation read permissions
        # prior to saving it, otherwise this will have no effect.
        if self.ADMIN_GROUP_ENABLED and self.request.LTI['is_staff']:
            self.logger.info('updating auth token for admin')
            self.headers['x-annotator-auth-token'] = self._retrieve_annotator_token(user_id=self.ADMIN_GROUP_ID)

    def search(self):
        timeout = 10.0
        params = self.request.GET.urlencode()
        database_url = self._get_database_url('/')
        self.logger.info('search request: url=%s headers=%s params=%s timeout=%s' % (database_url, self.headers, params, timeout))
        try:
            response = requests.get(database_url, headers=self.headers, params=params, timeout=timeout)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('search response status_code=%s content_length=%s' % (response.status_code, response.headers.get('content-length', 0)))
        return HttpResponse(response.content, status=response.status_code, content_type='application/json')

    def after_search(self, response):
        retrieved_self = self.request.LTI['launch_params'].get('user_id', '*') in self.request.GET.getlist('userid[]', self.request.GET.getlist('userid', []))
        return retrieved_self and int(json.loads(response.content)['total']) > 0

    def create(self, annotation_id):
        body = self._get_request_body()
        database_url = self._get_database_url('/%s' % annotation_id)
        data = json.dumps(body)
        self.logger.info('create request: url=%s headers=%s data=%s' % (database_url, self.headers, data))
        try:
            response = requests.post(database_url, data=data, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                is_graded = self.request.LTI['launch_params'].get('lis_outcome_service_url', False)
                self.logger.debug('*************************** passback grade({})'.format(is_graded))
                if is_graded:
                    self.lti_grade_passback(score=1)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('create response status_code=%s' % response.status_code)
        return HttpResponse(response.content, status=response.status_code, content_type='application/json')

    def update(self, annotation_id):
        body = self._get_request_body()
        database_url = self._get_database_url('/%s' % annotation_id)
        data = json.dumps(body)
        self.logger.info('update request: url=%s headers=%s data=%s' % (database_url, self.headers, data))
        try:
            response = requests.put(database_url, data=data, headers=self.headers, timeout=self.timeout)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('update response status_code=%s' % response.status_code)
        return HttpResponse(response.content, status=response.status_code, content_type='application/json')

    def delete(self, annotation_id):
        database_url = self._get_database_url('/%s' % annotation_id)
        self.logger.info('delete request: url=%s headers=%s' % (database_url, self.headers))
        try:
            response = requests.delete(database_url, headers=self.headers, timeout=self.timeout)
        except requests.exceptions.Timeout as e:
            self.logger.error("requested timed out!")
            return self._response_timeout()
        self.logger.info('delete response status_code=%s' % response.status_code)
        return HttpResponse(response)

    def _get_tool_provider(self):
        try:
            lti_secret = settings.LTI_SECRET_DICT[self.request.LTI.get('hx_context_id')]
        except KeyError:
            lti_secret = settings.LTI_SECRET

        if 'launch_params' in self.request.LTI:
            params = self.request.LTI['launch_params']

            # the middleware includes an LTI dict with all lti params for
            # lti_grade_passback() -- an lti request that is not a lti-launch.
            # py-lti only understands lti params that come directly in the POST
            mutable_post = self.request.POST.copy()
            mutable_post.update(params)
            self.request.POST = mutable_post

            return DjangoToolProvider.from_django_request(
                lti_secret, request=self.request)
        return DjangoToolProvider.from_django_request(
            lti_secret, request=self.request)

    def lti_grade_passback(self, score=1.0):
        if score < 0 or score > 1.0 or isinstance(score, str):
            return
        tool_provider = self._get_tool_provider()
        if not tool_provider.is_outcome_service():
            self.logger.debug("LTI consumer does not expect a grade for the current user and assignment")
            return
        self.logger.info("Initiating LTI Grade Passback: score=%s" % score)
        try:
            outcome = tool_provider.post_replace_result(score)
            self.logger.info(vars(outcome))
            if outcome.is_success():
                self.logger.info(u"LTI grade request was successful. Description: %s" % outcome.description)
            else:
                self.logger.error(u"LTI grade request failed. Description: %s" % outcome.description)
            self.outcome = outcome
        except Exception as e:
            self.logger.error("LTI post_replace_result request failed: %s" % str(e))
