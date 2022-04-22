from rauth.session import RauthSession
from rauth.service import Service, process_token_request
from rauth.utils import (OAuth2Auth, ENTITY_METHODS, parse_utf8_qsl)
from rauth.compat import parse_qsl, is_basestring, urlencode
import logging

OAUTH1_DEFAULT_TIMEOUT = OAUTH2_DEFAULT_TIMEOUT = OFLY_DEFAULT_TIMEOUT = 300.0

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

#requests_log = logging.getLogger("requests.packages.urllib3")
requests_log = logging.getLogger("urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
fh = logging.FileHandler("/home/stone/frappe-bench/logs/frappe.requests.log")
requests_log.addHandler(fh)

class WechatAuthSession(RauthSession):
    '''
    A specialized :class:`~requests.sessions.Session` object, wrapping OAuth
    2.0 logic.

    This object is utilized by the :class:`WechatAuthService` wrapper but can
    be used independently of that infrastructure. Essentially this is a loose
    wrapping around the standard Requests codepath. State may be tracked at
    this layer, especially if the instance is kept around and tracked via some
    unique identifier, e.g. access token. Things like request cookies will be
    preserved between requests and in fact all functionality provided by
    a Requests' :class:`~requests.sessions.Session` object should be exposed
    here.

    If you were to use this object by itself you could do so by instantiating
    it like this::

        session = WechatAuthSession('123', '456', access_token='321')

    You now have a session object which can be used to make requests exactly as
    you would with a normal Requests :class:`~requests.sessions.Session`
    instance. This anticipates that the standard OAuth 2.0 flow will be modeled
    outside of the scope of this class. In other words, if the fully qualified
    flow is useful to you then this object probably need not be used directly,
    instead consider using :class:`WechatAuthService`.

    Once the session object is setup, you may start making requests::

        r = session.get('https://example/com/api/resource',
                        params={'format': 'json'})
        print r.json()

    :param client_id: Client id, defaults to `None`.
    :type client_id: str
    :param client_secret: Client secret, defaults to `None`
    :type client_secret: str
    :param access_token: Access token, defaults to `None`.
    :type access_token: str
    :param access_token_key: The name of the access token key, defaults to
        `'access_token'`.
    :type access_token_key: str
    :param service: A back reference to the service wrapper, defaults to
        `None`.
    :type service: :class:`rauth.Service`
    :param access_token_key: The name of the access token key, defaults to
        `'access_token'`.
    :type access_token_key: str
    '''
    __attrs__ = RauthSession.__attrs__ + ['client_id',
                                          'client_secret',
                                          'access_token', 'openid']

    def __init__(self,
                 client_id=None,
                 client_secret=None,
                 access_token=None,
                 openid=None,
                 service=None,
                 access_token_key=None):

        #: Client credentials.
        self.client_id = client_id
        self.client_secret = client_secret

        #: Access token.
        self.access_token = access_token
        self.openid = openid

        #: Access token key, e.g. 'access_token'.
        self.access_token_key = access_token_key or 'access_token'

        super(WechatAuthSession, self).__init__(service)

    def request(self, method, url, bearer_auth=True, **req_kwargs):
        '''
        A loose wrapper around Requests' :class:`~requests.sessions.Session`
        which injects OAuth 2.0 parameters.

        :param method: A string representation of the HTTP method to be used.
        :type method: str
        :param url: The resource to be requested.
        :type url: str
        :param bearer_auth: Whether to use Bearer Authentication or not,
            defaults to `True`.
        :type bearer_auth: bool
        :param \*\*req_kwargs: Keyworded args to be passed down to Requests.
        :type \*\*req_kwargs: dict
        '''
        if not req_kwargs.get('params'):
            req_kwargs['params'] = {}

        url = self._set_url(url)

        if is_basestring(req_kwargs['params']):
            req_kwargs['params'] = dict(parse_qsl(req_kwargs['params']))

        #if bearer_auth and self.access_token is not None:
        #    req_kwargs['auth'] = OAuth2Auth(self.access_token)
        #else:
        req_kwargs['params'].update({self.access_token_key: self.access_token, 'openid': self.openid})

        req_kwargs.setdefault('timeout', OAUTH2_DEFAULT_TIMEOUT)

        return super(WechatAuthSession, self).request(method, url, **req_kwargs)


class WechatAuthService(Service):
    '''
    An OAuth 2.0 Service container.

    This class provides a wrapper around a specialized Requests'
    :class:`~requests.session.Session` object. Primarily this wrapper is used
    for producing authenticated session objects which are used to make requests
    against OAuth 2.0 endpoints.

    You might intialize :class:`WechatAuthService` something like this::

        service = WechatAuthService(
                   name='example',
                   client_id='123',
                   client_secret='456',
                   access_token_url='https://example.com/token',
                   authorize_url='https://example.com/authorize',
                   base_url='https://example.com/api/')

    Given the simplicity of OAuth 2.0 now this object `service` can be used to
    retrieve an authenticated session in two simple steps::

        # the return URL is used to validate the request
        params = {'redirect_uri': 'http://example.com/',
                  'response_type': 'code'}
        url = service.get_authorize_url(**params)

        # once the above URL is consumed by a client we can ask for an access
        # token. note that the code is retrieved from the redirect URL above,
        # as set by the provider
        data = {'code': 'foobar',
                'grant_type': 'authorization_code',
                'redirect_uri': 'http://example.com/'}

        session = service.get_auth_session(data=data)

    Now that we have retrieved a session, we may make requests against the
    OAuth 2.0 provider's endpoints. As much as possible the Requests' API
    is preserved and you may make requests using the same parameters you would
    using Requests::

        r = session.get('foo', params={'format': 'json'})
        print r.json()

    :param client_id: Client id.
    :type client_id: str
    :param client_secret: Client secret.
    :type client_secret: str
    :param name: The service name, defaults to `None`.
    :type name: str
    :param access_token_url: Access token endpoint, defaults to `None`.
    :type access_token_url: str
    :param authorize_url: Authorize endpoint, defaults to `None`.
    :type authorize_url: str
    :param base_url: A base URL from which to construct requests, defaults to
        `None`.
    :type base_url: str
    :param session_obj: Object used to construct sessions with, defaults to
        :class:`OAuth2Session`
    :type session_obj: :class:`rauth.Session`
    '''
    __attrs__ = Service.__attrs__ + ['client_id',
                                     'client_secret',
                                     'access_token_url',
                                     'session_obj']

    def __init__(self,
                 client_id,
                 client_secret,
                 name=None,
                 access_token_url=None,
                 authorize_url=None,
                 base_url=None,
                 session_obj=None):

        #: Client credentials.
        self.client_id = client_id
        self.client_secret = client_secret

        #: The provider's access token URL.
        self.access_token_url = access_token_url

        #: Object used to construct sessions with.
        self.session_obj = session_obj or WechatAuthSession

        #: Access token response.
        self.access_token_response = None

        super(WechatAuthService, self).__init__(name,
                                            base_url,
                                            authorize_url)

    def get_session(self, token=None, openid=None):
        '''
        If provided, the `token` parameter is used to initialize an
        authenticated session, otherwise an unauthenticated session object is
        generated. Returns an instance of :attr:`session_obj`..

        :param token: A token with which to initilize the session.
        :type token: str
        '''
        if token is not None:
            session = self.session_obj(self.client_id,
                                       self.client_secret,
                                       token,
                                       openid,
                                       service=self)
        else:  # pragma: no cover
            session = self.session_obj(self.client_id,
                                       self.client_secret,
                                       service=self)
        return session

    def get_authorize_url(self, **params):
        '''
        Returns a formatted authorize URL.

        :param \*\*params: Additional keyworded arguments to be added to the
            URL querystring.
        :type \*\*params: dict
        '''

        params.update({'appid': self.client_id})
        return self.authorize_url + '?' + urlencode(params)

    def get_raw_access_token(self, method='GET', **kwargs):
        '''
        Returns a Requests' response over the
        :attr:`WechatAuthService.access_token_url`.

        Use this if your endpoint if you need the full `Response` object.

        :param method: A string representation of the HTTP method to be used,
            defaults to `GET`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        key = 'params'
        if method in ENTITY_METHODS:
            key = 'data'

        kwargs.setdefault(key, {})
        kwargs[key].update({'appid': self.client_id,
                            'secret': self.client_secret})

        session = self.get_session()
        self.access_token_response = session.request(method,
                                                     self.access_token_url,
                                                     **kwargs)
        return self.access_token_response

    def foo_decoder(self, d):
        return d

    def get_access_token(self,
                         method='GET',
                         decoder=foo_decoder,
                         key='access_token',
                         **kwargs):
        '''
        Returns an access token.

        :param method: A string representation of the HTTP method to be used,
            defaults to `GET`.
        :type method: str
        :param decoder: A function used to parse the Response content. Should
            return a dictionary.
        :type decoder: func
        :param key: The key the access token will be decoded by, defaults to
            'access_token'.
        :type string:
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        r = self.get_raw_access_token(method, **kwargs)
        from frappe import logger, local
        logger("frappe.web", allow_site=local.site).info({"content": r.content})
        parsed = r.json()
        logger("frappe.web", allow_site=local.site).info({"parsed-content": parsed})

        from json import loads
        access_token, openid = process_token_request(r, loads, key, "openid")
        return access_token, openid

    def get_auth_session(self, method='GET', **kwargs):
        '''
        Gets an access token, intializes a new authenticated session with the
        access token. Returns an instance of :attr:`session_obj`.

        :param method: A string representation of the HTTP method to be used,
            defaults to `GET`.
        :type method: str
        :param \*\*kwargs: Optional arguments. Same as Requests.
        :type \*\*kwargs: dict
        '''
        access_token, openid = self.get_access_token(method, **kwargs)
        session = self.get_session(access_token, openid)

        if self.access_token_response:
            session.access_token_response = self.access_token_response

        return session
