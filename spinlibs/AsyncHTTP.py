#!/usr/bin/env python

# Copyright (c) 2015 Battlehouse Inc. All rights reserved.
# Use of this source code is governed by an MIT-style license that can be
# found in the LICENSE file.

import twisted.python.failure
import twisted.internet.defer
import twisted.internet.ssl
import twisted.internet.protocol
import twisted.internet.reactor
import twisted.web.iweb
import twisted.web.client
import twisted.web.http_headers
import twisted.web.error
from zope.interface import implements
import traceback
import time
import certifi
from collections import deque
from urllib import urlencode

# reduce log verbosity
twisted.internet.protocol.Factory.noisy = False

# compatibility shim for Twisted < 16.x
if hasattr(twisted.internet.ssl, 'trustRootFromCertificates'):
    trustRootFromCertificates = twisted.internet.ssl.trustRootFromCertificates
else:
    import twisted.internet._sslverify
    def trustRootFromCertificates(certificates):
        certs = []
        for cert in certificates:
            # PrivateCertificate or Certificate are both okay
            if isinstance(cert, twisted.internet._sslverify.CertBase):
                cert = cert.original
            else:
                raise TypeError(
                    "certificates items must be twisted.internet.ssl.CertBase"
                    " instances"
                    )
            certs.append(cert)
        return twisted.internet._sslverify.OpenSSLCertificateAuthorities(certs)

# helper that feeds an in-memory request body to twisted.web.client.Agent
class AgentBodySender(object):
    implements(twisted.web.iweb.IBodyProducer)
    def __init__(self, body):
        assert isinstance(body, bytes)
        self.body = body
        self.length = len(body)
    def startProducing(self, consumer):
        consumer.write(self.body)
        return twisted.internet.defer.succeed(None)
    def pauseProducing(self): pass
    def stopProducing(self): pass

# helper that accumulates an incoming response body from twisted.web.client.Agent
class AgentBodyReceiver(twisted.internet.protocol.Protocol):
    def __init__(self, deferred, status_code, status_phrase):
        self.d = deferred
        self.buf = bytes()
        # for HTTP errors, we need to remember the status during the body download,
        # so that we can call the errback with it plus the response body.
        self.status_code = status_code
        self.status_phrase = status_phrase
    def dataReceived(self, data):
        self.buf += data
    def connectionLost(self, reason):
        assert isinstance(reason, twisted.python.failure.Failure)
        # ResponseDone: this is the normal case
        # PotentialDataLoss: didn't get Content-Length, but return what we got anyway
        if isinstance(reason.value, twisted.web.client.ResponseDone) or \
           isinstance(reason.value, twisted.web.client.PotentialDataLoss):
            if self.status_code >= 200 and self.status_code <= 299:
                self.d.callback(self.buf)
            else:
                # fire errback for a non-normal status code
                self.d.errback(twisted.web.error.Error(self.status_code, message = self.status_phrase, response = self.buf))
        else:
            # a failure occurred
            self.d.errback(reason)

# helper that adapts a twisted.web.client.Agent response to the old HTTPClientFactory "getter" API
# which includes:
# .deferred, that calls back with the result body
# .status, the HTTP response code
# .response_headers, the headers in the form {key: [value0, value1, ...]}
#   * where "key" is lower-cased
class AgentAdaptor(object):
    def __init__(self, header_d):
        self.deferred = twisted.internet.defer.Deferred()
        self.status = 502 # dummy Bad Gateway status in case there is a failure before the real status comes back to us
        self.response_headers = {}
        header_d.addCallbacks(self.read_response, self.deferred.errback)
    def read_response(self, response):
        # note: lowercase the incoming header keys
        self.response_headers = dict((k.lower(), v) for k, v in response.headers.getAllRawHeaders())
        self.status = int(response.code) # note: this used to be a string
        recv = AgentBodyReceiver(self.deferred, self.status, response.phrase)
        response.deliverBody(recv)

# Twisted attempts to rely on the host OpenSSL's trust store, which doesn't work on OSX.
# Instead, manually read in the certifi trust store.
class AgentHTTPSPolicy(object):
    implements(twisted.web.iweb.IPolicyForHTTPS)
    def __init__(self):
        # read all CA certs supplied by certifi
        # this is a file located at certifi.where() with many certs concatenated together

        certs = []

        # use a little state machine to break them apart and load them individually
        cur_cert = None
        for line in open(certifi.where()).readlines():
            if line.startswith('-----BEGIN CERTIFICATE-----'):
                cur_cert = [line,]
            elif cur_cert is not None:
                cur_cert.append(line)
            if line.startswith('-----END CERTIFICATE-----'):
                the_cert = ''.join(cur_cert)
                certs.append(twisted.internet.ssl.Certificate.loadPEM(the_cert))
                cur_cert = None

        self.trust_root = trustRootFromCertificates(certs)

    def creatorForNetloc(self, hostname, post):
        return twisted.internet.ssl.optionsForClientTLS(unicode(hostname), trustRoot = self.trust_root)

agent_https_policy = AgentHTTPSPolicy()

class AsyncHTTPRequester(object):
    # there are two "modes" for the callbacks on a request:

    # callback receives one argument that is the response body (success)
    # or a stringified error message (failure)
    CALLBACK_BODY_ONLY = 'body_only'

    # callback receives keyword arguments {body:"asdf", headers:{"Content-Type":["image/jpeg"]}, status:200}
    # ** note that headers is multi-valued here ** (inconsistent with queue_request!)
    # and failure also gets ui_reason: "Some Exception Happened"
    CALLBACK_FULL = 'full'

    class Request:
        def __init__(self, qtime, method, url, headers, callback, error_callback, preflight_callback, postdata, max_tries, callback_type, accept_http_errors, user_agent):
            self.method = method
            self.url = url
            self.headers = headers # can be None, single-valued, or list-valued. Leaf values should be bytes.
            self.callback = callback
            self.error_callback = error_callback
            self.preflight_callback = preflight_callback
            self.callback_called = 0 # for debugging only
            self.postdata = postdata # can be None, or bytes, or a {string:string} dictionary, in which case we'll send it as www-form-urlencoded
            self.fire_time = qtime
            self.max_tries = max_tries
            self.callback_type = callback_type
            self.accept_http_errors = accept_http_errors
            self.user_agent = user_agent
            self.tries = 1
        def __hash__(self): return hash((self.url, self.method, self.fire_time, self.callback))
        def __repr__(self): return self.method + ' ' + self.url
        def get_stats(self):
            return {'method':self.method, 'url':self.url, 'time':self.fire_time, 'tries': self.tries, 'callback': self.callback_called}

        # "freeze" headers and postdata into the version we're going to submit to Twisted.
        # note that headers can be changed by the request's preflight callback, so we have to do this at the last moment before transmission.
        # returns (headers, postdata, list_of_warning_messages)
        def finalize_headers_and_postdata(self):
            final_headers = None
            final_postdata = None
            warnings = []

            if self.headers:
                assert isinstance(self.headers, dict)
                final_headers = {}
                for k, v in self.headers.iteritems():
                    k = bytes(k)
                    if not isinstance(v, list):
                        v = [v,]
                    for i in xrange(len(v)):
                        if not isinstance(v[i], bytes):
                            # uh-oh, a non-bytes value!
                            # not fatal, but the calling code should be fixed.
                            if isinstance(v[i], unicode):
                                warnings.append('value of HTTP header "%s" should be bytes, not unicode. Fixed it for you.' % k)
                                v[i] = v[i].encode('utf-8')
                            else:
                                raise Exception('non-string-valued HTTP header "%s": %r' % (k, type(v[i])))

                    final_headers[k] = v

            # twisted.web.client.Agent does not apply a User-Agent header automatically. Let's do that here.
            if self.user_agent:
                if not final_headers: final_headers = {}
                final_headers['User-Agent'] = [self.user_agent.encode('utf-8')]

            if self.postdata:
                if isinstance(self.postdata, dict):
                    # convert to form encoding
                    final_postdata = urlencode(self.postdata).encode('utf-8')
                    if final_headers is None:
                        final_headers = {}
                    final_headers['Content-Type'] = [b'application/x-www-form-urlencoded',]
                elif isinstance(self.postdata, bytes):
                    final_postdata = self.postdata
                else:
                    raise Exception('postdata must be dict or bytes, you sent %r' % type(self.postdata))

            return final_headers, final_postdata, warnings

    def __init__(self, concurrent_request_limit, total_request_limit, request_timeout, verbosity, log_exception_func,
                 max_tries = 1, retry_delay = 0, error_on_404 = True,
                 api = 'Agent', # use old 'HTTPClientFactory' or new 'Agent' API
                 user_agent = b'SpinPunch',
                 ):

        if api != 'Agent':
            raise Exception('only the Agent API is supported now')

        # reference to the server's global event Reactor
        self.reactor = twisted.internet.reactor

        # this semaphore limits the number of connections allowed concurrently
        # additional connection attempts are queued until previous ones finish
        if concurrent_request_limit > 0:
            self.semaphore = twisted.internet.defer.DeferredSemaphore(concurrent_request_limit)
        else:
            self.semaphore = None

        # requests that are not on the wire yet
        self.queue = deque()

        # requests on the wire that we are waiting to hear back on
        self.on_wire = set()

        # requests that are awaitng a requeue after failing
        self.waiting_for_retry = set()

        self.total_request_limit = total_request_limit
        self.request_timeout = request_timeout

        # disable overly verbose log messages
        self.verbosity = verbosity

        # only print request-setup warnings once, to avoid log spam
        self.warnings_seen = set()

        self.log_exception_func = log_exception_func
        self.default_max_tries = max_tries
        self.retry_delay = retry_delay
        self.error_on_404 = error_on_404
        self.api = api
        self.default_user_agent = user_agent

        # function to call when all outstanding requests have either succeeded or failed
        self.idle_cb = None

        self.n_dropped = 0
        self.n_accepted = 0
        self.n_fired = 0
        self.n_ok = 0
        self.n_errors = 0
        self.n_retries = 0

        # watchdog debug counters
        self.n_watchdog_created = 0
        self.n_watchdog_cancelled = 0
        self.n_watchdog_fired_late = 0
        self.n_watchdog_fired_real = 0
        self.n_watchdog_cancel_omitted = 0

    def num_on_wire(self): return len(self.on_wire)

    def call_when_idle(self, cb):
        assert not self.idle_cb
        self.idle_cb = cb
        # defer so that if we are in the shutdown path, we don't
        # prematurely shut down before other shutdown callbacks start their own I/O requests
        self.reactor.callLater(0, self.idlecheck)


    def idlecheck(self):
        if self.idle_cb and len(self.queue) == 0 and len(self.on_wire) == 0 and len(self.waiting_for_retry) == 0:
            cb = self.idle_cb
            self.idle_cb = None
            cb()

    # wrapper for queue_request that returns a Deferred
    def queue_request_deferred(self, qtime, url, method='GET', headers=None, postdata=None, preflight_callback=None, max_tries=None, callback_type = CALLBACK_BODY_ONLY, accept_http_errors = False, user_agent = None):
        d = twisted.internet.defer.Deferred()

        if callback_type == self.CALLBACK_BODY_ONLY:
            success_cb = d.callback
            error_cb = lambda err_reason, d=d: \
                       d.errback(twisted.python.failure.Failure(Exception('AsyncHTTP error: %r' % err_reason)))
        elif callback_type == self.CALLBACK_FULL:
            success_cb = lambda body=None, headers=None, status=None, d=d: d.callback((body, headers, status))
            error_cb = lambda ui_reason=None, body=None, headers=None, status=None, d=d: \
                       d.errback(twisted.python.failure.Failure(Exception('AsyncHTTP error: %r' % ui_reason)))

        self.queue_request(qtime, url, success_cb, method=method, headers=headers, postdata=postdata,
                           error_callback = error_cb,
                           preflight_callback=preflight_callback, max_tries=max_tries, callback_type=callback_type,
                           accept_http_errors=accept_http_errors,
                           user_agent=user_agent)
        return d

    def queue_request(self, qtime, url, user_callback, method='GET', headers=None, postdata=None, error_callback=None, preflight_callback=None, max_tries=None, callback_type = CALLBACK_BODY_ONLY, accept_http_errors = False, user_agent = None):
        if self.total_request_limit > 0 and len(self.queue) >= self.total_request_limit:
            self.log_exception_func('AsyncHTTPRequester queue is full, dropping request %s %s!' % (method,url))
            self.n_dropped += 1
            return

        self.n_accepted += 1

        if max_tries is None:
            max_tries = self.default_max_tries
        else:
            max_tries = max_tries # max(max_tries, self.default_max_tries)

        request = AsyncHTTPRequester.Request(qtime, method, url, headers, user_callback, error_callback, preflight_callback, postdata, max_tries, callback_type, accept_http_errors,
                                             user_agent or self.default_user_agent)

        self.queue.append(request)
        if self.verbosity >= 1:
            print 'AsyncHTTPRequester queueing request %s, %d now in queue' % (repr(request), len(self.queue))
        if self.semaphore:
            self.semaphore.run(self._send_request)
        else:
            self._send_request()

    def _send_request(self):
        request = self.queue.popleft()
        if request.preflight_callback: # allow caller to adjust headers/url/etc at the last minute before transmission
            request.preflight_callback(request)

        try:
            final_headers, final_postdata, warnings = request.finalize_headers_and_postdata()
        except Exception as e:
            self.log_exception_func('AsyncHTTP Request Setup Error: ' + traceback.format_exc())
            self.n_errors += 1
            request.callback_called = 2
            if request.error_callback:
                if request.callback_type == self.CALLBACK_FULL:
                    request.error_callback(ui_reason = repr(e), body = None, headers = {}, status = 500)
                else:
                    request.error_callback(repr(e))

            # for the semaphore only - allow it to release immediately
            return twisted.internet.defer.succeed(None)

        for w in warnings:
            if w not in self.warnings_seen:
                self.warnings_seen.add(w)
                self.log_exception_func('AsyncHTTP Request Setup Warning: ' + w + ' for ' + repr(request))

        self.n_fired += 1
        self.on_wire.add(request)
        if self.verbosity >= 1:
            print 'AsyncHTTPRequester opening connection %s, %d now in queue, %d now on wire' % (repr(request), len(self.queue), len(self.on_wire))

        getter = self.make_web_getter(request, bytes(request.url),
                                      method = bytes(request.method),
                                      headers= final_headers,
                                      user_agent = request.user_agent,
                                      timeout = self.request_timeout,
                                      postdata = final_postdata)
        d = getter.deferred
        assert not d.called
        d.addCallbacks(self.on_response, errback = self.on_error,
                       callbackArgs = (getter, request),
                       errbackArgs = (getter, request))
        return d

    def make_web_getter(self, *args, **kwargs):
        if self.api == 'Agent':
            return self.make_web_getter_Agent(*args, **kwargs)
        else:
            raise Exception('unknown api ' + self.api)

    # Add our own watchdog timer on top of the timeout we tell Twisted about.
    # Historically, Twisted had some bugs where hang-ups in certain phases of
    # HTTP requests (e.g. SSL negotiation) would not trigger its own timeout.
    # This is intended as a fallback to catch these cases.
    def apply_watchdog_to_getter(self, getter, request, timeout):
        if timeout is None or timeout < 0:
            return # do nothing

        assert not getter.deferred.called

        # track some metrics
        self.n_watchdog_created += 1

        # add slop time to allow Twisted's own timeout to fire first if it wants
        delay = timeout + 5 # seconds

        def watchdog_func(self, getter, request):
            if self.verbosity >= 1:
                self.log_exception_func('AsyncHTTP getter watchdog timeout at %r (deferred.called %r paused %r result %s) for %r' % \
                                        (time.time(), getter.deferred.called, getter.deferred.paused, repr(getter.deferred.result)[:500] if getter.deferred.called else '-', request.get_stats()))

            self.n_watchdog_fired_real += 1

            # abort the request and errback it with a failure, if it hasn't called back yet
            getter.deferred.cancel()

        watchdog = self.reactor.callLater(delay, watchdog_func, self, getter, request)

        # cancel the watchdog as soon as getter.deferred fires, regardless of whether it's a callback or errback
        def cancel_watchdog_and_continue(_, self, watchdog):
            if watchdog.active(): # we might be called downstream from the watchdog firing itself
                self.n_watchdog_cancelled += 1
                watchdog.cancel()
            else:
                self.n_watchdog_cancel_omitted += 1
            return _

        getter.deferred.addBoth(cancel_watchdog_and_continue, self, watchdog)
        return getter

    def make_web_getter_Agent(self, request, url, method = None, headers = None, user_agent = None, timeout = None, postdata = None):

        agent = twisted.web.client.Agent(self.reactor, contextFactory = agent_https_policy, connectTimeout = timeout)

        # compose a redirect handler (might want to make this optional, for security. FB portraits uses it.)
        agent = twisted.web.client.BrowserLikeRedirectAgent(agent)

        header_d = agent.request(method, url,
                                 # note: headers are list-valued, as frozen in 'list' mode
                                 headers = twisted.web.http_headers.Headers(headers) if headers else None,
                                 bodyProducer = AgentBodySender(postdata) if postdata else None)
        ret = AgentAdaptor(header_d)
        self.apply_watchdog_to_getter(ret, request, timeout)

        return ret

    def on_response(self, response, getter, request):
        self.n_ok += 1
        self.on_wire.remove(request)
        if self.verbosity >= 1:
            print 'AsyncHTTPRequester got response for', request
            if self.verbosity >= 3:
                print 'AsyncHTTPRequester response was:', 'status', getter.status, 'headers', getter.response_headers, 'body', repr(response[:100])
        try:
            request.callback_called = 1
            if request.callback_type == self.CALLBACK_FULL:
                request.callback(body = response, headers = getter.response_headers, status = getter.status)
            else:
                request.callback(response)
        except:
            self.log_exception_func('AsyncHTTP Exception: ' + traceback.format_exc())
        self.idlecheck()

    def retry(self, request):
        self.waiting_for_retry.remove(request)
        request.tries += 1
        self.n_retries += 1
        self.queue.append(request)
        if self.verbosity >= 1:
            print 'AsyncHTTPRequester retrying failed request %s, %d now in queue' % (repr(request), len(self.queue))
        if self.semaphore:
            self.semaphore.run(self._send_request)
        else:
            self._send_request()

    def on_error(self, reason, getter, request):
        # note: "reason" here is a twisted.python.failure.Failure object that wraps the exception that was thrown
        assert isinstance(reason, twisted.python.failure.Failure)

        # for HTTP errors, extract the HTTP status code
        if isinstance(reason.value, twisted.web.error.Error):
            http_code = int(reason.value.status) # note! "status" is returned as a string, not an integer!
            if http_code == 404 and (not self.error_on_404):
                # received a 404, but the client wants to treat it as success with buf = 'NOTFOUND'
                return self.on_response(b'NOTFOUND', getter, request)
            elif http_code == 204:
                # 204 is not actually an error, just an empty body
                return self.on_response(b'', getter, request)
            elif request.accept_http_errors:
                # pass through HTTP error responses without raising an exception
                return self.on_response(reason.value.response, getter, request)

        self.on_wire.remove(request)

        if request.tries < request.max_tries:
            # retry the request by putting it back on the queue
            self.waiting_for_retry.add(request)
            if self.retry_delay <= 0:
                self.retry(request)
            else:
                self.reactor.callLater(self.retry_delay, self.retry, request)
            return

        self.n_errors += 1

        if self.verbosity >= 0: # XXX maybe disable this if there's a reliable error_callback?
            # if reason.value is a twisted.web._newclient.WrapperException,
            # it includes a nested list of child Failures called "reasons".
            # we need to explicitly call getTraceback() on these in order to see what is going on.
            if hasattr(reason.value, 'reasons'):
                failure_list = reason.value.reasons
            else:
                failure_list = [reason,]
            ui_failure = '---'.join([f.getTraceback() for f in failure_list])
            self.log_exception_func('AsyncHTTPRequester error: ' + reason.getErrorMessage() + \
                                    '\n' + ui_failure + \
                                    ' for %s (after %d tries)' % (repr(request), request.tries))

        request.callback_called = 2
        if request.error_callback:
            try:
                # transform the Failure object to a human-readable string
                if isinstance(reason.value, twisted.web.error.Error):
                    # for HTTP errors, we want the status AND any explanatory response that came with it
                    # (since APIs like Facebook and S3 usually have useful info in the response body when returning errors)
                    ui_reason = 'twisted.web.error.Error(HTTP %s (%s): "%s")' % (reason.value.status, reason.value.message, reason.value.response)
                    body = reason.value.response
                else:
                    ui_reason = repr(reason.value)
                    body = None # things like TimeoutError have no .response attribute

                if request.callback_type == self.CALLBACK_FULL:
                    request.error_callback(ui_reason = ui_reason, body = body, headers = getter.response_headers,
                                           # first, note that getter.status is sometimes (always?) a string rather than a number
                                           # second, sometimes the getter fails before the request even gets to the server,
                                           # in which case it won't have a status attribute. Not sure on the best error code for
                                           # this but let's go with 502 Bad Gateway for now.
                                           status = int(getattr(getter, 'status', 502)))
                else:
                    request.error_callback(ui_reason)
            except:
                self.log_exception_func('AsyncHTTP Exception (error_callback): '+traceback.format_exc())

        self.idlecheck()

    # return JSON dictionary of usage statistics
    def get_stats(self, expose_info = True):
        queue = [x.get_stats() for x in self.queue] if expose_info else []
        on_wire = [x.get_stats() for x in self.on_wire] if expose_info else []
        waiting_for_retry = [x.get_stats() for x in self.waiting_for_retry] if expose_info else []
        return {'accepted':self.n_accepted,
                'dropped':self.n_dropped,

                'fired':self.n_fired,
                'retries':self.n_retries,

                'done_ok':self.n_ok,
                'done_error':self.n_errors,
                # all accepted requests should either be in flight, or end with OK/Error. Otherwise we're "leaking" requests.
                'missing': self.n_accepted - (self.n_ok + self.n_errors + len(self.queue) + len(self.on_wire)),

                # watchdog debug counters
                'watchdog_created': self.n_watchdog_created,
                'watchdog_cancelled': self.n_watchdog_cancelled,
                'watchdog_fired_late': self.n_watchdog_fired_late,
                'watchdog_fired_real': self.n_watchdog_fired_real,
                'watchdog_cancel_omitted': self.n_watchdog_cancel_omitted,

                'queue':queue, 'num_in_queue': len(self.queue),
                'on_wire':on_wire, 'num_on_wire': len(self.on_wire),
                'waiting_for_retry':waiting_for_retry, 'num_waiting_for_retry' : len(self.waiting_for_retry),
                }

    # merge together statistics from multiple AsyncHTTP instances (reduce)
    @staticmethod
    def merge_stats(statlist):
        ret = {}
        for stats in statlist:
            for key, val in stats.iteritems():
                if key in ('queue', 'on_wire', 'waiting_for_retry'):
                    ret[key] = ret.get(key,[]) + val
                else:
                    ret[key] = ret.get(key,0) + val
        return ret

    # convert JSON stats to HTML
    @staticmethod
    def stats_to_html(stats, cur_time, expose_info = True):
        ret = '<table border="1" cellspacing="0">'
        for key in ('accepted', 'dropped', 'fired', 'retries', 'done_ok', 'done_error', 'missing', 'num_on_wire','num_in_queue','num_waiting_for_retry', 'watchdog_created', 'watchdog_cancelled', 'watchdog_fired_late', 'watchdog_fired_real', 'watchdog_cancel_omitted'):
            val = str(stats[key])
            if key == 'missing' and stats[key] > 0:
                val = '<font color="#ff0000">'+val+'</font>'
            ret += '<tr><td>%s</td><td>%s</td></tr>' % (key, val)
        ret += '</table><p>'

        if expose_info:
            for key in ('queue', 'on_wire', 'waiting_for_retry'):
                ret += key+'<br>'
                ret += '<table border="1" cellspacing="1">'
                ret += '<tr><td>URL</td><td>AGE</td></tr>'
                for val in stats[key]:
                    url = val['method'] + ' ' + val['url']
                    age = '%.2f' % (cur_time - val['time'])
                    ret += '<tr><td>%s</td><td>%s</td></tr>' % (url, age)
                ret += '</table><p>'

        return ret

    def get_stats_html(self, cur_time, expose_info = True):
        return self.stats_to_html(self.get_stats(expose_info = expose_info), cur_time, expose_info = expose_info)


# TEST CODE

if __name__ == '__main__':
    import sys
    from twisted.python import log
    from twisted.internet import reactor

    log.startLogging(sys.stdout)
    req = AsyncHTTPRequester(2, 10, 10, 1, lambda x: log.msg(x), max_tries = 3, retry_delay = 1.0, api = 'Agent')
    server_time = int(time.time())
    req.queue_request(server_time, 'http://localhost:8000/clientcode/Predicates.js', lambda x: log.msg('RESPONSE A'))
    req.queue_request(server_time, 'http://localhost:8000/clientcode/SPay.js', lambda x: log.msg('RESPONSE B'))
    req.queue_request(server_time, 'http://localhost:8005/', lambda x: log.msg('RESPONSE C'))
    req.queue_request(server_time, 'http://localhost:8000/', lambda x: log.msg('RESPONSE D'))
    req.queue_request(server_time, 'http://localhost:8000/', lambda x: log.msg('RESPONSE D'), postdata = 'body data')
    req.queue_request(server_time, 'https://wrong.hostname.badssl.com/', lambda x: log.msg('RESPONSE D'))
    req.queue_request(server_time, 'https://www.battlehouse.com/feed/atom/', lambda x: log.msg('RESPONSE E'),
                      headers = {'X-AsyncHTTP-Test': 'foobar'})
    req.queue_request(server_time, 'https://s3-external-1.amazonaws.com/spinpunch-public/asdf', lambda x: log.msg('RESPONSE F %r' % x))

    req.queue_request(server_time, 'https://s3-external-1.amazonaws.com/spinpunch-scratch/hello2.txt',
                      lambda x: log.msg("PUT SUCCESSFUL %r" % x),
                      method = u'PUT',
                      headers = {'Date': 'Mon, 01 Jan 2018 11:08:38 GMT',
                                 'Content-Length': u'5',
                                 'Content-Type': 'text/plain',
                                 'Authorization': u'AWS abcdefg:hijklmnop'},
                      postdata = {'a':'bcd'})

    print req.get_stats_html(time.time())
    reactor.run()

    print req.get_stats()
