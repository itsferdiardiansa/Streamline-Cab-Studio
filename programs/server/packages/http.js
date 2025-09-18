(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var _ = Package.underscore._;
var URL = Package.url.URL;
var URLSearchParams = Package.url.URLSearchParams;

/* Package-scope variables */
var makeErrorByStatus, populateData, HTTP, HTTPInternals;

(function(){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// packages/http/httpcall_common.js                                                                                 //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
makeErrorByStatus = function(statusCode, content) {
  var MAX_LENGTH = 500; // if you change this, also change the appropriate test

  var truncate = function(str, length) {
    return str.length > length ? str.slice(0, length) + '...' : str;
  };

  var contentToCheck = typeof content == "string" ? content : content.toString();

  var message = "failed [" + statusCode + "]";

  if (contentToCheck) {
    message += " " + truncate(contentToCheck.replace(/\n/g, " "), MAX_LENGTH);
  }

  return new Error(message);
};


// Fill in `response.data` if the content-type is JSON.
populateData = function(response) {
  // Read Content-Type header, up to a ';' if there is one.
  // A typical header might be "application/json; charset=utf-8"
  // or just "application/json".
  var contentType = (response.headers['content-type'] || ';').split(';')[0];

  // Only try to parse data as JSON if server sets correct content type.
  if (_.include(['application/json', 'text/javascript',
      'application/javascript', 'application/x-javascript'], contentType)) {
    try {
      response.data = JSON.parse(response.content);
    } catch (err) {
      response.data = null;
    }
  } else {
    response.data = null;
  }
};

HTTP = {};

/**
 * @summary Send an HTTP `GET` request. Equivalent to calling [`HTTP.call`](#http_call) with "GET" as the first argument.
 * @param {String} url The URL to which the request should be sent.
 * @param {Object} [callOptions] Options passed on to [`HTTP.call`](#http_call).
 * @param {Function} [asyncCallback] Callback that is called when the request is completed. Required on the client.
 * @locus Anywhere
 */
HTTP.get = function (/* varargs */) {
  return HTTP.call.apply(this, ["GET"].concat(_.toArray(arguments)));
};

/**
 * @summary Send an HTTP `POST` request. Equivalent to calling [`HTTP.call`](#http_call) with "POST" as the first argument.
 * @param {String} url The URL to which the request should be sent.
 * @param {Object} [callOptions] Options passed on to [`HTTP.call`](#http_call).
 * @param {Function} [asyncCallback] Callback that is called when the request is completed. Required on the client.
 * @locus Anywhere
 */
HTTP.post = function (/* varargs */) {
  return HTTP.call.apply(this, ["POST"].concat(_.toArray(arguments)));
};

/**
 * @summary Send an HTTP `PUT` request. Equivalent to calling [`HTTP.call`](#http_call) with "PUT" as the first argument.
 * @param {String} url The URL to which the request should be sent.
 * @param {Object} [callOptions] Options passed on to [`HTTP.call`](#http_call).
 * @param {Function} [asyncCallback] Callback that is called when the request is completed. Required on the client.
 * @locus Anywhere
 */
HTTP.put = function (/* varargs */) {
  return HTTP.call.apply(this, ["PUT"].concat(_.toArray(arguments)));
};

/**
 * @summary Send an HTTP `DELETE` request. Equivalent to calling [`HTTP.call`](#http_call) with "DELETE" as the first argument. (Named `del` to avoid conflic with the Javascript keyword `delete`)
 * @param {String} url The URL to which the request should be sent.
 * @param {Object} [callOptions] Options passed on to [`HTTP.call`](#http_call).
 * @param {Function} [asyncCallback] Callback that is called when the request is completed. Required on the client.
 * @locus Anywhere
 */
HTTP.del = function (/* varargs */) {
  return HTTP.call.apply(this, ["DELETE"].concat(_.toArray(arguments)));
};

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function(){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// packages/http/httpcall_server.js                                                                                 //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
var path = Npm.require('path');
var request = Npm.require('request');
var url_util = Npm.require('url');

HTTPInternals = {
  NpmModules: {
    request: {
      version: Npm.require('request/package.json').version,
      module: request
    }
  }
};

// _call always runs asynchronously; HTTP.call, defined below,
// wraps _call and runs synchronously when no callback is provided.
var _call = function(method, url, options, callback) {

  ////////// Process arguments //////////

  if (! callback && typeof options === "function") {
    // support (method, url, callback) argument list
    callback = options;
    options = null;
  }

  options = options || {};

  if (_.has(options, 'beforeSend')) {
    throw new Error("Option beforeSend not supported on server.");
  }

  method = (method || "").toUpperCase();

  if (! /^https?:\/\//.test(url))
    throw new Error("url must be absolute and start with http:// or https://");

  var headers = {};

  var content = options.content;
  if (options.data) {
    content = JSON.stringify(options.data);
    headers['Content-Type'] = 'application/json';
  }


  var paramsForUrl, paramsForBody;
  if (content || method === "GET" || method === "HEAD")
    paramsForUrl = options.params;
  else
    paramsForBody = options.params;

  var newUrl = URL._constructUrl(url, options.query, paramsForUrl);

  if (options.auth) {
    if (options.auth.indexOf(':') < 0)
      throw new Error('auth option should be of the form "username:password"');
    headers['Authorization'] = "Basic "+
      (new Buffer(options.auth, "ascii")).toString("base64");
  }

  if (paramsForBody) {
    content = URL._encodeParams(paramsForBody);
    headers['Content-Type'] = "application/x-www-form-urlencoded";
  }

  _.extend(headers, options.headers || {});

  // wrap callback to add a 'response' property on an error, in case
  // we have both (http 4xx/5xx error, which has a response payload)
  callback = (function(callback) {
    return function(error, response) {
      if (error && response)
        error.response = response;
      callback(error, response);
    };
  })(callback);

  // safety belt: only call the callback once.
  callback = _.once(callback);


  ////////// Kickoff! //////////

  // Allow users to override any request option with the npmRequestOptions
  // option.
  var reqOptions = _.extend({
    url: newUrl,
    method: method,
    encoding: "utf8",
    jar: false,
    timeout: options.timeout,
    body: content,
    followRedirect: options.followRedirects,
    // Follow redirects on non-GET requests
    // also. (https://github.com/meteor/meteor/issues/2808)
    followAllRedirects: options.followRedirects,
    headers: headers
  }, options.npmRequestOptions || {});

  request(reqOptions, function(error, res, body) {
    var response = null;

    if (! error) {

      response = {};
      response.statusCode = res.statusCode;
      response.content = body;
      response.headers = res.headers;

      populateData(response);

      if (response.statusCode >= 400)
        error = makeErrorByStatus(response.statusCode, response.content);
    }

    callback(error, response);

  });
};

HTTP.call = Meteor.wrapAsync(_call);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);






(function(){

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                  //
// packages/http/deprecated.js                                                                                      //
//                                                                                                                  //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                    //
// The HTTP object used to be called Meteor.http.
// XXX COMPAT WITH 0.6.4
Meteor.http = HTTP;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}).call(this);


/* Exports */
Package._define("http", {
  HTTP: HTTP,
  HTTPInternals: HTTPInternals
});

})();
