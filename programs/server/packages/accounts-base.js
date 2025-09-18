(function () {

/* Imports */
var Meteor = Package.meteor.Meteor;
var global = Package.meteor.global;
var meteorEnv = Package.meteor.meteorEnv;
var ECMAScript = Package.ecmascript.ECMAScript;
var DDPRateLimiter = Package['ddp-rate-limiter'].DDPRateLimiter;
var check = Package.check.check;
var Match = Package.check.Match;
var Random = Package.random.Random;
var EJSON = Package.ejson.EJSON;
var Hook = Package['callback-hook'].Hook;
var URL = Package.url.URL;
var URLSearchParams = Package.url.URLSearchParams;
var DDP = Package['ddp-client'].DDP;
var DDPServer = Package['ddp-server'].DDPServer;
var MongoInternals = Package.mongo.MongoInternals;
var Mongo = Package.mongo.Mongo;
var meteorInstall = Package.modules.meteorInstall;
var Promise = Package.promise.Promise;

/* Package-scope variables */
var Accounts, options, stampedLoginToken, handler, name, query, oldestValidDate, user;

var require = meteorInstall({"node_modules":{"meteor":{"accounts-base":{"server_main.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/accounts-base/server_main.js                                                                             //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
!function (module1) {
  module1.export({
    AccountsServer: () => AccountsServer
  });
  let AccountsServer;
  module1.link("./accounts_server.js", {
    AccountsServer(v) {
      AccountsServer = v;
    }

  }, 0);

  /**
   * @namespace Accounts
   * @summary The namespace for all server-side accounts-related methods.
   */
  Accounts = new AccountsServer(Meteor.server); // Users table. Don't use the normal autopublish, since we want to hide
  // some fields. Code to autopublish this is in accounts_server.js.
  // XXX Allow users to configure this collection name.

  /**
   * @summary A [Mongo.Collection](#collections) containing user documents.
   * @locus Anywhere
   * @type {Mongo.Collection}
   * @importFromPackage meteor
  */

  Meteor.users = Accounts.users;
}.call(this, module);
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"accounts_common.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/accounts-base/accounts_common.js                                                                         //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 0);
module.export({
  AccountsCommon: () => AccountsCommon,
  EXPIRE_TOKENS_INTERVAL_MS: () => EXPIRE_TOKENS_INTERVAL_MS,
  CONNECTION_CLOSE_DELAY_MS: () => CONNECTION_CLOSE_DELAY_MS
});
let Meteor;
module.link("meteor/meteor", {
  Meteor(v) {
    Meteor = v;
  }

}, 0);
// config option keys
const VALID_CONFIG_KEYS = ['sendVerificationEmail', 'forbidClientAccountCreation', 'passwordEnrollTokenExpiration', 'passwordEnrollTokenExpirationInDays', 'restrictCreationByEmailDomain', 'loginExpirationInDays', 'loginExpiration', 'passwordResetTokenExpirationInDays', 'passwordResetTokenExpiration', 'ambiguousErrorMessages', 'bcryptRounds', 'defaultFieldSelector', 'loginTokenExpirationHours', 'tokenSequenceLength'];
/**
 * @summary Super-constructor for AccountsClient and AccountsServer.
 * @locus Anywhere
 * @class AccountsCommon
 * @instancename accountsClientOrServer
 * @param options {Object} an object with fields:
 * - connection {Object} Optional DDP connection to reuse.
 * - ddpUrl {String} Optional URL for creating a new DDP connection.
 */

class AccountsCommon {
  constructor(options) {
    // Currently this is read directly by packages like accounts-password
    // and accounts-ui-unstyled.
    this._options = {}; // Note that setting this.connection = null causes this.users to be a
    // LocalCollection, which is not what we want.

    this.connection = undefined;

    this._initConnection(options || {}); // There is an allow call in accounts_server.js that restricts writes to
    // this collection.


    this.users = new Mongo.Collection('users', {
      _preventAutopublish: true,
      connection: this.connection
    }); // Callback exceptions are printed with Meteor._debug and ignored.

    this._onLoginHook = new Hook({
      bindEnvironment: false,
      debugPrintExceptions: 'onLogin callback'
    });
    this._onLoginFailureHook = new Hook({
      bindEnvironment: false,
      debugPrintExceptions: 'onLoginFailure callback'
    });
    this._onLogoutHook = new Hook({
      bindEnvironment: false,
      debugPrintExceptions: 'onLogout callback'
    }); // Expose for testing.

    this.DEFAULT_LOGIN_EXPIRATION_DAYS = DEFAULT_LOGIN_EXPIRATION_DAYS;
    this.LOGIN_UNEXPIRING_TOKEN_DAYS = LOGIN_UNEXPIRING_TOKEN_DAYS; // Thrown when the user cancels the login process (eg, closes an oauth
    // popup, declines retina scan, etc)

    const lceName = 'Accounts.LoginCancelledError';
    this.LoginCancelledError = Meteor.makeErrorType(lceName, function (description) {
      this.message = description;
    });
    this.LoginCancelledError.prototype.name = lceName; // This is used to transmit specific subclass errors over the wire. We
    // should come up with a more generic way to do this (eg, with some sort of
    // symbolic error code rather than a number).

    this.LoginCancelledError.numericError = 0x8acdc2f; // loginServiceConfiguration and ConfigError are maintained for backwards compatibility

    Meteor.startup(() => {
      var _Meteor$settings, _Meteor$settings$pack;

      const {
        ServiceConfiguration
      } = Package['service-configuration'];
      this.loginServiceConfiguration = ServiceConfiguration.configurations;
      this.ConfigError = ServiceConfiguration.ConfigError;
      const settings = (_Meteor$settings = Meteor.settings) === null || _Meteor$settings === void 0 ? void 0 : (_Meteor$settings$pack = _Meteor$settings.packages) === null || _Meteor$settings$pack === void 0 ? void 0 : _Meteor$settings$pack['accounts-base'];

      if (settings) {
        if (settings.oauthSecretKey) {
          if (!Package['oauth-encryption']) {
            throw new Error('The oauth-encryption package must be loaded to set oauthSecretKey');
          }

          Package['oauth-encryption'].OAuthEncryption.loadKey(settings.oauthSecretKey);
          delete settings.oauthSecretKey;
        } // Validate config options keys


        Object.keys(settings).forEach(key => {
          if (!VALID_CONFIG_KEYS.includes(key)) {
            // TODO Consider just logging a debug message instead to allow for additional keys in the settings here?
            throw new Meteor.Error("Accounts configuration: Invalid key: ".concat(key));
          } else {
            // set values in Accounts._options
            this._options[key] = settings[key];
          }
        });
      }
    });
  }
  /**
   * @summary Get the current user id, or `null` if no user is logged in. A reactive data source.
   * @locus Anywhere
   */


  userId() {
    throw new Error('userId method not implemented');
  } // merge the defaultFieldSelector with an existing options object


  _addDefaultFieldSelector() {
    let options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    // this will be the most common case for most people, so make it quick
    if (!this._options.defaultFieldSelector) return options; // if no field selector then just use defaultFieldSelector

    if (!options.fields) return _objectSpread(_objectSpread({}, options), {}, {
      fields: this._options.defaultFieldSelector
    }); // if empty field selector then the full user object is explicitly requested, so obey

    const keys = Object.keys(options.fields);
    if (!keys.length) return options; // if the requested fields are +ve then ignore defaultFieldSelector
    // assume they are all either +ve or -ve because Mongo doesn't like mixed

    if (!!options.fields[keys[0]]) return options; // The requested fields are -ve.
    // If the defaultFieldSelector is +ve then use requested fields, otherwise merge them

    const keys2 = Object.keys(this._options.defaultFieldSelector);
    return this._options.defaultFieldSelector[keys2[0]] ? options : _objectSpread(_objectSpread({}, options), {}, {
      fields: _objectSpread(_objectSpread({}, options.fields), this._options.defaultFieldSelector)
    });
  }
  /**
   * @summary Get the current user record, or `null` if no user is logged in. A reactive data source.
   * @locus Anywhere
   * @param {Object} [options]
   * @param {MongoFieldSpecifier} options.fields Dictionary of fields to return or exclude.
   */


  user(options) {
    const userId = this.userId();
    return userId ? this.users.findOne(userId, this._addDefaultFieldSelector(options)) : null;
  } // Set up config for the accounts system. Call this on both the client
  // and the server.
  //
  // Note that this method gets overridden on AccountsServer.prototype, but
  // the overriding method calls the overridden method.
  //
  // XXX we should add some enforcement that this is called on both the
  // client and the server. Otherwise, a user can
  // 'forbidClientAccountCreation' only on the client and while it looks
  // like their app is secure, the server will still accept createUser
  // calls. https://github.com/meteor/meteor/issues/828
  //
  // @param options {Object} an object with fields:
  // - sendVerificationEmail {Boolean}
  //     Send email address verification emails to new users created from
  //     client signups.
  // - forbidClientAccountCreation {Boolean}
  //     Do not allow clients to create accounts directly.
  // - restrictCreationByEmailDomain {Function or String}
  //     Require created users to have an email matching the function or
  //     having the string as domain.
  // - loginExpirationInDays {Number}
  //     Number of days since login until a user is logged out (login token
  //     expires).
  // - passwordResetTokenExpirationInDays {Number}
  //     Number of days since password reset token creation until the
  //     token cannt be used any longer (password reset token expires).
  // - ambiguousErrorMessages {Boolean}
  //     Return ambiguous error messages from login failures to prevent
  //     user enumeration.
  // - bcryptRounds {Number}
  //     Allows override of number of bcrypt rounds (aka work factor) used
  //     to store passwords.

  /**
   * @summary Set global accounts options. You can also set these in `Meteor.settings.packages.accounts` without the need to call this function.
   * @locus Anywhere
   * @param {Object} options
   * @param {Boolean} options.sendVerificationEmail New users with an email address will receive an address verification email.
   * @param {Boolean} options.forbidClientAccountCreation Calls to [`createUser`](#accounts_createuser) from the client will be rejected. In addition, if you are using [accounts-ui](#accountsui), the "Create account" link will not be available.
   * @param {String | Function} options.restrictCreationByEmailDomain If set to a string, only allows new users if the domain part of their email address matches the string. If set to a function, only allows new users if the function returns true.  The function is passed the full email address of the proposed new user.  Works with password-based sign-in and external services that expose email addresses (Google, Facebook, GitHub). All existing users still can log in after enabling this option. Example: `Accounts.config({ restrictCreationByEmailDomain: 'school.edu' })`.
   * @param {Number} options.loginExpirationInDays The number of days from when a user logs in until their token expires and they are logged out. Defaults to 90. Set to `null` to disable login expiration.
   * @param {Number} options.loginExpiration The number of milliseconds from when a user logs in until their token expires and they are logged out, for a more granular control. If `loginExpirationInDays` is set, it takes precedent.
   * @param {String} options.oauthSecretKey When using the `oauth-encryption` package, the 16 byte key using to encrypt sensitive account credentials in the database, encoded in base64.  This option may only be specified on the server.  See packages/oauth-encryption/README.md for details.
   * @param {Number} options.passwordResetTokenExpirationInDays The number of days from when a link to reset password is sent until token expires and user can't reset password with the link anymore. Defaults to 3.
   * @param {Number} options.passwordResetTokenExpiration The number of milliseconds from when a link to reset password is sent until token expires and user can't reset password with the link anymore. If `passwordResetTokenExpirationInDays` is set, it takes precedent.
   * @param {Number} options.passwordEnrollTokenExpirationInDays The number of days from when a link to set initial password is sent until token expires and user can't set password with the link anymore. Defaults to 30.
   * @param {Number} options.passwordEnrollTokenExpiration The number of milliseconds from when a link to set initial password is sent until token expires and user can't set password with the link anymore. If `passwordEnrollTokenExpirationInDays` is set, it takes precedent.
   * @param {Boolean} options.ambiguousErrorMessages Return ambiguous error messages from login failures to prevent user enumeration. Defaults to false.
   * @param {MongoFieldSpecifier} options.defaultFieldSelector To exclude by default large custom fields from `Meteor.user()` and `Meteor.findUserBy...()` functions when called without a field selector, and all `onLogin`, `onLoginFailure` and `onLogout` callbacks.  Example: `Accounts.config({ defaultFieldSelector: { myBigArray: 0 }})`. Beware when using this. If, for instance, you do not include `email` when excluding the fields, you can have problems with functions like `forgotPassword` that will break because they won't have the required data available. It's recommend that you always keep the fields `_id`, `username`, and `email`.
   * @param {Number} options.loginTokenExpirationHours When using the package `accounts-2fa`, use this to set the amount of time a token sent is valid. As it's just a number, you can use, for example, 0.5 to make the token valid for just half hour. The default is 1 hour.
   * @param {Number} options.tokenSequenceLength When using the package `accounts-2fa`, use this to the size of the token sequence generated. The default is 6.
   */


  config(options) {
    // We don't want users to accidentally only call Accounts.config on the
    // client, where some of the options will have partial effects (eg removing
    // the "create account" button from accounts-ui if forbidClientAccountCreation
    // is set, or redirecting Google login to a specific-domain page) without
    // having their full effects.
    if (Meteor.isServer) {
      __meteor_runtime_config__.accountsConfigCalled = true;
    } else if (!__meteor_runtime_config__.accountsConfigCalled) {
      // XXX would be nice to "crash" the client and replace the UI with an error
      // message, but there's no trivial way to do this.
      Meteor._debug('Accounts.config was called on the client but not on the ' + 'server; some configuration options may not take effect.');
    } // We need to validate the oauthSecretKey option at the time
    // Accounts.config is called. We also deliberately don't store the
    // oauthSecretKey in Accounts._options.


    if (Object.prototype.hasOwnProperty.call(options, 'oauthSecretKey')) {
      if (Meteor.isClient) {
        throw new Error('The oauthSecretKey option may only be specified on the server');
      }

      if (!Package['oauth-encryption']) {
        throw new Error('The oauth-encryption package must be loaded to set oauthSecretKey');
      }

      Package['oauth-encryption'].OAuthEncryption.loadKey(options.oauthSecretKey);
      options = _objectSpread({}, options);
      delete options.oauthSecretKey;
    } // Validate config options keys


    Object.keys(options).forEach(key => {
      if (!VALID_CONFIG_KEYS.includes(key)) {
        throw new Meteor.Error("Accounts.config: Invalid key: ".concat(key));
      }
    }); // set values in Accounts._options

    VALID_CONFIG_KEYS.forEach(key => {
      if (key in options) {
        if (key in this._options) {
          throw new Meteor.Error("Can't set `".concat(key, "` more than once"));
        }

        this._options[key] = options[key];
      }
    });
  }
  /**
   * @summary Register a callback to be called after a login attempt succeeds.
   * @locus Anywhere
   * @param {Function} func The callback to be called when login is successful.
   *                        The callback receives a single object that
   *                        holds login details. This object contains the login
   *                        result type (password, resume, etc.) on both the
   *                        client and server. `onLogin` callbacks registered
   *                        on the server also receive extra data, such
   *                        as user details, connection information, etc.
   */


  onLogin(func) {
    let ret = this._onLoginHook.register(func); // call the just registered callback if already logged in


    this._startupCallback(ret.callback);

    return ret;
  }
  /**
   * @summary Register a callback to be called after a login attempt fails.
   * @locus Anywhere
   * @param {Function} func The callback to be called after the login has failed.
   */


  onLoginFailure(func) {
    return this._onLoginFailureHook.register(func);
  }
  /**
   * @summary Register a callback to be called after a logout attempt succeeds.
   * @locus Anywhere
   * @param {Function} func The callback to be called when logout is successful.
   */


  onLogout(func) {
    return this._onLogoutHook.register(func);
  }

  _initConnection(options) {
    if (!Meteor.isClient) {
      return;
    } // The connection used by the Accounts system. This is the connection
    // that will get logged in by Meteor.login(), and this is the
    // connection whose login state will be reflected by Meteor.userId().
    //
    // It would be much preferable for this to be in accounts_client.js,
    // but it has to be here because it's needed to create the
    // Meteor.users collection.


    if (options.connection) {
      this.connection = options.connection;
    } else if (options.ddpUrl) {
      this.connection = DDP.connect(options.ddpUrl);
    } else if (typeof __meteor_runtime_config__ !== 'undefined' && __meteor_runtime_config__.ACCOUNTS_CONNECTION_URL) {
      // Temporary, internal hook to allow the server to point the client
      // to a different authentication server. This is for a very
      // particular use case that comes up when implementing a oauth
      // server. Unsupported and may go away at any point in time.
      //
      // We will eventually provide a general way to use account-base
      // against any DDP connection, not just one special one.
      this.connection = DDP.connect(__meteor_runtime_config__.ACCOUNTS_CONNECTION_URL);
    } else {
      this.connection = Meteor.connection;
    }
  }

  _getTokenLifetimeMs() {
    // When loginExpirationInDays is set to null, we'll use a really high
    // number of days (LOGIN_UNEXPIRABLE_TOKEN_DAYS) to simulate an
    // unexpiring token.
    const loginExpirationInDays = this._options.loginExpirationInDays === null ? LOGIN_UNEXPIRING_TOKEN_DAYS : this._options.loginExpirationInDays;
    return this._options.loginExpiration || (loginExpirationInDays || DEFAULT_LOGIN_EXPIRATION_DAYS) * 86400000;
  }

  _getPasswordResetTokenLifetimeMs() {
    return this._options.passwordResetTokenExpiration || (this._options.passwordResetTokenExpirationInDays || DEFAULT_PASSWORD_RESET_TOKEN_EXPIRATION_DAYS) * 86400000;
  }

  _getPasswordEnrollTokenLifetimeMs() {
    return this._options.passwordEnrollTokenExpiration || (this._options.passwordEnrollTokenExpirationInDays || DEFAULT_PASSWORD_ENROLL_TOKEN_EXPIRATION_DAYS) * 86400000;
  }

  _tokenExpiration(when) {
    // We pass when through the Date constructor for backwards compatibility;
    // `when` used to be a number.
    return new Date(new Date(when).getTime() + this._getTokenLifetimeMs());
  }

  _tokenExpiresSoon(when) {
    let minLifetimeMs = 0.1 * this._getTokenLifetimeMs();

    const minLifetimeCapMs = MIN_TOKEN_LIFETIME_CAP_SECS * 1000;

    if (minLifetimeMs > minLifetimeCapMs) {
      minLifetimeMs = minLifetimeCapMs;
    }

    return new Date() > new Date(when) - minLifetimeMs;
  } // No-op on the server, overridden on the client.


  _startupCallback(callback) {}

}

// Note that Accounts is defined separately in accounts_client.js and
// accounts_server.js.

/**
 * @summary Get the current user id, or `null` if no user is logged in. A reactive data source.
 * @locus Anywhere but publish functions
 * @importFromPackage meteor
 */
Meteor.userId = () => Accounts.userId();
/**
 * @summary Get the current user record, or `null` if no user is logged in. A reactive data source.
 * @locus Anywhere but publish functions
 * @importFromPackage meteor
 * @param {Object} [options]
 * @param {MongoFieldSpecifier} options.fields Dictionary of fields to return or exclude.
 */


Meteor.user = options => Accounts.user(options); // how long (in days) until a login token expires


const DEFAULT_LOGIN_EXPIRATION_DAYS = 90; // how long (in days) until reset password token expires

const DEFAULT_PASSWORD_RESET_TOKEN_EXPIRATION_DAYS = 3; // how long (in days) until enrol password token expires

const DEFAULT_PASSWORD_ENROLL_TOKEN_EXPIRATION_DAYS = 30; // Clients don't try to auto-login with a token that is going to expire within
// .1 * DEFAULT_LOGIN_EXPIRATION_DAYS, capped at MIN_TOKEN_LIFETIME_CAP_SECS.
// Tries to avoid abrupt disconnects from expiring tokens.

const MIN_TOKEN_LIFETIME_CAP_SECS = 3600; // one hour
// how often (in milliseconds) we check for expired tokens

const EXPIRE_TOKENS_INTERVAL_MS = 600 * 1000;
const CONNECTION_CLOSE_DELAY_MS = 10 * 1000;
// A large number of expiration days (approximately 100 years worth) that is
// used when creating unexpiring tokens.
const LOGIN_UNEXPIRING_TOKEN_DAYS = 365 * 100;
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

},"accounts_server.js":function module(require,exports,module){

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                                   //
// packages/accounts-base/accounts_server.js                                                                         //
//                                                                                                                   //
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
                                                                                                                     //
const _excluded = ["token"];

let _objectWithoutProperties;

module.link("@babel/runtime/helpers/objectWithoutProperties", {
  default(v) {
    _objectWithoutProperties = v;
  }

}, 0);

let _objectSpread;

module.link("@babel/runtime/helpers/objectSpread2", {
  default(v) {
    _objectSpread = v;
  }

}, 1);
module.export({
  AccountsServer: () => AccountsServer
});
let crypto;
module.link("crypto", {
  default(v) {
    crypto = v;
  }

}, 0);
let AccountsCommon, EXPIRE_TOKENS_INTERVAL_MS;
module.link("./accounts_common.js", {
  AccountsCommon(v) {
    AccountsCommon = v;
  },

  EXPIRE_TOKENS_INTERVAL_MS(v) {
    EXPIRE_TOKENS_INTERVAL_MS = v;
  }

}, 1);
let URL;
module.link("meteor/url", {
  URL(v) {
    URL = v;
  }

}, 2);
const hasOwn = Object.prototype.hasOwnProperty; // XXX maybe this belongs in the check package

const NonEmptyString = Match.Where(x => {
  check(x, String);
  return x.length > 0;
});
/**
 * @summary Constructor for the `Accounts` namespace on the server.
 * @locus Server
 * @class AccountsServer
 * @extends AccountsCommon
 * @instancename accountsServer
 * @param {Object} server A server object such as `Meteor.server`.
 */

class AccountsServer extends AccountsCommon {
  // Note that this constructor is less likely to be instantiated multiple
  // times than the `AccountsClient` constructor, because a single server
  // can provide only one set of methods.
  constructor(server) {
    var _this;

    super();
    _this = this;

    this.onCreateLoginToken = function (func) {
      if (this._onCreateLoginTokenHook) {
        throw new Error('Can only call onCreateLoginToken once');
      }

      this._onCreateLoginTokenHook = func;
    };

    this._selectorForFastCaseInsensitiveLookup = (fieldName, string) => {
      // Performance seems to improve up to 4 prefix characters
      const prefix = string.substring(0, Math.min(string.length, 4));
      const orClause = generateCasePermutationsForString(prefix).map(prefixPermutation => {
        const selector = {};
        selector[fieldName] = new RegExp("^".concat(Meteor._escapeRegExp(prefixPermutation)));
        return selector;
      });
      const caseInsensitiveClause = {};
      caseInsensitiveClause[fieldName] = new RegExp("^".concat(Meteor._escapeRegExp(string), "$"), 'i');
      return {
        $and: [{
          $or: orClause
        }, caseInsensitiveClause]
      };
    };

    this._findUserByQuery = (query, options) => {
      let user = null;

      if (query.id) {
        // default field selector is added within getUserById()
        user = Meteor.users.findOne(query.id, this._addDefaultFieldSelector(options));
      } else {
        options = this._addDefaultFieldSelector(options);
        let fieldName;
        let fieldValue;

        if (query.username) {
          fieldName = 'username';
          fieldValue = query.username;
        } else if (query.email) {
          fieldName = 'emails.address';
          fieldValue = query.email;
        } else {
          throw new Error("shouldn't happen (validation missed something)");
        }

        let selector = {};
        selector[fieldName] = fieldValue;
        user = Meteor.users.findOne(selector, options); // If user is not found, try a case insensitive lookup

        if (!user) {
          selector = this._selectorForFastCaseInsensitiveLookup(fieldName, fieldValue);
          const candidateUsers = Meteor.users.find(selector, options).fetch(); // No match if multiple candidates are found

          if (candidateUsers.length === 1) {
            user = candidateUsers[0];
          }
        }
      }

      return user;
    };

    this._handleError = function (msg) {
      let throwError = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;
      let errorCode = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 403;
      const error = new Meteor.Error(errorCode, _this._options.ambiguousErrorMessages ? "Something went wrong. Please check your credentials." : msg);

      if (throwError) {
        throw error;
      }

      return error;
    };

    this._userQueryValidator = Match.Where(user => {
      check(user, {
        id: Match.Optional(NonEmptyString),
        username: Match.Optional(NonEmptyString),
        email: Match.Optional(NonEmptyString)
      });
      if (Object.keys(user).length !== 1) throw new Match.Error("User property must have exactly one field");
      return true;
    });
    this._server = server || Meteor.server; // Set up the server's methods, as if by calling Meteor.methods.

    this._initServerMethods();

    this._initAccountDataHooks(); // If autopublish is on, publish these user fields. Login service
    // packages (eg accounts-google) add to these by calling
    // addAutopublishFields.  Notably, this isn't implemented with multiple
    // publishes since DDP only merges only across top-level fields, not
    // subfields (such as 'services.facebook.accessToken')


    this._autopublishFields = {
      loggedInUser: ['profile', 'username', 'emails'],
      otherUsers: ['profile', 'username']
    }; // use object to keep the reference when used in functions
    // where _defaultPublishFields is destructured into lexical scope
    // for publish callbacks that need `this`

    this._defaultPublishFields = {
      projection: {
        profile: 1,
        username: 1,
        emails: 1
      }
    };

    this._initServerPublications(); // connectionId -> {connection, loginToken}


    this._accountData = {}; // connection id -> observe handle for the login token that this connection is
    // currently associated with, or a number. The number indicates that we are in
    // the process of setting up the observe (using a number instead of a single
    // sentinel allows multiple attempts to set up the observe to identify which
    // one was theirs).

    this._userObservesForConnections = {};
    this._nextUserObserveNumber = 1; // for the number described above.
    // list of all registered handlers.

    this._loginHandlers = [];
    setupUsersCollection(this.users);
    setupDefaultLoginHandlers(this);
    setExpireTokensInterval(this);
    this._validateLoginHook = new Hook({
      bindEnvironment: false
    });
    this._validateNewUserHooks = [defaultValidateNewUserHook.bind(this)];

    this._deleteSavedTokensForAllUsersOnStartup();

    this._skipCaseInsensitiveChecksForTest = {};
    this.urls = {
      resetPassword: (token, extraParams) => this.buildEmailUrl("#/reset-password/".concat(token), extraParams),
      verifyEmail: (token, extraParams) => this.buildEmailUrl("#/verify-email/".concat(token), extraParams),
      loginToken: (selector, token, extraParams) => this.buildEmailUrl("/?loginToken=".concat(token, "&selector=").concat(selector), extraParams),
      enrollAccount: (token, extraParams) => this.buildEmailUrl("#/enroll-account/".concat(token), extraParams)
    };
    this.addDefaultRateLimit();

    this.buildEmailUrl = function (path) {
      let extraParams = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
      const url = new URL(Meteor.absoluteUrl(path));
      const params = Object.entries(extraParams);

      if (params.length > 0) {
        // Add additional parameters to the url
        for (const [key, value] of params) {
          url.searchParams.append(key, value);
        }
      }

      return url.toString();
    };
  } ///
  /// CURRENT USER
  ///
  // @override of "abstract" non-implementation in accounts_common.js


  userId() {
    // This function only works if called inside a method or a pubication.
    // Using any of the information from Meteor.user() in a method or
    // publish function will always use the value from when the function first
    // runs. This is likely not what the user expects. The way to make this work
    // in a method or publish function is to do Meteor.find(this.userId).observe
    // and recompute when the user record changes.
    const currentInvocation = DDP._CurrentMethodInvocation.get() || DDP._CurrentPublicationInvocation.get();

    if (!currentInvocation) throw new Error("Meteor.userId can only be invoked in method calls or publications.");
    return currentInvocation.userId;
  } ///
  /// LOGIN HOOKS
  ///

  /**
   * @summary Validate login attempts.
   * @locus Server
   * @param {Function} func Called whenever a login is attempted (either successful or unsuccessful).  A login can be aborted by returning a falsy value or throwing an exception.
   */


  validateLoginAttempt(func) {
    // Exceptions inside the hook callback are passed up to us.
    return this._validateLoginHook.register(func);
  }
  /**
   * @summary Set restrictions on new user creation.
   * @locus Server
   * @param {Function} func Called whenever a new user is created. Takes the new user object, and returns true to allow the creation or false to abort.
   */


  validateNewUser(func) {
    this._validateNewUserHooks.push(func);
  }
  /**
   * @summary Validate login from external service
   * @locus Server
   * @param {Function} func Called whenever login/user creation from external service is attempted. Login or user creation based on this login can be aborted by passing a falsy value or throwing an exception.
   */


  beforeExternalLogin(func) {
    if (this._beforeExternalLoginHook) {
      throw new Error("Can only call beforeExternalLogin once");
    }

    this._beforeExternalLoginHook = func;
  } ///
  /// CREATE USER HOOKS
  ///

  /**
   * @summary Customize login token creation.
   * @locus Server
   * @param {Function} func Called whenever a new token is created.
   * Return the sequence and the user object. Return true to keep sending the default email, or false to override the behavior.
   */


  /**
   * @summary Customize new user creation.
   * @locus Server
   * @param {Function} func Called whenever a new user is created. Return the new user object, or throw an `Error` to abort the creation.
   */
  onCreateUser(func) {
    if (this._onCreateUserHook) {
      throw new Error("Can only call onCreateUser once");
    }

    this._onCreateUserHook = func;
  }
  /**
   * @summary Customize oauth user profile updates
   * @locus Server
   * @param {Function} func Called whenever a user is logged in via oauth. Return the profile object to be merged, or throw an `Error` to abort the creation.
   */


  onExternalLogin(func) {
    if (this._onExternalLoginHook) {
      throw new Error("Can only call onExternalLogin once");
    }

    this._onExternalLoginHook = func;
  }
  /**
   * @summary Customize user selection on external logins
   * @locus Server
   * @param {Function} func Called whenever a user is logged in via oauth and a
   * user is not found with the service id. Return the user or undefined.
   */


  setAdditionalFindUserOnExternalLogin(func) {
    if (this._additionalFindUserOnExternalLogin) {
      throw new Error("Can only call setAdditionalFindUserOnExternalLogin once");
    }

    this._additionalFindUserOnExternalLogin = func;
  }

  _validateLogin(connection, attempt) {
    this._validateLoginHook.forEach(callback => {
      let ret;

      try {
        ret = callback(cloneAttemptWithConnection(connection, attempt));
      } catch (e) {
        attempt.allowed = false; // XXX this means the last thrown error overrides previous error
        // messages. Maybe this is surprising to users and we should make
        // overriding errors more explicit. (see
        // https://github.com/meteor/meteor/issues/1960)

        attempt.error = e;
        return true;
      }

      if (!ret) {
        attempt.allowed = false; // don't override a specific error provided by a previous
        // validator or the initial attempt (eg "incorrect password").

        if (!attempt.error) attempt.error = new Meteor.Error(403, "Login forbidden");
      }

      return true;
    });
  }

  _successfulLogin(connection, attempt) {
    this._onLoginHook.each(callback => {
      callback(cloneAttemptWithConnection(connection, attempt));
      return true;
    });
  }

  _failedLogin(connection, attempt) {
    this._onLoginFailureHook.each(callback => {
      callback(cloneAttemptWithConnection(connection, attempt));
      return true;
    });
  }

  _successfulLogout(connection, userId) {
    // don't fetch the user object unless there are some callbacks registered
    let user;

    this._onLogoutHook.each(callback => {
      if (!user && userId) user = this.users.findOne(userId, {
        fields: this._options.defaultFieldSelector
      });
      callback({
        user,
        connection
      });
      return true;
    });
  }

  ///
  /// LOGIN METHODS
  ///
  // Login methods return to the client an object containing these
  // fields when the user was logged in successfully:
  //
  //   id: userId
  //   token: *
  //   tokenExpires: *
  //
  // tokenExpires is optional and intends to provide a hint to the
  // client as to when the token will expire. If not provided, the
  // client will call Accounts._tokenExpiration, passing it the date
  // that it received the token.
  //
  // The login method will throw an error back to the client if the user
  // failed to log in.
  //
  //
  // Login handlers and service specific login methods such as
  // `createUser` internally return a `result` object containing these
  // fields:
  //
  //   type:
  //     optional string; the service name, overrides the handler
  //     default if present.
  //
  //   error:
  //     exception; if the user is not allowed to login, the reason why.
  //
  //   userId:
  //     string; the user id of the user attempting to login (if
  //     known), required for an allowed login.
  //
  //   options:
  //     optional object merged into the result returned by the login
  //     method; used by HAMK from SRP.
  //
  //   stampedLoginToken:
  //     optional object with `token` and `when` indicating the login
  //     token is already present in the database, returned by the
  //     "resume" login handler.
  //
  // For convenience, login methods can also throw an exception, which
  // is converted into an {error} result.  However, if the id of the
  // user attempting the login is known, a {userId, error} result should
  // be returned instead since the user id is not captured when an
  // exception is thrown.
  //
  // This internal `result` object is automatically converted into the
  // public {id, token, tokenExpires} object returned to the client.
  // Try a login method, converting thrown exceptions into an {error}
  // result.  The `type` argument is a default, inserted into the result
  // object if not explicitly returned.
  //
  // Log in a user on a connection.
  //
  // We use the method invocation to set the user id on the connection,
  // not the connection object directly. setUserId is tied to methods to
  // enforce clear ordering of method application (using wait methods on
  // the client, and a no setUserId after unblock restriction on the
  // server)
  //
  // The `stampedLoginToken` parameter is optional.  When present, it
  // indicates that the login token has already been inserted into the
  // database and doesn't need to be inserted again.  (It's used by the
  // "resume" login handler).
  _loginUser(methodInvocation, userId, stampedLoginToken) {
    if (!stampedLoginToken) {
      stampedLoginToken = this._generateStampedLoginToken();

      this._insertLoginToken(userId, stampedLoginToken);
    } // This order (and the avoidance of yields) is important to make
    // sure that when publish functions are rerun, they see a
    // consistent view of the world: the userId is set and matches
    // the login token on the connection (not that there is
    // currently a public API for reading the login token on a
    // connection).


    Meteor._noYieldsAllowed(() => this._setLoginToken(userId, methodInvocation.connection, this._hashLoginToken(stampedLoginToken.token)));

    methodInvocation.setUserId(userId);
    return {
      id: userId,
      token: stampedLoginToken.token,
      tokenExpires: this._tokenExpiration(stampedLoginToken.when)
    };
  }

  // After a login method has completed, call the login hooks.  Note
  // that `attemptLogin` is called for *all* login attempts, even ones
  // which aren't successful (such as an invalid password, etc).
  //
  // If the login is allowed and isn't aborted by a validate login hook
  // callback, log in the user.
  //
  _attemptLogin(methodInvocation, methodName, methodArgs, result) {
    if (!result) throw new Error("result is required"); // XXX A programming error in a login handler can lead to this occurring, and
    // then we don't call onLogin or onLoginFailure callbacks. Should
    // tryLoginMethod catch this case and turn it into an error?

    if (!result.userId && !result.error) throw new Error("A login method must specify a userId or an error");
    let user;
    if (result.userId) user = this.users.findOne(result.userId, {
      fields: this._options.defaultFieldSelector
    });
    const attempt = {
      type: result.type || "unknown",
      allowed: !!(result.userId && !result.error),
      methodName: methodName,
      methodArguments: Array.from(methodArgs)
    };

    if (result.error) {
      attempt.error = result.error;
    }

    if (user) {
      attempt.user = user;
    } // _validateLogin may mutate `attempt` by adding an error and changing allowed
    // to false, but that's the only change it can make (and the user's callbacks
    // only get a clone of `attempt`).


    this._validateLogin(methodInvocation.connection, attempt);

    if (attempt.allowed) {
      const ret = _objectSpread(_objectSpread({}, this._loginUser(methodInvocation, result.userId, result.stampedLoginToken)), result.options);

      ret.type = attempt.type;

      this._successfulLogin(methodInvocation.connection, attempt);

      return ret;
    } else {
      this._failedLogin(methodInvocation.connection, attempt);

      throw attempt.error;
    }
  }

  // All service specific login methods should go through this function.
  // Ensure that thrown exceptions are caught and that login hook
  // callbacks are still called.
  //
  _loginMethod(methodInvocation, methodName, methodArgs, type, fn) {
    return this._attemptLogin(methodInvocation, methodName, methodArgs, tryLoginMethod(type, fn));
  }

  // Report a login attempt failed outside the context of a normal login
  // method. This is for use in the case where there is a multi-step login
  // procedure (eg SRP based password login). If a method early in the
  // chain fails, it should call this function to report a failure. There
  // is no corresponding method for a successful login; methods that can
  // succeed at logging a user in should always be actual login methods
  // (using either Accounts._loginMethod or Accounts.registerLoginHandler).
  _reportLoginFailure(methodInvocation, methodName, methodArgs, result) {
    const attempt = {
      type: result.type || "unknown",
      allowed: false,
      error: result.error,
      methodName: methodName,
      methodArguments: Array.from(methodArgs)
    };

    if (result.userId) {
      attempt.user = this.users.findOne(result.userId, {
        fields: this._options.defaultFieldSelector
      });
    }

    this._validateLogin(methodInvocation.connection, attempt);

    this._failedLogin(methodInvocation.connection, attempt); // _validateLogin may mutate attempt to set a new error message. Return
    // the modified version.


    return attempt;
  }

  ///
  /// LOGIN HANDLERS
  ///
  // The main entry point for auth packages to hook in to login.
  //
  // A login handler is a login method which can return `undefined` to
  // indicate that the login request is not handled by this handler.
  //
  // @param name {String} Optional.  The service name, used by default
  // if a specific service name isn't returned in the result.
  //
  // @param handler {Function} A function that receives an options object
  // (as passed as an argument to the `login` method) and returns one of:
  // - `undefined`, meaning don't handle;
  // - a login method result object
  registerLoginHandler(name, handler) {
    if (!handler) {
      handler = name;
      name = null;
    }

    this._loginHandlers.push({
      name: name,
      handler: handler
    });
  }

  // Checks a user's credentials against all the registered login
  // handlers, and returns a login token if the credentials are valid. It
  // is like the login method, except that it doesn't set the logged-in
  // user on the connection. Throws a Meteor.Error if logging in fails,
  // including the case where none of the login handlers handled the login
  // request. Otherwise, returns {id: userId, token: *, tokenExpires: *}.
  //
  // For example, if you want to login with a plaintext password, `options` could be
  //   { user: { username: <username> }, password: <password> }, or
  //   { user: { email: <email> }, password: <password> }.
  // Try all of the registered login handlers until one of them doesn't
  // return `undefined`, meaning it handled this call to `login`. Return
  // that return value.
  _runLoginHandlers(methodInvocation, options) {
    for (let handler of this._loginHandlers) {
      const result = tryLoginMethod(handler.name, () => handler.handler.call(methodInvocation, options));

      if (result) {
        return result;
      }

      if (result !== undefined) {
        throw new Meteor.Error(400, "A login handler should return a result or undefined");
      }
    }

    return {
      type: null,
      error: new Meteor.Error(400, "Unrecognized options for login request")
    };
  }

  // Deletes the given loginToken from the database.
  //
  // For new-style hashed token, this will cause all connections
  // associated with the token to be closed.
  //
  // Any connections associated with old-style unhashed tokens will be
  // in the process of becoming associated with hashed tokens and then
  // they'll get closed.
  destroyToken(userId, loginToken) {
    this.users.update(userId, {
      $pull: {
        "services.resume.loginTokens": {
          $or: [{
            hashedToken: loginToken
          }, {
            token: loginToken
          }]
        }
      }
    });
  }

  _initServerMethods() {
    // The methods created in this function need to be created here so that
    // this variable is available in their scope.
    const accounts = this; // This object will be populated with methods and then passed to
    // accounts._server.methods further below.

    const methods = {}; // @returns {Object|null}
    //   If successful, returns {token: reconnectToken, id: userId}
    //   If unsuccessful (for example, if the user closed the oauth login popup),
    //     throws an error describing the reason

    methods.login = function (options) {
      // Login handlers should really also check whatever field they look at in
      // options, but we don't enforce it.
      check(options, Object);

      const result = accounts._runLoginHandlers(this, options);

      return accounts._attemptLogin(this, "login", arguments, result);
    };

    methods.logout = function () {
      const token = accounts._getLoginToken(this.connection.id);

      accounts._setLoginToken(this.userId, this.connection, null);

      if (token && this.userId) {
        accounts.destroyToken(this.userId, token);
      }

      accounts._successfulLogout(this.connection, this.userId);

      this.setUserId(null);
    }; // Generates a new login token with the same expiration as the
    // connection's current token and saves it to the database. Associates
    // the connection with this new token and returns it. Throws an error
    // if called on a connection that isn't logged in.
    //
    // @returns Object
    //   If successful, returns { token: <new token>, id: <user id>,
    //   tokenExpires: <expiration date> }.


    methods.getNewToken = function () {
      const user = accounts.users.findOne(this.userId, {
        fields: {
          "services.resume.loginTokens": 1
        }
      });

      if (!this.userId || !user) {
        throw new Meteor.Error("You are not logged in.");
      } // Be careful not to generate a new token that has a later
      // expiration than the curren token. Otherwise, a bad guy with a
      // stolen token could use this method to stop his stolen token from
      // ever expiring.


      const currentHashedToken = accounts._getLoginToken(this.connection.id);

      const currentStampedToken = user.services.resume.loginTokens.find(stampedToken => stampedToken.hashedToken === currentHashedToken);

      if (!currentStampedToken) {
        // safety belt: this should never happen
        throw new Meteor.Error("Invalid login token");
      }

      const newStampedToken = accounts._generateStampedLoginToken();

      newStampedToken.when = currentStampedToken.when;

      accounts._insertLoginToken(this.userId, newStampedToken);

      return accounts._loginUser(this, this.userId, newStampedToken);
    }; // Removes all tokens except the token associated with the current
    // connection. Throws an error if the connection is not logged
    // in. Returns nothing on success.


    methods.removeOtherTokens = function () {
      if (!this.userId) {
        throw new Meteor.Error("You are not logged in.");
      }

      const currentToken = accounts._getLoginToken(this.connection.id);

      accounts.users.update(this.userId, {
        $pull: {
          "services.resume.loginTokens": {
            hashedToken: {
              $ne: currentToken
            }
          }
        }
      });
    }; // Allow a one-time configuration for a login service. Modifications
    // to this collection are also allowed in insecure mode.


    methods.configureLoginService = options => {
      check(options, Match.ObjectIncluding({
        service: String
      })); // Don't let random users configure a service we haven't added yet (so
      // that when we do later add it, it's set up with their configuration
      // instead of ours).
      // XXX if service configuration is oauth-specific then this code should
      //     be in accounts-oauth; if it's not then the registry should be
      //     in this package

      if (!(accounts.oauth && accounts.oauth.serviceNames().includes(options.service))) {
        throw new Meteor.Error(403, "Service unknown");
      }

      const {
        ServiceConfiguration
      } = Package['service-configuration'];
      if (ServiceConfiguration.configurations.findOne({
        service: options.service
      })) throw new Meteor.Error(403, "Service ".concat(options.service, " already configured"));
      if (hasOwn.call(options, 'secret') && usingOAuthEncryption()) options.secret = OAuthEncryption.seal(options.secret);
      ServiceConfiguration.configurations.insert(options);
    };

    accounts._server.methods(methods);
  }

  _initAccountDataHooks() {
    this._server.onConnection(connection => {
      this._accountData[connection.id] = {
        connection: connection
      };
      connection.onClose(() => {
        this._removeTokenFromConnection(connection.id);

        delete this._accountData[connection.id];
      });
    });
  }

  _initServerPublications() {
    // Bring into lexical scope for publish callbacks that need `this`
    const {
      users,
      _autopublishFields,
      _defaultPublishFields
    } = this; // Publish all login service configuration fields other than secret.

    this._server.publish("meteor.loginServiceConfiguration", () => {
      const {
        ServiceConfiguration
      } = Package['service-configuration'];
      return ServiceConfiguration.configurations.find({}, {
        fields: {
          secret: 0
        }
      });
    }, {
      is_auto: true
    }); // not technically autopublish, but stops the warning.
    // Use Meteor.startup to give other packages a chance to call
    // setDefaultPublishFields.


    Meteor.startup(() => {
      // Merge custom fields selector and default publish fields so that the client
      // gets all the necessary fields to run properly
      const customFields = this._addDefaultFieldSelector().fields || {};
      const keys = Object.keys(customFields); // If the custom fields are negative, then ignore them and only send the necessary fields

      const fields = keys.length > 0 && customFields[keys[0]] ? _objectSpread(_objectSpread({}, this._addDefaultFieldSelector().fields), _defaultPublishFields.projection) : _defaultPublishFields.projection; // Publish the current user's record to the client.

      this._server.publish(null, function () {
        if (this.userId) {
          return users.find({
            _id: this.userId
          }, {
            fields
          });
        } else {
          return null;
        }
      },
      /*suppress autopublish warning*/
      {
        is_auto: true
      });
    }); // Use Meteor.startup to give other packages a chance to call
    // addAutopublishFields.

    Package.autopublish && Meteor.startup(() => {
      // ['profile', 'username'] -> {profile: 1, username: 1}
      const toFieldSelector = fields => fields.reduce((prev, field) => _objectSpread(_objectSpread({}, prev), {}, {
        [field]: 1
      }), {});

      this._server.publish(null, function () {
        if (this.userId) {
          return users.find({
            _id: this.userId
          }, {
            fields: toFieldSelector(_autopublishFields.loggedInUser)
          });
        } else {
          return null;
        }
      },
      /*suppress autopublish warning*/
      {
        is_auto: true
      }); // XXX this publish is neither dedup-able nor is it optimized by our special
      // treatment of queries on a specific _id. Therefore this will have O(n^2)
      // run-time performance every time a user document is changed (eg someone
      // logging in). If this is a problem, we can instead write a manual publish
      // function which filters out fields based on 'this.userId'.


      this._server.publish(null, function () {
        const selector = this.userId ? {
          _id: {
            $ne: this.userId
          }
        } : {};
        return users.find(selector, {
          fields: toFieldSelector(_autopublishFields.otherUsers)
        });
      },
      /*suppress autopublish warning*/
      {
        is_auto: true
      });
    });
  }

  // Add to the list of fields or subfields to be automatically
  // published if autopublish is on. Must be called from top-level
  // code (ie, before Meteor.startup hooks run).
  //
  // @param opts {Object} with:
  //   - forLoggedInUser {Array} Array of fields published to the logged-in user
  //   - forOtherUsers {Array} Array of fields published to users that aren't logged in
  addAutopublishFields(opts) {
    this._autopublishFields.loggedInUser.push.apply(this._autopublishFields.loggedInUser, opts.forLoggedInUser);

    this._autopublishFields.otherUsers.push.apply(this._autopublishFields.otherUsers, opts.forOtherUsers);
  }

  // Replaces the fields to be automatically
  // published when the user logs in
  //
  // @param {MongoFieldSpecifier} fields Dictionary of fields to return or exclude.
  setDefaultPublishFields(fields) {
    this._defaultPublishFields.projection = fields;
  }

  ///
  /// ACCOUNT DATA
  ///
  // HACK: This is used by 'meteor-accounts' to get the loginToken for a
  // connection. Maybe there should be a public way to do that.
  _getAccountData(connectionId, field) {
    const data = this._accountData[connectionId];
    return data && data[field];
  }

  _setAccountData(connectionId, field, value) {
    const data = this._accountData[connectionId]; // safety belt. shouldn't happen. accountData is set in onConnection,
    // we don't have a connectionId until it is set.

    if (!data) return;
    if (value === undefined) delete data[field];else data[field] = value;
  }

  ///
  /// RECONNECT TOKENS
  ///
  /// support reconnecting using a meteor login token
  _hashLoginToken(loginToken) {
    const hash = crypto.createHash('sha256');
    hash.update(loginToken);
    return hash.digest('base64');
  }

  // {token, when} => {hashedToken, when}
  _hashStampedToken(stampedToken) {
    const {
      token
    } = stampedToken,
          hashedStampedToken = _objectWithoutProperties(stampedToken, _excluded);

    return _objectSpread(_objectSpread({}, hashedStampedToken), {}, {
      hashedToken: this._hashLoginToken(token)
    });
  }

  // Using $addToSet avoids getting an index error if another client
  // logging in simultaneously has already inserted the new hashed
  // token.
  _insertHashedLoginToken(userId, hashedToken, query) {
    query = query ? _objectSpread({}, query) : {};
    query._id = userId;
    this.users.update(query, {
      $addToSet: {
        "services.resume.loginTokens": hashedToken
      }
    });
  }

  // Exported for tests.
  _insertLoginToken(userId, stampedToken, query) {
    this._insertHashedLoginToken(userId, this._hashStampedToken(stampedToken), query);
  }

  _clearAllLoginTokens(userId) {
    this.users.update(userId, {
      $set: {
        'services.resume.loginTokens': []
      }
    });
  }

  // test hook
  _getUserObserve(connectionId) {
    return this._userObservesForConnections[connectionId];
  }

  // Clean up this connection's association with the token: that is, stop
  // the observe that we started when we associated the connection with
  // this token.
  _removeTokenFromConnection(connectionId) {
    if (hasOwn.call(this._userObservesForConnections, connectionId)) {
      const observe = this._userObservesForConnections[connectionId];

      if (typeof observe === 'number') {
        // We're in the process of setting up an observe for this connection. We
        // can't clean up that observe yet, but if we delete the placeholder for
        // this connection, then the observe will get cleaned up as soon as it has
        // been set up.
        delete this._userObservesForConnections[connectionId];
      } else {
        delete this._userObservesForConnections[connectionId];
        observe.stop();
      }
    }
  }

  _getLoginToken(connectionId) {
    return this._getAccountData(connectionId, 'loginToken');
  }

  // newToken is a hashed token.
  _setLoginToken(userId, connection, newToken) {
    this._removeTokenFromConnection(connection.id);

    this._setAccountData(connection.id, 'loginToken', newToken);

    if (newToken) {
      // Set up an observe for this token. If the token goes away, we need
      // to close the connection.  We defer the observe because there's
      // no need for it to be on the critical path for login; we just need
      // to ensure that the connection will get closed at some point if
      // the token gets deleted.
      //
      // Initially, we set the observe for this connection to a number; this
      // signifies to other code (which might run while we yield) that we are in
      // the process of setting up an observe for this connection. Once the
      // observe is ready to go, we replace the number with the real observe
      // handle (unless the placeholder has been deleted or replaced by a
      // different placehold number, signifying that the connection was closed
      // already -- in this case we just clean up the observe that we started).
      const myObserveNumber = ++this._nextUserObserveNumber;
      this._userObservesForConnections[connection.id] = myObserveNumber;
      Meteor.defer(() => {
        // If something else happened on this connection in the meantime (it got
        // closed, or another call to _setLoginToken happened), just do
        // nothing. We don't need to start an observe for an old connection or old
        // token.
        if (this._userObservesForConnections[connection.id] !== myObserveNumber) {
          return;
        }

        let foundMatchingUser; // Because we upgrade unhashed login tokens to hashed tokens at
        // login time, sessions will only be logged in with a hashed
        // token. Thus we only need to observe hashed tokens here.

        const observe = this.users.find({
          _id: userId,
          'services.resume.loginTokens.hashedToken': newToken
        }, {
          fields: {
            _id: 1
          }
        }).observeChanges({
          added: () => {
            foundMatchingUser = true;
          },
          removed: connection.close // The onClose callback for the connection takes care of
          // cleaning up the observe handle and any other state we have
          // lying around.

        }, {
          nonMutatingCallbacks: true
        }); // If the user ran another login or logout command we were waiting for the
        // defer or added to fire (ie, another call to _setLoginToken occurred),
        // then we let the later one win (start an observe, etc) and just stop our
        // observe now.
        //
        // Similarly, if the connection was already closed, then the onClose
        // callback would have called _removeTokenFromConnection and there won't
        // be an entry in _userObservesForConnections. We can stop the observe.

        if (this._userObservesForConnections[connection.id] !== myObserveNumber) {
          observe.stop();
          return;
        }

        this._userObservesForConnections[connection.id] = observe;

        if (!foundMatchingUser) {
          // We've set up an observe on the user associated with `newToken`,
          // so if the new token is removed from the database, we'll close
          // the connection. But the token might have already been deleted
          // before we set up the observe, which wouldn't have closed the
          // connection because the observe wasn't running yet.
          connection.close();
        }
      });
    }
  }

  // (Also used by Meteor Accounts server and tests).
  //
  _generateStampedLoginToken() {
    return {
      token: Random.secret(),
      when: new Date()
    };
  }

  ///
  /// TOKEN EXPIRATION
  ///
  // Deletes expired password reset tokens from the database.
  //
  // Exported for tests. Also, the arguments are only used by
  // tests. oldestValidDate is simulate expiring tokens without waiting
  // for them to actually expire. userId is used by tests to only expire
  // tokens for the test user.
  _expirePasswordResetTokens(oldestValidDate, userId) {
    const tokenLifetimeMs = this._getPasswordResetTokenLifetimeMs(); // when calling from a test with extra arguments, you must specify both!


    if (oldestValidDate && !userId || !oldestValidDate && userId) {
      throw new Error("Bad test. Must specify both oldestValidDate and userId.");
    }

    oldestValidDate = oldestValidDate || new Date(new Date() - tokenLifetimeMs);
    const tokenFilter = {
      $or: [{
        "services.password.reset.reason": "reset"
      }, {
        "services.password.reset.reason": {
          $exists: false
        }
      }]
    };
    expirePasswordToken(this, oldestValidDate, tokenFilter, userId);
  } // Deletes expired password enroll tokens from the database.
  //
  // Exported for tests. Also, the arguments are only used by
  // tests. oldestValidDate is simulate expiring tokens without waiting
  // for them to actually expire. userId is used by tests to only expire
  // tokens for the test user.


  _expirePasswordEnrollTokens(oldestValidDate, userId) {
    const tokenLifetimeMs = this._getPasswordEnrollTokenLifetimeMs(); // when calling from a test with extra arguments, you must specify both!


    if (oldestValidDate && !userId || !oldestValidDate && userId) {
      throw new Error("Bad test. Must specify both oldestValidDate and userId.");
    }

    oldestValidDate = oldestValidDate || new Date(new Date() - tokenLifetimeMs);
    const tokenFilter = {
      "services.password.enroll.reason": "enroll"
    };
    expirePasswordToken(this, oldestValidDate, tokenFilter, userId);
  } // Deletes expired tokens from the database and closes all open connections
  // associated with these tokens.
  //
  // Exported for tests. Also, the arguments are only used by
  // tests. oldestValidDate is simulate expiring tokens without waiting
  // for them to actually expire. userId is used by tests to only expire
  // tokens for the test user.


  _expireTokens(oldestValidDate, userId) {
    const tokenLifetimeMs = this._getTokenLifetimeMs(); // when calling from a test with extra arguments, you must specify both!


    if (oldestValidDate && !userId || !oldestValidDate && userId) {
      throw new Error("Bad test. Must specify both oldestValidDate and userId.");
    }

    oldestValidDate = oldestValidDate || new Date(new Date() - tokenLifetimeMs);
    const userFilter = userId ? {
      _id: userId
    } : {}; // Backwards compatible with older versions of meteor that stored login token
    // timestamps as numbers.

    this.users.update(_objectSpread(_objectSpread({}, userFilter), {}, {
      $or: [{
        "services.resume.loginTokens.when": {
          $lt: oldestValidDate
        }
      }, {
        "services.resume.loginTokens.when": {
          $lt: +oldestValidDate
        }
      }]
    }), {
      $pull: {
        "services.resume.loginTokens": {
          $or: [{
            when: {
              $lt: oldestValidDate
            }
          }, {
            when: {
              $lt: +oldestValidDate
            }
          }]
        }
      }
    }, {
      multi: true
    }); // The observe on Meteor.users will take care of closing connections for
    // expired tokens.
  }

  // @override from accounts_common.js
  config(options) {
    // Call the overridden implementation of the method.
    const superResult = AccountsCommon.prototype.config.apply(this, arguments); // If the user set loginExpirationInDays to null, then we need to clear the
    // timer that periodically expires tokens.

    if (hasOwn.call(this._options, 'loginExpirationInDays') && this._options.loginExpirationInDays === null && this.expireTokenInterval) {
      Meteor.clearInterval(this.expireTokenInterval);
      this.expireTokenInterval = null;
    }

    return superResult;
  }

  // Called by accounts-password
  insertUserDoc(options, user) {
    // - clone user document, to protect from modification
    // - add createdAt timestamp
    // - prepare an _id, so that you can modify other collections (eg
    // create a first task for every new user)
    //
    // XXX If the onCreateUser or validateNewUser hooks fail, we might
    // end up having modified some other collection
    // inappropriately. The solution is probably to have onCreateUser
    // accept two callbacks - one that gets called before inserting
    // the user document (in which you can modify its contents), and
    // one that gets called after (in which you should change other
    // collections)
    user = _objectSpread({
      createdAt: new Date(),
      _id: Random.id()
    }, user);

    if (user.services) {
      Object.keys(user.services).forEach(service => pinEncryptedFieldsToUser(user.services[service], user._id));
    }

    let fullUser;

    if (this._onCreateUserHook) {
      fullUser = this._onCreateUserHook(options, user); // This is *not* part of the API. We need this because we can't isolate
      // the global server environment between tests, meaning we can't test
      // both having a create user hook set and not having one set.

      if (fullUser === 'TEST DEFAULT HOOK') fullUser = defaultCreateUserHook(options, user);
    } else {
      fullUser = defaultCreateUserHook(options, user);
    }

    this._validateNewUserHooks.forEach(hook => {
      if (!hook(fullUser)) throw new Meteor.Error(403, "User validation failed");
    });

    let userId;

    try {
      userId = this.users.insert(fullUser);
    } catch (e) {
      // XXX string parsing sucks, maybe
      // https://jira.mongodb.org/browse/SERVER-3069 will get fixed one day
      // https://jira.mongodb.org/browse/SERVER-4637
      if (!e.errmsg) throw e;
      if (e.errmsg.includes('emails.address')) throw new Meteor.Error(403, "Email already exists.");
      if (e.errmsg.includes('username')) throw new Meteor.Error(403, "Username already exists.");
      throw e;
    }

    return userId;
  }

  // Helper function: returns false if email does not match company domain from
  // the configuration.
  _testEmailDomain(email) {
    const domain = this._options.restrictCreationByEmailDomain;
    return !domain || typeof domain === 'function' && domain(email) || typeof domain === 'string' && new RegExp("@".concat(Meteor._escapeRegExp(domain), "$"), 'i').test(email);
  }

  ///
  /// CLEAN UP FOR `logoutOtherClients`
  ///
  _deleteSavedTokensForUser(userId, tokensToDelete) {
    if (tokensToDelete) {
      this.users.update(userId, {
        $unset: {
          "services.resume.haveLoginTokensToDelete": 1,
          "services.resume.loginTokensToDelete": 1
        },
        $pullAll: {
          "services.resume.loginTokens": tokensToDelete
        }
      });
    }
  }

  _deleteSavedTokensForAllUsersOnStartup() {
    // If we find users who have saved tokens to delete on startup, delete
    // them now. It's possible that the server could have crashed and come
    // back up before new tokens are found in localStorage, but this
    // shouldn't happen very often. We shouldn't put a delay here because
    // that would give a lot of power to an attacker with a stolen login
    // token and the ability to crash the server.
    Meteor.startup(() => {
      this.users.find({
        "services.resume.haveLoginTokensToDelete": true
      }, {
        fields: {
          "services.resume.loginTokensToDelete": 1
        }
      }).forEach(user => {
        this._deleteSavedTokensForUser(user._id, user.services.resume.loginTokensToDelete);
      });
    });
  }

  ///
  /// MANAGING USER OBJECTS
  ///
  // Updates or creates a user after we authenticate with a 3rd party.
  //
  // @param serviceName {String} Service name (eg, twitter).
  // @param serviceData {Object} Data to store in the user's record
  //        under services[serviceName]. Must include an "id" field
  //        which is a unique identifier for the user in the service.
  // @param options {Object, optional} Other options to pass to insertUserDoc
  //        (eg, profile)
  // @returns {Object} Object with token and id keys, like the result
  //        of the "login" method.
  //
  updateOrCreateUserFromExternalService(serviceName, serviceData, options) {
    options = _objectSpread({}, options);

    if (serviceName === "password" || serviceName === "resume") {
      throw new Error("Can't use updateOrCreateUserFromExternalService with internal service " + serviceName);
    }

    if (!hasOwn.call(serviceData, 'id')) {
      throw new Error("Service data for service ".concat(serviceName, " must include id"));
    } // Look for a user with the appropriate service user id.


    const selector = {};
    const serviceIdKey = "services.".concat(serviceName, ".id"); // XXX Temporary special case for Twitter. (Issue #629)
    //   The serviceData.id will be a string representation of an integer.
    //   We want it to match either a stored string or int representation.
    //   This is to cater to earlier versions of Meteor storing twitter
    //   user IDs in number form, and recent versions storing them as strings.
    //   This can be removed once migration technology is in place, and twitter
    //   users stored with integer IDs have been migrated to string IDs.

    if (serviceName === "twitter" && !isNaN(serviceData.id)) {
      selector["$or"] = [{}, {}];
      selector["$or"][0][serviceIdKey] = serviceData.id;
      selector["$or"][1][serviceIdKey] = parseInt(serviceData.id, 10);
    } else {
      selector[serviceIdKey] = serviceData.id;
    }

    let user = this.users.findOne(selector, {
      fields: this._options.defaultFieldSelector
    }); // Check to see if the developer has a custom way to find the user outside
    // of the general selectors above.

    if (!user && this._additionalFindUserOnExternalLogin) {
      user = this._additionalFindUserOnExternalLogin({
        serviceName,
        serviceData,
        options
      });
    } // Before continuing, run user hook to see if we should continue


    if (this._beforeExternalLoginHook && !this._beforeExternalLoginHook(serviceName, serviceData, user)) {
      throw new Meteor.Error(403, "Login forbidden");
    } // When creating a new user we pass through all options. When updating an
    // existing user, by default we only process/pass through the serviceData
    // (eg, so that we keep an unexpired access token and don't cache old email
    // addresses in serviceData.email). The onExternalLogin hook can be used when
    // creating or updating a user, to modify or pass through more options as
    // needed.


    let opts = user ? {} : options;

    if (this._onExternalLoginHook) {
      opts = this._onExternalLoginHook(options, user);
    }

    if (user) {
      pinEncryptedFieldsToUser(serviceData, user._id);
      let setAttrs = {};
      Object.keys(serviceData).forEach(key => setAttrs["services.".concat(serviceName, ".").concat(key)] = serviceData[key]); // XXX Maybe we should re-use the selector above and notice if the update
      //     touches nothing?

      setAttrs = _objectSpread(_objectSpread({}, setAttrs), opts);
      this.users.update(user._id, {
        $set: setAttrs
      });
      return {
        type: serviceName,
        userId: user._id
      };
    } else {
      // Create a new user with the service data.
      user = {
        services: {}
      };
      user.services[serviceName] = serviceData;
      return {
        type: serviceName,
        userId: this.insertUserDoc(opts, user)
      };
    }
  }

  // Removes default rate limiting rule
  removeDefaultRateLimit() {
    const resp = DDPRateLimiter.removeRule(this.defaultRateLimiterRuleId);
    this.defaultRateLimiterRuleId = null;
    return resp;
  }

  // Add a default rule of limiting logins, creating new users and password reset
  // to 5 times every 10 seconds per connection.
  addDefaultRateLimit() {
    if (!this.defaultRateLimiterRuleId) {
      this.defaultRateLimiterRuleId = DDPRateLimiter.addRule({
        userId: null,
        clientAddress: null,
        type: 'method',
        name: name => ['login', 'createUser', 'resetPassword', 'forgotPassword'].includes(name),
        connectionId: connectionId => true
      }, 5, 10000);
    }
  }

  /**
   * @summary Creates options for email sending for reset password and enroll account emails.
   * You can use this function when customizing a reset password or enroll account email sending.
   * @locus Server
   * @param {Object} email Which address of the user's to send the email to.
   * @param {Object} user The user object to generate options for.
   * @param {String} url URL to which user is directed to confirm the email.
   * @param {String} reason `resetPassword` or `enrollAccount`.
   * @returns {Object} Options which can be passed to `Email.send`.
   * @importFromPackage accounts-base
   */
  generateOptionsForEmail(email, user, url, reason) {
    let extra = arguments.length > 4 && arguments[4] !== undefined ? arguments[4] : {};
    const options = {
      to: email,
      from: this.emailTemplates[reason].from ? this.emailTemplates[reason].from(user) : this.emailTemplates.from,
      subject: this.emailTemplates[reason].subject(user, url, extra)
    };

    if (typeof this.emailTemplates[reason].text === 'function') {
      options.text = this.emailTemplates[reason].text(user, url, extra);
    }

    if (typeof this.emailTemplates[reason].html === 'function') {
      options.html = this.emailTemplates[reason].html(user, url, extra);
    }

    if (typeof this.emailTemplates.headers === 'object') {
      options.headers = this.emailTemplates.headers;
    }

    return options;
  }

  _checkForCaseInsensitiveDuplicates(fieldName, displayName, fieldValue, ownUserId) {
    // Some tests need the ability to add users with the same case insensitive
    // value, hence the _skipCaseInsensitiveChecksForTest check
    const skipCheck = Object.prototype.hasOwnProperty.call(this._skipCaseInsensitiveChecksForTest, fieldValue);

    if (fieldValue && !skipCheck) {
      const matchedUsers = Meteor.users.find(this._selectorForFastCaseInsensitiveLookup(fieldName, fieldValue), {
        fields: {
          _id: 1
        },
        // we only need a maximum of 2 users for the logic below to work
        limit: 2
      }).fetch();

      if (matchedUsers.length > 0 && ( // If we don't have a userId yet, any match we find is a duplicate
      !ownUserId || // Otherwise, check to see if there are multiple matches or a match
      // that is not us
      matchedUsers.length > 1 || matchedUsers[0]._id !== ownUserId)) {
        this._handleError("".concat(displayName, " already exists."));
      }
    }
  }

  _createUserCheckingDuplicates(_ref) {
    let {
      user,
      email,
      username,
      options
    } = _ref;

    const newUser = _objectSpread(_objectSpread(_objectSpread({}, user), username ? {
      username
    } : {}), email ? {
      emails: [{
        address: email,
        verified: false
      }]
    } : {}); // Perform a case insensitive check before insert


    this._checkForCaseInsensitiveDuplicates('username', 'Username', username);

    this._checkForCaseInsensitiveDuplicates('emails.address', 'Email', email);

    const userId = this.insertUserDoc(options, newUser); // Perform another check after insert, in case a matching user has been
    // inserted in the meantime

    try {
      this._checkForCaseInsensitiveDuplicates('username', 'Username', username, userId);

      this._checkForCaseInsensitiveDuplicates('emails.address', 'Email', email, userId);
    } catch (ex) {
      // Remove inserted user if the check fails
      Meteor.users.remove(userId);
      throw ex;
    }

    return userId;
  }

}

// Give each login hook callback a fresh cloned copy of the attempt
// object, but don't clone the connection.
//
const cloneAttemptWithConnection = (connection, attempt) => {
  const clonedAttempt = EJSON.clone(attempt);
  clonedAttempt.connection = connection;
  return clonedAttempt;
};

const tryLoginMethod = (type, fn) => {
  let result;

  try {
    result = fn();
  } catch (e) {
    result = {
      error: e
    };
  }

  if (result && !result.type && type) result.type = type;
  return result;
};

const setupDefaultLoginHandlers = accounts => {
  accounts.registerLoginHandler("resume", function (options) {
    return defaultResumeLoginHandler.call(this, accounts, options);
  });
}; // Login handler for resume tokens.


const defaultResumeLoginHandler = (accounts, options) => {
  if (!options.resume) return undefined;
  check(options.resume, String);

  const hashedToken = accounts._hashLoginToken(options.resume); // First look for just the new-style hashed login token, to avoid
  // sending the unhashed token to the database in a query if we don't
  // need to.


  let user = accounts.users.findOne({
    "services.resume.loginTokens.hashedToken": hashedToken
  }, {
    fields: {
      "services.resume.loginTokens.$": 1
    }
  });

  if (!user) {
    // If we didn't find the hashed login token, try also looking for
    // the old-style unhashed token.  But we need to look for either
    // the old-style token OR the new-style token, because another
    // client connection logging in simultaneously might have already
    // converted the token.
    user = accounts.users.findOne({
      $or: [{
        "services.resume.loginTokens.hashedToken": hashedToken
      }, {
        "services.resume.loginTokens.token": options.resume
      }]
    }, // Note: Cannot use ...loginTokens.$ positional operator with $or query.
    {
      fields: {
        "services.resume.loginTokens": 1
      }
    });
  }

  if (!user) return {
    error: new Meteor.Error(403, "You've been logged out by the server. Please log in again.")
  }; // Find the token, which will either be an object with fields
  // {hashedToken, when} for a hashed token or {token, when} for an
  // unhashed token.

  let oldUnhashedStyleToken;
  let token = user.services.resume.loginTokens.find(token => token.hashedToken === hashedToken);

  if (token) {
    oldUnhashedStyleToken = false;
  } else {
    token = user.services.resume.loginTokens.find(token => token.token === options.resume);
    oldUnhashedStyleToken = true;
  }

  const tokenExpires = accounts._tokenExpiration(token.when);

  if (new Date() >= tokenExpires) return {
    userId: user._id,
    error: new Meteor.Error(403, "Your session has expired. Please log in again.")
  }; // Update to a hashed token when an unhashed token is encountered.

  if (oldUnhashedStyleToken) {
    // Only add the new hashed token if the old unhashed token still
    // exists (this avoids resurrecting the token if it was deleted
    // after we read it).  Using $addToSet avoids getting an index
    // error if another client logging in simultaneously has already
    // inserted the new hashed token.
    accounts.users.update({
      _id: user._id,
      "services.resume.loginTokens.token": options.resume
    }, {
      $addToSet: {
        "services.resume.loginTokens": {
          "hashedToken": hashedToken,
          "when": token.when
        }
      }
    }); // Remove the old token *after* adding the new, since otherwise
    // another client trying to login between our removing the old and
    // adding the new wouldn't find a token to login with.

    accounts.users.update(user._id, {
      $pull: {
        "services.resume.loginTokens": {
          "token": options.resume
        }
      }
    });
  }

  return {
    userId: user._id,
    stampedLoginToken: {
      token: options.resume,
      when: token.when
    }
  };
};

const expirePasswordToken = (accounts, oldestValidDate, tokenFilter, userId) => {
  // boolean value used to determine if this method was called from enroll account workflow
  let isEnroll = false;
  const userFilter = userId ? {
    _id: userId
  } : {}; // check if this method was called from enroll account workflow

  if (tokenFilter['services.password.enroll.reason']) {
    isEnroll = true;
  }

  let resetRangeOr = {
    $or: [{
      "services.password.reset.when": {
        $lt: oldestValidDate
      }
    }, {
      "services.password.reset.when": {
        $lt: +oldestValidDate
      }
    }]
  };

  if (isEnroll) {
    resetRangeOr = {
      $or: [{
        "services.password.enroll.when": {
          $lt: oldestValidDate
        }
      }, {
        "services.password.enroll.when": {
          $lt: +oldestValidDate
        }
      }]
    };
  }

  const expireFilter = {
    $and: [tokenFilter, resetRangeOr]
  };

  if (isEnroll) {
    accounts.users.update(_objectSpread(_objectSpread({}, userFilter), expireFilter), {
      $unset: {
        "services.password.enroll": ""
      }
    }, {
      multi: true
    });
  } else {
    accounts.users.update(_objectSpread(_objectSpread({}, userFilter), expireFilter), {
      $unset: {
        "services.password.reset": ""
      }
    }, {
      multi: true
    });
  }
};

const setExpireTokensInterval = accounts => {
  accounts.expireTokenInterval = Meteor.setInterval(() => {
    accounts._expireTokens();

    accounts._expirePasswordResetTokens();

    accounts._expirePasswordEnrollTokens();
  }, EXPIRE_TOKENS_INTERVAL_MS);
}; ///
/// OAuth Encryption Support
///


const OAuthEncryption = Package["oauth-encryption"] && Package["oauth-encryption"].OAuthEncryption;

const usingOAuthEncryption = () => {
  return OAuthEncryption && OAuthEncryption.keyIsLoaded();
}; // OAuth service data is temporarily stored in the pending credentials
// collection during the oauth authentication process.  Sensitive data
// such as access tokens are encrypted without the user id because
// we don't know the user id yet.  We re-encrypt these fields with the
// user id included when storing the service data permanently in
// the users collection.
//


const pinEncryptedFieldsToUser = (serviceData, userId) => {
  Object.keys(serviceData).forEach(key => {
    let value = serviceData[key];
    if (OAuthEncryption && OAuthEncryption.isSealed(value)) value = OAuthEncryption.seal(OAuthEncryption.open(value), userId);
    serviceData[key] = value;
  });
}; // Encrypt unencrypted login service secrets when oauth-encryption is
// added.
//
// XXX For the oauthSecretKey to be available here at startup, the
// developer must call Accounts.config({oauthSecretKey: ...}) at load
// time, instead of in a Meteor.startup block, because the startup
// block in the app code will run after this accounts-base startup
// block.  Perhaps we need a post-startup callback?


Meteor.startup(() => {
  if (!usingOAuthEncryption()) {
    return;
  }

  const {
    ServiceConfiguration
  } = Package['service-configuration'];
  ServiceConfiguration.configurations.find({
    $and: [{
      secret: {
        $exists: true
      }
    }, {
      "secret.algorithm": {
        $exists: false
      }
    }]
  }).forEach(config => {
    ServiceConfiguration.configurations.update(config._id, {
      $set: {
        secret: OAuthEncryption.seal(config.secret)
      }
    });
  });
}); // XXX see comment on Accounts.createUser in passwords_server about adding a
// second "server options" argument.

const defaultCreateUserHook = (options, user) => {
  if (options.profile) user.profile = options.profile;
  return user;
}; // Validate new user's email or Google/Facebook/GitHub account's email


function defaultValidateNewUserHook(user) {
  const domain = this._options.restrictCreationByEmailDomain;

  if (!domain) {
    return true;
  }

  let emailIsGood = false;

  if (user.emails && user.emails.length > 0) {
    emailIsGood = user.emails.reduce((prev, email) => prev || this._testEmailDomain(email.address), false);
  } else if (user.services && Object.values(user.services).length > 0) {
    // Find any email of any service and check it
    emailIsGood = Object.values(user.services).reduce((prev, service) => service.email && this._testEmailDomain(service.email), false);
  }

  if (emailIsGood) {
    return true;
  }

  if (typeof domain === 'string') {
    throw new Meteor.Error(403, "@".concat(domain, " email required"));
  } else {
    throw new Meteor.Error(403, "Email doesn't match the criteria.");
  }
}

const setupUsersCollection = users => {
  ///
  /// RESTRICTING WRITES TO USER OBJECTS
  ///
  users.allow({
    // clients can modify the profile field of their own document, and
    // nothing else.
    update: (userId, user, fields, modifier) => {
      // make sure it is our record
      if (user._id !== userId) {
        return false;
      } // user can only modify the 'profile' field. sets to multiple
      // sub-keys (eg profile.foo and profile.bar) are merged into entry
      // in the fields list.


      if (fields.length !== 1 || fields[0] !== 'profile') {
        return false;
      }

      return true;
    },
    fetch: ['_id'] // we only look at _id.

  }); /// DEFAULT INDEXES ON USERS

  users.createIndex('username', {
    unique: true,
    sparse: true
  });
  users.createIndex('emails.address', {
    unique: true,
    sparse: true
  });
  users.createIndex('services.resume.loginTokens.hashedToken', {
    unique: true,
    sparse: true
  });
  users.createIndex('services.resume.loginTokens.token', {
    unique: true,
    sparse: true
  }); // For taking care of logoutOtherClients calls that crashed before the
  // tokens were deleted.

  users.createIndex('services.resume.haveLoginTokensToDelete', {
    sparse: true
  }); // For expiring login tokens

  users.createIndex("services.resume.loginTokens.when", {
    sparse: true
  }); // For expiring password tokens

  users.createIndex('services.password.reset.when', {
    sparse: true
  });
  users.createIndex('services.password.enroll.when', {
    sparse: true
  });
}; // Generates permutations of all case variations of a given string.


const generateCasePermutationsForString = string => {
  let permutations = [''];

  for (let i = 0; i < string.length; i++) {
    const ch = string.charAt(i);
    permutations = [].concat(...permutations.map(prefix => {
      const lowerCaseChar = ch.toLowerCase();
      const upperCaseChar = ch.toUpperCase(); // Don't add unnecessary permutations when ch is not a letter

      if (lowerCaseChar === upperCaseChar) {
        return [prefix + ch];
      } else {
        return [prefix + lowerCaseChar, prefix + upperCaseChar];
      }
    }));
  }

  return permutations;
};
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

}}}}},{
  "extensions": [
    ".js",
    ".json"
  ]
});

var exports = require("/node_modules/meteor/accounts-base/server_main.js");

/* Exports */
Package._define("accounts-base", exports, {
  Accounts: Accounts
});

})();

//# sourceURL=meteor://💻app/packages/accounts-base.js
//# sourceMappingURL=data:application/json;charset=utf8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtYmFzZS9zZXJ2ZXJfbWFpbi5qcyIsIm1ldGVvcjovL/CfkrthcHAvcGFja2FnZXMvYWNjb3VudHMtYmFzZS9hY2NvdW50c19jb21tb24uanMiLCJtZXRlb3I6Ly/wn5K7YXBwL3BhY2thZ2VzL2FjY291bnRzLWJhc2UvYWNjb3VudHNfc2VydmVyLmpzIl0sIm5hbWVzIjpbIm1vZHVsZTEiLCJleHBvcnQiLCJBY2NvdW50c1NlcnZlciIsImxpbmsiLCJ2IiwiQWNjb3VudHMiLCJNZXRlb3IiLCJzZXJ2ZXIiLCJ1c2VycyIsIl9vYmplY3RTcHJlYWQiLCJtb2R1bGUiLCJkZWZhdWx0IiwiQWNjb3VudHNDb21tb24iLCJFWFBJUkVfVE9LRU5TX0lOVEVSVkFMX01TIiwiQ09OTkVDVElPTl9DTE9TRV9ERUxBWV9NUyIsIlZBTElEX0NPTkZJR19LRVlTIiwiY29uc3RydWN0b3IiLCJvcHRpb25zIiwiX29wdGlvbnMiLCJjb25uZWN0aW9uIiwidW5kZWZpbmVkIiwiX2luaXRDb25uZWN0aW9uIiwiTW9uZ28iLCJDb2xsZWN0aW9uIiwiX3ByZXZlbnRBdXRvcHVibGlzaCIsIl9vbkxvZ2luSG9vayIsIkhvb2siLCJiaW5kRW52aXJvbm1lbnQiLCJkZWJ1Z1ByaW50RXhjZXB0aW9ucyIsIl9vbkxvZ2luRmFpbHVyZUhvb2siLCJfb25Mb2dvdXRIb29rIiwiREVGQVVMVF9MT0dJTl9FWFBJUkFUSU9OX0RBWVMiLCJMT0dJTl9VTkVYUElSSU5HX1RPS0VOX0RBWVMiLCJsY2VOYW1lIiwiTG9naW5DYW5jZWxsZWRFcnJvciIsIm1ha2VFcnJvclR5cGUiLCJkZXNjcmlwdGlvbiIsIm1lc3NhZ2UiLCJwcm90b3R5cGUiLCJuYW1lIiwibnVtZXJpY0Vycm9yIiwic3RhcnR1cCIsIlNlcnZpY2VDb25maWd1cmF0aW9uIiwiUGFja2FnZSIsImxvZ2luU2VydmljZUNvbmZpZ3VyYXRpb24iLCJjb25maWd1cmF0aW9ucyIsIkNvbmZpZ0Vycm9yIiwic2V0dGluZ3MiLCJwYWNrYWdlcyIsIm9hdXRoU2VjcmV0S2V5IiwiRXJyb3IiLCJPQXV0aEVuY3J5cHRpb24iLCJsb2FkS2V5IiwiT2JqZWN0Iiwia2V5cyIsImZvckVhY2giLCJrZXkiLCJpbmNsdWRlcyIsInVzZXJJZCIsIl9hZGREZWZhdWx0RmllbGRTZWxlY3RvciIsImRlZmF1bHRGaWVsZFNlbGVjdG9yIiwiZmllbGRzIiwibGVuZ3RoIiwia2V5czIiLCJ1c2VyIiwiZmluZE9uZSIsImNvbmZpZyIsImlzU2VydmVyIiwiX19tZXRlb3JfcnVudGltZV9jb25maWdfXyIsImFjY291bnRzQ29uZmlnQ2FsbGVkIiwiX2RlYnVnIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwiaXNDbGllbnQiLCJvbkxvZ2luIiwiZnVuYyIsInJldCIsInJlZ2lzdGVyIiwiX3N0YXJ0dXBDYWxsYmFjayIsImNhbGxiYWNrIiwib25Mb2dpbkZhaWx1cmUiLCJvbkxvZ291dCIsImRkcFVybCIsIkREUCIsImNvbm5lY3QiLCJBQ0NPVU5UU19DT05ORUNUSU9OX1VSTCIsIl9nZXRUb2tlbkxpZmV0aW1lTXMiLCJsb2dpbkV4cGlyYXRpb25JbkRheXMiLCJsb2dpbkV4cGlyYXRpb24iLCJfZ2V0UGFzc3dvcmRSZXNldFRva2VuTGlmZXRpbWVNcyIsInBhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb24iLCJwYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uSW5EYXlzIiwiREVGQVVMVF9QQVNTV09SRF9SRVNFVF9UT0tFTl9FWFBJUkFUSU9OX0RBWVMiLCJfZ2V0UGFzc3dvcmRFbnJvbGxUb2tlbkxpZmV0aW1lTXMiLCJwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbiIsInBhc3N3b3JkRW5yb2xsVG9rZW5FeHBpcmF0aW9uSW5EYXlzIiwiREVGQVVMVF9QQVNTV09SRF9FTlJPTExfVE9LRU5fRVhQSVJBVElPTl9EQVlTIiwiX3Rva2VuRXhwaXJhdGlvbiIsIndoZW4iLCJEYXRlIiwiZ2V0VGltZSIsIl90b2tlbkV4cGlyZXNTb29uIiwibWluTGlmZXRpbWVNcyIsIm1pbkxpZmV0aW1lQ2FwTXMiLCJNSU5fVE9LRU5fTElGRVRJTUVfQ0FQX1NFQ1MiLCJfb2JqZWN0V2l0aG91dFByb3BlcnRpZXMiLCJjcnlwdG8iLCJVUkwiLCJoYXNPd24iLCJOb25FbXB0eVN0cmluZyIsIk1hdGNoIiwiV2hlcmUiLCJ4IiwiY2hlY2siLCJTdHJpbmciLCJvbkNyZWF0ZUxvZ2luVG9rZW4iLCJfb25DcmVhdGVMb2dpblRva2VuSG9vayIsIl9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAiLCJmaWVsZE5hbWUiLCJzdHJpbmciLCJwcmVmaXgiLCJzdWJzdHJpbmciLCJNYXRoIiwibWluIiwib3JDbGF1c2UiLCJnZW5lcmF0ZUNhc2VQZXJtdXRhdGlvbnNGb3JTdHJpbmciLCJtYXAiLCJwcmVmaXhQZXJtdXRhdGlvbiIsInNlbGVjdG9yIiwiUmVnRXhwIiwiX2VzY2FwZVJlZ0V4cCIsImNhc2VJbnNlbnNpdGl2ZUNsYXVzZSIsIiRhbmQiLCIkb3IiLCJfZmluZFVzZXJCeVF1ZXJ5IiwicXVlcnkiLCJpZCIsImZpZWxkVmFsdWUiLCJ1c2VybmFtZSIsImVtYWlsIiwiY2FuZGlkYXRlVXNlcnMiLCJmaW5kIiwiZmV0Y2giLCJfaGFuZGxlRXJyb3IiLCJtc2ciLCJ0aHJvd0Vycm9yIiwiZXJyb3JDb2RlIiwiZXJyb3IiLCJhbWJpZ3VvdXNFcnJvck1lc3NhZ2VzIiwiX3VzZXJRdWVyeVZhbGlkYXRvciIsIk9wdGlvbmFsIiwiX3NlcnZlciIsIl9pbml0U2VydmVyTWV0aG9kcyIsIl9pbml0QWNjb3VudERhdGFIb29rcyIsIl9hdXRvcHVibGlzaEZpZWxkcyIsImxvZ2dlZEluVXNlciIsIm90aGVyVXNlcnMiLCJfZGVmYXVsdFB1Ymxpc2hGaWVsZHMiLCJwcm9qZWN0aW9uIiwicHJvZmlsZSIsImVtYWlscyIsIl9pbml0U2VydmVyUHVibGljYXRpb25zIiwiX2FjY291bnREYXRhIiwiX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zIiwiX25leHRVc2VyT2JzZXJ2ZU51bWJlciIsIl9sb2dpbkhhbmRsZXJzIiwic2V0dXBVc2Vyc0NvbGxlY3Rpb24iLCJzZXR1cERlZmF1bHRMb2dpbkhhbmRsZXJzIiwic2V0RXhwaXJlVG9rZW5zSW50ZXJ2YWwiLCJfdmFsaWRhdGVMb2dpbkhvb2siLCJfdmFsaWRhdGVOZXdVc2VySG9va3MiLCJkZWZhdWx0VmFsaWRhdGVOZXdVc2VySG9vayIsImJpbmQiLCJfZGVsZXRlU2F2ZWRUb2tlbnNGb3JBbGxVc2Vyc09uU3RhcnR1cCIsIl9za2lwQ2FzZUluc2Vuc2l0aXZlQ2hlY2tzRm9yVGVzdCIsInVybHMiLCJyZXNldFBhc3N3b3JkIiwidG9rZW4iLCJleHRyYVBhcmFtcyIsImJ1aWxkRW1haWxVcmwiLCJ2ZXJpZnlFbWFpbCIsImxvZ2luVG9rZW4iLCJlbnJvbGxBY2NvdW50IiwiYWRkRGVmYXVsdFJhdGVMaW1pdCIsInBhdGgiLCJ1cmwiLCJhYnNvbHV0ZVVybCIsInBhcmFtcyIsImVudHJpZXMiLCJ2YWx1ZSIsInNlYXJjaFBhcmFtcyIsImFwcGVuZCIsInRvU3RyaW5nIiwiY3VycmVudEludm9jYXRpb24iLCJfQ3VycmVudE1ldGhvZEludm9jYXRpb24iLCJnZXQiLCJfQ3VycmVudFB1YmxpY2F0aW9uSW52b2NhdGlvbiIsInZhbGlkYXRlTG9naW5BdHRlbXB0IiwidmFsaWRhdGVOZXdVc2VyIiwicHVzaCIsImJlZm9yZUV4dGVybmFsTG9naW4iLCJfYmVmb3JlRXh0ZXJuYWxMb2dpbkhvb2siLCJvbkNyZWF0ZVVzZXIiLCJfb25DcmVhdGVVc2VySG9vayIsIm9uRXh0ZXJuYWxMb2dpbiIsIl9vbkV4dGVybmFsTG9naW5Ib29rIiwic2V0QWRkaXRpb25hbEZpbmRVc2VyT25FeHRlcm5hbExvZ2luIiwiX2FkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbiIsIl92YWxpZGF0ZUxvZ2luIiwiYXR0ZW1wdCIsImNsb25lQXR0ZW1wdFdpdGhDb25uZWN0aW9uIiwiZSIsImFsbG93ZWQiLCJfc3VjY2Vzc2Z1bExvZ2luIiwiZWFjaCIsIl9mYWlsZWRMb2dpbiIsIl9zdWNjZXNzZnVsTG9nb3V0IiwiX2xvZ2luVXNlciIsIm1ldGhvZEludm9jYXRpb24iLCJzdGFtcGVkTG9naW5Ub2tlbiIsIl9nZW5lcmF0ZVN0YW1wZWRMb2dpblRva2VuIiwiX2luc2VydExvZ2luVG9rZW4iLCJfbm9ZaWVsZHNBbGxvd2VkIiwiX3NldExvZ2luVG9rZW4iLCJfaGFzaExvZ2luVG9rZW4iLCJzZXRVc2VySWQiLCJ0b2tlbkV4cGlyZXMiLCJfYXR0ZW1wdExvZ2luIiwibWV0aG9kTmFtZSIsIm1ldGhvZEFyZ3MiLCJyZXN1bHQiLCJ0eXBlIiwibWV0aG9kQXJndW1lbnRzIiwiQXJyYXkiLCJmcm9tIiwiX2xvZ2luTWV0aG9kIiwiZm4iLCJ0cnlMb2dpbk1ldGhvZCIsIl9yZXBvcnRMb2dpbkZhaWx1cmUiLCJyZWdpc3RlckxvZ2luSGFuZGxlciIsImhhbmRsZXIiLCJfcnVuTG9naW5IYW5kbGVycyIsImRlc3Ryb3lUb2tlbiIsInVwZGF0ZSIsIiRwdWxsIiwiaGFzaGVkVG9rZW4iLCJhY2NvdW50cyIsIm1ldGhvZHMiLCJsb2dpbiIsImFyZ3VtZW50cyIsImxvZ291dCIsIl9nZXRMb2dpblRva2VuIiwiZ2V0TmV3VG9rZW4iLCJjdXJyZW50SGFzaGVkVG9rZW4iLCJjdXJyZW50U3RhbXBlZFRva2VuIiwic2VydmljZXMiLCJyZXN1bWUiLCJsb2dpblRva2VucyIsInN0YW1wZWRUb2tlbiIsIm5ld1N0YW1wZWRUb2tlbiIsInJlbW92ZU90aGVyVG9rZW5zIiwiY3VycmVudFRva2VuIiwiJG5lIiwiY29uZmlndXJlTG9naW5TZXJ2aWNlIiwiT2JqZWN0SW5jbHVkaW5nIiwic2VydmljZSIsIm9hdXRoIiwic2VydmljZU5hbWVzIiwidXNpbmdPQXV0aEVuY3J5cHRpb24iLCJzZWNyZXQiLCJzZWFsIiwiaW5zZXJ0Iiwib25Db25uZWN0aW9uIiwib25DbG9zZSIsIl9yZW1vdmVUb2tlbkZyb21Db25uZWN0aW9uIiwicHVibGlzaCIsImlzX2F1dG8iLCJjdXN0b21GaWVsZHMiLCJfaWQiLCJhdXRvcHVibGlzaCIsInRvRmllbGRTZWxlY3RvciIsInJlZHVjZSIsInByZXYiLCJmaWVsZCIsImFkZEF1dG9wdWJsaXNoRmllbGRzIiwib3B0cyIsImFwcGx5IiwiZm9yTG9nZ2VkSW5Vc2VyIiwiZm9yT3RoZXJVc2VycyIsInNldERlZmF1bHRQdWJsaXNoRmllbGRzIiwiX2dldEFjY291bnREYXRhIiwiY29ubmVjdGlvbklkIiwiZGF0YSIsIl9zZXRBY2NvdW50RGF0YSIsImhhc2giLCJjcmVhdGVIYXNoIiwiZGlnZXN0IiwiX2hhc2hTdGFtcGVkVG9rZW4iLCJoYXNoZWRTdGFtcGVkVG9rZW4iLCJfaW5zZXJ0SGFzaGVkTG9naW5Ub2tlbiIsIiRhZGRUb1NldCIsIl9jbGVhckFsbExvZ2luVG9rZW5zIiwiJHNldCIsIl9nZXRVc2VyT2JzZXJ2ZSIsIm9ic2VydmUiLCJzdG9wIiwibmV3VG9rZW4iLCJteU9ic2VydmVOdW1iZXIiLCJkZWZlciIsImZvdW5kTWF0Y2hpbmdVc2VyIiwib2JzZXJ2ZUNoYW5nZXMiLCJhZGRlZCIsInJlbW92ZWQiLCJjbG9zZSIsIm5vbk11dGF0aW5nQ2FsbGJhY2tzIiwiUmFuZG9tIiwiX2V4cGlyZVBhc3N3b3JkUmVzZXRUb2tlbnMiLCJvbGRlc3RWYWxpZERhdGUiLCJ0b2tlbkxpZmV0aW1lTXMiLCJ0b2tlbkZpbHRlciIsIiRleGlzdHMiLCJleHBpcmVQYXNzd29yZFRva2VuIiwiX2V4cGlyZVBhc3N3b3JkRW5yb2xsVG9rZW5zIiwiX2V4cGlyZVRva2VucyIsInVzZXJGaWx0ZXIiLCIkbHQiLCJtdWx0aSIsInN1cGVyUmVzdWx0IiwiZXhwaXJlVG9rZW5JbnRlcnZhbCIsImNsZWFySW50ZXJ2YWwiLCJpbnNlcnRVc2VyRG9jIiwiY3JlYXRlZEF0IiwicGluRW5jcnlwdGVkRmllbGRzVG9Vc2VyIiwiZnVsbFVzZXIiLCJkZWZhdWx0Q3JlYXRlVXNlckhvb2siLCJob29rIiwiZXJybXNnIiwiX3Rlc3RFbWFpbERvbWFpbiIsImRvbWFpbiIsInJlc3RyaWN0Q3JlYXRpb25CeUVtYWlsRG9tYWluIiwidGVzdCIsIl9kZWxldGVTYXZlZFRva2Vuc0ZvclVzZXIiLCJ0b2tlbnNUb0RlbGV0ZSIsIiR1bnNldCIsIiRwdWxsQWxsIiwibG9naW5Ub2tlbnNUb0RlbGV0ZSIsInVwZGF0ZU9yQ3JlYXRlVXNlckZyb21FeHRlcm5hbFNlcnZpY2UiLCJzZXJ2aWNlTmFtZSIsInNlcnZpY2VEYXRhIiwic2VydmljZUlkS2V5IiwiaXNOYU4iLCJwYXJzZUludCIsInNldEF0dHJzIiwicmVtb3ZlRGVmYXVsdFJhdGVMaW1pdCIsInJlc3AiLCJERFBSYXRlTGltaXRlciIsInJlbW92ZVJ1bGUiLCJkZWZhdWx0UmF0ZUxpbWl0ZXJSdWxlSWQiLCJhZGRSdWxlIiwiY2xpZW50QWRkcmVzcyIsImdlbmVyYXRlT3B0aW9uc0ZvckVtYWlsIiwicmVhc29uIiwiZXh0cmEiLCJ0byIsImVtYWlsVGVtcGxhdGVzIiwic3ViamVjdCIsInRleHQiLCJodG1sIiwiaGVhZGVycyIsIl9jaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMiLCJkaXNwbGF5TmFtZSIsIm93blVzZXJJZCIsInNraXBDaGVjayIsIm1hdGNoZWRVc2VycyIsImxpbWl0IiwiX2NyZWF0ZVVzZXJDaGVja2luZ0R1cGxpY2F0ZXMiLCJuZXdVc2VyIiwiYWRkcmVzcyIsInZlcmlmaWVkIiwiZXgiLCJyZW1vdmUiLCJjbG9uZWRBdHRlbXB0IiwiRUpTT04iLCJjbG9uZSIsImRlZmF1bHRSZXN1bWVMb2dpbkhhbmRsZXIiLCJvbGRVbmhhc2hlZFN0eWxlVG9rZW4iLCJpc0Vucm9sbCIsInJlc2V0UmFuZ2VPciIsImV4cGlyZUZpbHRlciIsInNldEludGVydmFsIiwia2V5SXNMb2FkZWQiLCJpc1NlYWxlZCIsIm9wZW4iLCJlbWFpbElzR29vZCIsInZhbHVlcyIsImFsbG93IiwibW9kaWZpZXIiLCJjcmVhdGVJbmRleCIsInVuaXF1ZSIsInNwYXJzZSIsInBlcm11dGF0aW9ucyIsImkiLCJjaCIsImNoYXJBdCIsImNvbmNhdCIsImxvd2VyQ2FzZUNoYXIiLCJ0b0xvd2VyQ2FzZSIsInVwcGVyQ2FzZUNoYXIiLCJ0b1VwcGVyQ2FzZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQUFBQSxTQUFPLENBQUNDLE1BQVIsQ0FBZTtBQUFDQyxrQkFBYyxFQUFDLE1BQUlBO0FBQXBCLEdBQWY7QUFBb0QsTUFBSUEsY0FBSjtBQUFtQkYsU0FBTyxDQUFDRyxJQUFSLENBQWEsc0JBQWIsRUFBb0M7QUFBQ0Qsa0JBQWMsQ0FBQ0UsQ0FBRCxFQUFHO0FBQUNGLG9CQUFjLEdBQUNFLENBQWY7QUFBaUI7O0FBQXBDLEdBQXBDLEVBQTBFLENBQTFFOztBQUV2RTtBQUNBO0FBQ0E7QUFDQTtBQUNBQyxVQUFRLEdBQUcsSUFBSUgsY0FBSixDQUFtQkksTUFBTSxDQUFDQyxNQUExQixDQUFYLEMsQ0FFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUNBRCxRQUFNLENBQUNFLEtBQVAsR0FBZUgsUUFBUSxDQUFDRyxLQUF4Qjs7Ozs7Ozs7Ozs7O0FDbEJBLElBQUlDLGFBQUo7O0FBQWtCQyxNQUFNLENBQUNQLElBQVAsQ0FBWSxzQ0FBWixFQUFtRDtBQUFDUSxTQUFPLENBQUNQLENBQUQsRUFBRztBQUFDSyxpQkFBYSxHQUFDTCxDQUFkO0FBQWdCOztBQUE1QixDQUFuRCxFQUFpRixDQUFqRjtBQUFsQk0sTUFBTSxDQUFDVCxNQUFQLENBQWM7QUFBQ1csZ0JBQWMsRUFBQyxNQUFJQSxjQUFwQjtBQUFtQ0MsMkJBQXlCLEVBQUMsTUFBSUEseUJBQWpFO0FBQTJGQywyQkFBeUIsRUFBQyxNQUFJQTtBQUF6SCxDQUFkO0FBQW1LLElBQUlSLE1BQUo7QUFBV0ksTUFBTSxDQUFDUCxJQUFQLENBQVksZUFBWixFQUE0QjtBQUFDRyxRQUFNLENBQUNGLENBQUQsRUFBRztB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TyxDQUFDMVIsTUFBTSxHQUFHNlIsYUFBVixFQUF5QjdSLE1BQU0sR0FBRytSLGFBQWxDLENBQVA7QUFDRDtBQUNGLEtBVDRCLENBQWQsQ0FBZjtBQVVEOztBQUNELFNBQU9QLFlBQVA7QUFDRCxDQWhCRCxDIiwiZmlsZSI6Ii9wYWNrYWdlcy9hY2NvdW50cy1iYXNlLmpzIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQWNjb3VudHNTZXJ2ZXIgfSBmcm9tIFwiLi9hY2NvdW50c19zZXJ2ZXIuanNcIjtcblxuLyoqXG4gKiBAbmFtZXNwYWNlIEFjY291bnRzXG4gKiBAc3VtbWFyeSBUaGUgbmFtZXNwYWNlIGZvciBhbGwgc2VydmVyLXNpZGUgYWNjb3VudHMtcmVsYXRlZCBtZXRob2RzLlxuICovXG5BY2NvdW50cyA9IG5ldyBBY2NvdW50c1NlcnZlcihNZXRlb3Iuc2VydmVyKTtcblxuLy8gVXNlcnMgdGFibGUuIERvbid0IHVzZSB0aGUgbm9ybWFsIGF1dG9wdWJsaXNoLCBzaW5jZSB3ZSB3YW50IHRvIGhpZGVcbi8vIHNvbWUgZmllbGRzLiBDb2RlIHRvIGF1dG9wdWJsaXNoIHRoaXMgaXMgaW4gYWNjb3VudHNfc2VydmVyLmpzLlxuLy8gWFhYIEFsbG93IHVzZXJzIHRvIGNvbmZpZ3VyZSB0aGlzIGNvbGxlY3Rpb24gbmFtZS5cblxuLyoqXG4gKiBAc3VtbWFyeSBBIFtNb25nby5Db2xsZWN0aW9uXSgjY29sbGVjdGlvbnMpIGNvbnRhaW5pbmcgdXNlciBkb2N1bWVudHMuXG4gKiBAbG9jdXMgQW55d2hlcmVcbiAqIEB0eXBlIHtNb25nby5Db2xsZWN0aW9ufVxuICogQGltcG9ydEZyb21QYWNrYWdlIG1ldGVvclxuKi9cbk1ldGVvci51c2VycyA9IEFjY291bnRzLnVzZXJzO1xuXG5leHBvcnQge1xuICAvLyBTaW5jZSB0aGlzIGZpbGUgaXMgdGhlIG1haW4gbW9kdWxlIGZvciB0aGUgc2VydmVyIHZlcnNpb24gb2YgdGhlXG4gIC8vIGFjY291bnRzLWJhc2UgcGFja2FnZSwgcHJvcGVydGllcyBvZiBub24tZW50cnktcG9pbnQgbW9kdWxlcyBuZWVkIHRvXG4gIC8vIGJlIHJlLWV4cG9ydGVkIGluIG9yZGVyIHRvIGJlIGFjY2Vzc2libGUgdG8gbW9kdWxlcyB0aGF0IGltcG9ydCB0aGVcbiAgLy8gYWNjb3VudHMtYmFzZSBwYWNrYWdlLlxuICBBY2NvdW50c1NlcnZlclxufTtcbiIsImltcG9ydCB7IE1ldGVvciB9IGZyb20gJ21ldGVvci9tZXRlb3InO1xuXG4vLyBjb25maWcgb3B0aW9uIGtleXNcbmNvbnN0IFZBTElEX0NPTkZJR19LRVlTID0gW1xuICAnc2VuZFZlcmlmaWNhdGlvbkVtYWlsJyxcbiAgJ2ZvcmJpZENsaWVudEFjY291bnRDcmVhdGlvbicsXG4gICdwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbicsXG4gICdwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbkluRGF5cycsXG4gICdyZXN0cmljdENyZWF0aW9uQnlFbWFpbERvbWFpbicsXG4gICdsb2dpbkV4cGlyYXRpb25JbkRheXMnLFxuICAnbG9naW5FeHBpcmF0aW9uJyxcbiAgJ3Bhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb25JbkRheXMnLFxuICAncGFzc3dvcmRSZXNldFRva2VuRXhwaXJhdGlvbicsXG4gICdhbWJpZ3VvdXNFcnJvck1lc3NhZ2VzJyxcbiAgJ2JjcnlwdFJvdW5kcycsXG4gICdkZWZhdWx0RmllbGRTZWxlY3RvcicsXG4gICdsb2dpblRva2VuRXhwaXJhdGlvbkhvdXJzJyxcbiAgJ3Rva2VuU2VxdWVuY2VMZW5ndGgnLFxuXTtcblxuLyoqXG4gKiBAc3VtbWFyeSBTdXBlci1jb25zdHJ1Y3RvciBmb3IgQWNjb3VudHNDbGllbnQgYW5kIEFjY291bnRzU2VydmVyLlxuICogQGxvY3VzIEFueXdoZXJlXG4gKiBAY2xhc3MgQWNjb3VudHNDb21tb25cbiAqIEBpbnN0YW5jZW5hbWUgYWNjb3VudHNDbGllbnRPclNlcnZlclxuICogQHBhcmFtIG9wdGlvbnMge09iamVjdH0gYW4gb2JqZWN0IHdpdGggZmllbGRzOlxuICogLSBjb25uZWN0aW9uIHtPYmplY3R9IE9wdGlvbmFsIEREUCBjb25uZWN0aW9uIHRvIHJldXNlLlxuICogLSBkZHBVcmwge1N0cmluZ30gT3B0aW9uYWwgVVJMIGZvciBjcmVhdGluZyBhIG5ldyBERFAgY29ubmVjdGlvbi5cbiAqL1xuZXhwb3J0IGNsYXNzIEFjY291bnRzQ29tbW9uIHtcbiAgY29uc3RydWN0b3Iob3B0aW9ucykge1xuICAgIC8vIEN1cnJlbnRseSB0aGlzIGlzIHJlYWQgZGlyZWN0bHkgYnkgcGFja2FnZXMgbGlrZSBhY2NvdW50cy1wYXNzd29yZFxuICAgIC8vIGFuZCBhY2NvdW50cy11aS11bnN0eWxlZC5cbiAgICB0aGlzLl9vcHRpb25zID0ge307XG5cbiAgICAvLyBOb3RlIHRoYXQgc2V0dGluZyB0aGlzLmNvbm5lY3Rpb24gPSBudWxsIGNhdXNlcyB0aGlzLnVzZXJzIHRvIGJlIGFcbiAgICAvLyBMb2NhbENvbGxlY3Rpb24sIHdoaWNoIGlzIG5vdCB3aGF0IHdlIHdhbnQuXG4gICAgdGhpcy5jb25uZWN0aW9uID0gdW5kZWZpbmVkO1xuICAgIHRoaXMuX2luaXRDb25uZWN0aW9uKG9wdGlvbnMgfHwge30pO1xuXG4gICAgLy8gVGhlcmUgaXMgYW4gYWxsb3cgY2FsbCBpbiBhY2NvdW50c19zZXJ2ZXIuanMgdGhhdCByZXN0cmljdHMgd3JpdGVzIHRvXG4gICAgLy8gdGhpcyBjb2xsZWN0aW9uLlxuICAgIHRoaXMudXNlcnMgPSBuZXcgTW9uZ28uQ29sbGVjdGlvbigndXNlcnMnLCB7XG4gICAgICBfcHJldmVudEF1dG9wdWJsaXNoOiB0cnVlLFxuICAgICAgY29ubmVjdGlvbjogdGhpcy5jb25uZWN0aW9uLFxuICAgIH0pO1xuXG4gICAgLy8gQ2FsbGJhY2sgZXhjZXB0aW9ucyBhcmUgcHJpbnRlZCB3aXRoIE1ldGVvci5fZGVidWcgYW5kIGlnbm9yZWQuXG4gICAgdGhpcy5fb25Mb2dpbkhvb2sgPSBuZXcgSG9vayh7XG4gICAgICBiaW5kRW52aXJvbm1lbnQ6IGZhbHNlLFxuICAgICAgZGVidWdQcmludEV4Y2VwdGlvbnM6ICdvbkxvZ2luIGNhbGxiYWNrJyxcbiAgICB9KTtcblxuICAgIHRoaXMuX29uTG9naW5GYWlsdXJlSG9vayA9IG5ldyBIb29rKHtcbiAgICAgIGJpbmRFbnZpcm9ubWVudDogZmFsc2UsXG4gICAgICBkZWJ1Z1ByaW50RXhjZXB0aW9uczogJ29uTG9naW5GYWlsdXJlIGNhbGxiYWNrJyxcbiAgICB9KTtcblxuICAgIHRoaXMuX29uTG9nb3V0SG9vayA9IG5ldyBIb29rKHtcbiAgICAgIGJpbmRFbnZpcm9ubWVudDogZmFsc2UsXG4gICAgICBkZWJ1Z1ByaW50RXhjZXB0aW9uczogJ29uTG9nb3V0IGNhbGxiYWNrJyxcbiAgICB9KTtcblxuICAgIC8vIEV4cG9zZSBmb3IgdGVzdGluZy5cbiAgICB0aGlzLkRFRkFVTFRfTE9HSU5fRVhQSVJBVElPTl9EQVlTID0gREVGQVVMVF9MT0dJTl9FWFBJUkFUSU9OX0RBWVM7XG4gICAgdGhpcy5MT0dJTl9VTkVYUElSSU5HX1RPS0VOX0RBWVMgPSBMT0dJTl9VTkVYUElSSU5HX1RPS0VOX0RBWVM7XG5cbiAgICAvLyBUaHJvd24gd2hlbiB0aGUgdXNlciBjYW5jZWxzIHRoZSBsb2dpbiBwcm9jZXNzIChlZywgY2xvc2VzIGFuIG9hdXRoXG4gICAgLy8gcG9wdXAsIGRlY2xpbmVzIHJldGluYSBzY2FuLCBldGMpXG4gICAgY29uc3QgbGNlTmFtZSA9ICdBY2NvdW50cy5Mb2dpbkNhbmNlbGxlZEVycm9yJztcbiAgICB0aGlzLkxvZ2luQ2FuY2VsbGVkRXJyb3IgPSBNZXRlb3IubWFrZUVycm9yVHlwZShsY2VOYW1lLCBmdW5jdGlvbihcbiAgICAgIGRlc2NyaXB0aW9uXG4gICAgKSB7XG4gICAgICB0aGlzLm1lc3NhZ2UgPSBkZXNjcmlwdGlvbjtcbiAgICB9KTtcbiAgICB0aGlzLkxvZ2luQ2FuY2VsbGVkRXJyb3IucHJvdG90eXBlLm5hbWUgPSBsY2VOYW1lO1xuXG4gICAgLy8gVGhpcyBpcyB1c2VkIHRvIHRyYW5zbWl0IHNwZWNpZmljIHN1YmNsYXNzIGVycm9ycyBvdmVyIHRoZSB3aXJlLiBXZVxuICAgIC8vIHNob3VsZCBjb21lIHVwIHdpdGggYSBtb3JlIGdlbmVyaWMgd2F5IHRvIGRvIHRoaXMgKGVnLCB3aXRoIHNvbWUgc29ydCBvZlxuICAgIC8vIHN5bWJvbGljIGVycm9yIGNvZGUgcmF0aGVyIHRoYW4gYSBudW1iZXIpLlxuICAgIHRoaXMuTG9naW5DYW5jZWxsZWRFcnJvci5udW1lcmljRXJyb3IgPSAweDhhY2RjMmY7XG5cbiAgICAvLyBsb2dpblNlcnZpY2VDb25maWd1cmF0aW9uIGFuZCBDb25maWdFcnJvciBhcmUgbWFpbnRhaW5lZCBmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHlcbiAgICBNZXRlb3Iuc3RhcnR1cCgoKSA9PiB7XG4gICAgICBjb25zdCB7IFNlcnZpY2VDb25maWd1cmF0aW9uIH0gPSBQYWNrYWdlWydzZXJ2aWNlLWNvbmZpZ3VyYXRpb24nXTtcbiAgICAgIHRoaXMubG9naW5TZXJ2aWNlQ29uZmlndXJhdGlvbiA9IFNlcnZpY2VDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zO1xuICAgICAgdGhpcy5Db25maWdFcnJvciA9IFNlcnZpY2VDb25maWd1cmF0aW9uLkNvbmZpZ0Vycm9yO1xuXG4gICAgICBjb25zdCBzZXR0aW5ncyA9IE1ldGVvci5zZXR0aW5ncz8ucGFja2FnZXM/LlsnYWNjb3VudHMtYmFzZSddO1xuICAgICAgaWYgKHNldHRpbmdzKSB7XG4gICAgICAgIGlmIChzZXR0aW5ncy5vYXV0aFNlY3JldEtleSkge1xuICAgICAgICAgIGlmICghUGFja2FnZVsnb2F1dGgtZW5jcnlwdGlvbiddKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgICAgICdUaGUgb2F1dGgtZW5jcnlwdGlvbiBwYWNrYWdlIG11c3QgYmUgbG9hZGVkIHRvIHNldCBvYXV0aFNlY3JldEtleSdcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICAgIFBhY2thZ2VbJ29hdXRoLWVuY3J5cHRpb24nXS5PQXV0aEVuY3J5cHRpb24ubG9hZEtleShcbiAgICAgICAgICAgIHNldHRpbmdzLm9hdXRoU2VjcmV0S2V5XG4gICAgICAgICAgKTtcbiAgICAgICAgICBkZWxldGUgc2V0dGluZ3Mub2F1dGhTZWNyZXRLZXk7XG4gICAgICAgIH1cbiAgICAgICAgLy8gVmFsaWRhdGUgY29uZmlnIG9wdGlvbnMga2V5c1xuICAgICAgICBPYmplY3Qua2V5cyhzZXR0aW5ncykuZm9yRWFjaChrZXkgPT4ge1xuICAgICAgICAgIGlmICghVkFMSURfQ09ORklHX0tFWVMuaW5jbHVkZXMoa2V5KSkge1xuICAgICAgICAgICAgLy8gVE9ETyBDb25zaWRlciBqdXN0IGxvZ2dpbmcgYSBkZWJ1ZyBtZXNzYWdlIGluc3RlYWQgdG8gYWxsb3cgZm9yIGFkZGl0aW9uYWwga2V5cyBpbiB0aGUgc2V0dGluZ3MgaGVyZT9cbiAgICAgICAgICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoXG4gICAgICAgICAgICAgIGBBY2NvdW50cyBjb25maWd1cmF0aW9uOiBJbnZhbGlkIGtleTogJHtrZXl9YFxuICAgICAgICAgICAgKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8gc2V0IHZhbHVlcyBpbiBBY2NvdW50cy5fb3B0aW9uc1xuICAgICAgICAgICAgdGhpcy5fb3B0aW9uc1trZXldID0gc2V0dGluZ3Nba2V5XTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IEdldCB0aGUgY3VycmVudCB1c2VyIGlkLCBvciBgbnVsbGAgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4uIEEgcmVhY3RpdmUgZGF0YSBzb3VyY2UuXG4gICAqIEBsb2N1cyBBbnl3aGVyZVxuICAgKi9cbiAgdXNlcklkKCkge1xuICAgIHRocm93IG5ldyBFcnJvcigndXNlcklkIG1ldGhvZCBub3QgaW1wbGVtZW50ZWQnKTtcbiAgfVxuXG4gIC8vIG1lcmdlIHRoZSBkZWZhdWx0RmllbGRTZWxlY3RvciB3aXRoIGFuIGV4aXN0aW5nIG9wdGlvbnMgb2JqZWN0XG4gIF9hZGREZWZhdWx0RmllbGRTZWxlY3RvcihvcHRpb25zID0ge30pIHtcbiAgICAvLyB0aGlzIHdpbGwgYmUgdGhlIG1vc3QgY29tbW9uIGNhc2UgZm9yIG1vc3QgcGVvcGxlLCBzbyBtYWtlIGl0IHF1aWNrXG4gICAgaWYgKCF0aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yKSByZXR1cm4gb3B0aW9ucztcblxuICAgIC8vIGlmIG5vIGZpZWxkIHNlbGVjdG9yIHRoZW4ganVzdCB1c2UgZGVmYXVsdEZpZWxkU2VsZWN0b3JcbiAgICBpZiAoIW9wdGlvbnMuZmllbGRzKVxuICAgICAgcmV0dXJuIHtcbiAgICAgICAgLi4ub3B0aW9ucyxcbiAgICAgICAgZmllbGRzOiB0aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yLFxuICAgICAgfTtcblxuICAgIC8vIGlmIGVtcHR5IGZpZWxkIHNlbGVjdG9yIHRoZW4gdGhlIGZ1bGwgdXNlciBvYmplY3QgaXMgZXhwbGljaXRseSByZXF1ZXN0ZWQsIHNvIG9iZXlcbiAgICBjb25zdCBrZXlzID0gT2JqZWN0LmtleXMob3B0aW9ucy5maWVsZHMpO1xuICAgIGlmICgha2V5cy5sZW5ndGgpIHJldHVybiBvcHRpb25zO1xuXG4gICAgLy8gaWYgdGhlIHJlcXVlc3RlZCBmaWVsZHMgYXJlICt2ZSB0aGVuIGlnbm9yZSBkZWZhdWx0RmllbGRTZWxlY3RvclxuICAgIC8vIGFzc3VtZSB0aGV5IGFyZSBhbGwgZWl0aGVyICt2ZSBvciAtdmUgYmVjYXVzZSBNb25nbyBkb2Vzbid0IGxpa2UgbWl4ZWRcbiAgICBpZiAoISFvcHRpb25zLmZpZWxkc1trZXlzWzBdXSkgcmV0dXJuIG9wdGlvbnM7XG5cbiAgICAvLyBUaGUgcmVxdWVzdGVkIGZpZWxkcyBhcmUgLXZlLlxuICAgIC8vIElmIHRoZSBkZWZhdWx0RmllbGRTZWxlY3RvciBpcyArdmUgdGhlbiB1c2UgcmVxdWVzdGVkIGZpZWxkcywgb3RoZXJ3aXNlIG1lcmdlIHRoZW1cbiAgICBjb25zdCBrZXlzMiA9IE9iamVjdC5rZXlzKHRoaXMuX29wdGlvbnMuZGVmYXVsdEZpZWxkU2VsZWN0b3IpO1xuICAgIHJldHVybiB0aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yW2tleXMyWzBdXVxuICAgICAgPyBvcHRpb25zXG4gICAgICA6IHtcbiAgICAgICAgICAuLi5vcHRpb25zLFxuICAgICAgICAgIGZpZWxkczoge1xuICAgICAgICAgICAgLi4ub3B0aW9ucy5maWVsZHMsXG4gICAgICAgICAgICAuLi50aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yLFxuICAgICAgICAgIH0sXG4gICAgICAgIH07XG4gIH1cblxuICAvKipcbiAgICogQHN1bW1hcnkgR2V0IHRoZSBjdXJyZW50IHVzZXIgcmVjb3JkLCBvciBgbnVsbGAgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4uIEEgcmVhY3RpdmUgZGF0YSBzb3VyY2UuXG4gICAqIEBsb2N1cyBBbnl3aGVyZVxuICAgKiBAcGFyYW0ge09iamVjdH0gW29wdGlvbnNdXG4gICAqIEBwYXJhbSB7TW9uZ29GaWVsZFNwZWNpZmllcn0gb3B0aW9ucy5maWVsZHMgRGljdGlvbmFyeSBvZiBmaWVsZHMgdG8gcmV0dXJuIG9yIGV4Y2x1ZGUuXG4gICAqL1xuICB1c2VyKG9wdGlvbnMpIHtcbiAgICBjb25zdCB1c2VySWQgPSB0aGlzLnVzZXJJZCgpO1xuICAgIHJldHVybiB1c2VySWRcbiAgICAgID8gdGhpcy51c2Vycy5maW5kT25lKHVzZXJJZCwgdGhpcy5fYWRkRGVmYXVsdEZpZWxkU2VsZWN0b3Iob3B0aW9ucykpXG4gICAgICA6IG51bGw7XG4gIH1cblxuICAvLyBTZXQgdXAgY29uZmlnIGZvciB0aGUgYWNjb3VudHMgc3lzdGVtLiBDYWxsIHRoaXMgb24gYm90aCB0aGUgY2xpZW50XG4gIC8vIGFuZCB0aGUgc2VydmVyLlxuICAvL1xuICAvLyBOb3RlIHRoYXQgdGhpcyBtZXRob2QgZ2V0cyBvdmVycmlkZGVuIG9uIEFjY291bnRzU2VydmVyLnByb3RvdHlwZSwgYnV0XG4gIC8vIHRoZSBvdmVycmlkaW5nIG1ldGhvZCBjYWxscyB0aGUgb3ZlcnJpZGRlbiBtZXRob2QuXG4gIC8vXG4gIC8vIFhYWCB3ZSBzaG91bGQgYWRkIHNvbWUgZW5mb3JjZW1lbnQgdGhhdCB0aGlzIGlzIGNhbGxlZCBvbiBib3RoIHRoZVxuICAvLyBjbGllbnQgYW5kIHRoZSBzZXJ2ZXIuIE90aGVyd2lzZSwgYSB1c2VyIGNhblxuICAvLyAnZm9yYmlkQ2xpZW50QWNjb3VudENyZWF0aW9uJyBvbmx5IG9uIHRoZSBjbGllbnQgYW5kIHdoaWxlIGl0IGxvb2tzXG4gIC8vIGxpa2UgdGhlaXIgYXBwIGlzIHNlY3VyZSwgdGhlIHNlcnZlciB3aWxsIHN0aWxsIGFjY2VwdCBjcmVhdGVVc2VyXG4gIC8vIGNhbGxzLiBodHRwczovL2dpdGh1Yi5jb20vbWV0ZW9yL21ldGVvci9pc3N1ZXMvODI4XG4gIC8vXG4gIC8vIEBwYXJhbSBvcHRpb25zIHtPYmplY3R9IGFuIG9iamVjdCB3aXRoIGZpZWxkczpcbiAgLy8gLSBzZW5kVmVyaWZpY2F0aW9uRW1haWwge0Jvb2xlYW59XG4gIC8vICAgICBTZW5kIGVtYWlsIGFkZHJlc3MgdmVyaWZpY2F0aW9uIGVtYWlscyB0byBuZXcgdXNlcnMgY3JlYXRlZCBmcm9tXG4gIC8vICAgICBjbGllbnQgc2lnbnVwcy5cbiAgLy8gLSBmb3JiaWRDbGllbnRBY2NvdW50Q3JlYXRpb24ge0Jvb2xlYW59XG4gIC8vICAgICBEbyBub3QgYWxsb3cgY2xpZW50cyB0byBjcmVhdGUgYWNjb3VudHMgZGlyZWN0bHkuXG4gIC8vIC0gcmVzdHJpY3RDcmVhdGlvbkJ5RW1haWxEb21haW4ge0Z1bmN0aW9uIG9yIFN0cmluZ31cbiAgLy8gICAgIFJlcXVpcmUgY3JlYXRlZCB1c2VycyB0byBoYXZlIGFuIGVtYWlsIG1hdGNoaW5nIHRoZSBmdW5jdGlvbiBvclxuICAvLyAgICAgaGF2aW5nIHRoZSBzdHJpbmcgYXMgZG9tYWluLlxuICAvLyAtIGxvZ2luRXhwaXJhdGlvbkluRGF5cyB7TnVtYmVyfVxuICAvLyAgICAgTnVtYmVyIG9mIGRheXMgc2luY2UgbG9naW4gdW50aWwgYSB1c2VyIGlzIGxvZ2dlZCBvdXQgKGxvZ2luIHRva2VuXG4gIC8vICAgICBleHBpcmVzKS5cbiAgLy8gLSBwYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uSW5EYXlzIHtOdW1iZXJ9XG4gIC8vICAgICBOdW1iZXIgb2YgZGF5cyBzaW5jZSBwYXNzd29yZCByZXNldCB0b2tlbiBjcmVhdGlvbiB1bnRpbCB0aGVcbiAgLy8gICAgIHRva2VuIGNhbm50IGJlIHVzZWQgYW55IGxvbmdlciAocGFzc3dvcmQgcmVzZXQgdG9rZW4gZXhwaXJlcykuXG4gIC8vIC0gYW1iaWd1b3VzRXJyb3JNZXNzYWdlcyB7Qm9vbGVhbn1cbiAgLy8gICAgIFJldHVybiBhbWJpZ3VvdXMgZXJyb3IgbWVzc2FnZXMgZnJvbSBsb2dpbiBmYWlsdXJlcyB0byBwcmV2ZW50XG4gIC8vICAgICB1c2VyIGVudW1lcmF0aW9uLlxuICAvLyAtIGJjcnlwdFJvdW5kcyB7TnVtYmVyfVxuICAvLyAgICAgQWxsb3dzIG92ZXJyaWRlIG9mIG51bWJlciBvZiBiY3J5cHQgcm91bmRzIChha2Egd29yayBmYWN0b3IpIHVzZWRcbiAgLy8gICAgIHRvIHN0b3JlIHBhc3N3b3Jkcy5cblxuICAvKipcbiAgICogQHN1bW1hcnkgU2V0IGdsb2JhbCBhY2NvdW50cyBvcHRpb25zLiBZb3UgY2FuIGFsc28gc2V0IHRoZXNlIGluIGBNZXRlb3Iuc2V0dGluZ3MucGFja2FnZXMuYWNjb3VudHNgIHdpdGhvdXQgdGhlIG5lZWQgdG8gY2FsbCB0aGlzIGZ1bmN0aW9uLlxuICAgKiBAbG9jdXMgQW55d2hlcmVcbiAgICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcbiAgICogQHBhcmFtIHtCb29sZWFufSBvcHRpb25zLnNlbmRWZXJpZmljYXRpb25FbWFpbCBOZXcgdXNlcnMgd2l0aCBhbiBlbWFpbCBhZGRyZXNzIHdpbGwgcmVjZWl2ZSBhbiBhZGRyZXNzIHZlcmlmaWNhdGlvbiBlbWFpbC5cbiAgICogQHBhcmFtIHtCb29sZWFufSBvcHRpb25zLmZvcmJpZENsaWVudEFjY291bnRDcmVhdGlvbiBDYWxscyB0byBbYGNyZWF0ZVVzZXJgXSgjYWNjb3VudHNfY3JlYXRldXNlcikgZnJvbSB0aGUgY2xpZW50IHdpbGwgYmUgcmVqZWN0ZWQuIEluIGFkZGl0aW9uLCBpZiB5b3UgYXJlIHVzaW5nIFthY2NvdW50cy11aV0oI2FjY291bnRzdWkpLCB0aGUgXCJDcmVhdGUgYWNjb3VudFwiIGxpbmsgd2lsbCBub3QgYmUgYXZhaWxhYmxlLlxuICAgKiBAcGFyYW0ge1N0cmluZyB8IEZ1bmN0aW9ufSBvcHRpb25zLnJlc3RyaWN0Q3JlYXRpb25CeUVtYWlsRG9tYWluIElmIHNldCB0byBhIHN0cmluZywgb25seSBhbGxvd3MgbmV3IHVzZXJzIGlmIHRoZSBkb21haW4gcGFydCBvZiB0aGVpciBlbWFpbCBhZGRyZXNzIG1hdGNoZXMgdGhlIHN0cmluZy4gSWYgc2V0IHRvIGEgZnVuY3Rpb24sIG9ubHkgYWxsb3dzIG5ldyB1c2VycyBpZiB0aGUgZnVuY3Rpb24gcmV0dXJucyB0cnVlLiAgVGhlIGZ1bmN0aW9uIGlzIHBhc3NlZCB0aGUgZnVsbCBlbWFpbCBhZGRyZXNzIG9mIHRoZSBwcm9wb3NlZCBuZXcgdXNlci4gIFdvcmtzIHdpdGggcGFzc3dvcmQtYmFzZWQgc2lnbi1pbiBhbmQgZXh0ZXJuYWwgc2VydmljZXMgdGhhdCBleHBvc2UgZW1haWwgYWRkcmVzc2VzIChHb29nbGUsIEZhY2Vib29rLCBHaXRIdWIpLiBBbGwgZXhpc3RpbmcgdXNlcnMgc3RpbGwgY2FuIGxvZyBpbiBhZnRlciBlbmFibGluZyB0aGlzIG9wdGlvbi4gRXhhbXBsZTogYEFjY291bnRzLmNvbmZpZyh7IHJlc3RyaWN0Q3JlYXRpb25CeUVtYWlsRG9tYWluOiAnc2Nob29sLmVkdScgfSlgLlxuICAgKiBAcGFyYW0ge051bWJlcn0gb3B0aW9ucy5sb2dpbkV4cGlyYXRpb25JbkRheXMgVGhlIG51bWJlciBvZiBkYXlzIGZyb20gd2hlbiBhIHVzZXIgbG9ncyBpbiB1bnRpbCB0aGVpciB0b2tlbiBleHBpcmVzIGFuZCB0aGV5IGFyZSBsb2dnZWQgb3V0LiBEZWZhdWx0cyB0byA5MC4gU2V0IHRvIGBudWxsYCB0byBkaXNhYmxlIGxvZ2luIGV4cGlyYXRpb24uXG4gICAqIEBwYXJhbSB7TnVtYmVyfSBvcHRpb25zLmxvZ2luRXhwaXJhdGlvbiBUaGUgbnVtYmVyIG9mIG1pbGxpc2Vjb25kcyBmcm9tIHdoZW4gYSB1c2VyIGxvZ3MgaW4gdW50aWwgdGhlaXIgdG9rZW4gZXhwaXJlcyBhbmQgdGhleSBhcmUgbG9nZ2VkIG91dCwgZm9yIGEgbW9yZSBncmFudWxhciBjb250cm9sLiBJZiBgbG9naW5FeHBpcmF0aW9uSW5EYXlzYCBpcyBzZXQsIGl0IHRha2VzIHByZWNlZGVudC5cbiAgICogQHBhcmFtIHtTdHJpbmd9IG9wdGlvbnMub2F1dGhTZWNyZXRLZXkgV2hlbiB1c2luZyB0aGUgYG9hdXRoLWVuY3J5cHRpb25gIHBhY2thZ2UsIHRoZSAxNiBieXRlIGtleSB1c2luZyB0byBlbmNyeXB0IHNlbnNpdGl2ZSBhY2NvdW50IGNyZWRlbnRpYWxzIGluIHRoZSBkYXRhYmFzZSwgZW5jb2RlZCBpbiBiYXNlNjQuICBUaGlzIG9wdGlvbiBtYXkgb25seSBiZSBzcGVjaWZpZWQgb24gdGhlIHNlcnZlci4gIFNlZSBwYWNrYWdlcy9vYXV0aC1lbmNyeXB0aW9uL1JFQURNRS5tZCBmb3IgZGV0YWlscy5cbiAgICogQHBhcmFtIHtOdW1iZXJ9IG9wdGlvbnMucGFzc3dvcmRSZXNldFRva2VuRXhwaXJhdGlvbkluRGF5cyBUaGUgbnVtYmVyIG9mIGRheXMgZnJvbSB3aGVuIGEgbGluayB0byByZXNldCBwYXNzd29yZCBpcyBzZW50IHVudGlsIHRva2VuIGV4cGlyZXMgYW5kIHVzZXIgY2FuJ3QgcmVzZXQgcGFzc3dvcmQgd2l0aCB0aGUgbGluayBhbnltb3JlLiBEZWZhdWx0cyB0byAzLlxuICAgKiBAcGFyYW0ge051bWJlcn0gb3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uIFRoZSBudW1iZXIgb2YgbWlsbGlzZWNvbmRzIGZyb20gd2hlbiBhIGxpbmsgdG8gcmVzZXQgcGFzc3dvcmQgaXMgc2VudCB1bnRpbCB0b2tlbiBleHBpcmVzIGFuZCB1c2VyIGNhbid0IHJlc2V0IHBhc3N3b3JkIHdpdGggdGhlIGxpbmsgYW55bW9yZS4gSWYgYHBhc3N3b3JkUmVzZXRUb2tlbkV4cGlyYXRpb25JbkRheXNgIGlzIHNldCwgaXQgdGFrZXMgcHJlY2VkZW50LlxuICAgKiBAcGFyYW0ge051bWJlcn0gb3B0aW9ucy5wYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbkluRGF5cyBUaGUgbnVtYmVyIG9mIGRheXMgZnJvbSB3aGVuIGEgbGluayB0byBzZXQgaW5pdGlhbCBwYXNzd29yZCBpcyBzZW50IHVudGlsIHRva2VuIGV4cGlyZXMgYW5kIHVzZXIgY2FuJ3Qgc2V0IHBhc3N3b3JkIHdpdGggdGhlIGxpbmsgYW55bW9yZS4gRGVmYXVsdHMgdG8gMzAuXG4gICAqIEBwYXJhbSB7TnVtYmVyfSBvcHRpb25zLnBhc3N3b3JkRW5yb2xsVG9rZW5FeHBpcmF0aW9uIFRoZSBudW1iZXIgb2YgbWlsbGlzZWNvbmRzIGZyb20gd2hlbiBhIGxpbmsgdG8gc2V0IGluaXRpYWwgcGFzc3dvcmQgaXMgc2VudCB1bnRpbCB0b2tlbiBleHBpcmVzIGFuZCB1c2VyIGNhbid0IHNldCBwYXNzd29yZCB3aXRoIHRoZSBsaW5rIGFueW1vcmUuIElmIGBwYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbkluRGF5c2AgaXMgc2V0LCBpdCB0YWtlcyBwcmVjZWRlbnQuXG4gICAqIEBwYXJhbSB7Qm9vbGVhbn0gb3B0aW9ucy5hbWJpZ3VvdXNFcnJvck1lc3NhZ2VzIFJldHVybiBhbWJpZ3VvdXMgZXJyb3IgbWVzc2FnZXMgZnJvbSBsb2dpbiBmYWlsdXJlcyB0byBwcmV2ZW50IHVzZXIgZW51bWVyYXRpb24uIERlZmF1bHRzIHRvIGZhbHNlLlxuICAgKiBAcGFyYW0ge01vbmdvRmllbGRTcGVjaWZpZXJ9IG9wdGlvbnMuZGVmYXVsdEZpZWxkU2VsZWN0b3IgVG8gZXhjbHVkZSBieSBkZWZhdWx0IGxhcmdlIGN1c3RvbSBmaWVsZHMgZnJvbSBgTWV0ZW9yLnVzZXIoKWAgYW5kIGBNZXRlb3IuZmluZFVzZXJCeS4uLigpYCBmdW5jdGlvbnMgd2hlbiBjYWxsZWQgd2l0aG91dCBhIGZpZWxkIHNlbGVjdG9yLCBhbmQgYWxsIGBvbkxvZ2luYCwgYG9uTG9naW5GYWlsdXJlYCBhbmQgYG9uTG9nb3V0YCBjYWxsYmFja3MuICBFeGFtcGxlOiBgQWNjb3VudHMuY29uZmlnKHsgZGVmYXVsdEZpZWxkU2VsZWN0b3I6IHsgbXlCaWdBcnJheTogMCB9fSlgLiBCZXdhcmUgd2hlbiB1c2luZyB0aGlzLiBJZiwgZm9yIGluc3RhbmNlLCB5b3UgZG8gbm90IGluY2x1ZGUgYGVtYWlsYCB3aGVuIGV4Y2x1ZGluZyB0aGUgZmllbGRzLCB5b3UgY2FuIGhhdmUgcHJvYmxlbXMgd2l0aCBmdW5jdGlvbnMgbGlrZSBgZm9yZ290UGFzc3dvcmRgIHRoYXQgd2lsbCBicmVhayBiZWNhdXNlIHRoZXkgd29uJ3QgaGF2ZSB0aGUgcmVxdWlyZWQgZGF0YSBhdmFpbGFibGUuIEl0J3MgcmVjb21tZW5kIHRoYXQgeW91IGFsd2F5cyBrZWVwIHRoZSBmaWVsZHMgYF9pZGAsIGB1c2VybmFtZWAsIGFuZCBgZW1haWxgLlxuICAgKiBAcGFyYW0ge051bWJlcn0gb3B0aW9ucy5sb2dpblRva2VuRXhwaXJhdGlvbkhvdXJzIFdoZW4gdXNpbmcgdGhlIHBhY2thZ2UgYGFjY291bnRzLTJmYWAsIHVzZSB0aGlzIHRvIHNldCB0aGUgYW1vdW50IG9mIHRpbWUgYSB0b2tlbiBzZW50IGlzIHZhbGlkLiBBcyBpdCdzIGp1c3QgYSBudW1iZXIsIHlvdSBjYW4gdXNlLCBmb3IgZXhhbXBsZSwgMC41IHRvIG1ha2UgdGhlIHRva2VuIHZhbGlkIGZvciBqdXN0IGhhbGYgaG91ci4gVGhlIGRlZmF1bHQgaXMgMSBob3VyLlxuICAgKiBAcGFyYW0ge051bWJlcn0gb3B0aW9ucy50b2tlblNlcXVlbmNlTGVuZ3RoIFdoZW4gdXNpbmcgdGhlIHBhY2thZ2UgYGFjY291bnRzLTJmYWAsIHVzZSB0aGlzIHRvIHRoZSBzaXplIG9mIHRoZSB0b2tlbiBzZXF1ZW5jZSBnZW5lcmF0ZWQuIFRoZSBkZWZhdWx0IGlzIDYuXG4gICAqL1xuICBjb25maWcob3B0aW9ucykge1xuICAgIC8vIFdlIGRvbid0IHdhbnQgdXNlcnMgdG8gYWNjaWRlbnRhbGx5IG9ubHkgY2FsbCBBY2NvdW50cy5jb25maWcgb24gdGhlXG4gICAgLy8gY2xpZW50LCB3aGVyZSBzb21lIG9mIHRoZSBvcHRpb25zIHdpbGwgaGF2ZSBwYXJ0aWFsIGVmZmVjdHMgKGVnIHJlbW92aW5nXG4gICAgLy8gdGhlIFwiY3JlYXRlIGFjY291bnRcIiBidXR0b24gZnJvbSBhY2NvdW50cy11aSBpZiBmb3JiaWRDbGllbnRBY2NvdW50Q3JlYXRpb25cbiAgICAvLyBpcyBzZXQsIG9yIHJlZGlyZWN0aW5nIEdvb2dsZSBsb2dpbiB0byBhIHNwZWNpZmljLWRvbWFpbiBwYWdlKSB3aXRob3V0XG4gICAgLy8gaGF2aW5nIHRoZWlyIGZ1bGwgZWZmZWN0cy5cbiAgICBpZiAoTWV0ZW9yLmlzU2VydmVyKSB7XG4gICAgICBfX21ldGVvcl9ydW50aW1lX2NvbmZpZ19fLmFjY291bnRzQ29uZmlnQ2FsbGVkID0gdHJ1ZTtcbiAgICB9IGVsc2UgaWYgKCFfX21ldGVvcl9ydW50aW1lX2NvbmZpZ19fLmFjY291bnRzQ29uZmlnQ2FsbGVkKSB7XG4gICAgICAvLyBYWFggd291bGQgYmUgbmljZSB0byBcImNyYXNoXCIgdGhlIGNsaWVudCBhbmQgcmVwbGFjZSB0aGUgVUkgd2l0aCBhbiBlcnJvclxuICAgICAgLy8gbWVzc2FnZSwgYnV0IHRoZXJlJ3Mgbm8gdHJpdmlhbCB3YXkgdG8gZG8gdGhpcy5cbiAgICAgIE1ldGVvci5fZGVidWcoXG4gICAgICAgICdBY2NvdW50cy5jb25maWcgd2FzIGNhbGxlZCBvbiB0aGUgY2xpZW50IGJ1dCBub3Qgb24gdGhlICcgK1xuICAgICAgICAgICdzZXJ2ZXI7IHNvbWUgY29uZmlndXJhdGlvbiBvcHRpb25zIG1heSBub3QgdGFrZSBlZmZlY3QuJ1xuICAgICAgKTtcbiAgICB9XG5cbiAgICAvLyBXZSBuZWVkIHRvIHZhbGlkYXRlIHRoZSBvYXV0aFNlY3JldEtleSBvcHRpb24gYXQgdGhlIHRpbWVcbiAgICAvLyBBY2NvdW50cy5jb25maWcgaXMgY2FsbGVkLiBXZSBhbHNvIGRlbGliZXJhdGVseSBkb24ndCBzdG9yZSB0aGVcbiAgICAvLyBvYXV0aFNlY3JldEtleSBpbiBBY2NvdW50cy5fb3B0aW9ucy5cbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9wdGlvbnMsICdvYXV0aFNlY3JldEtleScpKSB7XG4gICAgICBpZiAoTWV0ZW9yLmlzQ2xpZW50KSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnVGhlIG9hdXRoU2VjcmV0S2V5IG9wdGlvbiBtYXkgb25seSBiZSBzcGVjaWZpZWQgb24gdGhlIHNlcnZlcidcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGlmICghUGFja2FnZVsnb2F1dGgtZW5jcnlwdGlvbiddKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgICAnVGhlIG9hdXRoLWVuY3J5cHRpb24gcGFja2FnZSBtdXN0IGJlIGxvYWRlZCB0byBzZXQgb2F1dGhTZWNyZXRLZXknXG4gICAgICAgICk7XG4gICAgICB9XG4gICAgICBQYWNrYWdlWydvYXV0aC1lbmNyeXB0aW9uJ10uT0F1dGhFbmNyeXB0aW9uLmxvYWRLZXkoXG4gICAgICAgIG9wdGlvbnMub2F1dGhTZWNyZXRLZXlcbiAgICAgICk7XG4gICAgICBvcHRpb25zID0geyAuLi5vcHRpb25zIH07XG4gICAgICBkZWxldGUgb3B0aW9ucy5vYXV0aFNlY3JldEtleTtcbiAgICB9XG5cbiAgICAvLyBWYWxpZGF0ZSBjb25maWcgb3B0aW9ucyBrZXlzXG4gICAgT2JqZWN0LmtleXMob3B0aW9ucykuZm9yRWFjaChrZXkgPT4ge1xuICAgICAgaWYgKCFWQUxJRF9DT05GSUdfS0VZUy5pbmNsdWRlcyhrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoYEFjY291bnRzLmNvbmZpZzogSW52YWxpZCBrZXk6ICR7a2V5fWApO1xuICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy8gc2V0IHZhbHVlcyBpbiBBY2NvdW50cy5fb3B0aW9uc1xuICAgIFZBTElEX0NPTkZJR19LRVlTLmZvckVhY2goa2V5ID0+IHtcbiAgICAgIGlmIChrZXkgaW4gb3B0aW9ucykge1xuICAgICAgICBpZiAoa2V5IGluIHRoaXMuX29wdGlvbnMpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKGBDYW4ndCBzZXQgXFxgJHtrZXl9XFxgIG1vcmUgdGhhbiBvbmNlYCk7XG4gICAgICAgIH1cbiAgICAgICAgdGhpcy5fb3B0aW9uc1trZXldID0gb3B0aW9uc1trZXldO1xuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFJlZ2lzdGVyIGEgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGFmdGVyIGEgbG9naW4gYXR0ZW1wdCBzdWNjZWVkcy5cbiAgICogQGxvY3VzIEFueXdoZXJlXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgVGhlIGNhbGxiYWNrIHRvIGJlIGNhbGxlZCB3aGVuIGxvZ2luIGlzIHN1Y2Nlc3NmdWwuXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgVGhlIGNhbGxiYWNrIHJlY2VpdmVzIGEgc2luZ2xlIG9iamVjdCB0aGF0XG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgaG9sZHMgbG9naW4gZGV0YWlscy4gVGhpcyBvYmplY3QgY29udGFpbnMgdGhlIGxvZ2luXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgcmVzdWx0IHR5cGUgKHBhc3N3b3JkLCByZXN1bWUsIGV0Yy4pIG9uIGJvdGggdGhlXG4gICAqICAgICAgICAgICAgICAgICAgICAgICAgY2xpZW50IGFuZCBzZXJ2ZXIuIGBvbkxvZ2luYCBjYWxsYmFja3MgcmVnaXN0ZXJlZFxuICAgKiAgICAgICAgICAgICAgICAgICAgICAgIG9uIHRoZSBzZXJ2ZXIgYWxzbyByZWNlaXZlIGV4dHJhIGRhdGEsIHN1Y2hcbiAgICogICAgICAgICAgICAgICAgICAgICAgICBhcyB1c2VyIGRldGFpbHMsIGNvbm5lY3Rpb24gaW5mb3JtYXRpb24sIGV0Yy5cbiAgICovXG4gIG9uTG9naW4oZnVuYykge1xuICAgIGxldCByZXQgPSB0aGlzLl9vbkxvZ2luSG9vay5yZWdpc3RlcihmdW5jKTtcbiAgICAvLyBjYWxsIHRoZSBqdXN0IHJlZ2lzdGVyZWQgY2FsbGJhY2sgaWYgYWxyZWFkeSBsb2dnZWQgaW5cbiAgICB0aGlzLl9zdGFydHVwQ2FsbGJhY2socmV0LmNhbGxiYWNrKTtcbiAgICByZXR1cm4gcmV0O1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFJlZ2lzdGVyIGEgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGFmdGVyIGEgbG9naW4gYXR0ZW1wdCBmYWlscy5cbiAgICogQGxvY3VzIEFueXdoZXJlXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgVGhlIGNhbGxiYWNrIHRvIGJlIGNhbGxlZCBhZnRlciB0aGUgbG9naW4gaGFzIGZhaWxlZC5cbiAgICovXG4gIG9uTG9naW5GYWlsdXJlKGZ1bmMpIHtcbiAgICByZXR1cm4gdGhpcy5fb25Mb2dpbkZhaWx1cmVIb29rLnJlZ2lzdGVyKGZ1bmMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFJlZ2lzdGVyIGEgY2FsbGJhY2sgdG8gYmUgY2FsbGVkIGFmdGVyIGEgbG9nb3V0IGF0dGVtcHQgc3VjY2VlZHMuXG4gICAqIEBsb2N1cyBBbnl3aGVyZVxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIFRoZSBjYWxsYmFjayB0byBiZSBjYWxsZWQgd2hlbiBsb2dvdXQgaXMgc3VjY2Vzc2Z1bC5cbiAgICovXG4gIG9uTG9nb3V0KGZ1bmMpIHtcbiAgICByZXR1cm4gdGhpcy5fb25Mb2dvdXRIb29rLnJlZ2lzdGVyKGZ1bmMpO1xuICB9XG5cbiAgX2luaXRDb25uZWN0aW9uKG9wdGlvbnMpIHtcbiAgICBpZiAoIU1ldGVvci5pc0NsaWVudCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIFRoZSBjb25uZWN0aW9uIHVzZWQgYnkgdGhlIEFjY291bnRzIHN5c3RlbS4gVGhpcyBpcyB0aGUgY29ubmVjdGlvblxuICAgIC8vIHRoYXQgd2lsbCBnZXQgbG9nZ2VkIGluIGJ5IE1ldGVvci5sb2dpbigpLCBhbmQgdGhpcyBpcyB0aGVcbiAgICAvLyBjb25uZWN0aW9uIHdob3NlIGxvZ2luIHN0YXRlIHdpbGwgYmUgcmVmbGVjdGVkIGJ5IE1ldGVvci51c2VySWQoKS5cbiAgICAvL1xuICAgIC8vIEl0IHdvdWxkIGJlIG11Y2ggcHJlZmVyYWJsZSBmb3IgdGhpcyB0byBiZSBpbiBhY2NvdW50c19jbGllbnQuanMsXG4gICAgLy8gYnV0IGl0IGhhcyB0byBiZSBoZXJlIGJlY2F1c2UgaXQncyBuZWVkZWQgdG8gY3JlYXRlIHRoZVxuICAgIC8vIE1ldGVvci51c2VycyBjb2xsZWN0aW9uLlxuICAgIGlmIChvcHRpb25zLmNvbm5lY3Rpb24pIHtcbiAgICAgIHRoaXMuY29ubmVjdGlvbiA9IG9wdGlvbnMuY29ubmVjdGlvbjtcbiAgICB9IGVsc2UgaWYgKG9wdGlvbnMuZGRwVXJsKSB7XG4gICAgICB0aGlzLmNvbm5lY3Rpb24gPSBERFAuY29ubmVjdChvcHRpb25zLmRkcFVybCk7XG4gICAgfSBlbHNlIGlmIChcbiAgICAgIHR5cGVvZiBfX21ldGVvcl9ydW50aW1lX2NvbmZpZ19fICE9PSAndW5kZWZpbmVkJyAmJlxuICAgICAgX19tZXRlb3JfcnVudGltZV9jb25maWdfXy5BQ0NPVU5UU19DT05ORUNUSU9OX1VSTFxuICAgICkge1xuICAgICAgLy8gVGVtcG9yYXJ5LCBpbnRlcm5hbCBob29rIHRvIGFsbG93IHRoZSBzZXJ2ZXIgdG8gcG9pbnQgdGhlIGNsaWVudFxuICAgICAgLy8gdG8gYSBkaWZmZXJlbnQgYXV0aGVudGljYXRpb24gc2VydmVyLiBUaGlzIGlzIGZvciBhIHZlcnlcbiAgICAgIC8vIHBhcnRpY3VsYXIgdXNlIGNhc2UgdGhhdCBjb21lcyB1cCB3aGVuIGltcGxlbWVudGluZyBhIG9hdXRoXG4gICAgICAvLyBzZXJ2ZXIuIFVuc3VwcG9ydGVkIGFuZCBtYXkgZ28gYXdheSBhdCBhbnkgcG9pbnQgaW4gdGltZS5cbiAgICAgIC8vXG4gICAgICAvLyBXZSB3aWxsIGV2ZW50dWFsbHkgcHJvdmlkZSBhIGdlbmVyYWwgd2F5IHRvIHVzZSBhY2NvdW50LWJhc2VcbiAgICAgIC8vIGFnYWluc3QgYW55IEREUCBjb25uZWN0aW9uLCBub3QganVzdCBvbmUgc3BlY2lhbCBvbmUuXG4gICAgICB0aGlzLmNvbm5lY3Rpb24gPSBERFAuY29ubmVjdChcbiAgICAgICAgX19tZXRlb3JfcnVudGltZV9jb25maWdfXy5BQ0NPVU5UU19DT05ORUNUSU9OX1VSTFxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5jb25uZWN0aW9uID0gTWV0ZW9yLmNvbm5lY3Rpb247XG4gICAgfVxuICB9XG5cbiAgX2dldFRva2VuTGlmZXRpbWVNcygpIHtcbiAgICAvLyBXaGVuIGxvZ2luRXhwaXJhdGlvbkluRGF5cyBpcyBzZXQgdG8gbnVsbCwgd2UnbGwgdXNlIGEgcmVhbGx5IGhpZ2hcbiAgICAvLyBudW1iZXIgb2YgZGF5cyAoTE9HSU5fVU5FWFBJUkFCTEVfVE9LRU5fREFZUykgdG8gc2ltdWxhdGUgYW5cbiAgICAvLyB1bmV4cGlyaW5nIHRva2VuLlxuICAgIGNvbnN0IGxvZ2luRXhwaXJhdGlvbkluRGF5cyA9XG4gICAgICB0aGlzLl9vcHRpb25zLmxvZ2luRXhwaXJhdGlvbkluRGF5cyA9PT0gbnVsbFxuICAgICAgICA/IExPR0lOX1VORVhQSVJJTkdfVE9LRU5fREFZU1xuICAgICAgICA6IHRoaXMuX29wdGlvbnMubG9naW5FeHBpcmF0aW9uSW5EYXlzO1xuICAgIHJldHVybiAoXG4gICAgICB0aGlzLl9vcHRpb25zLmxvZ2luRXhwaXJhdGlvbiB8fFxuICAgICAgKGxvZ2luRXhwaXJhdGlvbkluRGF5cyB8fCBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUykgKiA4NjQwMDAwMFxuICAgICk7XG4gIH1cblxuICBfZ2V0UGFzc3dvcmRSZXNldFRva2VuTGlmZXRpbWVNcygpIHtcbiAgICByZXR1cm4gKFxuICAgICAgdGhpcy5fb3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uIHx8XG4gICAgICAodGhpcy5fb3B0aW9ucy5wYXNzd29yZFJlc2V0VG9rZW5FeHBpcmF0aW9uSW5EYXlzIHx8XG4gICAgICAgIERFRkFVTFRfUEFTU1dPUkRfUkVTRVRfVE9LRU5fRVhQSVJBVElPTl9EQVlTKSAqIDg2NDAwMDAwXG4gICAgKTtcbiAgfVxuXG4gIF9nZXRQYXNzd29yZEVucm9sbFRva2VuTGlmZXRpbWVNcygpIHtcbiAgICByZXR1cm4gKFxuICAgICAgdGhpcy5fb3B0aW9ucy5wYXNzd29yZEVucm9sbFRva2VuRXhwaXJhdGlvbiB8fFxuICAgICAgKHRoaXMuX29wdGlvbnMucGFzc3dvcmRFbnJvbGxUb2tlbkV4cGlyYXRpb25JbkRheXMgfHxcbiAgICAgICAgREVGQVVMVF9QQVNTV09SRF9FTlJPTExfVE9LRU5fRVhQSVJBVElPTl9EQVlTKSAqIDg2NDAwMDAwXG4gICAgKTtcbiAgfVxuXG4gIF90b2tlbkV4cGlyYXRpb24od2hlbikge1xuICAgIC8vIFdlIHBhc3Mgd2hlbiB0aHJvdWdoIHRoZSBEYXRlIGNvbnN0cnVjdG9yIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eTtcbiAgICAvLyBgd2hlbmAgdXNlZCB0byBiZSBhIG51bWJlci5cbiAgICByZXR1cm4gbmV3IERhdGUobmV3IERhdGUod2hlbikuZ2V0VGltZSgpICsgdGhpcy5fZ2V0VG9rZW5MaWZldGltZU1zKCkpO1xuICB9XG5cbiAgX3Rva2VuRXhwaXJlc1Nvb24od2hlbikge1xuICAgIGxldCBtaW5MaWZldGltZU1zID0gMC4xICogdGhpcy5fZ2V0VG9rZW5MaWZldGltZU1zKCk7XG4gICAgY29uc3QgbWluTGlmZXRpbWVDYXBNcyA9IE1JTl9UT0tFTl9MSUZFVElNRV9DQVBfU0VDUyAqIDEwMDA7XG4gICAgaWYgKG1pbkxpZmV0aW1lTXMgPiBtaW5MaWZldGltZUNhcE1zKSB7XG4gICAgICBtaW5MaWZldGltZU1zID0gbWluTGlmZXRpbWVDYXBNcztcbiAgICB9XG4gICAgcmV0dXJuIG5ldyBEYXRlKCkgPiBuZXcgRGF0ZSh3aGVuKSAtIG1pbkxpZmV0aW1lTXM7XG4gIH1cblxuICAvLyBOby1vcCBvbiB0aGUgc2VydmVyLCBvdmVycmlkZGVuIG9uIHRoZSBjbGllbnQuXG4gIF9zdGFydHVwQ2FsbGJhY2soY2FsbGJhY2spIHt9XG59XG5cbi8vIE5vdGUgdGhhdCBBY2NvdW50cyBpcyBkZWZpbmVkIHNlcGFyYXRlbHkgaW4gYWNjb3VudHNfY2xpZW50LmpzIGFuZFxuLy8gYWNjb3VudHNfc2VydmVyLmpzLlxuXG4vKipcbiAqIEBzdW1tYXJ5IEdldCB0aGUgY3VycmVudCB1c2VyIGlkLCBvciBgbnVsbGAgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4uIEEgcmVhY3RpdmUgZGF0YSBzb3VyY2UuXG4gKiBAbG9jdXMgQW55d2hlcmUgYnV0IHB1Ymxpc2ggZnVuY3Rpb25zXG4gKiBAaW1wb3J0RnJvbVBhY2thZ2UgbWV0ZW9yXG4gKi9cbk1ldGVvci51c2VySWQgPSAoKSA9PiBBY2NvdW50cy51c2VySWQoKTtcblxuLyoqXG4gKiBAc3VtbWFyeSBHZXQgdGhlIGN1cnJlbnQgdXNlciByZWNvcmQsIG9yIGBudWxsYCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbi4gQSByZWFjdGl2ZSBkYXRhIHNvdXJjZS5cbiAqIEBsb2N1cyBBbnl3aGVyZSBidXQgcHVibGlzaCBmdW5jdGlvbnNcbiAqIEBpbXBvcnRGcm9tUGFja2FnZSBtZXRlb3JcbiAqIEBwYXJhbSB7T2JqZWN0fSBbb3B0aW9uc11cbiAqIEBwYXJhbSB7TW9uZ29GaWVsZFNwZWNpZmllcn0gb3B0aW9ucy5maWVsZHMgRGljdGlvbmFyeSBvZiBmaWVsZHMgdG8gcmV0dXJuIG9yIGV4Y2x1ZGUuXG4gKi9cbk1ldGVvci51c2VyID0gb3B0aW9ucyA9PiBBY2NvdW50cy51c2VyKG9wdGlvbnMpO1xuXG4vLyBob3cgbG9uZyAoaW4gZGF5cykgdW50aWwgYSBsb2dpbiB0b2tlbiBleHBpcmVzXG5jb25zdCBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUyA9IDkwO1xuLy8gaG93IGxvbmcgKGluIGRheXMpIHVudGlsIHJlc2V0IHBhc3N3b3JkIHRva2VuIGV4cGlyZXNcbmNvbnN0IERFRkFVTFRfUEFTU1dPUkRfUkVTRVRfVE9LRU5fRVhQSVJBVElPTl9EQVlTID0gMztcbi8vIGhvdyBsb25nIChpbiBkYXlzKSB1bnRpbCBlbnJvbCBwYXNzd29yZCB0b2tlbiBleHBpcmVzXG5jb25zdCBERUZBVUxUX1BBU1NXT1JEX0VOUk9MTF9UT0tFTl9FWFBJUkFUSU9OX0RBWVMgPSAzMDtcbi8vIENsaWVudHMgZG9uJ3QgdHJ5IHRvIGF1dG8tbG9naW4gd2l0aCBhIHRva2VuIHRoYXQgaXMgZ29pbmcgdG8gZXhwaXJlIHdpdGhpblxuLy8gLjEgKiBERUZBVUxUX0xPR0lOX0VYUElSQVRJT05fREFZUywgY2FwcGVkIGF0IE1JTl9UT0tFTl9MSUZFVElNRV9DQVBfU0VDUy5cbi8vIFRyaWVzIHRvIGF2b2lkIGFicnVwdCBkaXNjb25uZWN0cyBmcm9tIGV4cGlyaW5nIHRva2Vucy5cbmNvbnN0IE1JTl9UT0tFTl9MSUZFVElNRV9DQVBfU0VDUyA9IDM2MDA7IC8vIG9uZSBob3VyXG4vLyBob3cgb2Z0ZW4gKGluIG1pbGxpc2Vjb25kcykgd2UgY2hlY2sgZm9yIGV4cGlyZWQgdG9rZW5zXG5leHBvcnQgY29uc3QgRVhQSVJFX1RPS0VOU19JTlRFUlZBTF9NUyA9IDYwMCAqIDEwMDA7IC8vIDEwIG1pbnV0ZXNcbi8vIGhvdyBsb25nIHdlIHdhaXQgYmVmb3JlIGxvZ2dpbmcgb3V0IGNsaWVudHMgd2hlbiBNZXRlb3IubG9nb3V0T3RoZXJDbGllbnRzIGlzXG4vLyBjYWxsZWRcbmV4cG9ydCBjb25zdCBDT05ORUNUSU9OX0NMT1NFX0RFTEFZX01TID0gMTAgKiAxMDAwO1xuLy8gQSBsYXJnZSBudW1iZXIgb2YgZXhwaXJhdGlvbiBkYXlzIChhcHByb3hpbWF0ZWx5IDEwMCB5ZWFycyB3b3J0aCkgdGhhdCBpc1xuLy8gdXNlZCB3aGVuIGNyZWF0aW5nIHVuZXhwaXJpbmcgdG9rZW5zLlxuY29uc3QgTE9HSU5fVU5FWFBJUklOR19UT0tFTl9EQVlTID0gMzY1ICogMTAwO1xuIiwiaW1wb3J0IGNyeXB0byBmcm9tICdjcnlwdG8nO1xuaW1wb3J0IHtcbiAgQWNjb3VudHNDb21tb24sXG4gIEVYUElSRV9UT0tFTlNfSU5URVJWQUxfTVMsXG59IGZyb20gJy4vYWNjb3VudHNfY29tbW9uLmpzJztcbmltcG9ydCB7IFVSTCB9IGZyb20gJ21ldGVvci91cmwnO1xuXG5jb25zdCBoYXNPd24gPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xuXG4vLyBYWFggbWF5YmUgdGhpcyBiZWxvbmdzIGluIHRoZSBjaGVjayBwYWNrYWdlXG5jb25zdCBOb25FbXB0eVN0cmluZyA9IE1hdGNoLldoZXJlKHggPT4ge1xuICBjaGVjayh4LCBTdHJpbmcpO1xuICByZXR1cm4geC5sZW5ndGggPiAwO1xufSk7XG5cbi8qKlxuICogQHN1bW1hcnkgQ29uc3RydWN0b3IgZm9yIHRoZSBgQWNjb3VudHNgIG5hbWVzcGFjZSBvbiB0aGUgc2VydmVyLlxuICogQGxvY3VzIFNlcnZlclxuICogQGNsYXNzIEFjY291bnRzU2VydmVyXG4gKiBAZXh0ZW5kcyBBY2NvdW50c0NvbW1vblxuICogQGluc3RhbmNlbmFtZSBhY2NvdW50c1NlcnZlclxuICogQHBhcmFtIHtPYmplY3R9IHNlcnZlciBBIHNlcnZlciBvYmplY3Qgc3VjaCBhcyBgTWV0ZW9yLnNlcnZlcmAuXG4gKi9cbmV4cG9ydCBjbGFzcyBBY2NvdW50c1NlcnZlciBleHRlbmRzIEFjY291bnRzQ29tbW9uIHtcbiAgLy8gTm90ZSB0aGF0IHRoaXMgY29uc3RydWN0b3IgaXMgbGVzcyBsaWtlbHkgdG8gYmUgaW5zdGFudGlhdGVkIG11bHRpcGxlXG4gIC8vIHRpbWVzIHRoYW4gdGhlIGBBY2NvdW50c0NsaWVudGAgY29uc3RydWN0b3IsIGJlY2F1c2UgYSBzaW5nbGUgc2VydmVyXG4gIC8vIGNhbiBwcm92aWRlIG9ubHkgb25lIHNldCBvZiBtZXRob2RzLlxuICBjb25zdHJ1Y3RvcihzZXJ2ZXIpIHtcbiAgICBzdXBlcigpO1xuXG4gICAgdGhpcy5fc2VydmVyID0gc2VydmVyIHx8IE1ldGVvci5zZXJ2ZXI7XG4gICAgLy8gU2V0IHVwIHRoZSBzZXJ2ZXIncyBtZXRob2RzLCBhcyBpZiBieSBjYWxsaW5nIE1ldGVvci5tZXRob2RzLlxuICAgIHRoaXMuX2luaXRTZXJ2ZXJNZXRob2RzKCk7XG5cbiAgICB0aGlzLl9pbml0QWNjb3VudERhdGFIb29rcygpO1xuXG4gICAgLy8gSWYgYXV0b3B1Ymxpc2ggaXMgb24sIHB1Ymxpc2ggdGhlc2UgdXNlciBmaWVsZHMuIExvZ2luIHNlcnZpY2VcbiAgICAvLyBwYWNrYWdlcyAoZWcgYWNjb3VudHMtZ29vZ2xlKSBhZGQgdG8gdGhlc2UgYnkgY2FsbGluZ1xuICAgIC8vIGFkZEF1dG9wdWJsaXNoRmllbGRzLiAgTm90YWJseSwgdGhpcyBpc24ndCBpbXBsZW1lbnRlZCB3aXRoIG11bHRpcGxlXG4gICAgLy8gcHVibGlzaGVzIHNpbmNlIEREUCBvbmx5IG1lcmdlcyBvbmx5IGFjcm9zcyB0b3AtbGV2ZWwgZmllbGRzLCBub3RcbiAgICAvLyBzdWJmaWVsZHMgKHN1Y2ggYXMgJ3NlcnZpY2VzLmZhY2Vib29rLmFjY2Vzc1Rva2VuJylcbiAgICB0aGlzLl9hdXRvcHVibGlzaEZpZWxkcyA9IHtcbiAgICAgIGxvZ2dlZEluVXNlcjogWydwcm9maWxlJywgJ3VzZXJuYW1lJywgJ2VtYWlscyddLFxuICAgICAgb3RoZXJVc2VyczogWydwcm9maWxlJywgJ3VzZXJuYW1lJ11cbiAgICB9O1xuXG4gICAgLy8gdXNlIG9iamVjdCB0byBrZWVwIHRoZSByZWZlcmVuY2Ugd2hlbiB1c2VkIGluIGZ1bmN0aW9uc1xuICAgIC8vIHdoZXJlIF9kZWZhdWx0UHVibGlzaEZpZWxkcyBpcyBkZXN0cnVjdHVyZWQgaW50byBsZXhpY2FsIHNjb3BlXG4gICAgLy8gZm9yIHB1Ymxpc2ggY2FsbGJhY2tzIHRoYXQgbmVlZCBgdGhpc2BcbiAgICB0aGlzLl9kZWZhdWx0UHVibGlzaEZpZWxkcyA9IHtcbiAgICAgIHByb2plY3Rpb246IHtcbiAgICAgICAgcHJvZmlsZTogMSxcbiAgICAgICAgdXNlcm5hbWU6IDEsXG4gICAgICAgIGVtYWlsczogMSxcbiAgICAgIH1cbiAgICB9O1xuXG4gICAgdGhpcy5faW5pdFNlcnZlclB1YmxpY2F0aW9ucygpO1xuXG4gICAgLy8gY29ubmVjdGlvbklkIC0+IHtjb25uZWN0aW9uLCBsb2dpblRva2VufVxuICAgIHRoaXMuX2FjY291bnREYXRhID0ge307XG5cbiAgICAvLyBjb25uZWN0aW9uIGlkIC0+IG9ic2VydmUgaGFuZGxlIGZvciB0aGUgbG9naW4gdG9rZW4gdGhhdCB0aGlzIGNvbm5lY3Rpb24gaXNcbiAgICAvLyBjdXJyZW50bHkgYXNzb2NpYXRlZCB3aXRoLCBvciBhIG51bWJlci4gVGhlIG51bWJlciBpbmRpY2F0ZXMgdGhhdCB3ZSBhcmUgaW5cbiAgICAvLyB0aGUgcHJvY2VzcyBvZiBzZXR0aW5nIHVwIHRoZSBvYnNlcnZlICh1c2luZyBhIG51bWJlciBpbnN0ZWFkIG9mIGEgc2luZ2xlXG4gICAgLy8gc2VudGluZWwgYWxsb3dzIG11bHRpcGxlIGF0dGVtcHRzIHRvIHNldCB1cCB0aGUgb2JzZXJ2ZSB0byBpZGVudGlmeSB3aGljaFxuICAgIC8vIG9uZSB3YXMgdGhlaXJzKS5cbiAgICB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9ucyA9IHt9O1xuICAgIHRoaXMuX25leHRVc2VyT2JzZXJ2ZU51bWJlciA9IDE7ICAvLyBmb3IgdGhlIG51bWJlciBkZXNjcmliZWQgYWJvdmUuXG5cbiAgICAvLyBsaXN0IG9mIGFsbCByZWdpc3RlcmVkIGhhbmRsZXJzLlxuICAgIHRoaXMuX2xvZ2luSGFuZGxlcnMgPSBbXTtcblxuICAgIHNldHVwVXNlcnNDb2xsZWN0aW9uKHRoaXMudXNlcnMpO1xuICAgIHNldHVwRGVmYXVsdExvZ2luSGFuZGxlcnModGhpcyk7XG4gICAgc2V0RXhwaXJlVG9rZW5zSW50ZXJ2YWwodGhpcyk7XG5cbiAgICB0aGlzLl92YWxpZGF0ZUxvZ2luSG9vayA9IG5ldyBIb29rKHsgYmluZEVudmlyb25tZW50OiBmYWxzZSB9KTtcbiAgICB0aGlzLl92YWxpZGF0ZU5ld1VzZXJIb29rcyA9IFtcbiAgICAgIGRlZmF1bHRWYWxpZGF0ZU5ld1VzZXJIb29rLmJpbmQodGhpcylcbiAgICBdO1xuXG4gICAgdGhpcy5fZGVsZXRlU2F2ZWRUb2tlbnNGb3JBbGxVc2Vyc09uU3RhcnR1cCgpO1xuXG4gICAgdGhpcy5fc2tpcENhc2VJbnNlbnNpdGl2ZUNoZWNrc0ZvclRlc3QgPSB7fTtcblxuICAgIHRoaXMudXJscyA9IHtcbiAgICAgIHJlc2V0UGFzc3dvcmQ6ICh0b2tlbiwgZXh0cmFQYXJhbXMpID0+IHRoaXMuYnVpbGRFbWFpbFVybChgIy9yZXNldC1wYXNzd29yZC8ke3Rva2VufWAsIGV4dHJhUGFyYW1zKSxcbiAgICAgIHZlcmlmeUVtYWlsOiAodG9rZW4sIGV4dHJhUGFyYW1zKSA9PiB0aGlzLmJ1aWxkRW1haWxVcmwoYCMvdmVyaWZ5LWVtYWlsLyR7dG9rZW59YCwgZXh0cmFQYXJhbXMpLFxuICAgICAgbG9naW5Ub2tlbjogKHNlbGVjdG9yLCB0b2tlbiwgZXh0cmFQYXJhbXMpID0+XG4gICAgICAgIHRoaXMuYnVpbGRFbWFpbFVybChgLz9sb2dpblRva2VuPSR7dG9rZW59JnNlbGVjdG9yPSR7c2VsZWN0b3J9YCwgZXh0cmFQYXJhbXMpLFxuICAgICAgZW5yb2xsQWNjb3VudDogKHRva2VuLCBleHRyYVBhcmFtcykgPT4gdGhpcy5idWlsZEVtYWlsVXJsKGAjL2Vucm9sbC1hY2NvdW50LyR7dG9rZW59YCwgZXh0cmFQYXJhbXMpLFxuICAgIH07XG5cbiAgICB0aGlzLmFkZERlZmF1bHRSYXRlTGltaXQoKTtcblxuICAgIHRoaXMuYnVpbGRFbWFpbFVybCA9IChwYXRoLCBleHRyYVBhcmFtcyA9IHt9KSA9PiB7XG4gICAgICBjb25zdCB1cmwgPSBuZXcgVVJMKE1ldGVvci5hYnNvbHV0ZVVybChwYXRoKSk7XG4gICAgICBjb25zdCBwYXJhbXMgPSBPYmplY3QuZW50cmllcyhleHRyYVBhcmFtcyk7XG4gICAgICBpZiAocGFyYW1zLmxlbmd0aCA+IDApIHtcbiAgICAgICAgLy8gQWRkIGFkZGl0aW9uYWwgcGFyYW1ldGVycyB0byB0aGUgdXJsXG4gICAgICAgIGZvciAoY29uc3QgW2tleSwgdmFsdWVdIG9mIHBhcmFtcykge1xuICAgICAgICAgIHVybC5zZWFyY2hQYXJhbXMuYXBwZW5kKGtleSwgdmFsdWUpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gdXJsLnRvU3RyaW5nKCk7XG4gICAgfTtcbiAgfVxuXG4gIC8vL1xuICAvLy8gQ1VSUkVOVCBVU0VSXG4gIC8vL1xuXG4gIC8vIEBvdmVycmlkZSBvZiBcImFic3RyYWN0XCIgbm9uLWltcGxlbWVudGF0aW9uIGluIGFjY291bnRzX2NvbW1vbi5qc1xuICB1c2VySWQoKSB7XG4gICAgLy8gVGhpcyBmdW5jdGlvbiBvbmx5IHdvcmtzIGlmIGNhbGxlZCBpbnNpZGUgYSBtZXRob2Qgb3IgYSBwdWJpY2F0aW9uLlxuICAgIC8vIFVzaW5nIGFueSBvZiB0aGUgaW5mb3JtYXRpb24gZnJvbSBNZXRlb3IudXNlcigpIGluIGEgbWV0aG9kIG9yXG4gICAgLy8gcHVibGlzaCBmdW5jdGlvbiB3aWxsIGFsd2F5cyB1c2UgdGhlIHZhbHVlIGZyb20gd2hlbiB0aGUgZnVuY3Rpb24gZmlyc3RcbiAgICAvLyBydW5zLiBUaGlzIGlzIGxpa2VseSBub3Qgd2hhdCB0aGUgdXNlciBleHBlY3RzLiBUaGUgd2F5IHRvIG1ha2UgdGhpcyB3b3JrXG4gICAgLy8gaW4gYSBtZXRob2Qgb3IgcHVibGlzaCBmdW5jdGlvbiBpcyB0byBkbyBNZXRlb3IuZmluZCh0aGlzLnVzZXJJZCkub2JzZXJ2ZVxuICAgIC8vIGFuZCByZWNvbXB1dGUgd2hlbiB0aGUgdXNlciByZWNvcmQgY2hhbmdlcy5cbiAgICBjb25zdCBjdXJyZW50SW52b2NhdGlvbiA9IEREUC5fQ3VycmVudE1ldGhvZEludm9jYXRpb24uZ2V0KCkgfHwgRERQLl9DdXJyZW50UHVibGljYXRpb25JbnZvY2F0aW9uLmdldCgpO1xuICAgIGlmICghY3VycmVudEludm9jYXRpb24pXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJNZXRlb3IudXNlcklkIGNhbiBvbmx5IGJlIGludm9rZWQgaW4gbWV0aG9kIGNhbGxzIG9yIHB1YmxpY2F0aW9ucy5cIik7XG4gICAgcmV0dXJuIGN1cnJlbnRJbnZvY2F0aW9uLnVzZXJJZDtcbiAgfVxuXG4gIC8vL1xuICAvLy8gTE9HSU4gSE9PS1NcbiAgLy8vXG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFZhbGlkYXRlIGxvZ2luIGF0dGVtcHRzLlxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgQ2FsbGVkIHdoZW5ldmVyIGEgbG9naW4gaXMgYXR0ZW1wdGVkIChlaXRoZXIgc3VjY2Vzc2Z1bCBvciB1bnN1Y2Nlc3NmdWwpLiAgQSBsb2dpbiBjYW4gYmUgYWJvcnRlZCBieSByZXR1cm5pbmcgYSBmYWxzeSB2YWx1ZSBvciB0aHJvd2luZyBhbiBleGNlcHRpb24uXG4gICAqL1xuICB2YWxpZGF0ZUxvZ2luQXR0ZW1wdChmdW5jKSB7XG4gICAgLy8gRXhjZXB0aW9ucyBpbnNpZGUgdGhlIGhvb2sgY2FsbGJhY2sgYXJlIHBhc3NlZCB1cCB0byB1cy5cbiAgICByZXR1cm4gdGhpcy5fdmFsaWRhdGVMb2dpbkhvb2sucmVnaXN0ZXIoZnVuYyk7XG4gIH1cblxuICAvKipcbiAgICogQHN1bW1hcnkgU2V0IHJlc3RyaWN0aW9ucyBvbiBuZXcgdXNlciBjcmVhdGlvbi5cbiAgICogQGxvY3VzIFNlcnZlclxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIENhbGxlZCB3aGVuZXZlciBhIG5ldyB1c2VyIGlzIGNyZWF0ZWQuIFRha2VzIHRoZSBuZXcgdXNlciBvYmplY3QsIGFuZCByZXR1cm5zIHRydWUgdG8gYWxsb3cgdGhlIGNyZWF0aW9uIG9yIGZhbHNlIHRvIGFib3J0LlxuICAgKi9cbiAgdmFsaWRhdGVOZXdVc2VyKGZ1bmMpIHtcbiAgICB0aGlzLl92YWxpZGF0ZU5ld1VzZXJIb29rcy5wdXNoKGZ1bmMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IFZhbGlkYXRlIGxvZ2luIGZyb20gZXh0ZXJuYWwgc2VydmljZVxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgQ2FsbGVkIHdoZW5ldmVyIGxvZ2luL3VzZXIgY3JlYXRpb24gZnJvbSBleHRlcm5hbCBzZXJ2aWNlIGlzIGF0dGVtcHRlZC4gTG9naW4gb3IgdXNlciBjcmVhdGlvbiBiYXNlZCBvbiB0aGlzIGxvZ2luIGNhbiBiZSBhYm9ydGVkIGJ5IHBhc3NpbmcgYSBmYWxzeSB2YWx1ZSBvciB0aHJvd2luZyBhbiBleGNlcHRpb24uXG4gICAqL1xuICBiZWZvcmVFeHRlcm5hbExvZ2luKGZ1bmMpIHtcbiAgICBpZiAodGhpcy5fYmVmb3JlRXh0ZXJuYWxMb2dpbkhvb2spIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkNhbiBvbmx5IGNhbGwgYmVmb3JlRXh0ZXJuYWxMb2dpbiBvbmNlXCIpO1xuICAgIH1cblxuICAgIHRoaXMuX2JlZm9yZUV4dGVybmFsTG9naW5Ib29rID0gZnVuYztcbiAgfVxuXG4gIC8vL1xuICAvLy8gQ1JFQVRFIFVTRVIgSE9PS1NcbiAgLy8vXG5cbiAgLyoqXG4gICAqIEBzdW1tYXJ5IEN1c3RvbWl6ZSBsb2dpbiB0b2tlbiBjcmVhdGlvbi5cbiAgICogQGxvY3VzIFNlcnZlclxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIENhbGxlZCB3aGVuZXZlciBhIG5ldyB0b2tlbiBpcyBjcmVhdGVkLlxuICAgKiBSZXR1cm4gdGhlIHNlcXVlbmNlIGFuZCB0aGUgdXNlciBvYmplY3QuIFJldHVybiB0cnVlIHRvIGtlZXAgc2VuZGluZyB0aGUgZGVmYXVsdCBlbWFpbCwgb3IgZmFsc2UgdG8gb3ZlcnJpZGUgdGhlIGJlaGF2aW9yLlxuICAgKi9cbiAgb25DcmVhdGVMb2dpblRva2VuID0gZnVuY3Rpb24oZnVuYykge1xuICAgIGlmICh0aGlzLl9vbkNyZWF0ZUxvZ2luVG9rZW5Ib29rKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBvbmx5IGNhbGwgb25DcmVhdGVMb2dpblRva2VuIG9uY2UnKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vbkNyZWF0ZUxvZ2luVG9rZW5Ib29rID0gZnVuYztcbiAgfTtcblxuICAvKipcbiAgICogQHN1bW1hcnkgQ3VzdG9taXplIG5ldyB1c2VyIGNyZWF0aW9uLlxuICAgKiBAbG9jdXMgU2VydmVyXG4gICAqIEBwYXJhbSB7RnVuY3Rpb259IGZ1bmMgQ2FsbGVkIHdoZW5ldmVyIGEgbmV3IHVzZXIgaXMgY3JlYXRlZC4gUmV0dXJuIHRoZSBuZXcgdXNlciBvYmplY3QsIG9yIHRocm93IGFuIGBFcnJvcmAgdG8gYWJvcnQgdGhlIGNyZWF0aW9uLlxuICAgKi9cbiAgb25DcmVhdGVVc2VyKGZ1bmMpIHtcbiAgICBpZiAodGhpcy5fb25DcmVhdGVVc2VySG9vaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2FuIG9ubHkgY2FsbCBvbkNyZWF0ZVVzZXIgb25jZVwiKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vbkNyZWF0ZVVzZXJIb29rID0gZnVuYztcbiAgfVxuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBDdXN0b21pemUgb2F1dGggdXNlciBwcm9maWxlIHVwZGF0ZXNcbiAgICogQGxvY3VzIFNlcnZlclxuICAgKiBAcGFyYW0ge0Z1bmN0aW9ufSBmdW5jIENhbGxlZCB3aGVuZXZlciBhIHVzZXIgaXMgbG9nZ2VkIGluIHZpYSBvYXV0aC4gUmV0dXJuIHRoZSBwcm9maWxlIG9iamVjdCB0byBiZSBtZXJnZWQsIG9yIHRocm93IGFuIGBFcnJvcmAgdG8gYWJvcnQgdGhlIGNyZWF0aW9uLlxuICAgKi9cbiAgb25FeHRlcm5hbExvZ2luKGZ1bmMpIHtcbiAgICBpZiAodGhpcy5fb25FeHRlcm5hbExvZ2luSG9vaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2FuIG9ubHkgY2FsbCBvbkV4dGVybmFsTG9naW4gb25jZVwiKTtcbiAgICB9XG5cbiAgICB0aGlzLl9vbkV4dGVybmFsTG9naW5Ib29rID0gZnVuYztcbiAgfVxuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBDdXN0b21pemUgdXNlciBzZWxlY3Rpb24gb24gZXh0ZXJuYWwgbG9naW5zXG4gICAqIEBsb2N1cyBTZXJ2ZXJcbiAgICogQHBhcmFtIHtGdW5jdGlvbn0gZnVuYyBDYWxsZWQgd2hlbmV2ZXIgYSB1c2VyIGlzIGxvZ2dlZCBpbiB2aWEgb2F1dGggYW5kIGFcbiAgICogdXNlciBpcyBub3QgZm91bmQgd2l0aCB0aGUgc2VydmljZSBpZC4gUmV0dXJuIHRoZSB1c2VyIG9yIHVuZGVmaW5lZC5cbiAgICovXG4gIHNldEFkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbihmdW5jKSB7XG4gICAgaWYgKHRoaXMuX2FkZGl0aW9uYWxGaW5kVXNlck9uRXh0ZXJuYWxMb2dpbikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ2FuIG9ubHkgY2FsbCBzZXRBZGRpdGlvbmFsRmluZFVzZXJPbkV4dGVybmFsTG9naW4gb25jZVwiKTtcbiAgICB9XG4gICAgdGhpcy5fYWRkaXRpb25hbEZpbmRVc2VyT25FeHRlcm5hbExvZ2luID0gZnVuYztcbiAgfVxuXG4gIF92YWxpZGF0ZUxvZ2luKGNvbm5lY3Rpb24sIGF0dGVtcHQpIHtcbiAgICB0aGlzLl92YWxpZGF0ZUxvZ2luSG9vay5mb3JFYWNoKGNhbGxiYWNrID0+IHtcbiAgICAgIGxldCByZXQ7XG4gICAgICB0cnkge1xuICAgICAgICByZXQgPSBjYWxsYmFjayhjbG9uZUF0dGVtcHRXaXRoQ29ubmVjdGlvbihjb25uZWN0aW9uLCBhdHRlbXB0KSk7XG4gICAgICB9XG4gICAgICBjYXRjaCAoZSkge1xuICAgICAgICBhdHRlbXB0LmFsbG93ZWQgPSBmYWxzZTtcbiAgICAgICAgLy8gWFhYIHRoaXMgbWVhbnMgdGhlIGxhc3QgdGhyb3duIGVycm9yIG92ZXJyaWRlcyBwcmV2aW91cyBlcnJvclxuICAgICAgICAvLyBtZXNzYWdlcy4gTWF5YmUgdGhpcyBpcyBzdXJwcmlzaW5nIHRvIHVzZXJzIGFuZCB3ZSBzaG91bGQgbWFrZVxuICAgICAgICAvLyBvdmVycmlkaW5nIGVycm9ycyBtb3JlIGV4cGxpY2l0LiAoc2VlXG4gICAgICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS9tZXRlb3IvbWV0ZW9yL2lzc3Vlcy8xOTYwKVxuICAgICAgICBhdHRlbXB0LmVycm9yID0gZTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9XG4gICAgICBpZiAoISByZXQpIHtcbiAgICAgICAgYXR0ZW1wdC5hbGxvd2VkID0gZmFsc2U7XG4gICAgICAgIC8vIGRvbid0IG92ZXJyaWRlIGEgc3BlY2lmaWMgZXJyb3IgcHJvdmlkZWQgYnkgYSBwcmV2aW91c1xuICAgICAgICAvLyB2YWxpZGF0b3Igb3IgdGhlIGluaXRpYWwgYXR0ZW1wdCAoZWcgXCJpbmNvcnJlY3QgcGFzc3dvcmRcIikuXG4gICAgICAgIGlmICghYXR0ZW1wdC5lcnJvcilcbiAgICAgICAgICBhdHRlbXB0LmVycm9yID0gbmV3IE1ldGVvci5FcnJvcig0MDMsIFwiTG9naW4gZm9yYmlkZGVuXCIpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSk7XG4gIH07XG5cbiAgX3N1Y2Nlc3NmdWxMb2dpbihjb25uZWN0aW9uLCBhdHRlbXB0KSB7XG4gICAgdGhpcy5fb25Mb2dpbkhvb2suZWFjaChjYWxsYmFjayA9PiB7XG4gICAgICBjYWxsYmFjayhjbG9uZUF0dGVtcHRXaXRoQ29ubmVjdGlvbihjb25uZWN0aW9uLCBhdHRlbXB0KSk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9KTtcbiAgfTtcblxuICBfZmFpbGVkTG9naW4oY29ubmVjdGlvbiwgYXR0ZW1wdCkge1xuICAgIHRoaXMuX29uTG9naW5GYWlsdXJlSG9vay5lYWNoKGNhbGxiYWNrID0+IHtcbiAgICAgIGNhbGxiYWNrKGNsb25lQXR0ZW1wdFdpdGhDb25uZWN0aW9uKGNvbm5lY3Rpb24sIGF0dGVtcHQpKTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0pO1xuICB9O1xuXG4gIF9zdWNjZXNzZnVsTG9nb3V0KGNvbm5lY3Rpb24sIHVzZXJJZCkge1xuICAgIC8vIGRvbid0IGZldGNoIHRoZSB1c2VyIG9iamVjdCB1bmxlc3MgdGhlcmUgYXJlIHNvbWUgY2FsbGJhY2tzIHJlZ2lzdGVyZWRcbiAgICBsZXQgdXNlcjtcbiAgICB0aGlzLl9vbkxvZ291dEhvb2suZWFjaChjYWxsYmFjayA9PiB7XG4gICAgICBpZiAoIXVzZXIgJiYgdXNlcklkKSB1c2VyID0gdGhpcy51c2Vycy5maW5kT25lKHVzZXJJZCwge2ZpZWxkczogdGhpcy5fb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3Rvcn0pO1xuICAgICAgY2FsbGJhY2soeyB1c2VyLCBjb25uZWN0aW9uIH0pO1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSk7XG4gIH07XG5cbiAgLy8gR2VuZXJhdGVzIGEgTW9uZ29EQiBzZWxlY3RvciB0aGF0IGNhbiBiZSB1c2VkIHRvIHBlcmZvcm0gYSBmYXN0IGNhc2VcbiAgLy8gaW5zZW5zaXRpdmUgbG9va3VwIGZvciB0aGUgZ2l2ZW4gZmllbGROYW1lIGFuZCBzdHJpbmcuIFNpbmNlIE1vbmdvREIgZG9lc1xuICAvLyBub3Qgc3VwcG9ydCBjYXNlIGluc2Vuc2l0aXZlIGluZGV4ZXMsIGFuZCBjYXNlIGluc2Vuc2l0aXZlIHJlZ2V4IHF1ZXJpZXNcbiAgLy8gYXJlIHNsb3csIHdlIGNvbnN0cnVjdCBhIHNldCBvZiBwcmVmaXggc2VsZWN0b3JzIGZvciBhbGwgcGVybXV0YXRpb25zIG9mXG4gIC8vIHRoZSBmaXJzdCA0IGNoYXJhY3RlcnMgb3Vyc2VsdmVzLiBXZSBmaXJzdCBhdHRlbXB0IHRvIG1hdGNoaW5nIGFnYWluc3RcbiAgLy8gdGhlc2UsIGFuZCBiZWNhdXNlICdwcmVmaXggZXhwcmVzc2lvbicgcmVnZXggcXVlcmllcyBkbyB1c2UgaW5kZXhlcyAoc2VlXG4gIC8vIGh0dHA6Ly9kb2NzLm1vbmdvZGIub3JnL3YyLjYvcmVmZXJlbmNlL29wZXJhdG9yL3F1ZXJ5L3JlZ2V4LyNpbmRleC11c2UpLFxuICAvLyB0aGlzIGhhcyBiZWVuIGZvdW5kIHRvIGdyZWF0bHkgaW1wcm92ZSBwZXJmb3JtYW5jZSAoZnJvbSAxMjAwbXMgdG8gNW1zIGluIGFcbiAgLy8gdGVzdCB3aXRoIDEuMDAwLjAwMCB1c2VycykuXG4gIF9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAgPSAoZmllbGROYW1lLCBzdHJpbmcpID0+IHtcbiAgICAvLyBQZXJmb3JtYW5jZSBzZWVtcyB0byBpbXByb3ZlIHVwIHRvIDQgcHJlZml4IGNoYXJhY3RlcnNcbiAgICBjb25zdCBwcmVmaXggPSBzdHJpbmcuc3Vic3RyaW5nKDAsIE1hdGgubWluKHN0cmluZy5sZW5ndGgsIDQpKTtcbiAgICBjb25zdCBvckNsYXVzZSA9IGdlbmVyYXRlQ2FzZVBlcm11dGF0aW9uc0ZvclN0cmluZyhwcmVmaXgpLm1hcChcbiAgICAgICAgcHJlZml4UGVybXV0YXRpb24gPT4ge1xuICAgICAgICAgIGNvbnN0IHNlbGVjdG9yID0ge307XG4gICAgICAgICAgc2VsZWN0b3JbZmllbGROYW1lXSA9XG4gICAgICAgICAgICAgIG5ldyBSZWdFeHAoYF4ke01ldGVvci5fZXNjYXBlUmVnRXhwKHByZWZpeFBlcm11dGF0aW9uKX1gKTtcbiAgICAgICAgICByZXR1cm4gc2VsZWN0b3I7XG4gICAgICAgIH0pO1xuICAgIGNvbnN0IGNhc2VJbnNlbnNpdGl2ZUNsYXVzZSA9IHt9O1xuICAgIGNhc2VJbnNlbnNpdGl2ZUNsYXVzZVtmaWVsZE5hbWVdID1cbiAgICAgICAgbmV3IFJlZ0V4cChgXiR7TWV0ZW9yLl9lc2NhcGVSZWdFeHAoc3RyaW5nKX0kYCwgJ2knKVxuICAgIHJldHVybiB7JGFuZDogW3skb3I6IG9yQ2xhdXNlfSwgY2FzZUluc2Vuc2l0aXZlQ2xhdXNlXX07XG4gIH1cblxuICBfZmluZFVzZXJCeVF1ZXJ5ID0gKHF1ZXJ5LCBvcHRpb25zKSA9PiB7XG4gICAgbGV0IHVzZXIgPSBudWxsO1xuXG4gICAgaWYgKHF1ZXJ5LmlkKSB7XG4gICAgICAvLyBkZWZhdWx0IGZpZWxkIHNlbGVjdG9yIGlzIGFkZGVkIHdpdGhpbiBnZXRVc2VyQnlJZCgpXG4gICAgICB1c2VyID0gTWV0ZW9yLnVzZXJzLmZpbmRPbmUocXVlcnkuaWQsIHRoaXMuX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKG9wdGlvbnMpKTtcbiAgICB9IGVsc2Uge1xuICAgICAgb3B0aW9ucyA9IHRoaXMuX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKG9wdGlvbnMpO1xuICAgICAgbGV0IGZpZWxkTmFtZTtcbiAgICAgIGxldCBmaWVsZFZhbHVlO1xuICAgICAgaWYgKHF1ZXJ5LnVzZXJuYW1lKSB7XG4gICAgICAgIGZpZWxkTmFtZSA9ICd1c2VybmFtZSc7XG4gICAgICAgIGZpZWxkVmFsdWUgPSBxdWVyeS51c2VybmFtZTtcbiAgICAgIH0gZWxzZSBpZiAocXVlcnkuZW1haWwpIHtcbiAgICAgICAgZmllbGROYW1lID0gJ2VtYWlscy5hZGRyZXNzJztcbiAgICAgICAgZmllbGRWYWx1ZSA9IHF1ZXJ5LmVtYWlsO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwic2hvdWxkbid0IGhhcHBlbiAodmFsaWRhdGlvbiBtaXNzZWQgc29tZXRoaW5nKVwiKTtcbiAgICAgIH1cbiAgICAgIGxldCBzZWxlY3RvciA9IHt9O1xuICAgICAgc2VsZWN0b3JbZmllbGROYW1lXSA9IGZpZWxkVmFsdWU7XG4gICAgICB1c2VyID0gTWV0ZW9yLnVzZXJzLmZpbmRPbmUoc2VsZWN0b3IsIG9wdGlvbnMpO1xuICAgICAgLy8gSWYgdXNlciBpcyBub3QgZm91bmQsIHRyeSBhIGNhc2UgaW5zZW5zaXRpdmUgbG9va3VwXG4gICAgICBpZiAoIXVzZXIpIHtcbiAgICAgICAgc2VsZWN0b3IgPSB0aGlzLl9zZWxlY3RvckZvckZhc3RDYXNlSW5zZW5zaXRpdmVMb29rdXAoZmllbGROYW1lLCBmaWVsZFZhbHVlKTtcbiAgICAgICAgY29uc3QgY2FuZGlkYXRlVXNlcnMgPSBNZXRlb3IudXNlcnMuZmluZChzZWxlY3Rvciwgb3B0aW9ucykuZmV0Y2goKTtcbiAgICAgICAgLy8gTm8gbWF0Y2ggaWYgbXVsdGlwbGUgY2FuZGlkYXRlcyBhcmUgZm91bmRcbiAgICAgICAgaWYgKGNhbmRpZGF0ZVVzZXJzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgIHVzZXIgPSBjYW5kaWRhdGVVc2Vyc1swXTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB1c2VyO1xuICB9XG5cbiAgLy8vXG4gIC8vLyBMT0dJTiBNRVRIT0RTXG4gIC8vL1xuXG4gIC8vIExvZ2luIG1ldGhvZHMgcmV0dXJuIHRvIHRoZSBjbGllbnQgYW4gb2JqZWN0IGNvbnRhaW5pbmcgdGhlc2VcbiAgLy8gZmllbGRzIHdoZW4gdGhlIHVzZXIgd2FzIGxvZ2dlZCBpbiBzdWNjZXNzZnVsbHk6XG4gIC8vXG4gIC8vICAgaWQ6IHVzZXJJZFxuICAvLyAgIHRva2VuOiAqXG4gIC8vICAgdG9rZW5FeHBpcmVzOiAqXG4gIC8vXG4gIC8vIHRva2VuRXhwaXJlcyBpcyBvcHRpb25hbCBhbmQgaW50ZW5kcyB0byBwcm92aWRlIGEgaGludCB0byB0aGVcbiAgLy8gY2xpZW50IGFzIHRvIHdoZW4gdGhlIHRva2VuIHdpbGwgZXhwaXJlLiBJZiBub3QgcHJvdmlkZWQsIHRoZVxuICAvLyBjbGllbnQgd2lsbCBjYWxsIEFjY291bnRzLl90b2tlbkV4cGlyYXRpb24sIHBhc3NpbmcgaXQgdGhlIGRhdGVcbiAgLy8gdGhhdCBpdCByZWNlaXZlZCB0aGUgdG9rZW4uXG4gIC8vXG4gIC8vIFRoZSBsb2dpbiBtZXRob2Qgd2lsbCB0aHJvdyBhbiBlcnJvciBiYWNrIHRvIHRoZSBjbGllbnQgaWYgdGhlIHVzZXJcbiAgLy8gZmFpbGVkIHRvIGxvZyBpbi5cbiAgLy9cbiAgLy9cbiAgLy8gTG9naW4gaGFuZGxlcnMgYW5kIHNlcnZpY2Ugc3BlY2lmaWMgbG9naW4gbWV0aG9kcyBzdWNoIGFzXG4gIC8vIGBjcmVhdGVVc2VyYCBpbnRlcm5hbGx5IHJldHVybiBhIGByZXN1bHRgIG9iamVjdCBjb250YWluaW5nIHRoZXNlXG4gIC8vIGZpZWxkczpcbiAgLy9cbiAgLy8gICB0eXBlOlxuICAvLyAgICAgb3B0aW9uYWwgc3RyaW5nOyB0aGUgc2VydmljZSBuYW1lLCBvdmVycmlkZXMgdGhlIGhhbmRsZXJcbiAgLy8gICAgIGRlZmF1bHQgaWYgcHJlc2VudC5cbiAgLy9cbiAgLy8gICBlcnJvcjpcbiAgLy8gICAgIGV4Y2VwdGlvbjsgaWYgdGhlIHVzZXIgaXMgbm90IGFsbG93ZWQgdG8gbG9naW4sIHRoZSByZWFzb24gd2h5LlxuICAvL1xuICAvLyAgIHVzZXJJZDpcbiAgLy8gICAgIHN0cmluZzsgdGhlIHVzZXIgaWQgb2YgdGhlIHVzZXIgYXR0ZW1wdGluZyB0byBsb2dpbiAoaWZcbiAgLy8gICAgIGtub3duKSwgcmVxdWlyZWQgZm9yIGFuIGFsbG93ZWQgbG9naW4uXG4gIC8vXG4gIC8vICAgb3B0aW9uczpcbiAgLy8gICAgIG9wdGlvbmFsIG9iamVjdCBtZXJnZWQgaW50byB0aGUgcmVzdWx0IHJldHVybmVkIGJ5IHRoZSBsb2dpblxuICAvLyAgICAgbWV0aG9kOyB1c2VkIGJ5IEhBTUsgZnJvbSBTUlAuXG4gIC8vXG4gIC8vICAgc3RhbXBlZExvZ2luVG9rZW46XG4gIC8vICAgICBvcHRpb25hbCBvYmplY3Qgd2l0aCBgdG9rZW5gIGFuZCBgd2hlbmAgaW5kaWNhdGluZyB0aGUgbG9naW5cbiAgLy8gICAgIHRva2VuIGlzIGFscmVhZHkgcHJlc2VudCBpbiB0aGUgZGF0YWJhc2UsIHJldHVybmVkIGJ5IHRoZVxuICAvLyAgICAgXCJyZXN1bWVcIiBsb2dpbiBoYW5kbGVyLlxuICAvL1xuICAvLyBGb3IgY29udmVuaWVuY2UsIGxvZ2luIG1ldGhvZHMgY2FuIGFsc28gdGhyb3cgYW4gZXhjZXB0aW9uLCB3aGljaFxuICAvLyBpcyBjb252ZXJ0ZWQgaW50byBhbiB7ZXJyb3J9IHJlc3VsdC4gIEhvd2V2ZXIsIGlmIHRoZSBpZCBvZiB0aGVcbiAgLy8gdXNlciBhdHRlbXB0aW5nIHRoZSBsb2dpbiBpcyBrbm93biwgYSB7dXNlcklkLCBlcnJvcn0gcmVzdWx0IHNob3VsZFxuICAvLyBiZSByZXR1cm5lZCBpbnN0ZWFkIHNpbmNlIHRoZSB1c2VyIGlkIGlzIG5vdCBjYXB0dXJlZCB3aGVuIGFuXG4gIC8vIGV4Y2VwdGlvbiBpcyB0aHJvd24uXG4gIC8vXG4gIC8vIFRoaXMgaW50ZXJuYWwgYHJlc3VsdGAgb2JqZWN0IGlzIGF1dG9tYXRpY2FsbHkgY29udmVydGVkIGludG8gdGhlXG4gIC8vIHB1YmxpYyB7aWQsIHRva2VuLCB0b2tlbkV4cGlyZXN9IG9iamVjdCByZXR1cm5lZCB0byB0aGUgY2xpZW50LlxuXG4gIC8vIFRyeSBhIGxvZ2luIG1ldGhvZCwgY29udmVydGluZyB0aHJvd24gZXhjZXB0aW9ucyBpbnRvIGFuIHtlcnJvcn1cbiAgLy8gcmVzdWx0LiAgVGhlIGB0eXBlYCBhcmd1bWVudCBpcyBhIGRlZmF1bHQsIGluc2VydGVkIGludG8gdGhlIHJlc3VsdFxuICAvLyBvYmplY3QgaWYgbm90IGV4cGxpY2l0bHkgcmV0dXJuZWQuXG4gIC8vXG4gIC8vIExvZyBpbiBhIHVzZXIgb24gYSBjb25uZWN0aW9uLlxuICAvL1xuICAvLyBXZSB1c2UgdGhlIG1ldGhvZCBpbnZvY2F0aW9uIHRvIHNldCB0aGUgdXNlciBpZCBvbiB0aGUgY29ubmVjdGlvbixcbiAgLy8gbm90IHRoZSBjb25uZWN0aW9uIG9iamVjdCBkaXJlY3RseS4gc2V0VXNlcklkIGlzIHRpZWQgdG8gbWV0aG9kcyB0b1xuICAvLyBlbmZvcmNlIGNsZWFyIG9yZGVyaW5nIG9mIG1ldGhvZCBhcHBsaWNhdGlvbiAodXNpbmcgd2FpdCBtZXRob2RzIG9uXG4gIC8vIHRoZSBjbGllbnQsIGFuZCBhIG5vIHNldFVzZXJJZCBhZnRlciB1bmJsb2NrIHJlc3RyaWN0aW9uIG9uIHRoZVxuICAvLyBzZXJ2ZXIpXG4gIC8vXG4gIC8vIFRoZSBgc3RhbXBlZExvZ2luVG9rZW5gIHBhcmFtZXRlciBpcyBvcHRpb25hbC4gIFdoZW4gcHJlc2VudCwgaXRcbiAgLy8gaW5kaWNhdGVzIHRoYXQgdGhlIGxvZ2luIHRva2VuIGhhcyBhbHJlYWR5IGJlZW4gaW5zZXJ0ZWQgaW50byB0aGVcbiAgLy8gZGF0YWJhc2UgYW5kIGRvZXNuJ3QgbmVlZCB0byBiZSBpbnNlcnRlZCBhZ2Fpbi4gIChJdCdzIHVzZWQgYnkgdGhlXG4gIC8vIFwicmVzdW1lXCIgbG9naW4gaGFuZGxlcikuXG4gIF9sb2dpblVzZXIobWV0aG9kSW52b2NhdGlvbiwgdXNlcklkLCBzdGFtcGVkTG9naW5Ub2tlbikge1xuICAgIGlmICghIHN0YW1wZWRMb2dpblRva2VuKSB7XG4gICAgICBzdGFtcGVkTG9naW5Ub2tlbiA9IHRoaXMuX2dlbmVyYXRlU3RhbXBlZExvZ2luVG9rZW4oKTtcbiAgICAgIHRoaXMuX2luc2VydExvZ2luVG9rZW4odXNlcklkLCBzdGFtcGVkTG9naW5Ub2tlbik7XG4gICAgfVxuXG4gICAgLy8gVGhpcyBvcmRlciAoYW5kIHRoZSBhdm9pZGFuY2Ugb2YgeWllbGRzKSBpcyBpbXBvcnRhbnQgdG8gbWFrZVxuICAgIC8vIHN1cmUgdGhhdCB3aGVuIHB1Ymxpc2ggZnVuY3Rpb25zIGFyZSByZXJ1biwgdGhleSBzZWUgYVxuICAgIC8vIGNvbnNpc3RlbnQgdmlldyBvZiB0aGUgd29ybGQ6IHRoZSB1c2VySWQgaXMgc2V0IGFuZCBtYXRjaGVzXG4gICAgLy8gdGhlIGxvZ2luIHRva2VuIG9uIHRoZSBjb25uZWN0aW9uIChub3QgdGhhdCB0aGVyZSBpc1xuICAgIC8vIGN1cnJlbnRseSBhIHB1YmxpYyBBUEkgZm9yIHJlYWRpbmcgdGhlIGxvZ2luIHRva2VuIG9uIGFcbiAgICAvLyBjb25uZWN0aW9uKS5cbiAgICBNZXRlb3IuX25vWWllbGRzQWxsb3dlZCgoKSA9PlxuICAgICAgdGhpcy5fc2V0TG9naW5Ub2tlbihcbiAgICAgICAgdXNlcklkLFxuICAgICAgICBtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sXG4gICAgICAgIHRoaXMuX2hhc2hMb2dpblRva2VuKHN0YW1wZWRMb2dpblRva2VuLnRva2VuKVxuICAgICAgKVxuICAgICk7XG5cbiAgICBtZXRob2RJbnZvY2F0aW9uLnNldFVzZXJJZCh1c2VySWQpO1xuXG4gICAgcmV0dXJuIHtcbiAgICAgIGlkOiB1c2VySWQsXG4gICAgICB0b2tlbjogc3RhbXBlZExvZ2luVG9rZW4udG9rZW4sXG4gICAgICB0b2tlbkV4cGlyZXM6IHRoaXMuX3Rva2VuRXhwaXJhdGlvbihzdGFtcGVkTG9naW5Ub2tlbi53aGVuKVxuICAgIH07XG4gIH07XG5cbiAgLy8gQWZ0ZXIgYSBsb2dpbiBtZXRob2QgaGFzIGNvbXBsZXRlZCwgY2FsbCB0aGUgbG9naW4gaG9va3MuICBOb3RlXG4gIC8vIHRoYXQgYGF0dGVtcHRMb2dpbmAgaXMgY2FsbGVkIGZvciAqYWxsKiBsb2dpbiBhdHRlbXB0cywgZXZlbiBvbmVzXG4gIC8vIHdoaWNoIGFyZW4ndCBzdWNjZXNzZnVsIChzdWNoIGFzIGFuIGludmFsaWQgcGFzc3dvcmQsIGV0YykuXG4gIC8vXG4gIC8vIElmIHRoZSBsb2dpbiBpcyBhbGxvd2VkIGFuZCBpc24ndCBhYm9ydGVkIGJ5IGEgdmFsaWRhdGUgbG9naW4gaG9va1xuICAvLyBjYWxsYmFjaywgbG9nIGluIHRoZSB1c2VyLlxuICAvL1xuICBfYXR0ZW1wdExvZ2luKFxuICAgIG1ldGhvZEludm9jYXRpb24sXG4gICAgbWV0aG9kTmFtZSxcbiAgICBtZXRob2RBcmdzLFxuICAgIHJlc3VsdFxuICApIHtcbiAgICBpZiAoIXJlc3VsdClcbiAgICAgIHRocm93IG5ldyBFcnJvcihcInJlc3VsdCBpcyByZXF1aXJlZFwiKTtcblxuICAgIC8vIFhYWCBBIHByb2dyYW1taW5nIGVycm9yIGluIGEgbG9naW4gaGFuZGxlciBjYW4gbGVhZCB0byB0aGlzIG9jY3VycmluZywgYW5kXG4gICAgLy8gdGhlbiB3ZSBkb24ndCBjYWxsIG9uTG9naW4gb3Igb25Mb2dpbkZhaWx1cmUgY2FsbGJhY2tzLiBTaG91bGRcbiAgICAvLyB0cnlMb2dpbk1ldGhvZCBjYXRjaCB0aGlzIGNhc2UgYW5kIHR1cm4gaXQgaW50byBhbiBlcnJvcj9cbiAgICBpZiAoIXJlc3VsdC51c2VySWQgJiYgIXJlc3VsdC5lcnJvcilcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkEgbG9naW4gbWV0aG9kIG11c3Qgc3BlY2lmeSBhIHVzZXJJZCBvciBhbiBlcnJvclwiKTtcblxuICAgIGxldCB1c2VyO1xuICAgIGlmIChyZXN1bHQudXNlcklkKVxuICAgICAgdXNlciA9IHRoaXMudXNlcnMuZmluZE9uZShyZXN1bHQudXNlcklkLCB7ZmllbGRzOiB0aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yfSk7XG5cbiAgICBjb25zdCBhdHRlbXB0ID0ge1xuICAgICAgdHlwZTogcmVzdWx0LnR5cGUgfHwgXCJ1bmtub3duXCIsXG4gICAgICBhbGxvd2VkOiAhISAocmVzdWx0LnVzZXJJZCAmJiAhcmVzdWx0LmVycm9yKSxcbiAgICAgIG1ldGhvZE5hbWU6IG1ldGhvZE5hbWUsXG4gICAgICBtZXRob2RBcmd1bWVudHM6IEFycmF5LmZyb20obWV0aG9kQXJncylcbiAgICB9O1xuICAgIGlmIChyZXN1bHQuZXJyb3IpIHtcbiAgICAgIGF0dGVtcHQuZXJyb3IgPSByZXN1bHQuZXJyb3I7XG4gICAgfVxuICAgIGlmICh1c2VyKSB7XG4gICAgICBhdHRlbXB0LnVzZXIgPSB1c2VyO1xuICAgIH1cblxuICAgIC8vIF92YWxpZGF0ZUxvZ2luIG1heSBtdXRhdGUgYGF0dGVtcHRgIGJ5IGFkZGluZyBhbiBlcnJvciBhbmQgY2hhbmdpbmcgYWxsb3dlZFxuICAgIC8vIHRvIGZhbHNlLCBidXQgdGhhdCdzIHRoZSBvbmx5IGNoYW5nZSBpdCBjYW4gbWFrZSAoYW5kIHRoZSB1c2VyJ3MgY2FsbGJhY2tzXG4gICAgLy8gb25seSBnZXQgYSBjbG9uZSBvZiBgYXR0ZW1wdGApLlxuICAgIHRoaXMuX3ZhbGlkYXRlTG9naW4obWV0aG9kSW52b2NhdGlvbi5jb25uZWN0aW9uLCBhdHRlbXB0KTtcblxuICAgIGlmIChhdHRlbXB0LmFsbG93ZWQpIHtcbiAgICAgIGNvbnN0IHJldCA9IHtcbiAgICAgICAgLi4udGhpcy5fbG9naW5Vc2VyKFxuICAgICAgICAgIG1ldGhvZEludm9jYXRpb24sXG4gICAgICAgICAgcmVzdWx0LnVzZXJJZCxcbiAgICAgICAgICByZXN1bHQuc3RhbXBlZExvZ2luVG9rZW5cbiAgICAgICAgKSxcbiAgICAgICAgLi4ucmVzdWx0Lm9wdGlvbnNcbiAgICAgIH07XG4gICAgICByZXQudHlwZSA9IGF0dGVtcHQudHlwZTtcbiAgICAgIHRoaXMuX3N1Y2Nlc3NmdWxMb2dpbihtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sIGF0dGVtcHQpO1xuICAgICAgcmV0dXJuIHJldDtcbiAgICB9XG4gICAgZWxzZSB7XG4gICAgICB0aGlzLl9mYWlsZWRMb2dpbihtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sIGF0dGVtcHQpO1xuICAgICAgdGhyb3cgYXR0ZW1wdC5lcnJvcjtcbiAgICB9XG4gIH07XG5cbiAgLy8gQWxsIHNlcnZpY2Ugc3BlY2lmaWMgbG9naW4gbWV0aG9kcyBzaG91bGQgZ28gdGhyb3VnaCB0aGlzIGZ1bmN0aW9uLlxuICAvLyBFbnN1cmUgdGhhdCB0aHJvd24gZXhjZXB0aW9ucyBhcmUgY2F1Z2h0IGFuZCB0aGF0IGxvZ2luIGhvb2tcbiAgLy8gY2FsbGJhY2tzIGFyZSBzdGlsbCBjYWxsZWQuXG4gIC8vXG4gIF9sb2dpbk1ldGhvZChcbiAgICBtZXRob2RJbnZvY2F0aW9uLFxuICAgIG1ldGhvZE5hbWUsXG4gICAgbWV0aG9kQXJncyxcbiAgICB0eXBlLFxuICAgIGZuXG4gICkge1xuICAgIHJldHVybiB0aGlzLl9hdHRlbXB0TG9naW4oXG4gICAgICBtZXRob2RJbnZvY2F0aW9uLFxuICAgICAgbWV0aG9kTmFtZSxcbiAgICAgIG1ldGhvZEFyZ3MsXG4gICAgICB0cnlMb2dpbk1ldGhvZCh0eXBlLCBmbilcbiAgICApO1xuICB9O1xuXG5cbiAgLy8gUmVwb3J0IGEgbG9naW4gYXR0ZW1wdCBmYWlsZWQgb3V0c2lkZSB0aGUgY29udGV4dCBvZiBhIG5vcm1hbCBsb2dpblxuICAvLyBtZXRob2QuIFRoaXMgaXMgZm9yIHVzZSBpbiB0aGUgY2FzZSB3aGVyZSB0aGVyZSBpcyBhIG11bHRpLXN0ZXAgbG9naW5cbiAgLy8gcHJvY2VkdXJlIChlZyBTUlAgYmFzZWQgcGFzc3dvcmQgbG9naW4pLiBJZiBhIG1ldGhvZCBlYXJseSBpbiB0aGVcbiAgLy8gY2hhaW4gZmFpbHMsIGl0IHNob3VsZCBjYWxsIHRoaXMgZnVuY3Rpb24gdG8gcmVwb3J0IGEgZmFpbHVyZS4gVGhlcmVcbiAgLy8gaXMgbm8gY29ycmVzcG9uZGluZyBtZXRob2QgZm9yIGEgc3VjY2Vzc2Z1bCBsb2dpbjsgbWV0aG9kcyB0aGF0IGNhblxuICAvLyBzdWNjZWVkIGF0IGxvZ2dpbmcgYSB1c2VyIGluIHNob3VsZCBhbHdheXMgYmUgYWN0dWFsIGxvZ2luIG1ldGhvZHNcbiAgLy8gKHVzaW5nIGVpdGhlciBBY2NvdW50cy5fbG9naW5NZXRob2Qgb3IgQWNjb3VudHMucmVnaXN0ZXJMb2dpbkhhbmRsZXIpLlxuICBfcmVwb3J0TG9naW5GYWlsdXJlKFxuICAgIG1ldGhvZEludm9jYXRpb24sXG4gICAgbWV0aG9kTmFtZSxcbiAgICBtZXRob2RBcmdzLFxuICAgIHJlc3VsdFxuICApIHtcbiAgICBjb25zdCBhdHRlbXB0ID0ge1xuICAgICAgdHlwZTogcmVzdWx0LnR5cGUgfHwgXCJ1bmtub3duXCIsXG4gICAgICBhbGxvd2VkOiBmYWxzZSxcbiAgICAgIGVycm9yOiByZXN1bHQuZXJyb3IsXG4gICAgICBtZXRob2ROYW1lOiBtZXRob2ROYW1lLFxuICAgICAgbWV0aG9kQXJndW1lbnRzOiBBcnJheS5mcm9tKG1ldGhvZEFyZ3MpXG4gICAgfTtcblxuICAgIGlmIChyZXN1bHQudXNlcklkKSB7XG4gICAgICBhdHRlbXB0LnVzZXIgPSB0aGlzLnVzZXJzLmZpbmRPbmUocmVzdWx0LnVzZXJJZCwge2ZpZWxkczogdGhpcy5fb3B0aW9ucy5kZWZhdWx0RmllbGRTZWxlY3Rvcn0pO1xuICAgIH1cblxuICAgIHRoaXMuX3ZhbGlkYXRlTG9naW4obWV0aG9kSW52b2NhdGlvbi5jb25uZWN0aW9uLCBhdHRlbXB0KTtcbiAgICB0aGlzLl9mYWlsZWRMb2dpbihtZXRob2RJbnZvY2F0aW9uLmNvbm5lY3Rpb24sIGF0dGVtcHQpO1xuXG4gICAgLy8gX3ZhbGlkYXRlTG9naW4gbWF5IG11dGF0ZSBhdHRlbXB0IHRvIHNldCBhIG5ldyBlcnJvciBtZXNzYWdlLiBSZXR1cm5cbiAgICAvLyB0aGUgbW9kaWZpZWQgdmVyc2lvbi5cbiAgICByZXR1cm4gYXR0ZW1wdDtcbiAgfTtcblxuICAvLy9cbiAgLy8vIExPR0lOIEhBTkRMRVJTXG4gIC8vL1xuXG4gIC8vIFRoZSBtYWluIGVudHJ5IHBvaW50IGZvciBhdXRoIHBhY2thZ2VzIHRvIGhvb2sgaW4gdG8gbG9naW4uXG4gIC8vXG4gIC8vIEEgbG9naW4gaGFuZGxlciBpcyBhIGxvZ2luIG1ldGhvZCB3aGljaCBjYW4gcmV0dXJuIGB1bmRlZmluZWRgIHRvXG4gIC8vIGluZGljYXRlIHRoYXQgdGhlIGxvZ2luIHJlcXVlc3QgaXMgbm90IGhhbmRsZWQgYnkgdGhpcyBoYW5kbGVyLlxuICAvL1xuICAvLyBAcGFyYW0gbmFtZSB7U3RyaW5nfSBPcHRpb25hbC4gIFRoZSBzZXJ2aWNlIG5hbWUsIHVzZWQgYnkgZGVmYXVsdFxuICAvLyBpZiBhIHNwZWNpZmljIHNlcnZpY2UgbmFtZSBpc24ndCByZXR1cm5lZCBpbiB0aGUgcmVzdWx0LlxuICAvL1xuICAvLyBAcGFyYW0gaGFuZGxlciB7RnVuY3Rpb259IEEgZnVuY3Rpb24gdGhhdCByZWNlaXZlcyBhbiBvcHRpb25zIG9iamVjdFxuICAvLyAoYXMgcGFzc2VkIGFzIGFuIGFyZ3VtZW50IHRvIHRoZSBgbG9naW5gIG1ldGhvZCkgYW5kIHJldHVybnMgb25lIG9mOlxuICAvLyAtIGB1bmRlZmluZWRgLCBtZWFuaW5nIGRvbid0IGhhbmRsZTtcbiAgLy8gLSBhIGxvZ2luIG1ldGhvZCByZXN1bHQgb2JqZWN0XG5cbiAgcmVnaXN0ZXJMb2dpbkhhbmRsZXIobmFtZSwgaGFuZGxlcikge1xuICAgIGlmICghIGhhbmRsZXIpIHtcbiAgICAgIGhhbmRsZXIgPSBuYW1lO1xuICAgICAgbmFtZSA9IG51bGw7XG4gICAgfVxuXG4gICAgdGhpcy5fbG9naW5IYW5kbGVycy5wdXNoKHtcbiAgICAgIG5hbWU6IG5hbWUsXG4gICAgICBoYW5kbGVyOiBoYW5kbGVyXG4gICAgfSk7XG4gIH07XG5cblxuICAvLyBDaGVja3MgYSB1c2VyJ3MgY3JlZGVudGlhbHMgYWdhaW5zdCBhbGwgdGhlIHJlZ2lzdGVyZWQgbG9naW5cbiAgLy8gaGFuZGxlcnMsIGFuZCByZXR1cm5zIGEgbG9naW4gdG9rZW4gaWYgdGhlIGNyZWRlbnRpYWxzIGFyZSB2YWxpZC4gSXRcbiAgLy8gaXMgbGlrZSB0aGUgbG9naW4gbWV0aG9kLCBleGNlcHQgdGhhdCBpdCBkb2Vzbid0IHNldCB0aGUgbG9nZ2VkLWluXG4gIC8vIHVzZXIgb24gdGhlIGNvbm5lY3Rpb24uIFRocm93cyBhIE1ldGVvci5FcnJvciBpZiBsb2dnaW5nIGluIGZhaWxzLFxuICAvLyBpbmNsdWRpbmcgdGhlIGNhc2Ugd2hlcmUgbm9uZSBvZiB0aGUgbG9naW4gaGFuZGxlcnMgaGFuZGxlZCB0aGUgbG9naW5cbiAgLy8gcmVxdWVzdC4gT3RoZXJ3aXNlLCByZXR1cm5zIHtpZDogdXNlcklkLCB0b2tlbjogKiwgdG9rZW5FeHBpcmVzOiAqfS5cbiAgLy9cbiAgLy8gRm9yIGV4YW1wbGUsIGlmIHlvdSB3YW50IHRvIGxvZ2luIHdpdGggYSBwbGFpbnRleHQgcGFzc3dvcmQsIGBvcHRpb25zYCBjb3VsZCBiZVxuICAvLyAgIHsgdXNlcjogeyB1c2VybmFtZTogPHVzZXJuYW1lPiB9LCBwYXNzd29yZDogPHBhc3N3b3JkPiB9LCBvclxuICAvLyAgIHsgdXNlcjogeyBlbWFpbDogPGVtYWlsPiB9LCBwYXNzd29yZDogPHBhc3N3b3JkPiB9LlxuXG4gIC8vIFRyeSBhbGwgb2YgdGhlIHJlZ2lzdGVyZWQgbG9naW4gaGFuZGxlcnMgdW50aWwgb25lIG9mIHRoZW0gZG9lc24ndFxuICAvLyByZXR1cm4gYHVuZGVmaW5lZGAsIG1lYW5pbmcgaXQgaGFuZGxlZCB0aGlzIGNhbGwgdG8gYGxvZ2luYC4gUmV0dXJuXG4gIC8vIHRoYXQgcmV0dXJuIHZhbHVlLlxuICBfcnVuTG9naW5IYW5kbGVycyhtZXRob2RJbnZvY2F0aW9uLCBvcHRpb25zKSB7XG4gICAgZm9yIChsZXQgaGFuZGxlciBvZiB0aGlzLl9sb2dpbkhhbmRsZXJzKSB7XG4gICAgICBjb25zdCByZXN1bHQgPSB0cnlMb2dpbk1ldGhvZChcbiAgICAgICAgaGFuZGxlci5uYW1lLFxuICAgICAgICAoKSA9PiBoYW5kbGVyLmhhbmRsZXIuY2FsbChtZXRob2RJbnZvY2F0aW9uLCBvcHRpb25zKVxuICAgICAgKTtcblxuICAgICAgaWYgKHJlc3VsdCkge1xuICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgfVxuXG4gICAgICBpZiAocmVzdWx0ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgdGhyb3cgbmV3IE1ldGVvci5FcnJvcig0MDAsIFwiQSBsb2dpbiBoYW5kbGVyIHNob3VsZCByZXR1cm4gYSByZXN1bHQgb3IgdW5kZWZpbmVkXCIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB7XG4gICAgICB0eXBlOiBudWxsLFxuICAgICAgZXJyb3I6IG5ldyBNZXRlb3IuRXJyb3IoNDAwLCBcIlVucmVjb2duaXplZCBvcHRpb25zIGZvciBsb2dpbiByZXF1ZXN0XCIpXG4gICAgfTtcbiAgfTtcblxuICAvLyBEZWxldGVzIHRoZSBnaXZlbiBsb2dpblRva2VuIGZyb20gdGhlIGRhdGFiYXNlLlxuICAvL1xuICAvLyBGb3IgbmV3LXN0eWxlIGhhc2hlZCB0b2tlbiwgdGhpcyB3aWxsIGNhdXNlIGFsbCBjb25uZWN0aW9uc1xuICAvLyBhc3NvY2lhdGVkIHdpdGggdGhlIHRva2VuIHRvIGJlIGNsb3NlZC5cbiAgLy9cbiAgLy8gQW55IGNvbm5lY3Rpb25zIGFzc29jaWF0ZWQgd2l0aCBvbGQtc3R5bGUgdW5oYXNoZWQgdG9rZW5zIHdpbGwgYmVcbiAgLy8gaW4gdGhlIHByb2Nlc3Mgb2YgYmVjb21pbmcgYXNzb2NpYXRlZCB3aXRoIGhhc2hlZCB0b2tlbnMgYW5kIHRoZW5cbiAgLy8gdGhleSdsbCBnZXQgY2xvc2VkLlxuICBkZXN0cm95VG9rZW4odXNlcklkLCBsb2dpblRva2VuKSB7XG4gICAgdGhpcy51c2Vycy51cGRhdGUodXNlcklkLCB7XG4gICAgICAkcHVsbDoge1xuICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB7XG4gICAgICAgICAgJG9yOiBbXG4gICAgICAgICAgICB7IGhhc2hlZFRva2VuOiBsb2dpblRva2VuIH0sXG4gICAgICAgICAgICB7IHRva2VuOiBsb2dpblRva2VuIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgfTtcblxuICBfaW5pdFNlcnZlck1ldGhvZHMoKSB7XG4gICAgLy8gVGhlIG1ldGhvZHMgY3JlYXRlZCBpbiB0aGlzIGZ1bmN0aW9uIG5lZWQgdG8gYmUgY3JlYXRlZCBoZXJlIHNvIHRoYXRcbiAgICAvLyB0aGlzIHZhcmlhYmxlIGlzIGF2YWlsYWJsZSBpbiB0aGVpciBzY29wZS5cbiAgICBjb25zdCBhY2NvdW50cyA9IHRoaXM7XG5cblxuICAgIC8vIFRoaXMgb2JqZWN0IHdpbGwgYmUgcG9wdWxhdGVkIHdpdGggbWV0aG9kcyBhbmQgdGhlbiBwYXNzZWQgdG9cbiAgICAvLyBhY2NvdW50cy5fc2VydmVyLm1ldGhvZHMgZnVydGhlciBiZWxvdy5cbiAgICBjb25zdCBtZXRob2RzID0ge307XG5cbiAgICAvLyBAcmV0dXJucyB7T2JqZWN0fG51bGx9XG4gICAgLy8gICBJZiBzdWNjZXNzZnVsLCByZXR1cm5zIHt0b2tlbjogcmVjb25uZWN0VG9rZW4sIGlkOiB1c2VySWR9XG4gICAgLy8gICBJZiB1bnN1Y2Nlc3NmdWwgKGZvciBleGFtcGxlLCBpZiB0aGUgdXNlciBjbG9zZWQgdGhlIG9hdXRoIGxvZ2luIHBvcHVwKSxcbiAgICAvLyAgICAgdGhyb3dzIGFuIGVycm9yIGRlc2NyaWJpbmcgdGhlIHJlYXNvblxuICAgIG1ldGhvZHMubG9naW4gPSBmdW5jdGlvbiAob3B0aW9ucykge1xuICAgICAgLy8gTG9naW4gaGFuZGxlcnMgc2hvdWxkIHJlYWxseSBhbHNvIGNoZWNrIHdoYXRldmVyIGZpZWxkIHRoZXkgbG9vayBhdCBpblxuICAgICAgLy8gb3B0aW9ucywgYnV0IHdlIGRvbid0IGVuZm9yY2UgaXQuXG4gICAgICBjaGVjayhvcHRpb25zLCBPYmplY3QpO1xuXG4gICAgICBjb25zdCByZXN1bHQgPSBhY2NvdW50cy5fcnVuTG9naW5IYW5kbGVycyh0aGlzLCBvcHRpb25zKTtcblxuICAgICAgcmV0dXJuIGFjY291bnRzLl9hdHRlbXB0TG9naW4odGhpcywgXCJsb2dpblwiLCBhcmd1bWVudHMsIHJlc3VsdCk7XG4gICAgfTtcblxuICAgIG1ldGhvZHMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgY29uc3QgdG9rZW4gPSBhY2NvdW50cy5fZ2V0TG9naW5Ub2tlbih0aGlzLmNvbm5lY3Rpb24uaWQpO1xuICAgICAgYWNjb3VudHMuX3NldExvZ2luVG9rZW4odGhpcy51c2VySWQsIHRoaXMuY29ubmVjdGlvbiwgbnVsbCk7XG4gICAgICBpZiAodG9rZW4gJiYgdGhpcy51c2VySWQpIHtcbiAgICAgICAgYWNjb3VudHMuZGVzdHJveVRva2VuKHRoaXMudXNlcklkLCB0b2tlbik7XG4gICAgICB9XG4gICAgICBhY2NvdW50cy5fc3VjY2Vzc2Z1bExvZ291dCh0aGlzLmNvbm5lY3Rpb24sIHRoaXMudXNlcklkKTtcbiAgICAgIHRoaXMuc2V0VXNlcklkKG51bGwpO1xuICAgIH07XG5cbiAgICAvLyBHZW5lcmF0ZXMgYSBuZXcgbG9naW4gdG9rZW4gd2l0aCB0aGUgc2FtZSBleHBpcmF0aW9uIGFzIHRoZVxuICAgIC8vIGNvbm5lY3Rpb24ncyBjdXJyZW50IHRva2VuIGFuZCBzYXZlcyBpdCB0byB0aGUgZGF0YWJhc2UuIEFzc29jaWF0ZXNcbiAgICAvLyB0aGUgY29ubmVjdGlvbiB3aXRoIHRoaXMgbmV3IHRva2VuIGFuZCByZXR1cm5zIGl0LiBUaHJvd3MgYW4gZXJyb3JcbiAgICAvLyBpZiBjYWxsZWQgb24gYSBjb25uZWN0aW9uIHRoYXQgaXNuJ3QgbG9nZ2VkIGluLlxuICAgIC8vXG4gICAgLy8gQHJldHVybnMgT2JqZWN0XG4gICAgLy8gICBJZiBzdWNjZXNzZnVsLCByZXR1cm5zIHsgdG9rZW46IDxuZXcgdG9rZW4+LCBpZDogPHVzZXIgaWQ+LFxuICAgIC8vICAgdG9rZW5FeHBpcmVzOiA8ZXhwaXJhdGlvbiBkYXRlPiB9LlxuICAgIG1ldGhvZHMuZ2V0TmV3VG9rZW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICBjb25zdCB1c2VyID0gYWNjb3VudHMudXNlcnMuZmluZE9uZSh0aGlzLnVzZXJJZCwge1xuICAgICAgICBmaWVsZHM6IHsgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjogMSB9XG4gICAgICB9KTtcbiAgICAgIGlmICghIHRoaXMudXNlcklkIHx8ICEgdXNlcikge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKFwiWW91IGFyZSBub3QgbG9nZ2VkIGluLlwiKTtcbiAgICAgIH1cbiAgICAgIC8vIEJlIGNhcmVmdWwgbm90IHRvIGdlbmVyYXRlIGEgbmV3IHRva2VuIHRoYXQgaGFzIGEgbGF0ZXJcbiAgICAgIC8vIGV4cGlyYXRpb24gdGhhbiB0aGUgY3VycmVuIHRva2VuLiBPdGhlcndpc2UsIGEgYmFkIGd1eSB3aXRoIGFcbiAgICAgIC8vIHN0b2xlbiB0b2tlbiBjb3VsZCB1c2UgdGhpcyBtZXRob2QgdG8gc3RvcCBoaXMgc3RvbGVuIHRva2VuIGZyb21cbiAgICAgIC8vIGV2ZXIgZXhwaXJpbmcuXG4gICAgICBjb25zdCBjdXJyZW50SGFzaGVkVG9rZW4gPSBhY2NvdW50cy5fZ2V0TG9naW5Ub2tlbih0aGlzLmNvbm5lY3Rpb24uaWQpO1xuICAgICAgY29uc3QgY3VycmVudFN0YW1wZWRUb2tlbiA9IHVzZXIuc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmZpbmQoXG4gICAgICAgIHN0YW1wZWRUb2tlbiA9PiBzdGFtcGVkVG9rZW4uaGFzaGVkVG9rZW4gPT09IGN1cnJlbnRIYXNoZWRUb2tlblxuICAgICAgKTtcbiAgICAgIGlmICghIGN1cnJlbnRTdGFtcGVkVG9rZW4pIHsgLy8gc2FmZXR5IGJlbHQ6IHRoaXMgc2hvdWxkIG5ldmVyIGhhcHBlblxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKFwiSW52YWxpZCBsb2dpbiB0b2tlblwiKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IG5ld1N0YW1wZWRUb2tlbiA9IGFjY291bnRzLl9nZW5lcmF0ZVN0YW1wZWRMb2dpblRva2VuKCk7XG4gICAgICBuZXdTdGFtcGVkVG9rZW4ud2hlbiA9IGN1cnJlbnRTdGFtcGVkVG9rZW4ud2hlbjtcbiAgICAgIGFjY291bnRzLl9pbnNlcnRMb2dpblRva2VuKHRoaXMudXNlcklkLCBuZXdTdGFtcGVkVG9rZW4pO1xuICAgICAgcmV0dXJuIGFjY291bnRzLl9sb2dpblVzZXIodGhpcywgdGhpcy51c2VySWQsIG5ld1N0YW1wZWRUb2tlbik7XG4gICAgfTtcblxuICAgIC8vIFJlbW92ZXMgYWxsIHRva2VucyBleGNlcHQgdGhlIHRva2VuIGFzc29jaWF0ZWQgd2l0aCB0aGUgY3VycmVudFxuICAgIC8vIGNvbm5lY3Rpb24uIFRocm93cyBhbiBlcnJvciBpZiB0aGUgY29ubmVjdGlvbiBpcyBub3QgbG9nZ2VkXG4gICAgLy8gaW4uIFJldHVybnMgbm90aGluZyBvbiBzdWNjZXNzLlxuICAgIG1ldGhvZHMucmVtb3ZlT3RoZXJUb2tlbnMgPSBmdW5jdGlvbiAoKSB7XG4gICAgICBpZiAoISB0aGlzLnVzZXJJZCkge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKFwiWW91IGFyZSBub3QgbG9nZ2VkIGluLlwiKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGN1cnJlbnRUb2tlbiA9IGFjY291bnRzLl9nZXRMb2dpblRva2VuKHRoaXMuY29ubmVjdGlvbi5pZCk7XG4gICAgICBhY2NvdW50cy51c2Vycy51cGRhdGUodGhpcy51c2VySWQsIHtcbiAgICAgICAgJHB1bGw6IHtcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB7IGhhc2hlZFRva2VuOiB7ICRuZTogY3VycmVudFRva2VuIH0gfVxuICAgICAgICB9XG4gICAgICB9KTtcbiAgICB9O1xuXG4gICAgLy8gQWxsb3cgYSBvbmUtdGltZSBjb25maWd1cmF0aW9uIGZvciBhIGxvZ2luIHNlcnZpY2UuIE1vZGlmaWNhdGlvbnNcbiAgICAvLyB0byB0aGlzIGNvbGxlY3Rpb24gYXJlIGFsc28gYWxsb3dlZCBpbiBpbnNlY3VyZSBtb2RlLlxuICAgIG1ldGhvZHMuY29uZmlndXJlTG9naW5TZXJ2aWNlID0gKG9wdGlvbnMpID0+IHtcbiAgICAgIGNoZWNrKG9wdGlvbnMsIE1hdGNoLk9iamVjdEluY2x1ZGluZyh7c2VydmljZTogU3RyaW5nfSkpO1xuICAgICAgLy8gRG9uJ3QgbGV0IHJhbmRvbSB1c2VycyBjb25maWd1cmUgYSBzZXJ2aWNlIHdlIGhhdmVuJ3QgYWRkZWQgeWV0IChzb1xuICAgICAgLy8gdGhhdCB3aGVuIHdlIGRvIGxhdGVyIGFkZCBpdCwgaXQncyBzZXQgdXAgd2l0aCB0aGVpciBjb25maWd1cmF0aW9uXG4gICAgICAvLyBpbnN0ZWFkIG9mIG91cnMpLlxuICAgICAgLy8gWFhYIGlmIHNlcnZpY2UgY29uZmlndXJhdGlvbiBpcyBvYXV0aC1zcGVjaWZpYyB0aGVuIHRoaXMgY29kZSBzaG91bGRcbiAgICAgIC8vICAgICBiZSBpbiBhY2NvdW50cy1vYXV0aDsgaWYgaXQncyBub3QgdGhlbiB0aGUgcmVnaXN0cnkgc2hvdWxkIGJlXG4gICAgICAvLyAgICAgaW4gdGhpcyBwYWNrYWdlXG4gICAgICBpZiAoIShhY2NvdW50cy5vYXV0aFxuICAgICAgICAmJiBhY2NvdW50cy5vYXV0aC5zZXJ2aWNlTmFtZXMoKS5pbmNsdWRlcyhvcHRpb25zLnNlcnZpY2UpKSkge1xuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJTZXJ2aWNlIHVua25vd25cIik7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHsgU2VydmljZUNvbmZpZ3VyYXRpb24gfSA9IFBhY2thZ2VbJ3NlcnZpY2UtY29uZmlndXJhdGlvbiddO1xuICAgICAgaWYgKFNlcnZpY2VDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zLmZpbmRPbmUoe3NlcnZpY2U6IG9wdGlvbnMuc2VydmljZX0pKVxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgYFNlcnZpY2UgJHtvcHRpb25zLnNlcnZpY2V9IGFscmVhZHkgY29uZmlndXJlZGApO1xuXG4gICAgICBpZiAoaGFzT3duLmNhbGwob3B0aW9ucywgJ3NlY3JldCcpICYmIHVzaW5nT0F1dGhFbmNyeXB0aW9uKCkpXG4gICAgICAgIG9wdGlvbnMuc2VjcmV0ID0gT0F1dGhFbmNyeXB0aW9uLnNlYWwob3B0aW9ucy5zZWNyZXQpO1xuXG4gICAgICBTZXJ2aWNlQ29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucy5pbnNlcnQob3B0aW9ucyk7XG4gICAgfTtcblxuICAgIGFjY291bnRzLl9zZXJ2ZXIubWV0aG9kcyhtZXRob2RzKTtcbiAgfTtcblxuICBfaW5pdEFjY291bnREYXRhSG9va3MoKSB7XG4gICAgdGhpcy5fc2VydmVyLm9uQ29ubmVjdGlvbihjb25uZWN0aW9uID0+IHtcbiAgICAgIHRoaXMuX2FjY291bnREYXRhW2Nvbm5lY3Rpb24uaWRdID0ge1xuICAgICAgICBjb25uZWN0aW9uOiBjb25uZWN0aW9uXG4gICAgICB9O1xuXG4gICAgICBjb25uZWN0aW9uLm9uQ2xvc2UoKCkgPT4ge1xuICAgICAgICB0aGlzLl9yZW1vdmVUb2tlbkZyb21Db25uZWN0aW9uKGNvbm5lY3Rpb24uaWQpO1xuICAgICAgICBkZWxldGUgdGhpcy5fYWNjb3VudERhdGFbY29ubmVjdGlvbi5pZF07XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfTtcblxuICBfaW5pdFNlcnZlclB1YmxpY2F0aW9ucygpIHtcbiAgICAvLyBCcmluZyBpbnRvIGxleGljYWwgc2NvcGUgZm9yIHB1Ymxpc2ggY2FsbGJhY2tzIHRoYXQgbmVlZCBgdGhpc2BcbiAgICBjb25zdCB7IHVzZXJzLCBfYXV0b3B1Ymxpc2hGaWVsZHMsIF9kZWZhdWx0UHVibGlzaEZpZWxkcyB9ID0gdGhpcztcblxuICAgIC8vIFB1Ymxpc2ggYWxsIGxvZ2luIHNlcnZpY2UgY29uZmlndXJhdGlvbiBmaWVsZHMgb3RoZXIgdGhhbiBzZWNyZXQuXG4gICAgdGhpcy5fc2VydmVyLnB1Ymxpc2goXCJtZXRlb3IubG9naW5TZXJ2aWNlQ29uZmlndXJhdGlvblwiLCAoKSA9PiB7XG4gICAgICBjb25zdCB7IFNlcnZpY2VDb25maWd1cmF0aW9uIH0gPSBQYWNrYWdlWydzZXJ2aWNlLWNvbmZpZ3VyYXRpb24nXTtcbiAgICAgIHJldHVybiBTZXJ2aWNlQ29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucy5maW5kKHt9LCB7ZmllbGRzOiB7c2VjcmV0OiAwfX0pO1xuICAgIH0sIHtpc19hdXRvOiB0cnVlfSk7IC8vIG5vdCB0ZWNobmljYWxseSBhdXRvcHVibGlzaCwgYnV0IHN0b3BzIHRoZSB3YXJuaW5nLlxuXG4gICAgLy8gVXNlIE1ldGVvci5zdGFydHVwIHRvIGdpdmUgb3RoZXIgcGFja2FnZXMgYSBjaGFuY2UgdG8gY2FsbFxuICAgIC8vIHNldERlZmF1bHRQdWJsaXNoRmllbGRzLlxuICAgIE1ldGVvci5zdGFydHVwKCgpID0+IHtcbiAgICAgIC8vIE1lcmdlIGN1c3RvbSBmaWVsZHMgc2VsZWN0b3IgYW5kIGRlZmF1bHQgcHVibGlzaCBmaWVsZHMgc28gdGhhdCB0aGUgY2xpZW50XG4gICAgICAvLyBnZXRzIGFsbCB0aGUgbmVjZXNzYXJ5IGZpZWxkcyB0byBydW4gcHJvcGVybHlcbiAgICAgIGNvbnN0IGN1c3RvbUZpZWxkcyA9IHRoaXMuX2FkZERlZmF1bHRGaWVsZFNlbGVjdG9yKCkuZmllbGRzIHx8IHt9O1xuICAgICAgY29uc3Qga2V5cyA9IE9iamVjdC5rZXlzKGN1c3RvbUZpZWxkcyk7XG4gICAgICAvLyBJZiB0aGUgY3VzdG9tIGZpZWxkcyBhcmUgbmVnYXRpdmUsIHRoZW4gaWdub3JlIHRoZW0gYW5kIG9ubHkgc2VuZCB0aGUgbmVjZXNzYXJ5IGZpZWxkc1xuICAgICAgY29uc3QgZmllbGRzID0ga2V5cy5sZW5ndGggPiAwICYmIGN1c3RvbUZpZWxkc1trZXlzWzBdXSA/IHtcbiAgICAgICAgLi4udGhpcy5fYWRkRGVmYXVsdEZpZWxkU2VsZWN0b3IoKS5maWVsZHMsXG4gICAgICAgIC4uLl9kZWZhdWx0UHVibGlzaEZpZWxkcy5wcm9qZWN0aW9uXG4gICAgICB9IDogX2RlZmF1bHRQdWJsaXNoRmllbGRzLnByb2plY3Rpb25cbiAgICAgIC8vIFB1Ymxpc2ggdGhlIGN1cnJlbnQgdXNlcidzIHJlY29yZCB0byB0aGUgY2xpZW50LlxuICAgICAgdGhpcy5fc2VydmVyLnB1Ymxpc2gobnVsbCwgZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAodGhpcy51c2VySWQpIHtcbiAgICAgICAgICByZXR1cm4gdXNlcnMuZmluZCh7XG4gICAgICAgICAgICBfaWQ6IHRoaXMudXNlcklkXG4gICAgICAgICAgfSwge1xuICAgICAgICAgICAgZmllbGRzLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICB9XG4gICAgICB9LCAvKnN1cHByZXNzIGF1dG9wdWJsaXNoIHdhcm5pbmcqL3tpc19hdXRvOiB0cnVlfSk7XG4gICAgfSk7XG5cbiAgICAvLyBVc2UgTWV0ZW9yLnN0YXJ0dXAgdG8gZ2l2ZSBvdGhlciBwYWNrYWdlcyBhIGNoYW5jZSB0byBjYWxsXG4gICAgLy8gYWRkQXV0b3B1Ymxpc2hGaWVsZHMuXG4gICAgUGFja2FnZS5hdXRvcHVibGlzaCAmJiBNZXRlb3Iuc3RhcnR1cCgoKSA9PiB7XG4gICAgICAvLyBbJ3Byb2ZpbGUnLCAndXNlcm5hbWUnXSAtPiB7cHJvZmlsZTogMSwgdXNlcm5hbWU6IDF9XG4gICAgICBjb25zdCB0b0ZpZWxkU2VsZWN0b3IgPSBmaWVsZHMgPT4gZmllbGRzLnJlZHVjZSgocHJldiwgZmllbGQpID0+IChcbiAgICAgICAgICB7IC4uLnByZXYsIFtmaWVsZF06IDEgfSksXG4gICAgICAgIHt9XG4gICAgICApO1xuICAgICAgdGhpcy5fc2VydmVyLnB1Ymxpc2gobnVsbCwgZnVuY3Rpb24gKCkge1xuICAgICAgICBpZiAodGhpcy51c2VySWQpIHtcbiAgICAgICAgICByZXR1cm4gdXNlcnMuZmluZCh7IF9pZDogdGhpcy51c2VySWQgfSwge1xuICAgICAgICAgICAgZmllbGRzOiB0b0ZpZWxkU2VsZWN0b3IoX2F1dG9wdWJsaXNoRmllbGRzLmxvZ2dlZEluVXNlciksXG4gICAgICAgICAgfSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuICAgICAgfSwgLypzdXBwcmVzcyBhdXRvcHVibGlzaCB3YXJuaW5nKi97aXNfYXV0bzogdHJ1ZX0pO1xuXG4gICAgICAvLyBYWFggdGhpcyBwdWJsaXNoIGlzIG5laXRoZXIgZGVkdXAtYWJsZSBub3IgaXMgaXQgb3B0aW1pemVkIGJ5IG91ciBzcGVjaWFsXG4gICAgICAvLyB0cmVhdG1lbnQgb2YgcXVlcmllcyBvbiBhIHNwZWNpZmljIF9pZC4gVGhlcmVmb3JlIHRoaXMgd2lsbCBoYXZlIE8obl4yKVxuICAgICAgLy8gcnVuLXRpbWUgcGVyZm9ybWFuY2UgZXZlcnkgdGltZSBhIHVzZXIgZG9jdW1lbnQgaXMgY2hhbmdlZCAoZWcgc29tZW9uZVxuICAgICAgLy8gbG9nZ2luZyBpbikuIElmIHRoaXMgaXMgYSBwcm9ibGVtLCB3ZSBjYW4gaW5zdGVhZCB3cml0ZSBhIG1hbnVhbCBwdWJsaXNoXG4gICAgICAvLyBmdW5jdGlvbiB3aGljaCBmaWx0ZXJzIG91dCBmaWVsZHMgYmFzZWQgb24gJ3RoaXMudXNlcklkJy5cbiAgICAgIHRoaXMuX3NlcnZlci5wdWJsaXNoKG51bGwsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgY29uc3Qgc2VsZWN0b3IgPSB0aGlzLnVzZXJJZCA/IHsgX2lkOiB7ICRuZTogdGhpcy51c2VySWQgfSB9IDoge307XG4gICAgICAgIHJldHVybiB1c2Vycy5maW5kKHNlbGVjdG9yLCB7XG4gICAgICAgICAgZmllbGRzOiB0b0ZpZWxkU2VsZWN0b3IoX2F1dG9wdWJsaXNoRmllbGRzLm90aGVyVXNlcnMpLFxuICAgICAgICB9KVxuICAgICAgfSwgLypzdXBwcmVzcyBhdXRvcHVibGlzaCB3YXJuaW5nKi97aXNfYXV0bzogdHJ1ZX0pO1xuICAgIH0pO1xuICB9O1xuXG4gIC8vIEFkZCB0byB0aGUgbGlzdCBvZiBmaWVsZHMgb3Igc3ViZmllbGRzIHRvIGJlIGF1dG9tYXRpY2FsbHlcbiAgLy8gcHVibGlzaGVkIGlmIGF1dG9wdWJsaXNoIGlzIG9uLiBNdXN0IGJlIGNhbGxlZCBmcm9tIHRvcC1sZXZlbFxuICAvLyBjb2RlIChpZSwgYmVmb3JlIE1ldGVvci5zdGFydHVwIGhvb2tzIHJ1bikuXG4gIC8vXG4gIC8vIEBwYXJhbSBvcHRzIHtPYmplY3R9IHdpdGg6XG4gIC8vICAgLSBmb3JMb2dnZWRJblVzZXIge0FycmF5fSBBcnJheSBvZiBmaWVsZHMgcHVibGlzaGVkIHRvIHRoZSBsb2dnZWQtaW4gdXNlclxuICAvLyAgIC0gZm9yT3RoZXJVc2VycyB7QXJyYXl9IEFycmF5IG9mIGZpZWxkcyBwdWJsaXNoZWQgdG8gdXNlcnMgdGhhdCBhcmVuJ3QgbG9nZ2VkIGluXG4gIGFkZEF1dG9wdWJsaXNoRmllbGRzKG9wdHMpIHtcbiAgICB0aGlzLl9hdXRvcHVibGlzaEZpZWxkcy5sb2dnZWRJblVzZXIucHVzaC5hcHBseShcbiAgICAgIHRoaXMuX2F1dG9wdWJsaXNoRmllbGRzLmxvZ2dlZEluVXNlciwgb3B0cy5mb3JMb2dnZWRJblVzZXIpO1xuICAgIHRoaXMuX2F1dG9wdWJsaXNoRmllbGRzLm90aGVyVXNlcnMucHVzaC5hcHBseShcbiAgICAgIHRoaXMuX2F1dG9wdWJsaXNoRmllbGRzLm90aGVyVXNlcnMsIG9wdHMuZm9yT3RoZXJVc2Vycyk7XG4gIH07XG5cbiAgLy8gUmVwbGFjZXMgdGhlIGZpZWxkcyB0byBiZSBhdXRvbWF0aWNhbGx5XG4gIC8vIHB1Ymxpc2hlZCB3aGVuIHRoZSB1c2VyIGxvZ3MgaW5cbiAgLy9cbiAgLy8gQHBhcmFtIHtNb25nb0ZpZWxkU3BlY2lmaWVyfSBmaWVsZHMgRGljdGlvbmFyeSBvZiBmaWVsZHMgdG8gcmV0dXJuIG9yIGV4Y2x1ZGUuXG4gIHNldERlZmF1bHRQdWJsaXNoRmllbGRzKGZpZWxkcykge1xuICAgIHRoaXMuX2RlZmF1bHRQdWJsaXNoRmllbGRzLnByb2plY3Rpb24gPSBmaWVsZHM7XG4gIH07XG5cbiAgLy8vXG4gIC8vLyBBQ0NPVU5UIERBVEFcbiAgLy8vXG5cbiAgLy8gSEFDSzogVGhpcyBpcyB1c2VkIGJ5ICdtZXRlb3ItYWNjb3VudHMnIHRvIGdldCB0aGUgbG9naW5Ub2tlbiBmb3IgYVxuICAvLyBjb25uZWN0aW9uLiBNYXliZSB0aGVyZSBzaG91bGQgYmUgYSBwdWJsaWMgd2F5IHRvIGRvIHRoYXQuXG4gIF9nZXRBY2NvdW50RGF0YShjb25uZWN0aW9uSWQsIGZpZWxkKSB7XG4gICAgY29uc3QgZGF0YSA9IHRoaXMuX2FjY291bnREYXRhW2Nvbm5lY3Rpb25JZF07XG4gICAgcmV0dXJuIGRhdGEgJiYgZGF0YVtmaWVsZF07XG4gIH07XG5cbiAgX3NldEFjY291bnREYXRhKGNvbm5lY3Rpb25JZCwgZmllbGQsIHZhbHVlKSB7XG4gICAgY29uc3QgZGF0YSA9IHRoaXMuX2FjY291bnREYXRhW2Nvbm5lY3Rpb25JZF07XG5cbiAgICAvLyBzYWZldHkgYmVsdC4gc2hvdWxkbid0IGhhcHBlbi4gYWNjb3VudERhdGEgaXMgc2V0IGluIG9uQ29ubmVjdGlvbixcbiAgICAvLyB3ZSBkb24ndCBoYXZlIGEgY29ubmVjdGlvbklkIHVudGlsIGl0IGlzIHNldC5cbiAgICBpZiAoIWRhdGEpXG4gICAgICByZXR1cm47XG5cbiAgICBpZiAodmFsdWUgPT09IHVuZGVmaW5lZClcbiAgICAgIGRlbGV0ZSBkYXRhW2ZpZWxkXTtcbiAgICBlbHNlXG4gICAgICBkYXRhW2ZpZWxkXSA9IHZhbHVlO1xuICB9O1xuXG4gIC8vL1xuICAvLy8gUkVDT05ORUNUIFRPS0VOU1xuICAvLy9cbiAgLy8vIHN1cHBvcnQgcmVjb25uZWN0aW5nIHVzaW5nIGEgbWV0ZW9yIGxvZ2luIHRva2VuXG5cbiAgX2hhc2hMb2dpblRva2VuKGxvZ2luVG9rZW4pIHtcbiAgICBjb25zdCBoYXNoID0gY3J5cHRvLmNyZWF0ZUhhc2goJ3NoYTI1NicpO1xuICAgIGhhc2gudXBkYXRlKGxvZ2luVG9rZW4pO1xuICAgIHJldHVybiBoYXNoLmRpZ2VzdCgnYmFzZTY0Jyk7XG4gIH07XG5cbiAgLy8ge3Rva2VuLCB3aGVufSA9PiB7aGFzaGVkVG9rZW4sIHdoZW59XG4gIF9oYXNoU3RhbXBlZFRva2VuKHN0YW1wZWRUb2tlbikge1xuICAgIGNvbnN0IHsgdG9rZW4sIC4uLmhhc2hlZFN0YW1wZWRUb2tlbiB9ID0gc3RhbXBlZFRva2VuO1xuICAgIHJldHVybiB7XG4gICAgICAuLi5oYXNoZWRTdGFtcGVkVG9rZW4sXG4gICAgICBoYXNoZWRUb2tlbjogdGhpcy5faGFzaExvZ2luVG9rZW4odG9rZW4pXG4gICAgfTtcbiAgfTtcblxuICAvLyBVc2luZyAkYWRkVG9TZXQgYXZvaWRzIGdldHRpbmcgYW4gaW5kZXggZXJyb3IgaWYgYW5vdGhlciBjbGllbnRcbiAgLy8gbG9nZ2luZyBpbiBzaW11bHRhbmVvdXNseSBoYXMgYWxyZWFkeSBpbnNlcnRlZCB0aGUgbmV3IGhhc2hlZFxuICAvLyB0b2tlbi5cbiAgX2luc2VydEhhc2hlZExvZ2luVG9rZW4odXNlcklkLCBoYXNoZWRUb2tlbiwgcXVlcnkpIHtcbiAgICBxdWVyeSA9IHF1ZXJ5ID8geyAuLi5xdWVyeSB9IDoge307XG4gICAgcXVlcnkuX2lkID0gdXNlcklkO1xuICAgIHRoaXMudXNlcnMudXBkYXRlKHF1ZXJ5LCB7XG4gICAgICAkYWRkVG9TZXQ6IHtcbiAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjogaGFzaGVkVG9rZW5cbiAgICAgIH1cbiAgICB9KTtcbiAgfTtcblxuICAvLyBFeHBvcnRlZCBmb3IgdGVzdHMuXG4gIF9pbnNlcnRMb2dpblRva2VuKHVzZXJJZCwgc3RhbXBlZFRva2VuLCBxdWVyeSkge1xuICAgIHRoaXMuX2luc2VydEhhc2hlZExvZ2luVG9rZW4oXG4gICAgICB1c2VySWQsXG4gICAgICB0aGlzLl9oYXNoU3RhbXBlZFRva2VuKHN0YW1wZWRUb2tlbiksXG4gICAgICBxdWVyeVxuICAgICk7XG4gIH07XG5cbiAgX2NsZWFyQWxsTG9naW5Ub2tlbnModXNlcklkKSB7XG4gICAgdGhpcy51c2Vycy51cGRhdGUodXNlcklkLCB7XG4gICAgICAkc2V0OiB7XG4gICAgICAgICdzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMnOiBbXVxuICAgICAgfVxuICAgIH0pO1xuICB9O1xuXG4gIC8vIHRlc3QgaG9va1xuICBfZ2V0VXNlck9ic2VydmUoY29ubmVjdGlvbklkKSB7XG4gICAgcmV0dXJuIHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb25JZF07XG4gIH07XG5cbiAgLy8gQ2xlYW4gdXAgdGhpcyBjb25uZWN0aW9uJ3MgYXNzb2NpYXRpb24gd2l0aCB0aGUgdG9rZW46IHRoYXQgaXMsIHN0b3BcbiAgLy8gdGhlIG9ic2VydmUgdGhhdCB3ZSBzdGFydGVkIHdoZW4gd2UgYXNzb2NpYXRlZCB0aGUgY29ubmVjdGlvbiB3aXRoXG4gIC8vIHRoaXMgdG9rZW4uXG4gIF9yZW1vdmVUb2tlbkZyb21Db25uZWN0aW9uKGNvbm5lY3Rpb25JZCkge1xuICAgIGlmIChoYXNPd24uY2FsbCh0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9ucywgY29ubmVjdGlvbklkKSkge1xuICAgICAgY29uc3Qgb2JzZXJ2ZSA9IHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb25JZF07XG4gICAgICBpZiAodHlwZW9mIG9ic2VydmUgPT09ICdudW1iZXInKSB7XG4gICAgICAgIC8vIFdlJ3JlIGluIHRoZSBwcm9jZXNzIG9mIHNldHRpbmcgdXAgYW4gb2JzZXJ2ZSBmb3IgdGhpcyBjb25uZWN0aW9uLiBXZVxuICAgICAgICAvLyBjYW4ndCBjbGVhbiB1cCB0aGF0IG9ic2VydmUgeWV0LCBidXQgaWYgd2UgZGVsZXRlIHRoZSBwbGFjZWhvbGRlciBmb3JcbiAgICAgICAgLy8gdGhpcyBjb25uZWN0aW9uLCB0aGVuIHRoZSBvYnNlcnZlIHdpbGwgZ2V0IGNsZWFuZWQgdXAgYXMgc29vbiBhcyBpdCBoYXNcbiAgICAgICAgLy8gYmVlbiBzZXQgdXAuXG4gICAgICAgIGRlbGV0ZSB0aGlzLl91c2VyT2JzZXJ2ZXNGb3JDb25uZWN0aW9uc1tjb25uZWN0aW9uSWRdO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgZGVsZXRlIHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb25JZF07XG4gICAgICAgIG9ic2VydmUuc3RvcCgpO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICBfZ2V0TG9naW5Ub2tlbihjb25uZWN0aW9uSWQpIHtcbiAgICByZXR1cm4gdGhpcy5fZ2V0QWNjb3VudERhdGEoY29ubmVjdGlvbklkLCAnbG9naW5Ub2tlbicpO1xuICB9O1xuXG4gIC8vIG5ld1Rva2VuIGlzIGEgaGFzaGVkIHRva2VuLlxuICBfc2V0TG9naW5Ub2tlbih1c2VySWQsIGNvbm5lY3Rpb24sIG5ld1Rva2VuKSB7XG4gICAgdGhpcy5fcmVtb3ZlVG9rZW5Gcm9tQ29ubmVjdGlvbihjb25uZWN0aW9uLmlkKTtcbiAgICB0aGlzLl9zZXRBY2NvdW50RGF0YShjb25uZWN0aW9uLmlkLCAnbG9naW5Ub2tlbicsIG5ld1Rva2VuKTtcblxuICAgIGlmIChuZXdUb2tlbikge1xuICAgICAgLy8gU2V0IHVwIGFuIG9ic2VydmUgZm9yIHRoaXMgdG9rZW4uIElmIHRoZSB0b2tlbiBnb2VzIGF3YXksIHdlIG5lZWRcbiAgICAgIC8vIHRvIGNsb3NlIHRoZSBjb25uZWN0aW9uLiAgV2UgZGVmZXIgdGhlIG9ic2VydmUgYmVjYXVzZSB0aGVyZSdzXG4gICAgICAvLyBubyBuZWVkIGZvciBpdCB0byBiZSBvbiB0aGUgY3JpdGljYWwgcGF0aCBmb3IgbG9naW47IHdlIGp1c3QgbmVlZFxuICAgICAgLy8gdG8gZW5zdXJlIHRoYXQgdGhlIGNvbm5lY3Rpb24gd2lsbCBnZXQgY2xvc2VkIGF0IHNvbWUgcG9pbnQgaWZcbiAgICAgIC8vIHRoZSB0b2tlbiBnZXRzIGRlbGV0ZWQuXG4gICAgICAvL1xuICAgICAgLy8gSW5pdGlhbGx5LCB3ZSBzZXQgdGhlIG9ic2VydmUgZm9yIHRoaXMgY29ubmVjdGlvbiB0byBhIG51bWJlcjsgdGhpc1xuICAgICAgLy8gc2lnbmlmaWVzIHRvIG90aGVyIGNvZGUgKHdoaWNoIG1pZ2h0IHJ1biB3aGlsZSB3ZSB5aWVsZCkgdGhhdCB3ZSBhcmUgaW5cbiAgICAgIC8vIHRoZSBwcm9jZXNzIG9mIHNldHRpbmcgdXAgYW4gb2JzZXJ2ZSBmb3IgdGhpcyBjb25uZWN0aW9uLiBPbmNlIHRoZVxuICAgICAgLy8gb2JzZXJ2ZSBpcyByZWFkeSB0byBnbywgd2UgcmVwbGFjZSB0aGUgbnVtYmVyIHdpdGggdGhlIHJlYWwgb2JzZXJ2ZVxuICAgICAgLy8gaGFuZGxlICh1bmxlc3MgdGhlIHBsYWNlaG9sZGVyIGhhcyBiZWVuIGRlbGV0ZWQgb3IgcmVwbGFjZWQgYnkgYVxuICAgICAgLy8gZGlmZmVyZW50IHBsYWNlaG9sZCBudW1iZXIsIHNpZ25pZnlpbmcgdGhhdCB0aGUgY29ubmVjdGlvbiB3YXMgY2xvc2VkXG4gICAgICAvLyBhbHJlYWR5IC0tIGluIHRoaXMgY2FzZSB3ZSBqdXN0IGNsZWFuIHVwIHRoZSBvYnNlcnZlIHRoYXQgd2Ugc3RhcnRlZCkuXG4gICAgICBjb25zdCBteU9ic2VydmVOdW1iZXIgPSArK3RoaXMuX25leHRVc2VyT2JzZXJ2ZU51bWJlcjtcbiAgICAgIHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb24uaWRdID0gbXlPYnNlcnZlTnVtYmVyO1xuICAgICAgTWV0ZW9yLmRlZmVyKCgpID0+IHtcbiAgICAgICAgLy8gSWYgc29tZXRoaW5nIGVsc2UgaGFwcGVuZWQgb24gdGhpcyBjb25uZWN0aW9uIGluIHRoZSBtZWFudGltZSAoaXQgZ290XG4gICAgICAgIC8vIGNsb3NlZCwgb3IgYW5vdGhlciBjYWxsIHRvIF9zZXRMb2dpblRva2VuIGhhcHBlbmVkKSwganVzdCBkb1xuICAgICAgICAvLyBub3RoaW5nLiBXZSBkb24ndCBuZWVkIHRvIHN0YXJ0IGFuIG9ic2VydmUgZm9yIGFuIG9sZCBjb25uZWN0aW9uIG9yIG9sZFxuICAgICAgICAvLyB0b2tlbi5cbiAgICAgICAgaWYgKHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb24uaWRdICE9PSBteU9ic2VydmVOdW1iZXIpIHtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBsZXQgZm91bmRNYXRjaGluZ1VzZXI7XG4gICAgICAgIC8vIEJlY2F1c2Ugd2UgdXBncmFkZSB1bmhhc2hlZCBsb2dpbiB0b2tlbnMgdG8gaGFzaGVkIHRva2VucyBhdFxuICAgICAgICAvLyBsb2dpbiB0aW1lLCBzZXNzaW9ucyB3aWxsIG9ubHkgYmUgbG9nZ2VkIGluIHdpdGggYSBoYXNoZWRcbiAgICAgICAgLy8gdG9rZW4uIFRodXMgd2Ugb25seSBuZWVkIHRvIG9ic2VydmUgaGFzaGVkIHRva2VucyBoZXJlLlxuICAgICAgICBjb25zdCBvYnNlcnZlID0gdGhpcy51c2Vycy5maW5kKHtcbiAgICAgICAgICBfaWQ6IHVzZXJJZCxcbiAgICAgICAgICAnc2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmhhc2hlZFRva2VuJzogbmV3VG9rZW5cbiAgICAgICAgfSwgeyBmaWVsZHM6IHsgX2lkOiAxIH0gfSkub2JzZXJ2ZUNoYW5nZXMoe1xuICAgICAgICAgIGFkZGVkOiAoKSA9PiB7XG4gICAgICAgICAgICBmb3VuZE1hdGNoaW5nVXNlciA9IHRydWU7XG4gICAgICAgICAgfSxcbiAgICAgICAgICByZW1vdmVkOiBjb25uZWN0aW9uLmNsb3NlLFxuICAgICAgICAgIC8vIFRoZSBvbkNsb3NlIGNhbGxiYWNrIGZvciB0aGUgY29ubmVjdGlvbiB0YWtlcyBjYXJlIG9mXG4gICAgICAgICAgLy8gY2xlYW5pbmcgdXAgdGhlIG9ic2VydmUgaGFuZGxlIGFuZCBhbnkgb3RoZXIgc3RhdGUgd2UgaGF2ZVxuICAgICAgICAgIC8vIGx5aW5nIGFyb3VuZC5cbiAgICAgICAgfSwgeyBub25NdXRhdGluZ0NhbGxiYWNrczogdHJ1ZSB9KTtcblxuICAgICAgICAvLyBJZiB0aGUgdXNlciByYW4gYW5vdGhlciBsb2dpbiBvciBsb2dvdXQgY29tbWFuZCB3ZSB3ZXJlIHdhaXRpbmcgZm9yIHRoZVxuICAgICAgICAvLyBkZWZlciBvciBhZGRlZCB0byBmaXJlIChpZSwgYW5vdGhlciBjYWxsIHRvIF9zZXRMb2dpblRva2VuIG9jY3VycmVkKSxcbiAgICAgICAgLy8gdGhlbiB3ZSBsZXQgdGhlIGxhdGVyIG9uZSB3aW4gKHN0YXJ0IGFuIG9ic2VydmUsIGV0YykgYW5kIGp1c3Qgc3RvcCBvdXJcbiAgICAgICAgLy8gb2JzZXJ2ZSBub3cuXG4gICAgICAgIC8vXG4gICAgICAgIC8vIFNpbWlsYXJseSwgaWYgdGhlIGNvbm5lY3Rpb24gd2FzIGFscmVhZHkgY2xvc2VkLCB0aGVuIHRoZSBvbkNsb3NlXG4gICAgICAgIC8vIGNhbGxiYWNrIHdvdWxkIGhhdmUgY2FsbGVkIF9yZW1vdmVUb2tlbkZyb21Db25uZWN0aW9uIGFuZCB0aGVyZSB3b24ndFxuICAgICAgICAvLyBiZSBhbiBlbnRyeSBpbiBfdXNlck9ic2VydmVzRm9yQ29ubmVjdGlvbnMuIFdlIGNhbiBzdG9wIHRoZSBvYnNlcnZlLlxuICAgICAgICBpZiAodGhpcy5fdXNlck9ic2VydmVzRm9yQ29ubmVjdGlvbnNbY29ubmVjdGlvbi5pZF0gIT09IG15T2JzZXJ2ZU51bWJlcikge1xuICAgICAgICAgIG9ic2VydmUuc3RvcCgpO1xuICAgICAgICAgIHJldHVybjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuX3VzZXJPYnNlcnZlc0ZvckNvbm5lY3Rpb25zW2Nvbm5lY3Rpb24uaWRdID0gb2JzZXJ2ZTtcblxuICAgICAgICBpZiAoISBmb3VuZE1hdGNoaW5nVXNlcikge1xuICAgICAgICAgIC8vIFdlJ3ZlIHNldCB1cCBhbiBvYnNlcnZlIG9uIHRoZSB1c2VyIGFzc29jaWF0ZWQgd2l0aCBgbmV3VG9rZW5gLFxuICAgICAgICAgIC8vIHNvIGlmIHRoZSBuZXcgdG9rZW4gaXMgcmVtb3ZlZCBmcm9tIHRoZSBkYXRhYmFzZSwgd2UnbGwgY2xvc2VcbiAgICAgICAgICAvLyB0aGUgY29ubmVjdGlvbi4gQnV0IHRoZSB0b2tlbiBtaWdodCBoYXZlIGFscmVhZHkgYmVlbiBkZWxldGVkXG4gICAgICAgICAgLy8gYmVmb3JlIHdlIHNldCB1cCB0aGUgb2JzZXJ2ZSwgd2hpY2ggd291bGRuJ3QgaGF2ZSBjbG9zZWQgdGhlXG4gICAgICAgICAgLy8gY29ubmVjdGlvbiBiZWNhdXNlIHRoZSBvYnNlcnZlIHdhc24ndCBydW5uaW5nIHlldC5cbiAgICAgICAgICBjb25uZWN0aW9uLmNsb3NlKCk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cbiAgfTtcblxuICAvLyAoQWxzbyB1c2VkIGJ5IE1ldGVvciBBY2NvdW50cyBzZXJ2ZXIgYW5kIHRlc3RzKS5cbiAgLy9cbiAgX2dlbmVyYXRlU3RhbXBlZExvZ2luVG9rZW4oKSB7XG4gICAgcmV0dXJuIHtcbiAgICAgIHRva2VuOiBSYW5kb20uc2VjcmV0KCksXG4gICAgICB3aGVuOiBuZXcgRGF0ZVxuICAgIH07XG4gIH07XG5cbiAgLy8vXG4gIC8vLyBUT0tFTiBFWFBJUkFUSU9OXG4gIC8vL1xuXG4gIC8vIERlbGV0ZXMgZXhwaXJlZCBwYXNzd29yZCByZXNldCB0b2tlbnMgZnJvbSB0aGUgZGF0YWJhc2UuXG4gIC8vXG4gIC8vIEV4cG9ydGVkIGZvciB0ZXN0cy4gQWxzbywgdGhlIGFyZ3VtZW50cyBhcmUgb25seSB1c2VkIGJ5XG4gIC8vIHRlc3RzLiBvbGRlc3RWYWxpZERhdGUgaXMgc2ltdWxhdGUgZXhwaXJpbmcgdG9rZW5zIHdpdGhvdXQgd2FpdGluZ1xuICAvLyBmb3IgdGhlbSB0byBhY3R1YWxseSBleHBpcmUuIHVzZXJJZCBpcyB1c2VkIGJ5IHRlc3RzIHRvIG9ubHkgZXhwaXJlXG4gIC8vIHRva2VucyBmb3IgdGhlIHRlc3QgdXNlci5cbiAgX2V4cGlyZVBhc3N3b3JkUmVzZXRUb2tlbnMob2xkZXN0VmFsaWREYXRlLCB1c2VySWQpIHtcbiAgICBjb25zdCB0b2tlbkxpZmV0aW1lTXMgPSB0aGlzLl9nZXRQYXNzd29yZFJlc2V0VG9rZW5MaWZldGltZU1zKCk7XG5cbiAgICAvLyB3aGVuIGNhbGxpbmcgZnJvbSBhIHRlc3Qgd2l0aCBleHRyYSBhcmd1bWVudHMsIHlvdSBtdXN0IHNwZWNpZnkgYm90aCFcbiAgICBpZiAoKG9sZGVzdFZhbGlkRGF0ZSAmJiAhdXNlcklkKSB8fCAoIW9sZGVzdFZhbGlkRGF0ZSAmJiB1c2VySWQpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJCYWQgdGVzdC4gTXVzdCBzcGVjaWZ5IGJvdGggb2xkZXN0VmFsaWREYXRlIGFuZCB1c2VySWQuXCIpO1xuICAgIH1cblxuICAgIG9sZGVzdFZhbGlkRGF0ZSA9IG9sZGVzdFZhbGlkRGF0ZSB8fFxuICAgICAgKG5ldyBEYXRlKG5ldyBEYXRlKCkgLSB0b2tlbkxpZmV0aW1lTXMpKTtcblxuICAgIGNvbnN0IHRva2VuRmlsdGVyID0ge1xuICAgICAgJG9yOiBbXG4gICAgICAgIHsgXCJzZXJ2aWNlcy5wYXNzd29yZC5yZXNldC5yZWFzb25cIjogXCJyZXNldFwifSxcbiAgICAgICAgeyBcInNlcnZpY2VzLnBhc3N3b3JkLnJlc2V0LnJlYXNvblwiOiB7JGV4aXN0czogZmFsc2V9fVxuICAgICAgXVxuICAgIH07XG5cbiAgICBleHBpcmVQYXNzd29yZFRva2VuKHRoaXMsIG9sZGVzdFZhbGlkRGF0ZSwgdG9rZW5GaWx0ZXIsIHVzZXJJZCk7XG4gIH1cblxuICAvLyBEZWxldGVzIGV4cGlyZWQgcGFzc3dvcmQgZW5yb2xsIHRva2VucyBmcm9tIHRoZSBkYXRhYmFzZS5cbiAgLy9cbiAgLy8gRXhwb3J0ZWQgZm9yIHRlc3RzLiBBbHNvLCB0aGUgYXJndW1lbnRzIGFyZSBvbmx5IHVzZWQgYnlcbiAgLy8gdGVzdHMuIG9sZGVzdFZhbGlkRGF0ZSBpcyBzaW11bGF0ZSBleHBpcmluZyB0b2tlbnMgd2l0aG91dCB3YWl0aW5nXG4gIC8vIGZvciB0aGVtIHRvIGFjdHVhbGx5IGV4cGlyZS4gdXNlcklkIGlzIHVzZWQgYnkgdGVzdHMgdG8gb25seSBleHBpcmVcbiAgLy8gdG9rZW5zIGZvciB0aGUgdGVzdCB1c2VyLlxuICBfZXhwaXJlUGFzc3dvcmRFbnJvbGxUb2tlbnMob2xkZXN0VmFsaWREYXRlLCB1c2VySWQpIHtcbiAgICBjb25zdCB0b2tlbkxpZmV0aW1lTXMgPSB0aGlzLl9nZXRQYXNzd29yZEVucm9sbFRva2VuTGlmZXRpbWVNcygpO1xuXG4gICAgLy8gd2hlbiBjYWxsaW5nIGZyb20gYSB0ZXN0IHdpdGggZXh0cmEgYXJndW1lbnRzLCB5b3UgbXVzdCBzcGVjaWZ5IGJvdGghXG4gICAgaWYgKChvbGRlc3RWYWxpZERhdGUgJiYgIXVzZXJJZCkgfHwgKCFvbGRlc3RWYWxpZERhdGUgJiYgdXNlcklkKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQmFkIHRlc3QuIE11c3Qgc3BlY2lmeSBib3RoIG9sZGVzdFZhbGlkRGF0ZSBhbmQgdXNlcklkLlwiKTtcbiAgICB9XG5cbiAgICBvbGRlc3RWYWxpZERhdGUgPSBvbGRlc3RWYWxpZERhdGUgfHxcbiAgICAgIChuZXcgRGF0ZShuZXcgRGF0ZSgpIC0gdG9rZW5MaWZldGltZU1zKSk7XG5cbiAgICBjb25zdCB0b2tlbkZpbHRlciA9IHtcbiAgICAgIFwic2VydmljZXMucGFzc3dvcmQuZW5yb2xsLnJlYXNvblwiOiBcImVucm9sbFwiXG4gICAgfTtcblxuICAgIGV4cGlyZVBhc3N3b3JkVG9rZW4odGhpcywgb2xkZXN0VmFsaWREYXRlLCB0b2tlbkZpbHRlciwgdXNlcklkKTtcbiAgfVxuXG4gIC8vIERlbGV0ZXMgZXhwaXJlZCB0b2tlbnMgZnJvbSB0aGUgZGF0YWJhc2UgYW5kIGNsb3NlcyBhbGwgb3BlbiBjb25uZWN0aW9uc1xuICAvLyBhc3NvY2lhdGVkIHdpdGggdGhlc2UgdG9rZW5zLlxuICAvL1xuICAvLyBFeHBvcnRlZCBmb3IgdGVzdHMuIEFsc28sIHRoZSBhcmd1bWVudHMgYXJlIG9ubHkgdXNlZCBieVxuICAvLyB0ZXN0cy4gb2xkZXN0VmFsaWREYXRlIGlzIHNpbXVsYXRlIGV4cGlyaW5nIHRva2VucyB3aXRob3V0IHdhaXRpbmdcbiAgLy8gZm9yIHRoZW0gdG8gYWN0dWFsbHkgZXhwaXJlLiB1c2VySWQgaXMgdXNlZCBieSB0ZXN0cyB0byBvbmx5IGV4cGlyZVxuICAvLyB0b2tlbnMgZm9yIHRoZSB0ZXN0IHVzZXIuXG4gIF9leHBpcmVUb2tlbnMob2xkZXN0VmFsaWREYXRlLCB1c2VySWQpIHtcbiAgICBjb25zdCB0b2tlbkxpZmV0aW1lTXMgPSB0aGlzLl9nZXRUb2tlbkxpZmV0aW1lTXMoKTtcblxuICAgIC8vIHdoZW4gY2FsbGluZyBmcm9tIGEgdGVzdCB3aXRoIGV4dHJhIGFyZ3VtZW50cywgeW91IG11c3Qgc3BlY2lmeSBib3RoIVxuICAgIGlmICgob2xkZXN0VmFsaWREYXRlICYmICF1c2VySWQpIHx8ICghb2xkZXN0VmFsaWREYXRlICYmIHVzZXJJZCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcIkJhZCB0ZXN0LiBNdXN0IHNwZWNpZnkgYm90aCBvbGRlc3RWYWxpZERhdGUgYW5kIHVzZXJJZC5cIik7XG4gICAgfVxuXG4gICAgb2xkZXN0VmFsaWREYXRlID0gb2xkZXN0VmFsaWREYXRlIHx8XG4gICAgICAobmV3IERhdGUobmV3IERhdGUoKSAtIHRva2VuTGlmZXRpbWVNcykpO1xuICAgIGNvbnN0IHVzZXJGaWx0ZXIgPSB1c2VySWQgPyB7X2lkOiB1c2VySWR9IDoge307XG5cblxuICAgIC8vIEJhY2t3YXJkcyBjb21wYXRpYmxlIHdpdGggb2xkZXIgdmVyc2lvbnMgb2YgbWV0ZW9yIHRoYXQgc3RvcmVkIGxvZ2luIHRva2VuXG4gICAgLy8gdGltZXN0YW1wcyBhcyBudW1iZXJzLlxuICAgIHRoaXMudXNlcnMudXBkYXRlKHsgLi4udXNlckZpbHRlcixcbiAgICAgICRvcjogW1xuICAgICAgICB7IFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLndoZW5cIjogeyAkbHQ6IG9sZGVzdFZhbGlkRGF0ZSB9IH0sXG4gICAgICAgIHsgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMud2hlblwiOiB7ICRsdDogK29sZGVzdFZhbGlkRGF0ZSB9IH1cbiAgICAgIF1cbiAgICB9LCB7XG4gICAgICAkcHVsbDoge1xuICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1wiOiB7XG4gICAgICAgICAgJG9yOiBbXG4gICAgICAgICAgICB7IHdoZW46IHsgJGx0OiBvbGRlc3RWYWxpZERhdGUgfSB9LFxuICAgICAgICAgICAgeyB3aGVuOiB7ICRsdDogK29sZGVzdFZhbGlkRGF0ZSB9IH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LCB7IG11bHRpOiB0cnVlIH0pO1xuICAgIC8vIFRoZSBvYnNlcnZlIG9uIE1ldGVvci51c2VycyB3aWxsIHRha2UgY2FyZSBvZiBjbG9zaW5nIGNvbm5lY3Rpb25zIGZvclxuICAgIC8vIGV4cGlyZWQgdG9rZW5zLlxuICB9O1xuXG4gIC8vIEBvdmVycmlkZSBmcm9tIGFjY291bnRzX2NvbW1vbi5qc1xuICBjb25maWcob3B0aW9ucykge1xuICAgIC8vIENhbGwgdGhlIG92ZXJyaWRkZW4gaW1wbGVtZW50YXRpb24gb2YgdGhlIG1ldGhvZC5cbiAgICBjb25zdCBzdXBlclJlc3VsdCA9IEFjY291bnRzQ29tbW9uLnByb3RvdHlwZS5jb25maWcuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcblxuICAgIC8vIElmIHRoZSB1c2VyIHNldCBsb2dpbkV4cGlyYXRpb25JbkRheXMgdG8gbnVsbCwgdGhlbiB3ZSBuZWVkIHRvIGNsZWFyIHRoZVxuICAgIC8vIHRpbWVyIHRoYXQgcGVyaW9kaWNhbGx5IGV4cGlyZXMgdG9rZW5zLlxuICAgIGlmIChoYXNPd24uY2FsbCh0aGlzLl9vcHRpb25zLCAnbG9naW5FeHBpcmF0aW9uSW5EYXlzJykgJiZcbiAgICAgIHRoaXMuX29wdGlvbnMubG9naW5FeHBpcmF0aW9uSW5EYXlzID09PSBudWxsICYmXG4gICAgICB0aGlzLmV4cGlyZVRva2VuSW50ZXJ2YWwpIHtcbiAgICAgIE1ldGVvci5jbGVhckludGVydmFsKHRoaXMuZXhwaXJlVG9rZW5JbnRlcnZhbCk7XG4gICAgICB0aGlzLmV4cGlyZVRva2VuSW50ZXJ2YWwgPSBudWxsO1xuICAgIH1cblxuICAgIHJldHVybiBzdXBlclJlc3VsdDtcbiAgfTtcblxuICAvLyBDYWxsZWQgYnkgYWNjb3VudHMtcGFzc3dvcmRcbiAgaW5zZXJ0VXNlckRvYyhvcHRpb25zLCB1c2VyKSB7XG4gICAgLy8gLSBjbG9uZSB1c2VyIGRvY3VtZW50LCB0byBwcm90ZWN0IGZyb20gbW9kaWZpY2F0aW9uXG4gICAgLy8gLSBhZGQgY3JlYXRlZEF0IHRpbWVzdGFtcFxuICAgIC8vIC0gcHJlcGFyZSBhbiBfaWQsIHNvIHRoYXQgeW91IGNhbiBtb2RpZnkgb3RoZXIgY29sbGVjdGlvbnMgKGVnXG4gICAgLy8gY3JlYXRlIGEgZmlyc3QgdGFzayBmb3IgZXZlcnkgbmV3IHVzZXIpXG4gICAgLy9cbiAgICAvLyBYWFggSWYgdGhlIG9uQ3JlYXRlVXNlciBvciB2YWxpZGF0ZU5ld1VzZXIgaG9va3MgZmFpbCwgd2UgbWlnaHRcbiAgICAvLyBlbmQgdXAgaGF2aW5nIG1vZGlmaWVkIHNvbWUgb3RoZXIgY29sbGVjdGlvblxuICAgIC8vIGluYXBwcm9wcmlhdGVseS4gVGhlIHNvbHV0aW9uIGlzIHByb2JhYmx5IHRvIGhhdmUgb25DcmVhdGVVc2VyXG4gICAgLy8gYWNjZXB0IHR3byBjYWxsYmFja3MgLSBvbmUgdGhhdCBnZXRzIGNhbGxlZCBiZWZvcmUgaW5zZXJ0aW5nXG4gICAgLy8gdGhlIHVzZXIgZG9jdW1lbnQgKGluIHdoaWNoIHlvdSBjYW4gbW9kaWZ5IGl0cyBjb250ZW50cyksIGFuZFxuICAgIC8vIG9uZSB0aGF0IGdldHMgY2FsbGVkIGFmdGVyIChpbiB3aGljaCB5b3Ugc2hvdWxkIGNoYW5nZSBvdGhlclxuICAgIC8vIGNvbGxlY3Rpb25zKVxuICAgIHVzZXIgPSB7XG4gICAgICBjcmVhdGVkQXQ6IG5ldyBEYXRlKCksXG4gICAgICBfaWQ6IFJhbmRvbS5pZCgpLFxuICAgICAgLi4udXNlcixcbiAgICB9O1xuXG4gICAgaWYgKHVzZXIuc2VydmljZXMpIHtcbiAgICAgIE9iamVjdC5rZXlzKHVzZXIuc2VydmljZXMpLmZvckVhY2goc2VydmljZSA9PlxuICAgICAgICBwaW5FbmNyeXB0ZWRGaWVsZHNUb1VzZXIodXNlci5zZXJ2aWNlc1tzZXJ2aWNlXSwgdXNlci5faWQpXG4gICAgICApO1xuICAgIH1cblxuICAgIGxldCBmdWxsVXNlcjtcbiAgICBpZiAodGhpcy5fb25DcmVhdGVVc2VySG9vaykge1xuICAgICAgZnVsbFVzZXIgPSB0aGlzLl9vbkNyZWF0ZVVzZXJIb29rKG9wdGlvbnMsIHVzZXIpO1xuXG4gICAgICAvLyBUaGlzIGlzICpub3QqIHBhcnQgb2YgdGhlIEFQSS4gV2UgbmVlZCB0aGlzIGJlY2F1c2Ugd2UgY2FuJ3QgaXNvbGF0ZVxuICAgICAgLy8gdGhlIGdsb2JhbCBzZXJ2ZXIgZW52aXJvbm1lbnQgYmV0d2VlbiB0ZXN0cywgbWVhbmluZyB3ZSBjYW4ndCB0ZXN0XG4gICAgICAvLyBib3RoIGhhdmluZyBhIGNyZWF0ZSB1c2VyIGhvb2sgc2V0IGFuZCBub3QgaGF2aW5nIG9uZSBzZXQuXG4gICAgICBpZiAoZnVsbFVzZXIgPT09ICdURVNUIERFRkFVTFQgSE9PSycpXG4gICAgICAgIGZ1bGxVc2VyID0gZGVmYXVsdENyZWF0ZVVzZXJIb29rKG9wdGlvbnMsIHVzZXIpO1xuICAgIH0gZWxzZSB7XG4gICAgICBmdWxsVXNlciA9IGRlZmF1bHRDcmVhdGVVc2VySG9vayhvcHRpb25zLCB1c2VyKTtcbiAgICB9XG5cbiAgICB0aGlzLl92YWxpZGF0ZU5ld1VzZXJIb29rcy5mb3JFYWNoKGhvb2sgPT4ge1xuICAgICAgaWYgKCEgaG9vayhmdWxsVXNlcikpXG4gICAgICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIlVzZXIgdmFsaWRhdGlvbiBmYWlsZWRcIik7XG4gICAgfSk7XG5cbiAgICBsZXQgdXNlcklkO1xuICAgIHRyeSB7XG4gICAgICB1c2VySWQgPSB0aGlzLnVzZXJzLmluc2VydChmdWxsVXNlcik7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgLy8gWFhYIHN0cmluZyBwYXJzaW5nIHN1Y2tzLCBtYXliZVxuICAgICAgLy8gaHR0cHM6Ly9qaXJhLm1vbmdvZGIub3JnL2Jyb3dzZS9TRVJWRVItMzA2OSB3aWxsIGdldCBmaXhlZCBvbmUgZGF5XG4gICAgICAvLyBodHRwczovL2ppcmEubW9uZ29kYi5vcmcvYnJvd3NlL1NFUlZFUi00NjM3XG4gICAgICBpZiAoIWUuZXJybXNnKSB0aHJvdyBlO1xuICAgICAgaWYgKGUuZXJybXNnLmluY2x1ZGVzKCdlbWFpbHMuYWRkcmVzcycpKVxuICAgICAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJFbWFpbCBhbHJlYWR5IGV4aXN0cy5cIik7XG4gICAgICBpZiAoZS5lcnJtc2cuaW5jbHVkZXMoJ3VzZXJuYW1lJykpXG4gICAgICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIlVzZXJuYW1lIGFscmVhZHkgZXhpc3RzLlwiKTtcbiAgICAgIHRocm93IGU7XG4gICAgfVxuICAgIHJldHVybiB1c2VySWQ7XG4gIH07XG5cbiAgLy8gSGVscGVyIGZ1bmN0aW9uOiByZXR1cm5zIGZhbHNlIGlmIGVtYWlsIGRvZXMgbm90IG1hdGNoIGNvbXBhbnkgZG9tYWluIGZyb21cbiAgLy8gdGhlIGNvbmZpZ3VyYXRpb24uXG4gIF90ZXN0RW1haWxEb21haW4oZW1haWwpIHtcbiAgICBjb25zdCBkb21haW4gPSB0aGlzLl9vcHRpb25zLnJlc3RyaWN0Q3JlYXRpb25CeUVtYWlsRG9tYWluO1xuXG4gICAgcmV0dXJuICFkb21haW4gfHxcbiAgICAgICh0eXBlb2YgZG9tYWluID09PSAnZnVuY3Rpb24nICYmIGRvbWFpbihlbWFpbCkpIHx8XG4gICAgICAodHlwZW9mIGRvbWFpbiA9PT0gJ3N0cmluZycgJiZcbiAgICAgICAgKG5ldyBSZWdFeHAoYEAke01ldGVvci5fZXNjYXBlUmVnRXhwKGRvbWFpbil9JGAsICdpJykpLnRlc3QoZW1haWwpKTtcbiAgfTtcblxuICAvLy9cbiAgLy8vIENMRUFOIFVQIEZPUiBgbG9nb3V0T3RoZXJDbGllbnRzYFxuICAvLy9cblxuICBfZGVsZXRlU2F2ZWRUb2tlbnNGb3JVc2VyKHVzZXJJZCwgdG9rZW5zVG9EZWxldGUpIHtcbiAgICBpZiAodG9rZW5zVG9EZWxldGUpIHtcbiAgICAgIHRoaXMudXNlcnMudXBkYXRlKHVzZXJJZCwge1xuICAgICAgICAkdW5zZXQ6IHtcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5oYXZlTG9naW5Ub2tlbnNUb0RlbGV0ZVwiOiAxLFxuICAgICAgICAgIFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zVG9EZWxldGVcIjogMVxuICAgICAgICB9LFxuICAgICAgICAkcHVsbEFsbDoge1xuICAgICAgICAgIFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zXCI6IHRva2Vuc1RvRGVsZXRlXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cbiAgfTtcblxuICBfZGVsZXRlU2F2ZWRUb2tlbnNGb3JBbGxVc2Vyc09uU3RhcnR1cCgpIHtcbiAgICAvLyBJZiB3ZSBmaW5kIHVzZXJzIHdobyBoYXZlIHNhdmVkIHRva2VucyB0byBkZWxldGUgb24gc3RhcnR1cCwgZGVsZXRlXG4gICAgLy8gdGhlbSBub3cuIEl0J3MgcG9zc2libGUgdGhhdCB0aGUgc2VydmVyIGNvdWxkIGhhdmUgY3Jhc2hlZCBhbmQgY29tZVxuICAgIC8vIGJhY2sgdXAgYmVmb3JlIG5ldyB0b2tlbnMgYXJlIGZvdW5kIGluIGxvY2FsU3RvcmFnZSwgYnV0IHRoaXNcbiAgICAvLyBzaG91bGRuJ3QgaGFwcGVuIHZlcnkgb2Z0ZW4uIFdlIHNob3VsZG4ndCBwdXQgYSBkZWxheSBoZXJlIGJlY2F1c2VcbiAgICAvLyB0aGF0IHdvdWxkIGdpdmUgYSBsb3Qgb2YgcG93ZXIgdG8gYW4gYXR0YWNrZXIgd2l0aCBhIHN0b2xlbiBsb2dpblxuICAgIC8vIHRva2VuIGFuZCB0aGUgYWJpbGl0eSB0byBjcmFzaCB0aGUgc2VydmVyLlxuICAgIE1ldGVvci5zdGFydHVwKCgpID0+IHtcbiAgICAgIHRoaXMudXNlcnMuZmluZCh7XG4gICAgICAgIFwic2VydmljZXMucmVzdW1lLmhhdmVMb2dpblRva2Vuc1RvRGVsZXRlXCI6IHRydWVcbiAgICAgIH0sIHtmaWVsZHM6IHtcbiAgICAgICAgICBcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1RvRGVsZXRlXCI6IDFcbiAgICAgICAgfX0pLmZvckVhY2godXNlciA9PiB7XG4gICAgICAgIHRoaXMuX2RlbGV0ZVNhdmVkVG9rZW5zRm9yVXNlcihcbiAgICAgICAgICB1c2VyLl9pZCxcbiAgICAgICAgICB1c2VyLnNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vuc1RvRGVsZXRlXG4gICAgICAgICk7XG4gICAgICB9KTtcbiAgICB9KTtcbiAgfTtcblxuICAvLy9cbiAgLy8vIE1BTkFHSU5HIFVTRVIgT0JKRUNUU1xuICAvLy9cblxuICAvLyBVcGRhdGVzIG9yIGNyZWF0ZXMgYSB1c2VyIGFmdGVyIHdlIGF1dGhlbnRpY2F0ZSB3aXRoIGEgM3JkIHBhcnR5LlxuICAvL1xuICAvLyBAcGFyYW0gc2VydmljZU5hbWUge1N0cmluZ30gU2VydmljZSBuYW1lIChlZywgdHdpdHRlcikuXG4gIC8vIEBwYXJhbSBzZXJ2aWNlRGF0YSB7T2JqZWN0fSBEYXRhIHRvIHN0b3JlIGluIHRoZSB1c2VyJ3MgcmVjb3JkXG4gIC8vICAgICAgICB1bmRlciBzZXJ2aWNlc1tzZXJ2aWNlTmFtZV0uIE11c3QgaW5jbHVkZSBhbiBcImlkXCIgZmllbGRcbiAgLy8gICAgICAgIHdoaWNoIGlzIGEgdW5pcXVlIGlkZW50aWZpZXIgZm9yIHRoZSB1c2VyIGluIHRoZSBzZXJ2aWNlLlxuICAvLyBAcGFyYW0gb3B0aW9ucyB7T2JqZWN0LCBvcHRpb25hbH0gT3RoZXIgb3B0aW9ucyB0byBwYXNzIHRvIGluc2VydFVzZXJEb2NcbiAgLy8gICAgICAgIChlZywgcHJvZmlsZSlcbiAgLy8gQHJldHVybnMge09iamVjdH0gT2JqZWN0IHdpdGggdG9rZW4gYW5kIGlkIGtleXMsIGxpa2UgdGhlIHJlc3VsdFxuICAvLyAgICAgICAgb2YgdGhlIFwibG9naW5cIiBtZXRob2QuXG4gIC8vXG4gIHVwZGF0ZU9yQ3JlYXRlVXNlckZyb21FeHRlcm5hbFNlcnZpY2UoXG4gICAgc2VydmljZU5hbWUsXG4gICAgc2VydmljZURhdGEsXG4gICAgb3B0aW9uc1xuICApIHtcbiAgICBvcHRpb25zID0geyAuLi5vcHRpb25zIH07XG5cbiAgICBpZiAoc2VydmljZU5hbWUgPT09IFwicGFzc3dvcmRcIiB8fCBzZXJ2aWNlTmFtZSA9PT0gXCJyZXN1bWVcIikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcIkNhbid0IHVzZSB1cGRhdGVPckNyZWF0ZVVzZXJGcm9tRXh0ZXJuYWxTZXJ2aWNlIHdpdGggaW50ZXJuYWwgc2VydmljZSBcIlxuICAgICAgICArIHNlcnZpY2VOYW1lKTtcbiAgICB9XG4gICAgaWYgKCFoYXNPd24uY2FsbChzZXJ2aWNlRGF0YSwgJ2lkJykpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYFNlcnZpY2UgZGF0YSBmb3Igc2VydmljZSAke3NlcnZpY2VOYW1lfSBtdXN0IGluY2x1ZGUgaWRgKTtcbiAgICB9XG5cbiAgICAvLyBMb29rIGZvciBhIHVzZXIgd2l0aCB0aGUgYXBwcm9wcmlhdGUgc2VydmljZSB1c2VyIGlkLlxuICAgIGNvbnN0IHNlbGVjdG9yID0ge307XG4gICAgY29uc3Qgc2VydmljZUlkS2V5ID0gYHNlcnZpY2VzLiR7c2VydmljZU5hbWV9LmlkYDtcblxuICAgIC8vIFhYWCBUZW1wb3Jhcnkgc3BlY2lhbCBjYXNlIGZvciBUd2l0dGVyLiAoSXNzdWUgIzYyOSlcbiAgICAvLyAgIFRoZSBzZXJ2aWNlRGF0YS5pZCB3aWxsIGJlIGEgc3RyaW5nIHJlcHJlc2VudGF0aW9uIG9mIGFuIGludGVnZXIuXG4gICAgLy8gICBXZSB3YW50IGl0IHRvIG1hdGNoIGVpdGhlciBhIHN0b3JlZCBzdHJpbmcgb3IgaW50IHJlcHJlc2VudGF0aW9uLlxuICAgIC8vICAgVGhpcyBpcyB0byBjYXRlciB0byBlYXJsaWVyIHZlcnNpb25zIG9mIE1ldGVvciBzdG9yaW5nIHR3aXR0ZXJcbiAgICAvLyAgIHVzZXIgSURzIGluIG51bWJlciBmb3JtLCBhbmQgcmVjZW50IHZlcnNpb25zIHN0b3JpbmcgdGhlbSBhcyBzdHJpbmdzLlxuICAgIC8vICAgVGhpcyBjYW4gYmUgcmVtb3ZlZCBvbmNlIG1pZ3JhdGlvbiB0ZWNobm9sb2d5IGlzIGluIHBsYWNlLCBhbmQgdHdpdHRlclxuICAgIC8vICAgdXNlcnMgc3RvcmVkIHdpdGggaW50ZWdlciBJRHMgaGF2ZSBiZWVuIG1pZ3JhdGVkIHRvIHN0cmluZyBJRHMuXG4gICAgaWYgKHNlcnZpY2VOYW1lID09PSBcInR3aXR0ZXJcIiAmJiAhaXNOYU4oc2VydmljZURhdGEuaWQpKSB7XG4gICAgICBzZWxlY3RvcltcIiRvclwiXSA9IFt7fSx7fV07XG4gICAgICBzZWxlY3RvcltcIiRvclwiXVswXVtzZXJ2aWNlSWRLZXldID0gc2VydmljZURhdGEuaWQ7XG4gICAgICBzZWxlY3RvcltcIiRvclwiXVsxXVtzZXJ2aWNlSWRLZXldID0gcGFyc2VJbnQoc2VydmljZURhdGEuaWQsIDEwKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc2VsZWN0b3Jbc2VydmljZUlkS2V5XSA9IHNlcnZpY2VEYXRhLmlkO1xuICAgIH1cblxuICAgIGxldCB1c2VyID0gdGhpcy51c2Vycy5maW5kT25lKHNlbGVjdG9yLCB7ZmllbGRzOiB0aGlzLl9vcHRpb25zLmRlZmF1bHRGaWVsZFNlbGVjdG9yfSk7XG5cbiAgICAvLyBDaGVjayB0byBzZWUgaWYgdGhlIGRldmVsb3BlciBoYXMgYSBjdXN0b20gd2F5IHRvIGZpbmQgdGhlIHVzZXIgb3V0c2lkZVxuICAgIC8vIG9mIHRoZSBnZW5lcmFsIHNlbGVjdG9ycyBhYm92ZS5cbiAgICBpZiAoIXVzZXIgJiYgdGhpcy5fYWRkaXRpb25hbEZpbmRVc2VyT25FeHRlcm5hbExvZ2luKSB7XG4gICAgICB1c2VyID0gdGhpcy5fYWRkaXRpb25hbEZpbmRVc2VyT25FeHRlcm5hbExvZ2luKHtzZXJ2aWNlTmFtZSwgc2VydmljZURhdGEsIG9wdGlvbnN9KVxuICAgIH1cblxuICAgIC8vIEJlZm9yZSBjb250aW51aW5nLCBydW4gdXNlciBob29rIHRvIHNlZSBpZiB3ZSBzaG91bGQgY29udGludWVcbiAgICBpZiAodGhpcy5fYmVmb3JlRXh0ZXJuYWxMb2dpbkhvb2sgJiYgIXRoaXMuX2JlZm9yZUV4dGVybmFsTG9naW5Ib29rKHNlcnZpY2VOYW1lLCBzZXJ2aWNlRGF0YSwgdXNlcikpIHtcbiAgICAgIHRocm93IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIkxvZ2luIGZvcmJpZGRlblwiKTtcbiAgICB9XG5cbiAgICAvLyBXaGVuIGNyZWF0aW5nIGEgbmV3IHVzZXIgd2UgcGFzcyB0aHJvdWdoIGFsbCBvcHRpb25zLiBXaGVuIHVwZGF0aW5nIGFuXG4gICAgLy8gZXhpc3RpbmcgdXNlciwgYnkgZGVmYXVsdCB3ZSBvbmx5IHByb2Nlc3MvcGFzcyB0aHJvdWdoIHRoZSBzZXJ2aWNlRGF0YVxuICAgIC8vIChlZywgc28gdGhhdCB3ZSBrZWVwIGFuIHVuZXhwaXJlZCBhY2Nlc3MgdG9rZW4gYW5kIGRvbid0IGNhY2hlIG9sZCBlbWFpbFxuICAgIC8vIGFkZHJlc3NlcyBpbiBzZXJ2aWNlRGF0YS5lbWFpbCkuIFRoZSBvbkV4dGVybmFsTG9naW4gaG9vayBjYW4gYmUgdXNlZCB3aGVuXG4gICAgLy8gY3JlYXRpbmcgb3IgdXBkYXRpbmcgYSB1c2VyLCB0byBtb2RpZnkgb3IgcGFzcyB0aHJvdWdoIG1vcmUgb3B0aW9ucyBhc1xuICAgIC8vIG5lZWRlZC5cbiAgICBsZXQgb3B0cyA9IHVzZXIgPyB7fSA6IG9wdGlvbnM7XG4gICAgaWYgKHRoaXMuX29uRXh0ZXJuYWxMb2dpbkhvb2spIHtcbiAgICAgIG9wdHMgPSB0aGlzLl9vbkV4dGVybmFsTG9naW5Ib29rKG9wdGlvbnMsIHVzZXIpO1xuICAgIH1cblxuICAgIGlmICh1c2VyKSB7XG4gICAgICBwaW5FbmNyeXB0ZWRGaWVsZHNUb1VzZXIoc2VydmljZURhdGEsIHVzZXIuX2lkKTtcblxuICAgICAgbGV0IHNldEF0dHJzID0ge307XG4gICAgICBPYmplY3Qua2V5cyhzZXJ2aWNlRGF0YSkuZm9yRWFjaChrZXkgPT5cbiAgICAgICAgc2V0QXR0cnNbYHNlcnZpY2VzLiR7c2VydmljZU5hbWV9LiR7a2V5fWBdID0gc2VydmljZURhdGFba2V5XVxuICAgICAgKTtcblxuICAgICAgLy8gWFhYIE1heWJlIHdlIHNob3VsZCByZS11c2UgdGhlIHNlbGVjdG9yIGFib3ZlIGFuZCBub3RpY2UgaWYgdGhlIHVwZGF0ZVxuICAgICAgLy8gICAgIHRvdWNoZXMgbm90aGluZz9cbiAgICAgIHNldEF0dHJzID0geyAuLi5zZXRBdHRycywgLi4ub3B0cyB9O1xuICAgICAgdGhpcy51c2Vycy51cGRhdGUodXNlci5faWQsIHtcbiAgICAgICAgJHNldDogc2V0QXR0cnNcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4ge1xuICAgICAgICB0eXBlOiBzZXJ2aWNlTmFtZSxcbiAgICAgICAgdXNlcklkOiB1c2VyLl9pZFxuICAgICAgfTtcbiAgICB9IGVsc2Uge1xuICAgICAgLy8gQ3JlYXRlIGEgbmV3IHVzZXIgd2l0aCB0aGUgc2VydmljZSBkYXRhLlxuICAgICAgdXNlciA9IHtzZXJ2aWNlczoge319O1xuICAgICAgdXNlci5zZXJ2aWNlc1tzZXJ2aWNlTmFtZV0gPSBzZXJ2aWNlRGF0YTtcbiAgICAgIHJldHVybiB7XG4gICAgICAgIHR5cGU6IHNlcnZpY2VOYW1lLFxuICAgICAgICB1c2VySWQ6IHRoaXMuaW5zZXJ0VXNlckRvYyhvcHRzLCB1c2VyKVxuICAgICAgfTtcbiAgICB9XG4gIH07XG5cbiAgLy8gUmVtb3ZlcyBkZWZhdWx0IHJhdGUgbGltaXRpbmcgcnVsZVxuICByZW1vdmVEZWZhdWx0UmF0ZUxpbWl0KCkge1xuICAgIGNvbnN0IHJlc3AgPSBERFBSYXRlTGltaXRlci5yZW1vdmVSdWxlKHRoaXMuZGVmYXVsdFJhdGVMaW1pdGVyUnVsZUlkKTtcbiAgICB0aGlzLmRlZmF1bHRSYXRlTGltaXRlclJ1bGVJZCA9IG51bGw7XG4gICAgcmV0dXJuIHJlc3A7XG4gIH07XG5cbiAgLy8gQWRkIGEgZGVmYXVsdCBydWxlIG9mIGxpbWl0aW5nIGxvZ2lucywgY3JlYXRpbmcgbmV3IHVzZXJzIGFuZCBwYXNzd29yZCByZXNldFxuICAvLyB0byA1IHRpbWVzIGV2ZXJ5IDEwIHNlY29uZHMgcGVyIGNvbm5lY3Rpb24uXG4gIGFkZERlZmF1bHRSYXRlTGltaXQoKSB7XG4gICAgaWYgKCF0aGlzLmRlZmF1bHRSYXRlTGltaXRlclJ1bGVJZCkge1xuICAgICAgdGhpcy5kZWZhdWx0UmF0ZUxpbWl0ZXJSdWxlSWQgPSBERFBSYXRlTGltaXRlci5hZGRSdWxlKHtcbiAgICAgICAgdXNlcklkOiBudWxsLFxuICAgICAgICBjbGllbnRBZGRyZXNzOiBudWxsLFxuICAgICAgICB0eXBlOiAnbWV0aG9kJyxcbiAgICAgICAgbmFtZTogbmFtZSA9PiBbJ2xvZ2luJywgJ2NyZWF0ZVVzZXInLCAncmVzZXRQYXNzd29yZCcsICdmb3Jnb3RQYXNzd29yZCddXG4gICAgICAgICAgLmluY2x1ZGVzKG5hbWUpLFxuICAgICAgICBjb25uZWN0aW9uSWQ6IChjb25uZWN0aW9uSWQpID0+IHRydWUsXG4gICAgICB9LCA1LCAxMDAwMCk7XG4gICAgfVxuICB9O1xuXG4gIC8qKlxuICAgKiBAc3VtbWFyeSBDcmVhdGVzIG9wdGlvbnMgZm9yIGVtYWlsIHNlbmRpbmcgZm9yIHJlc2V0IHBhc3N3b3JkIGFuZCBlbnJvbGwgYWNjb3VudCBlbWFpbHMuXG4gICAqIFlvdSBjYW4gdXNlIHRoaXMgZnVuY3Rpb24gd2hlbiBjdXN0b21pemluZyBhIHJlc2V0IHBhc3N3b3JkIG9yIGVucm9sbCBhY2NvdW50IGVtYWlsIHNlbmRpbmcuXG4gICAqIEBsb2N1cyBTZXJ2ZXJcbiAgICogQHBhcmFtIHtPYmplY3R9IGVtYWlsIFdoaWNoIGFkZHJlc3Mgb2YgdGhlIHVzZXIncyB0byBzZW5kIHRoZSBlbWFpbCB0by5cbiAgICogQHBhcmFtIHtPYmplY3R9IHVzZXIgVGhlIHVzZXIgb2JqZWN0IHRvIGdlbmVyYXRlIG9wdGlvbnMgZm9yLlxuICAgKiBAcGFyYW0ge1N0cmluZ30gdXJsIFVSTCB0byB3aGljaCB1c2VyIGlzIGRpcmVjdGVkIHRvIGNvbmZpcm0gdGhlIGVtYWlsLlxuICAgKiBAcGFyYW0ge1N0cmluZ30gcmVhc29uIGByZXNldFBhc3N3b3JkYCBvciBgZW5yb2xsQWNjb3VudGAuXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IE9wdGlvbnMgd2hpY2ggY2FuIGJlIHBhc3NlZCB0byBgRW1haWwuc2VuZGAuXG4gICAqIEBpbXBvcnRGcm9tUGFja2FnZSBhY2NvdW50cy1iYXNlXG4gICAqL1xuICBnZW5lcmF0ZU9wdGlvbnNGb3JFbWFpbChlbWFpbCwgdXNlciwgdXJsLCByZWFzb24sIGV4dHJhID0ge30pe1xuICAgIGNvbnN0IG9wdGlvbnMgPSB7XG4gICAgICB0bzogZW1haWwsXG4gICAgICBmcm9tOiB0aGlzLmVtYWlsVGVtcGxhdGVzW3JlYXNvbl0uZnJvbVxuICAgICAgICA/IHRoaXMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS5mcm9tKHVzZXIpXG4gICAgICAgIDogdGhpcy5lbWFpbFRlbXBsYXRlcy5mcm9tLFxuICAgICAgc3ViamVjdDogdGhpcy5lbWFpbFRlbXBsYXRlc1tyZWFzb25dLnN1YmplY3QodXNlciwgdXJsLCBleHRyYSksXG4gICAgfTtcblxuICAgIGlmICh0eXBlb2YgdGhpcy5lbWFpbFRlbXBsYXRlc1tyZWFzb25dLnRleHQgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIG9wdGlvbnMudGV4dCA9IHRoaXMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS50ZXh0KHVzZXIsIHVybCwgZXh0cmEpO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgdGhpcy5lbWFpbFRlbXBsYXRlc1tyZWFzb25dLmh0bWwgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIG9wdGlvbnMuaHRtbCA9IHRoaXMuZW1haWxUZW1wbGF0ZXNbcmVhc29uXS5odG1sKHVzZXIsIHVybCwgZXh0cmEpO1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgdGhpcy5lbWFpbFRlbXBsYXRlcy5oZWFkZXJzID09PSAnb2JqZWN0Jykge1xuICAgICAgb3B0aW9ucy5oZWFkZXJzID0gdGhpcy5lbWFpbFRlbXBsYXRlcy5oZWFkZXJzO1xuICAgIH1cblxuICAgIHJldHVybiBvcHRpb25zO1xuICB9O1xuXG4gIF9jaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoXG4gICAgZmllbGROYW1lLFxuICAgIGRpc3BsYXlOYW1lLFxuICAgIGZpZWxkVmFsdWUsXG4gICAgb3duVXNlcklkXG4gICkge1xuICAgIC8vIFNvbWUgdGVzdHMgbmVlZCB0aGUgYWJpbGl0eSB0byBhZGQgdXNlcnMgd2l0aCB0aGUgc2FtZSBjYXNlIGluc2Vuc2l0aXZlXG4gICAgLy8gdmFsdWUsIGhlbmNlIHRoZSBfc2tpcENhc2VJbnNlbnNpdGl2ZUNoZWNrc0ZvclRlc3QgY2hlY2tcbiAgICBjb25zdCBza2lwQ2hlY2sgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoXG4gICAgICB0aGlzLl9za2lwQ2FzZUluc2Vuc2l0aXZlQ2hlY2tzRm9yVGVzdCxcbiAgICAgIGZpZWxkVmFsdWVcbiAgICApO1xuXG4gICAgaWYgKGZpZWxkVmFsdWUgJiYgIXNraXBDaGVjaykge1xuICAgICAgY29uc3QgbWF0Y2hlZFVzZXJzID0gTWV0ZW9yLnVzZXJzXG4gICAgICAgIC5maW5kKFxuICAgICAgICAgIHRoaXMuX3NlbGVjdG9yRm9yRmFzdENhc2VJbnNlbnNpdGl2ZUxvb2t1cChmaWVsZE5hbWUsIGZpZWxkVmFsdWUpLFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGZpZWxkczogeyBfaWQ6IDEgfSxcbiAgICAgICAgICAgIC8vIHdlIG9ubHkgbmVlZCBhIG1heGltdW0gb2YgMiB1c2VycyBmb3IgdGhlIGxvZ2ljIGJlbG93IHRvIHdvcmtcbiAgICAgICAgICAgIGxpbWl0OiAyLFxuICAgICAgICAgIH1cbiAgICAgICAgKVxuICAgICAgICAuZmV0Y2goKTtcblxuICAgICAgaWYgKFxuICAgICAgICBtYXRjaGVkVXNlcnMubGVuZ3RoID4gMCAmJlxuICAgICAgICAvLyBJZiB3ZSBkb24ndCBoYXZlIGEgdXNlcklkIHlldCwgYW55IG1hdGNoIHdlIGZpbmQgaXMgYSBkdXBsaWNhdGVcbiAgICAgICAgKCFvd25Vc2VySWQgfHxcbiAgICAgICAgICAvLyBPdGhlcndpc2UsIGNoZWNrIHRvIHNlZSBpZiB0aGVyZSBhcmUgbXVsdGlwbGUgbWF0Y2hlcyBvciBhIG1hdGNoXG4gICAgICAgICAgLy8gdGhhdCBpcyBub3QgdXNcbiAgICAgICAgICBtYXRjaGVkVXNlcnMubGVuZ3RoID4gMSB8fCBtYXRjaGVkVXNlcnNbMF0uX2lkICE9PSBvd25Vc2VySWQpXG4gICAgICApIHtcbiAgICAgICAgdGhpcy5faGFuZGxlRXJyb3IoYCR7ZGlzcGxheU5hbWV9IGFscmVhZHkgZXhpc3RzLmApO1xuICAgICAgfVxuICAgIH1cbiAgfTtcblxuICBfY3JlYXRlVXNlckNoZWNraW5nRHVwbGljYXRlcyh7IHVzZXIsIGVtYWlsLCB1c2VybmFtZSwgb3B0aW9ucyB9KSB7XG4gICAgY29uc3QgbmV3VXNlciA9IHtcbiAgICAgIC4uLnVzZXIsXG4gICAgICAuLi4odXNlcm5hbWUgPyB7IHVzZXJuYW1lIH0gOiB7fSksXG4gICAgICAuLi4oZW1haWwgPyB7IGVtYWlsczogW3sgYWRkcmVzczogZW1haWwsIHZlcmlmaWVkOiBmYWxzZSB9XSB9IDoge30pLFxuICAgIH07XG5cbiAgICAvLyBQZXJmb3JtIGEgY2FzZSBpbnNlbnNpdGl2ZSBjaGVjayBiZWZvcmUgaW5zZXJ0XG4gICAgdGhpcy5fY2hlY2tGb3JDYXNlSW5zZW5zaXRpdmVEdXBsaWNhdGVzKCd1c2VybmFtZScsICdVc2VybmFtZScsIHVzZXJuYW1lKTtcbiAgICB0aGlzLl9jaGVja0ZvckNhc2VJbnNlbnNpdGl2ZUR1cGxpY2F0ZXMoJ2VtYWlscy5hZGRyZXNzJywgJ0VtYWlsJywgZW1haWwpO1xuXG4gICAgY29uc3QgdXNlcklkID0gdGhpcy5pbnNlcnRVc2VyRG9jKG9wdGlvbnMsIG5ld1VzZXIpO1xuICAgIC8vIFBlcmZvcm0gYW5vdGhlciBjaGVjayBhZnRlciBpbnNlcnQsIGluIGNhc2UgYSBtYXRjaGluZyB1c2VyIGhhcyBiZWVuXG4gICAgLy8gaW5zZXJ0ZWQgaW4gdGhlIG1lYW50aW1lXG4gICAgdHJ5IHtcbiAgICAgIHRoaXMuX2NoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcygndXNlcm5hbWUnLCAnVXNlcm5hbWUnLCB1c2VybmFtZSwgdXNlcklkKTtcbiAgICAgIHRoaXMuX2NoZWNrRm9yQ2FzZUluc2Vuc2l0aXZlRHVwbGljYXRlcygnZW1haWxzLmFkZHJlc3MnLCAnRW1haWwnLCBlbWFpbCwgdXNlcklkKTtcbiAgICB9IGNhdGNoIChleCkge1xuICAgICAgLy8gUmVtb3ZlIGluc2VydGVkIHVzZXIgaWYgdGhlIGNoZWNrIGZhaWxzXG4gICAgICBNZXRlb3IudXNlcnMucmVtb3ZlKHVzZXJJZCk7XG4gICAgICB0aHJvdyBleDtcbiAgICB9XG4gICAgcmV0dXJuIHVzZXJJZDtcbiAgfVxuXG4gIF9oYW5kbGVFcnJvciA9IChtc2csIHRocm93RXJyb3IgPSB0cnVlLCBlcnJvckNvZGUgPSA0MDMpID0+IHtcbiAgICBjb25zdCBlcnJvciA9IG5ldyBNZXRlb3IuRXJyb3IoXG4gICAgICBlcnJvckNvZGUsXG4gICAgICB0aGlzLl9vcHRpb25zLmFtYmlndW91c0Vycm9yTWVzc2FnZXNcbiAgICAgICAgPyBcIlNvbWV0aGluZyB3ZW50IHdyb25nLiBQbGVhc2UgY2hlY2sgeW91ciBjcmVkZW50aWFscy5cIlxuICAgICAgICA6IG1zZ1xuICAgICk7XG4gICAgaWYgKHRocm93RXJyb3IpIHtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgICByZXR1cm4gZXJyb3I7XG4gIH1cblxuICBfdXNlclF1ZXJ5VmFsaWRhdG9yID0gTWF0Y2guV2hlcmUodXNlciA9PiB7XG4gICAgY2hlY2sodXNlciwge1xuICAgICAgaWQ6IE1hdGNoLk9wdGlvbmFsKE5vbkVtcHR5U3RyaW5nKSxcbiAgICAgIHVzZXJuYW1lOiBNYXRjaC5PcHRpb25hbChOb25FbXB0eVN0cmluZyksXG4gICAgICBlbWFpbDogTWF0Y2guT3B0aW9uYWwoTm9uRW1wdHlTdHJpbmcpXG4gICAgfSk7XG4gICAgaWYgKE9iamVjdC5rZXlzKHVzZXIpLmxlbmd0aCAhPT0gMSlcbiAgICAgIHRocm93IG5ldyBNYXRjaC5FcnJvcihcIlVzZXIgcHJvcGVydHkgbXVzdCBoYXZlIGV4YWN0bHkgb25lIGZpZWxkXCIpO1xuICAgIHJldHVybiB0cnVlO1xuICB9KTtcblxufVxuXG4vLyBHaXZlIGVhY2ggbG9naW4gaG9vayBjYWxsYmFjayBhIGZyZXNoIGNsb25lZCBjb3B5IG9mIHRoZSBhdHRlbXB0XG4vLyBvYmplY3QsIGJ1dCBkb24ndCBjbG9uZSB0aGUgY29ubmVjdGlvbi5cbi8vXG5jb25zdCBjbG9uZUF0dGVtcHRXaXRoQ29ubmVjdGlvbiA9IChjb25uZWN0aW9uLCBhdHRlbXB0KSA9PiB7XG4gIGNvbnN0IGNsb25lZEF0dGVtcHQgPSBFSlNPTi5jbG9uZShhdHRlbXB0KTtcbiAgY2xvbmVkQXR0ZW1wdC5jb25uZWN0aW9uID0gY29ubmVjdGlvbjtcbiAgcmV0dXJuIGNsb25lZEF0dGVtcHQ7XG59O1xuXG5jb25zdCB0cnlMb2dpbk1ldGhvZCA9ICh0eXBlLCBmbikgPT4ge1xuICBsZXQgcmVzdWx0O1xuICB0cnkge1xuICAgIHJlc3VsdCA9IGZuKCk7XG4gIH1cbiAgY2F0Y2ggKGUpIHtcbiAgICByZXN1bHQgPSB7ZXJyb3I6IGV9O1xuICB9XG5cbiAgaWYgKHJlc3VsdCAmJiAhcmVzdWx0LnR5cGUgJiYgdHlwZSlcbiAgICByZXN1bHQudHlwZSA9IHR5cGU7XG5cbiAgcmV0dXJuIHJlc3VsdDtcbn07XG5cbmNvbnN0IHNldHVwRGVmYXVsdExvZ2luSGFuZGxlcnMgPSBhY2NvdW50cyA9PiB7XG4gIGFjY291bnRzLnJlZ2lzdGVyTG9naW5IYW5kbGVyKFwicmVzdW1lXCIsIGZ1bmN0aW9uIChvcHRpb25zKSB7XG4gICAgcmV0dXJuIGRlZmF1bHRSZXN1bWVMb2dpbkhhbmRsZXIuY2FsbCh0aGlzLCBhY2NvdW50cywgb3B0aW9ucyk7XG4gIH0pO1xufTtcblxuLy8gTG9naW4gaGFuZGxlciBmb3IgcmVzdW1lIHRva2Vucy5cbmNvbnN0IGRlZmF1bHRSZXN1bWVMb2dpbkhhbmRsZXIgPSAoYWNjb3VudHMsIG9wdGlvbnMpID0+IHtcbiAgaWYgKCFvcHRpb25zLnJlc3VtZSlcbiAgICByZXR1cm4gdW5kZWZpbmVkO1xuXG4gIGNoZWNrKG9wdGlvbnMucmVzdW1lLCBTdHJpbmcpO1xuXG4gIGNvbnN0IGhhc2hlZFRva2VuID0gYWNjb3VudHMuX2hhc2hMb2dpblRva2VuKG9wdGlvbnMucmVzdW1lKTtcblxuICAvLyBGaXJzdCBsb29rIGZvciBqdXN0IHRoZSBuZXctc3R5bGUgaGFzaGVkIGxvZ2luIHRva2VuLCB0byBhdm9pZFxuICAvLyBzZW5kaW5nIHRoZSB1bmhhc2hlZCB0b2tlbiB0byB0aGUgZGF0YWJhc2UgaW4gYSBxdWVyeSBpZiB3ZSBkb24ndFxuICAvLyBuZWVkIHRvLlxuICBsZXQgdXNlciA9IGFjY291bnRzLnVzZXJzLmZpbmRPbmUoXG4gICAge1wic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLmhhc2hlZFRva2VuXCI6IGhhc2hlZFRva2VufSxcbiAgICB7ZmllbGRzOiB7XCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMuJFwiOiAxfX0pO1xuXG4gIGlmICghIHVzZXIpIHtcbiAgICAvLyBJZiB3ZSBkaWRuJ3QgZmluZCB0aGUgaGFzaGVkIGxvZ2luIHRva2VuLCB0cnkgYWxzbyBsb29raW5nIGZvclxuICAgIC8vIHRoZSBvbGQtc3R5bGUgdW5oYXNoZWQgdG9rZW4uICBCdXQgd2UgbmVlZCB0byBsb29rIGZvciBlaXRoZXJcbiAgICAvLyB0aGUgb2xkLXN0eWxlIHRva2VuIE9SIHRoZSBuZXctc3R5bGUgdG9rZW4sIGJlY2F1c2UgYW5vdGhlclxuICAgIC8vIGNsaWVudCBjb25uZWN0aW9uIGxvZ2dpbmcgaW4gc2ltdWx0YW5lb3VzbHkgbWlnaHQgaGF2ZSBhbHJlYWR5XG4gICAgLy8gY29udmVydGVkIHRoZSB0b2tlbi5cbiAgICB1c2VyID0gYWNjb3VudHMudXNlcnMuZmluZE9uZSh7XG4gICAgICAgICRvcjogW1xuICAgICAgICAgIHtcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy5oYXNoZWRUb2tlblwiOiBoYXNoZWRUb2tlbn0sXG4gICAgICAgICAge1wic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zLnRva2VuXCI6IG9wdGlvbnMucmVzdW1lfVxuICAgICAgICBdXG4gICAgICB9LFxuICAgICAgLy8gTm90ZTogQ2Fubm90IHVzZSAuLi5sb2dpblRva2Vucy4kIHBvc2l0aW9uYWwgb3BlcmF0b3Igd2l0aCAkb3IgcXVlcnkuXG4gICAgICB7ZmllbGRzOiB7XCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjogMX19KTtcbiAgfVxuXG4gIGlmICghIHVzZXIpXG4gICAgcmV0dXJuIHtcbiAgICAgIGVycm9yOiBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJZb3UndmUgYmVlbiBsb2dnZWQgb3V0IGJ5IHRoZSBzZXJ2ZXIuIFBsZWFzZSBsb2cgaW4gYWdhaW4uXCIpXG4gICAgfTtcblxuICAvLyBGaW5kIHRoZSB0b2tlbiwgd2hpY2ggd2lsbCBlaXRoZXIgYmUgYW4gb2JqZWN0IHdpdGggZmllbGRzXG4gIC8vIHtoYXNoZWRUb2tlbiwgd2hlbn0gZm9yIGEgaGFzaGVkIHRva2VuIG9yIHt0b2tlbiwgd2hlbn0gZm9yIGFuXG4gIC8vIHVuaGFzaGVkIHRva2VuLlxuICBsZXQgb2xkVW5oYXNoZWRTdHlsZVRva2VuO1xuICBsZXQgdG9rZW4gPSB1c2VyLnNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy5maW5kKHRva2VuID0+XG4gICAgdG9rZW4uaGFzaGVkVG9rZW4gPT09IGhhc2hlZFRva2VuXG4gICk7XG4gIGlmICh0b2tlbikge1xuICAgIG9sZFVuaGFzaGVkU3R5bGVUb2tlbiA9IGZhbHNlO1xuICB9IGVsc2Uge1xuICAgIHRva2VuID0gdXNlci5zZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMuZmluZCh0b2tlbiA9PlxuICAgICAgdG9rZW4udG9rZW4gPT09IG9wdGlvbnMucmVzdW1lXG4gICAgKTtcbiAgICBvbGRVbmhhc2hlZFN0eWxlVG9rZW4gPSB0cnVlO1xuICB9XG5cbiAgY29uc3QgdG9rZW5FeHBpcmVzID0gYWNjb3VudHMuX3Rva2VuRXhwaXJhdGlvbih0b2tlbi53aGVuKTtcbiAgaWYgKG5ldyBEYXRlKCkgPj0gdG9rZW5FeHBpcmVzKVxuICAgIHJldHVybiB7XG4gICAgICB1c2VySWQ6IHVzZXIuX2lkLFxuICAgICAgZXJyb3I6IG5ldyBNZXRlb3IuRXJyb3IoNDAzLCBcIllvdXIgc2Vzc2lvbiBoYXMgZXhwaXJlZC4gUGxlYXNlIGxvZyBpbiBhZ2Fpbi5cIilcbiAgICB9O1xuXG4gIC8vIFVwZGF0ZSB0byBhIGhhc2hlZCB0b2tlbiB3aGVuIGFuIHVuaGFzaGVkIHRva2VuIGlzIGVuY291bnRlcmVkLlxuICBpZiAob2xkVW5oYXNoZWRTdHlsZVRva2VuKSB7XG4gICAgLy8gT25seSBhZGQgdGhlIG5ldyBoYXNoZWQgdG9rZW4gaWYgdGhlIG9sZCB1bmhhc2hlZCB0b2tlbiBzdGlsbFxuICAgIC8vIGV4aXN0cyAodGhpcyBhdm9pZHMgcmVzdXJyZWN0aW5nIHRoZSB0b2tlbiBpZiBpdCB3YXMgZGVsZXRlZFxuICAgIC8vIGFmdGVyIHdlIHJlYWQgaXQpLiAgVXNpbmcgJGFkZFRvU2V0IGF2b2lkcyBnZXR0aW5nIGFuIGluZGV4XG4gICAgLy8gZXJyb3IgaWYgYW5vdGhlciBjbGllbnQgbG9nZ2luZyBpbiBzaW11bHRhbmVvdXNseSBoYXMgYWxyZWFkeVxuICAgIC8vIGluc2VydGVkIHRoZSBuZXcgaGFzaGVkIHRva2VuLlxuICAgIGFjY291bnRzLnVzZXJzLnVwZGF0ZShcbiAgICAgIHtcbiAgICAgICAgX2lkOiB1c2VyLl9pZCxcbiAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnMudG9rZW5cIjogb3B0aW9ucy5yZXN1bWVcbiAgICAgIH0sXG4gICAgICB7JGFkZFRvU2V0OiB7XG4gICAgICAgICAgXCJzZXJ2aWNlcy5yZXN1bWUubG9naW5Ub2tlbnNcIjoge1xuICAgICAgICAgICAgXCJoYXNoZWRUb2tlblwiOiBoYXNoZWRUb2tlbixcbiAgICAgICAgICAgIFwid2hlblwiOiB0b2tlbi53aGVuXG4gICAgICAgICAgfVxuICAgICAgICB9fVxuICAgICk7XG5cbiAgICAvLyBSZW1vdmUgdGhlIG9sZCB0b2tlbiAqYWZ0ZXIqIGFkZGluZyB0aGUgbmV3LCBzaW5jZSBvdGhlcndpc2VcbiAgICAvLyBhbm90aGVyIGNsaWVudCB0cnlpbmcgdG8gbG9naW4gYmV0d2VlbiBvdXIgcmVtb3ZpbmcgdGhlIG9sZCBhbmRcbiAgICAvLyBhZGRpbmcgdGhlIG5ldyB3b3VsZG4ndCBmaW5kIGEgdG9rZW4gdG8gbG9naW4gd2l0aC5cbiAgICBhY2NvdW50cy51c2Vycy51cGRhdGUodXNlci5faWQsIHtcbiAgICAgICRwdWxsOiB7XG4gICAgICAgIFwic2VydmljZXMucmVzdW1lLmxvZ2luVG9rZW5zXCI6IHsgXCJ0b2tlblwiOiBvcHRpb25zLnJlc3VtZSB9XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICByZXR1cm4ge1xuICAgIHVzZXJJZDogdXNlci5faWQsXG4gICAgc3RhbXBlZExvZ2luVG9rZW46IHtcbiAgICAgIHRva2VuOiBvcHRpb25zLnJlc3VtZSxcbiAgICAgIHdoZW46IHRva2VuLndoZW5cbiAgICB9XG4gIH07XG59O1xuXG5jb25zdCBleHBpcmVQYXNzd29yZFRva2VuID0gKFxuICBhY2NvdW50cyxcbiAgb2xkZXN0VmFsaWREYXRlLFxuICB0b2tlbkZpbHRlcixcbiAgdXNlcklkXG4pID0+IHtcbiAgLy8gYm9vbGVhbiB2YWx1ZSB1c2VkIHRvIGRldGVybWluZSBpZiB0aGlzIG1ldGhvZCB3YXMgY2FsbGVkIGZyb20gZW5yb2xsIGFjY291bnQgd29ya2Zsb3dcbiAgbGV0IGlzRW5yb2xsID0gZmFsc2U7XG4gIGNvbnN0IHVzZXJGaWx0ZXIgPSB1c2VySWQgPyB7X2lkOiB1c2VySWR9IDoge307XG4gIC8vIGNoZWNrIGlmIHRoaXMgbWV0aG9kIHdhcyBjYWxsZWQgZnJvbSBlbnJvbGwgYWNjb3VudCB3b3JrZmxvd1xuICBpZih0b2tlbkZpbHRlclsnc2VydmljZXMucGFzc3dvcmQuZW5yb2xsLnJlYXNvbiddKSB7XG4gICAgaXNFbnJvbGwgPSB0cnVlO1xuICB9XG4gIGxldCByZXNldFJhbmdlT3IgPSB7XG4gICAgJG9yOiBbXG4gICAgICB7IFwic2VydmljZXMucGFzc3dvcmQucmVzZXQud2hlblwiOiB7ICRsdDogb2xkZXN0VmFsaWREYXRlIH0gfSxcbiAgICAgIHsgXCJzZXJ2aWNlcy5wYXNzd29yZC5yZXNldC53aGVuXCI6IHsgJGx0OiArb2xkZXN0VmFsaWREYXRlIH0gfVxuICAgIF1cbiAgfTtcbiAgaWYoaXNFbnJvbGwpIHtcbiAgICByZXNldFJhbmdlT3IgPSB7XG4gICAgICAkb3I6IFtcbiAgICAgICAgeyBcInNlcnZpY2VzLnBhc3N3b3JkLmVucm9sbC53aGVuXCI6IHsgJGx0OiBvbGRlc3RWYWxpZERhdGUgfSB9LFxuICAgICAgICB7IFwic2VydmljZXMucGFzc3dvcmQuZW5yb2xsLndoZW5cIjogeyAkbHQ6ICtvbGRlc3RWYWxpZERhdGUgfSB9XG4gICAgICBdXG4gICAgfTtcbiAgfVxuICBjb25zdCBleHBpcmVGaWx0ZXIgPSB7ICRhbmQ6IFt0b2tlbkZpbHRlciwgcmVzZXRSYW5nZU9yXSB9O1xuICBpZihpc0Vucm9sbCkge1xuICAgIGFjY291bnRzLnVzZXJzLnVwZGF0ZSh7Li4udXNlckZpbHRlciwgLi4uZXhwaXJlRmlsdGVyfSwge1xuICAgICAgJHVuc2V0OiB7XG4gICAgICAgIFwic2VydmljZXMucGFzc3dvcmQuZW5yb2xsXCI6IFwiXCJcbiAgICAgIH1cbiAgICB9LCB7IG11bHRpOiB0cnVlIH0pO1xuICB9IGVsc2Uge1xuICAgIGFjY291bnRzLnVzZXJzLnVwZGF0ZSh7Li4udXNlckZpbHRlciwgLi4uZXhwaXJlRmlsdGVyfSwge1xuICAgICAgJHVuc2V0OiB7XG4gICAgICAgIFwic2VydmljZXMucGFzc3dvcmQucmVzZXRcIjogXCJcIlxuICAgICAgfVxuICAgIH0sIHsgbXVsdGk6IHRydWUgfSk7XG4gIH1cblxufTtcblxuY29uc3Qgc2V0RXhwaXJlVG9rZW5zSW50ZXJ2YWwgPSBhY2NvdW50cyA9PiB7XG4gIGFjY291bnRzLmV4cGlyZVRva2VuSW50ZXJ2YWwgPSBNZXRlb3Iuc2V0SW50ZXJ2YWwoKCkgPT4ge1xuICAgIGFjY291bnRzLl9leHBpcmVUb2tlbnMoKTtcbiAgICBhY2NvdW50cy5fZXhwaXJlUGFzc3dvcmRSZXNldFRva2VucygpO1xuICAgIGFjY291bnRzLl9leHBpcmVQYXNzd29yZEVucm9sbFRva2VucygpO1xuICB9LCBFWFBJUkVfVE9LRU5TX0lOVEVSVkFMX01TKTtcbn07XG5cbi8vL1xuLy8vIE9BdXRoIEVuY3J5cHRpb24gU3VwcG9ydFxuLy8vXG5cbmNvbnN0IE9BdXRoRW5jcnlwdGlvbiA9XG4gIFBhY2thZ2VbXCJvYXV0aC1lbmNyeXB0aW9uXCJdICYmXG4gIFBhY2thZ2VbXCJvYXV0aC1lbmNyeXB0aW9uXCJdLk9BdXRoRW5jcnlwdGlvbjtcblxuY29uc3QgdXNpbmdPQXV0aEVuY3J5cHRpb24gPSAoKSA9PiB7XG4gIHJldHVybiBPQXV0aEVuY3J5cHRpb24gJiYgT0F1dGhFbmNyeXB0aW9uLmtleUlzTG9hZGVkKCk7XG59O1xuXG4vLyBPQXV0aCBzZXJ2aWNlIGRhdGEgaXMgdGVtcG9yYXJpbHkgc3RvcmVkIGluIHRoZSBwZW5kaW5nIGNyZWRlbnRpYWxzXG4vLyBjb2xsZWN0aW9uIGR1cmluZyB0aGUgb2F1dGggYXV0aGVudGljYXRpb24gcHJvY2Vzcy4gIFNlbnNpdGl2ZSBkYXRhXG4vLyBzdWNoIGFzIGFjY2VzcyB0b2tlbnMgYXJlIGVuY3J5cHRlZCB3aXRob3V0IHRoZSB1c2VyIGlkIGJlY2F1c2Vcbi8vIHdlIGRvbid0IGtub3cgdGhlIHVzZXIgaWQgeWV0LiAgV2UgcmUtZW5jcnlwdCB0aGVzZSBmaWVsZHMgd2l0aCB0aGVcbi8vIHVzZXIgaWQgaW5jbHVkZWQgd2hlbiBzdG9yaW5nIHRoZSBzZXJ2aWNlIGRhdGEgcGVybWFuZW50bHkgaW5cbi8vIHRoZSB1c2VycyBjb2xsZWN0aW9uLlxuLy9cbmNvbnN0IHBpbkVuY3J5cHRlZEZpZWxkc1RvVXNlciA9IChzZXJ2aWNlRGF0YSwgdXNlcklkKSA9PiB7XG4gIE9iamVjdC5rZXlzKHNlcnZpY2VEYXRhKS5mb3JFYWNoKGtleSA9PiB7XG4gICAgbGV0IHZhbHVlID0gc2VydmljZURhdGFba2V5XTtcbiAgICBpZiAoT0F1dGhFbmNyeXB0aW9uICYmIE9BdXRoRW5jcnlwdGlvbi5pc1NlYWxlZCh2YWx1ZSkpXG4gICAgICB2YWx1ZSA9IE9BdXRoRW5jcnlwdGlvbi5zZWFsKE9BdXRoRW5jcnlwdGlvbi5vcGVuKHZhbHVlKSwgdXNlcklkKTtcbiAgICBzZXJ2aWNlRGF0YVtrZXldID0gdmFsdWU7XG4gIH0pO1xufTtcblxuXG4vLyBFbmNyeXB0IHVuZW5jcnlwdGVkIGxvZ2luIHNlcnZpY2Ugc2VjcmV0cyB3aGVuIG9hdXRoLWVuY3J5cHRpb24gaXNcbi8vIGFkZGVkLlxuLy9cbi8vIFhYWCBGb3IgdGhlIG9hdXRoU2VjcmV0S2V5IHRvIGJlIGF2YWlsYWJsZSBoZXJlIGF0IHN0YXJ0dXAsIHRoZVxuLy8gZGV2ZWxvcGVyIG11c3QgY2FsbCBBY2NvdW50cy5jb25maWcoe29hdXRoU2VjcmV0S2V5OiAuLi59KSBhdCBsb2FkXG4vLyB0aW1lLCBpbnN0ZWFkIG9mIGluIGEgTWV0ZW9yLnN0YXJ0dXAgYmxvY2ssIGJlY2F1c2UgdGhlIHN0YXJ0dXBcbi8vIGJsb2NrIGluIHRoZSBhcHAgY29kZSB3aWxsIHJ1biBhZnRlciB0aGlzIGFjY291bnRzLWJhc2Ugc3RhcnR1cFxuLy8gYmxvY2suICBQZXJoYXBzIHdlIG5lZWQgYSBwb3N0LXN0YXJ0dXAgY2FsbGJhY2s/XG5cbk1ldGVvci5zdGFydHVwKCgpID0+IHtcbiAgaWYgKCEgdXNpbmdPQXV0aEVuY3J5cHRpb24oKSkge1xuICAgIHJldHVybjtcbiAgfVxuXG4gIGNvbnN0IHsgU2VydmljZUNvbmZpZ3VyYXRpb24gfSA9IFBhY2thZ2VbJ3NlcnZpY2UtY29uZmlndXJhdGlvbiddO1xuXG4gIFNlcnZpY2VDb25maWd1cmF0aW9uLmNvbmZpZ3VyYXRpb25zLmZpbmQoe1xuICAgICRhbmQ6IFt7XG4gICAgICBzZWNyZXQ6IHsgJGV4aXN0czogdHJ1ZSB9XG4gICAgfSwge1xuICAgICAgXCJzZWNyZXQuYWxnb3JpdGhtXCI6IHsgJGV4aXN0czogZmFsc2UgfVxuICAgIH1dXG4gIH0pLmZvckVhY2goY29uZmlnID0+IHtcbiAgICBTZXJ2aWNlQ29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucy51cGRhdGUoY29uZmlnLl9pZCwge1xuICAgICAgJHNldDoge1xuICAgICAgICBzZWNyZXQ6IE9BdXRoRW5jcnlwdGlvbi5zZWFsKGNvbmZpZy5zZWNyZXQpXG4gICAgICB9XG4gICAgfSk7XG4gIH0pO1xufSk7XG5cbi8vIFhYWCBzZWUgY29tbWVudCBvbiBBY2NvdW50cy5jcmVhdGVVc2VyIGluIHBhc3N3b3Jkc19zZXJ2ZXIgYWJvdXQgYWRkaW5nIGFcbi8vIHNlY29uZCBcInNlcnZlciBvcHRpb25zXCIgYXJndW1lbnQuXG5jb25zdCBkZWZhdWx0Q3JlYXRlVXNlckhvb2sgPSAob3B0aW9ucywgdXNlcikgPT4ge1xuICBpZiAob3B0aW9ucy5wcm9maWxlKVxuICAgIHVzZXIucHJvZmlsZSA9IG9wdGlvbnMucHJvZmlsZTtcbiAgcmV0dXJuIHVzZXI7XG59O1xuXG4vLyBWYWxpZGF0ZSBuZXcgdXNlcidzIGVtYWlsIG9yIEdvb2dsZS9GYWNlYm9vay9HaXRIdWIgYWNjb3VudCdzIGVtYWlsXG5mdW5jdGlvbiBkZWZhdWx0VmFsaWRhdGVOZXdVc2VySG9vayh1c2VyKSB7XG4gIGNvbnN0IGRvbWFpbiA9IHRoaXMuX29wdGlvbnMucmVzdHJpY3RDcmVhdGlvbkJ5RW1haWxEb21haW47XG4gIGlmICghZG9tYWluKSB7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBsZXQgZW1haWxJc0dvb2QgPSBmYWxzZTtcbiAgaWYgKHVzZXIuZW1haWxzICYmIHVzZXIuZW1haWxzLmxlbmd0aCA+IDApIHtcbiAgICBlbWFpbElzR29vZCA9IHVzZXIuZW1haWxzLnJlZHVjZShcbiAgICAgIChwcmV2LCBlbWFpbCkgPT4gcHJldiB8fCB0aGlzLl90ZXN0RW1haWxEb21haW4oZW1haWwuYWRkcmVzcyksIGZhbHNlXG4gICAgKTtcbiAgfSBlbHNlIGlmICh1c2VyLnNlcnZpY2VzICYmIE9iamVjdC52YWx1ZXModXNlci5zZXJ2aWNlcykubGVuZ3RoID4gMCkge1xuICAgIC8vIEZpbmQgYW55IGVtYWlsIG9mIGFueSBzZXJ2aWNlIGFuZCBjaGVjayBpdFxuICAgIGVtYWlsSXNHb29kID0gT2JqZWN0LnZhbHVlcyh1c2VyLnNlcnZpY2VzKS5yZWR1Y2UoXG4gICAgICAocHJldiwgc2VydmljZSkgPT4gc2VydmljZS5lbWFpbCAmJiB0aGlzLl90ZXN0RW1haWxEb21haW4oc2VydmljZS5lbWFpbCksXG4gICAgICBmYWxzZSxcbiAgICApO1xuICB9XG5cbiAgaWYgKGVtYWlsSXNHb29kKSB7XG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBpZiAodHlwZW9mIGRvbWFpbiA9PT0gJ3N0cmluZycpIHtcbiAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgYEAke2RvbWFpbn0gZW1haWwgcmVxdWlyZWRgKTtcbiAgfSBlbHNlIHtcbiAgICB0aHJvdyBuZXcgTWV0ZW9yLkVycm9yKDQwMywgXCJFbWFpbCBkb2Vzbid0IG1hdGNoIHRoZSBjcml0ZXJpYS5cIik7XG4gIH1cbn1cblxuY29uc3Qgc2V0dXBVc2Vyc0NvbGxlY3Rpb24gPSB1c2VycyA9PiB7XG4gIC8vL1xuICAvLy8gUkVTVFJJQ1RJTkcgV1JJVEVTIFRPIFVTRVIgT0JKRUNUU1xuICAvLy9cbiAgdXNlcnMuYWxsb3coe1xuICAgIC8vIGNsaWVudHMgY2FuIG1vZGlmeSB0aGUgcHJvZmlsZSBmaWVsZCBvZiB0aGVpciBvd24gZG9jdW1lbnQsIGFuZFxuICAgIC8vIG5vdGhpbmcgZWxzZS5cbiAgICB1cGRhdGU6ICh1c2VySWQsIHVzZXIsIGZpZWxkcywgbW9kaWZpZXIpID0+IHtcbiAgICAgIC8vIG1ha2Ugc3VyZSBpdCBpcyBvdXIgcmVjb3JkXG4gICAgICBpZiAodXNlci5faWQgIT09IHVzZXJJZCkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG5cbiAgICAgIC8vIHVzZXIgY2FuIG9ubHkgbW9kaWZ5IHRoZSAncHJvZmlsZScgZmllbGQuIHNldHMgdG8gbXVsdGlwbGVcbiAgICAgIC8vIHN1Yi1rZXlzIChlZyBwcm9maWxlLmZvbyBhbmQgcHJvZmlsZS5iYXIpIGFyZSBtZXJnZWQgaW50byBlbnRyeVxuICAgICAgLy8gaW4gdGhlIGZpZWxkcyBsaXN0LlxuICAgICAgaWYgKGZpZWxkcy5sZW5ndGggIT09IDEgfHwgZmllbGRzWzBdICE9PSAncHJvZmlsZScpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9LFxuICAgIGZldGNoOiBbJ19pZCddIC8vIHdlIG9ubHkgbG9vayBhdCBfaWQuXG4gIH0pO1xuXG4gIC8vLyBERUZBVUxUIElOREVYRVMgT04gVVNFUlNcbiAgdXNlcnMuY3JlYXRlSW5kZXgoJ3VzZXJuYW1lJywgeyB1bmlxdWU6IHRydWUsIHNwYXJzZTogdHJ1ZSB9KTtcbiAgdXNlcnMuY3JlYXRlSW5kZXgoJ2VtYWlscy5hZGRyZXNzJywgeyB1bmlxdWU6IHRydWUsIHNwYXJzZTogdHJ1ZSB9KTtcbiAgdXNlcnMuY3JlYXRlSW5kZXgoJ3NlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy5oYXNoZWRUb2tlbicsXG4gICAgeyB1bmlxdWU6IHRydWUsIHNwYXJzZTogdHJ1ZSB9KTtcbiAgdXNlcnMuY3JlYXRlSW5kZXgoJ3NlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy50b2tlbicsXG4gICAgeyB1bmlxdWU6IHRydWUsIHNwYXJzZTogdHJ1ZSB9KTtcbiAgLy8gRm9yIHRha2luZyBjYXJlIG9mIGxvZ291dE90aGVyQ2xpZW50cyBjYWxscyB0aGF0IGNyYXNoZWQgYmVmb3JlIHRoZVxuICAvLyB0b2tlbnMgd2VyZSBkZWxldGVkLlxuICB1c2Vycy5jcmVhdGVJbmRleCgnc2VydmljZXMucmVzdW1lLmhhdmVMb2dpblRva2Vuc1RvRGVsZXRlJyxcbiAgICB7IHNwYXJzZTogdHJ1ZSB9KTtcbiAgLy8gRm9yIGV4cGlyaW5nIGxvZ2luIHRva2Vuc1xuICB1c2Vycy5jcmVhdGVJbmRleChcInNlcnZpY2VzLnJlc3VtZS5sb2dpblRva2Vucy53aGVuXCIsIHsgc3BhcnNlOiB0cnVlIH0pO1xuICAvLyBGb3IgZXhwaXJpbmcgcGFzc3dvcmQgdG9rZW5zXG4gIHVzZXJzLmNyZWF0ZUluZGV4KCdzZXJ2aWNlcy5wYXNzd29yZC5yZXNldC53aGVuJywgeyBzcGFyc2U6IHRydWUgfSk7XG4gIHVzZXJzLmNyZWF0ZUluZGV4KCdzZXJ2aWNlcy5wYXNzd29yZC5lbnJvbGwud2hlbicsIHsgc3BhcnNlOiB0cnVlIH0pO1xufTtcblxuXG4vLyBHZW5lcmF0ZXMgcGVybXV0YXRpb25zIG9mIGFsbCBjYXNlIHZhcmlhdGlvbnMgb2YgYSBnaXZlbiBzdHJpbmcuXG5jb25zdCBnZW5lcmF0ZUNhc2VQZXJtdXRhdGlvbnNGb3JTdHJpbmcgPSBzdHJpbmcgPT4ge1xuICBsZXQgcGVybXV0YXRpb25zID0gWycnXTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCBzdHJpbmcubGVuZ3RoOyBpKyspIHtcbiAgICBjb25zdCBjaCA9IHN0cmluZy5jaGFyQXQoaSk7XG4gICAgcGVybXV0YXRpb25zID0gW10uY29uY2F0KC4uLihwZXJtdXRhdGlvbnMubWFwKHByZWZpeCA9PiB7XG4gICAgICBjb25zdCBsb3dlckNhc2VDaGFyID0gY2gudG9Mb3dlckNhc2UoKTtcbiAgICAgIGNvbnN0IHVwcGVyQ2FzZUNoYXIgPSBjaC50b1VwcGVyQ2FzZSgpO1xuICAgICAgLy8gRG9uJ3QgYWRkIHVubmVjZXNzYXJ5IHBlcm11dGF0aW9ucyB3aGVuIGNoIGlzIG5vdCBhIGxldHRlclxuICAgICAgaWYgKGxvd2VyQ2FzZUNoYXIgPT09IHVwcGVyQ2FzZUNoYXIpIHtcbiAgICAgICAgcmV0dXJuIFtwcmVmaXggKyBjaF07XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gW3ByZWZpeCArIGxvd2VyQ2FzZUNoYXIsIHByZWZpeCArIHVwcGVyQ2FzZUNoYXJdO1xuICAgICAgfVxuICAgIH0pKSk7XG4gIH1cbiAgcmV0dXJuIHBlcm11dGF0aW9ucztcbn1cblxuIl19
