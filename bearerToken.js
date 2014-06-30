'use strict';
var jwt = require('jwt-simple');
var _ = require('lodash');
var debug = false;

function verify(token, options) {
  if (Math.round(Date.now()) / 1000 >= token.exp) {
    if (debug) console.error('Auth token expired', token);
    return false;
  }

  if (options.audience) {
    if (token.aud !== options.audience) {
      if (debug) console.error('Auth token audience mismatch', token, options);
      return false;
    }
  }

  if (options.issuer) {
    if (token.iss !== options.issuer) {
      if (debug) console.error('Auth token issuer mismatch', token, options);
      return false;
    }
  }

  // multiple scopes are space delimited
  // this rule must be last as it returns on a true
  if (options.scope) {
    var optScopes = options.scope.split(' ');
    var tokScopes = token.scope.split(' ');
    var oscope, i = optScopes.length;
    while (i--) {
      oscope = optScopes[i];
      if (tokScopes.indexOf(oscope) >= 0) return true;
    }
    if (debug) console.error('Auth token scope mismatch', token, options);
    return false;
  }

  return true;
}

/**
 * Determines if at least one authorization object is truthy.
 */
function verifyOperation(token, auths) {
  // no auths means it's not protected
  if (!auths || !auths.length) return true;

  return _.some(auths, function(auth) {
    return verify(token, auth);
  });
}

/**
 * Ensures JWT has scope.
 */
module.exports = function(options) {
  debug = options.debug;

  return function oauth2(req, res, next) {
    // skip operations without oauth2 authorizations
    var op = req.__eapi.operation;
    var resource = req.__eapi.resource;

    // authorizations can be at operation level or for the entire resource
    var auths;
    if (op.authorizations && op.authorizations.oauth2)
      auths = op.authorizations.oauth2;
    else if (resource.authorizations && resource.authorizations.oauth2)
      auths = resource.authorizations.oauth2;

    if (!auths) return next();

    try {
      var bearerToken = req.headers && req.headers.authorization;
      if (!bearerToken) {
        if (debug) console.error('Bearer token not found in header');
        return res.send(403);
      }

      // Skip 'Bearer '
      bearerToken = bearerToken.substr(7);

      // shouldn't algorithm be in the header?
      var token = jwt.decode(bearerToken, options.signingKey, 'HS512');
      if (!token) {
        if (debug) console.error('Could not decode bearer token');
        return res.send(403);
      }

      // verify original options then verify operation specific auths
      if (!verify(token, options) && !verifyOperation(token, auths)) {
        if (debug) console.error('Failed to verify');
        return res.send(403);
      }

      req.__eapi.token = token;
      if (debug) console.log('Bearer OK');
      next();
    } catch(err) {
      console.error(err);
      return res.send(403);
    }
  };
};
