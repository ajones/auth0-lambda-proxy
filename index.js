"use strict";
const got = require("got");
const jwt = require("jsonwebtoken");

const DOWNSTREAM_TARGET_ENV = "DOWNSTREAM_TARGET";
const JWT_VERIFY_CERT = "JWT_VERIFY_CERT";
const AUTHORIZED_USER_ID_HEADER = "x-authorized-userid";

//cert available from `wget https://[your_domain].auth0.com/pem`
const pemCert = process.env[JWT_VERIFY_CERT];
const downstreamTarget = process.env[DOWNSTREAM_TARGET_ENV];

if (!downstreamTarget || downstreamTarget.length == 0) {
  throw new Error(`${DOWNSTREAM_TARGET_ENV} env not set`);
}

function verbToMethod(verb = "") {
  const loweredVerb = verb.toLowerCase();
  return got[loweredVerb];
}

async function validateToken(token) {
  // If there is no token user is not logged in
  if (!token || token.length === 0) {
    throw new Error("missing authorization header");
  }

  const tokenCrop = token.replace("Bearer ", "");
  const decodedToken = jwt.verify(tokenCrop, pemCert, { algorithm: "RS256" });
  const userId = decodedToken.sub.replace("auth0|", "");

  console.log("Authorized user", userId);

  return userId;
}

exports.handler = async (event) => {
  const { httpMethod, path, headers, body, queryStringParameters } = event;

  const requestMethod = verbToMethod(httpMethod);
  const fullURL = `${downstreamTarget}${path}`;

  // validate authorization
  try {
    const userId = await validateToken(headers.authorization);
    headers[AUTHORIZED_USER_ID_HEADER] = userId;
  } catch (ex) {
    return {
      statusCode: 401,
      body: `${ex}`,
    };
  }

  // proxy request
  try {
    const resp = await requestMethod(fullURL, {
      headers,
      body: httpMethod == "GET" ? undefined : body,
      searchParams: queryStringParameters,
    });
    console.log("resp", resp.statusCode, resp.body);
    return {
      statusCode: resp.statusCode,
      body: resp.body,
      headers: resp.headers,
    };
  } catch (ex) {
    return {
      statusCode: 500,
      body: `${ex}`,
    };
  }
};
