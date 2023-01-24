/* global Base64 */

export function getClientIdFromOptions(options, servicesConfig) {
  const { shard } = options;
  if (shard) {
    return servicesConfig[`clientId-${shard}`];
  }
  return servicesConfig.clientId;
}

export function getAppIdFromOptions(options) {
  const { appId } = options;
  return appId || null;
}

export function getServiceConfiguration({ appId = null }) {
  // eslint-disable-next-line no-undef
  const service = ServiceConfiguration.configurations.findOne({
    service: 'apple',
  });
  if (!appId) {
    return service;
  }
  if (
    !Array.isArray(service.apps) ||
    (Meteor.isServer && !Array.isArray(service.secret))
  ) {
    throw new Error('No service configuration found for multiple apps');
  }
  const appIdMap = service.apps.reduce(
    (acc, { appId: id, ...appConfig }) => ({
      ...acc,
      [id]: appConfig,
    }),
    {}
  );
  const secretMap = ((Meteor.isServer && service.secret) || []).reduce(
    (acc, { appId: id, secret }) => ({
      ...acc,
      [id]: secret,
    }),
    {}
  );
  if (!appIdMap[appId] || (Meteor.isServer && !secretMap[appId])) {
    throw new Error(`No service configuration found for ${appId}`);
  }
  return {
    ...appIdMap[appId],
    secret: secretMap[appId],
  };
}

export function stateParam({
  loginStyle,
  credentialToken,
  redirectUrl,
  ...rest
}) {
  const state = {
    loginStyle,
    credentialToken,
    isCordova: Meteor.isCordova,
    ...rest,
  };

  if (loginStyle === 'redirect' || loginStyle === 'popup') state.redirectUrl = redirectUrl || `${window.location}`;

  // Encode base64 as not all login services URI-encode the state
  // parameter when they pass it back to us.
  // Use the 'base64' package here because 'btoa' isn't supported in IE8/9.
  return Base64.encode(JSON.stringify(state));
}

export const METHOD_NAMES = {
  NATIVE: 'native-apple',
  WEB: 'web-apple'
}
