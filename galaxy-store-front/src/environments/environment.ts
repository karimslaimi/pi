// The file contents for the current environment will overwrite these during build.
// The build system defaults to the dev environment which uses `environment.ts`, but if you do
// `ng build --env=prod` then `environment.prod.ts` will be used instead.
// The list of which env maps to which file can be found in `angular-cli.json`.

export const environment = {
  production: false,
  API_URL: 'http://localhost:3000',
  ICE_SERVERS: [ 'stun:stun1.l.google.com:19302', 'stun:stun2.l.google.com:19302'],
  OAuthKey: 'JoNbnHtUjki0NoPkoqzLYUVeanQ'
};
