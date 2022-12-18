// src/index.ts
import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';

// src/lib/get-text.ts
function getText({ text }) {
  api.asApp().requestJira(route`rest/api/3/issue`);
  return 'Hello, world!\n' + text;
}

// src/lib/permissions.ts
import { authorize } from '@forge/api';
var administerPermission = 'ADMINISTER';
function isGlobalAdminPermission(permission) {
  return permission.permission === administerPermission;
}
async function isJiraGlobalAdmin() {
  const permissions = await authorize().onJira([
    { permissions: [administerPermission] },
  ]);
  return permissions.every(isGlobalAdminPermission);
}

// src/index.ts
var resolver = new Resolver();
resolver.define('getText' /* getText */, async (req) => {
  console.log('called getText()');
  await requireAccess({ req });
  const accountId = requireAccountId(req);
  //const payload = getTextSchema.parse(req.payload);
  const payload = { text: 'hi' };
  console.log('accessed getText()');
  return getText({ ...payload, accountId });
});

async function requireAccess({ req }) {
  const isAdmin = await isJiraGlobalAdmin();
  if (!isAdmin) {
    throw new Error('not permitted');
  }
}
function requireAccountId(req) {
  //return mod.string().parse(req.context.accountId);
  return 'hi';
}
var handler = resolver.getDefinitions();
export { handler };
