import Resolver from '@forge/resolver';
import { kvs } from '@forge/kvs';

const resolver = new Resolver();

function save(key, record) {
  kvs.set(key, record);
  record;
}

function update(payload) {
  if (payload) {
    const record = {};
    save('key', record);
  }
  if (payload) {
    const record = {};
    save('key', record);
  }
}

resolver.define('read', () => {});
resolver.define('update', update);
export const handler = resolver.getDefinitions();
