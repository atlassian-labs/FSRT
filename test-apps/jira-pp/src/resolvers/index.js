import api, { route, fetch } from "@forge/api";
import Resolver from "@forge/resolver";

function merge(tgt, src) {
  for (const attr of Object.keys(src)) {
    console.log(`merging: ${attr}`);
    if (typeof src[attr] === "object") {
      console.log(`recursive merge of ${JSON.stringify(src[attr])}`);
      merge(tgt[attr], src[attr]);
    } else {
      tgt[attr] = src[attr];
    }
  }
}

function merge2(tgt, src) {
  let { p1, p2 } = src.dummy;
  tgt[p1][p2] = src.foo;
}

const resolver = new Resolver();

resolver.define("anon", async ({ payload, context }) => {
  merge2({}, payload);
  console.log(`entered anon, version: ${process.version}`);
  console.log(`payload: ${JSON.stringify(payload)}`);
  console.log(`context: ${JSON.stringify(context)}`);
  const response = await fetch("https://google.com");
  console.log(`Response: ${response.status} ${response.statusText}`);
});

resolver.define("asApp", async ({ payload, context }) => {
  console.log("entered asApp");
  console.log(
    `payload: ${JSON.stringify(payload)}, context: ${JSON.stringify(context)}`,
  );
  const {
    extension: {
      issue: { key },
    },
  } = context;
  merge({}, payload);
  // TEST polluting OPTIONS
  // pollution should create a new comment instead of fetching all comments
  console.log(`body: ${{}.body}, method: ${{}.method}`);
  console.log(`version: ${process.version}`);
  const response = await api.asApp().requestJira(route`/rest/api/3/serverInfo`);

  console.log(`Response: ${response.status} ${response.statusText}`);
  console.log(await response.json());
  return "Hello, world!";
});

export const handler = resolver.getDefinitions();
