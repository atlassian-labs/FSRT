import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
import api, { route } from '@forge/api';
import { testFn } from './test';

const foo = () => {
  const res = api.asApp().requestConfluence(route`/rest/api/3/test`);
  test_function("hi")
  return res;
};

let test_function = (word) => {
  console.log(word);
  let test_var = "test_var";
}

const App = () => {
  foo();
  test_function("test_word");
  testFn();
  return (
    <Fragment>
      <Text>Hello world!</Text>
    </Fragment>
  );
};

export const run = render(<Macro app={<App />} />);
