import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
import api, { route, fetch } from '@forge/api';
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

    let testObjectOther = {
        someFunction(): any {
            let a = "b";
        }
    }

  let testObject = {
    someFunction() {
      const res = api.asApp().requestConfluence(route`/rest/api/3/test`);
      test_function("hi")
      return res;
    }
  }

    let value = "value"

    let h = { headers: { authorization: "test" } }
    h.headers.authorization = process.env.SECRET
    h.headers.authorization = `test ${value}`


    fetch("url", h)

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
