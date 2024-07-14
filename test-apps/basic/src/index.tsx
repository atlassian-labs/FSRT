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

function complex(a) {
  let b = a - 20;
  let c = b + 1;
  b = 10;
  return b * 10;
}

function simple() {
  let a = 4;
  let b = 7;
  a = 10;
  a = 5;
}

function reassign() {
  let a = 4;
  let b = "7";
  b = "7" + a;
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
