import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
import api, { route } from '@forge/api';

const foo = () => {
  const res = api.asApp().requestConfluence(route`/rest/api/3/test`);
  return res;
};

const App = () => {
  foo();
  return (
    <Fragment>
      <Text>Hello world!</Text>
    </Fragment>
  );
};

export const run = render(<Macro app={<App />} />);
