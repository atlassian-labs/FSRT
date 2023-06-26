import ForgeUI, {
  useEffect,
  useState,
  render,
  AdminPage,
  IssueGlance,
  Table,
  Head,
  Row,
  Cell,
  Fragment,
  Form,
  TextField,
  Text,
  useProductContext,
} from '@forge/ui';
import api, { webTrigger, route, storage, properties } from '@forge/api';
import { createHash } from 'crypto';
import jwt from 'jsonwebtoken';
import { fetchIssueSummary } from './utils';

function SharedSecretForm() {
  const [hashedSecret, setHashedSecret] = useState(null);
  const onSubmit = async ({ sharedSecret }) => {
    storage.setSecret('sharedSecret', sharedSecret);
    const hash = createHash('sha256');
    hash.update(sharedSecret);
    setHashedSecret(hash.digest('hex'));
  };
  const [webTriggerUrl] = useState(async () => {
    return await getWebTrigger();
  });
  return (
    <Fragment>
      <Form onSubmit={onSubmit}>
        <TextField name="sharedSecret" label="Set Shared Secret" />
      </Form>
      {hashedSecret && <Text>{hashedSecret}</Text>}
      {webTriggerUrl && <Text>{webTriggerUrl}</Text>}
    </Fragment>
  );
}

function Challenge({ name, value }) {
  return (
    <Fragment>
      <Row>
        <Cell>
          <Text>{name}</Text>
        </Cell>
        <Cell>
          <Text>{value}</Text>
        </Cell>
      </Row>
    </Fragment>
  );
}

function FirstChallenge() {
  return (
    <Challenge name="FirstChallenge" value={process.env.FIRST_CHALLENGE} />
  );
}

function ChallengeHeader() {
  return (
    <Fragment>
      <Head>
        <Cell>
          <Text>Challenge</Text>
        </Cell>
        <Cell>
          <Text>Flag Value</Text>
        </Cell>
      </Head>
    </Fragment>
  );
}

const App = () => {
  return (
    <Fragment>
      <Text>Only admins should be able to access this!</Text>
      <Table>
        <ChallengeHeader />
        <FirstChallenge />
      </Table>
      <SharedSecretForm />
    </Fragment>
  );
};

function SecureGlance() {
  const { platformContext } = useProductContext();
  if (platformContext.type !== 'jira') {
    return '';
  }
  const [flagVal] = useState(async () => {
    let test_values = "should not be seen";
    const issueData = await fetchIssueSummary(platformContext.issueKey);
    test_values = "should not be seen 2";
    // const issueData2 = await fetchIssueSummary(platformContext.issueKey);
    return JSON.stringify(issueData);
  });

  return (
    <Fragment>
      <Table>
        <ChallengeHeader />
        <Challenge name="SecondChallenge" value={flagVal} />
      </Table>
    </Fragment>
  );
}

export const glance = render(
  <IssueGlance>
    <SecureGlance />
  </IssueGlance>
);

async function getWebTrigger() {
  return await webTrigger.getUrl('authenticated-webtrigger');
}

export function runWebTrigger({ method, path, headers }, { installContext }) {
  console.log(
    `method: ${method}, path: ${path}, headers: ${JSON.stringify(headers)}`
  );
  const [bearer, token] = headers['x-forge-authenticate'][0].split(' ');
  console.log(`bearer: ${bearer}, token: ${token}`);
  if (bearer !== 'Bearer') {
    return { statusCode: 500, body: 'Invalid authentication method' };
  }
  const secret = storage.getSecret('sharedSecret');
  console.log(`secret: ${secret}`);
  try {
    jwt.verify(token, secret, {
      algorithms: ['HS256', 'HS512'],
      audience: installContext,
    });
  } catch (err) {
    return { statusCode: 500, body: `Invalid token: ${err.message}` };
  }
  return { statusCode: 200, body: process.env.AUTHENTICATION_WEBHOOK_FLAG };
}

export const run = render(
  <AdminPage>
    <App />
  </AdminPage>
);
