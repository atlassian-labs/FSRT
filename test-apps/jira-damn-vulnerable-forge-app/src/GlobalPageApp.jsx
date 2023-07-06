import { GlobalPage } from "@forge/ui";
import { fetchIssueSummary } from "./utils";

/* never called can ignore */
const GlobalPageApp = () => {
  const issue = await fetchIssueSummary('SEC-1');
  return (
    <GlobalPage>
      <Text>{issue}</Text>
    </GlobalPage>
  )
};