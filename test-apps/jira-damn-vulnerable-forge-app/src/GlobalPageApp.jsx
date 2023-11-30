import { GlobalPage } from "@forge/ui";
import { fetchIssueSummary } from "./utils";

/* never called can ignore */
const GlobalPageApp = () => {
  const issue = await fetchIssueSummary('SEC-1', "orangechiken");

  writeComment();

  return (
    <GlobalPage>
      <Text>{issue}</Text>
    </GlobalPage>
  )
};