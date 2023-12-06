import React, { useEffect, useState } from "react";
import ForgeReconciler, { Option, Select, Form, TextField } from "@forge/react";
import { invoke } from "@forge/bridge";

const App = () => {
  const onSubmit = ({ input, func: { value } }) => {
    console.log(`submitted: ${input} to ${value}`);
    const parsed = JSON.parse(input);
    console.log(`parsed: ${input} to ${value}`);
    invoke(value, parsed);
  };

  return (
    <>
      <Form onSubmit={onSubmit}>
        <TextField name="input" label="Input" />
        <Select label="function name" name="func">
          <Option defaultSelected label="AsApp" value="asApp" />
          <Option label="Anon" value="anon" />
        </Select>
      </Form>
    </>
  );
};

ForgeReconciler.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
