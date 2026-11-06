import React from "react";
import ReactDOM from "react-dom/client";
import { MantineProvider } from "@mantine/core";
import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import { queryClient } from "./api";
import { App } from "./App";
import { theme } from "./theme";
import "@mantine/core/styles.layer.css";
import "mantine-datatable/styles.layer.css";
import "./style.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
        <Toaster
          position="bottom-right"
          toastOptions={{
            duration: 5000,
            style: {
              fontFamily: "var(--mantine-font-family)",
              fontSize: "var(--mantine-font-size-sm)",
              padding: "var(--mantine-spacing-xs) var(--mantine-spacing-sm)",
              borderRadius: "var(--mantine-radius-sm)",
              background: "var(--mantine-color-default)",
              color: "var(--mantine-color-text)",
              border: "1px solid var(--mantine-color-default-border)",
              boxShadow: "var(--mantine-shadow-sm)",
            },
          }}
        />
      </QueryClientProvider>
    </MantineProvider>
  </React.StrictMode>,
);
