import React from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app/App";
import "@xyflow/react/dist/style.css";
import "../assets/app.css";

createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
