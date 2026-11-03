import { createFileRoute } from "@tanstack/react-router";
import { OfficialPluginsPanel } from "../../official-plugins.js";

export const Route = createFileRoute("/_shell/plugins")({
  staticData: { breadcrumb: "官方插件" },
  component: OfficialPluginsPanel,
});
