import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, it } from "vitest";
import { SidebarMenu, SidebarProvider } from "../components/ui/sidebar.js";
import { HelpChannels, SidebarHelp } from "./sidebar-help.js";
import { trialNoticeLabel } from "./trial-notice.js";

function footerMarkup(): string {
  return renderToStaticMarkup(
    <SidebarProvider>
      <SidebarMenu>
        <SidebarHelp />
      </SidebarMenu>
    </SidebarProvider>,
  );
}

describe("the sidebar help item", () => {
  it("names itself and stays shut until it is asked", () => {
    const markup = footerMarkup();

    assert.match(markup, /Help/u);
    assert.match(markup, /aria-expanded="false"/u);
    // Nothing about support is on screen before the popover opens.
    assert.doesNotMatch(markup, /discord/iu);
    assert.doesNotMatch(markup, /paseo\.sh/u);
  });
});

describe("the help popover's copy", () => {
  it("offers the Discord channel and the mailbox, each as a working link", () => {
    const markup = renderToStaticMarkup(<HelpChannels />);

    assert.match(markup, /href="https:\/\/discord\.gg\/[A-Za-z0-9]+"/u);
    assert.match(markup, /#paseo-hub/u);
    assert.match(markup, /href="mailto:hello@paseo\.sh"/u);
    assert.match(markup, />hello@paseo\.sh</u);
  });

  it("opens Discord in a new tab without handing it this session", () => {
    const markup = renderToStaticMarkup(<HelpChannels />);

    assert.match(markup, /target="_blank"[^>]*rel="noreferrer"/u);
  });
});

describe("the trial reminder's copy", () => {
  it("counts days, and one day as a day", () => {
    assert.equal(trialNoticeLabel(12), "12 days left in trial");
    assert.equal(trialNoticeLabel(1), "1 day left in trial");
    assert.equal(trialNoticeLabel(0), "0 days left in trial");
  });
});

describe("official plugin distribution", () => {
  it("pins install and update to the same public commit without requiring an app release", async () => {
    const { officialDirectorySchema, pluginCommands, OfficialPluginCard } =
      await import("../official-plugins.js");
    const entry = officialDirectorySchema.parse({
      registry: { url: "https://clawmuse.com/registry" },
      plugins: [
        {
          id: "clawmuse/device-preview",
          name: "设备预览",
          description: "主机模拟器预览",
          artifact: {
            kind: "git",
            remote: "https://github.com/endvin/clawmuse-plugins.git",
            pluginPath: "device-preview",
            commit: "a".repeat(40),
          },
        },
      ],
    }).plugins[0];
    assert.ok(entry);
    const commands = pluginCommands(entry);
    assert.match(commands.install, /--id clawmuse-device-preview/u);
    assert.ok(commands.install.includes(`--ref ${"a".repeat(40)}`));
    assert.ok(commands.update.includes(`--ref ${"a".repeat(40)}`));
    const markup = renderToStaticMarkup(<OfficialPluginCard entry={entry} />);
    assert.match(markup, /设备预览/u);
    assert.match(markup, /clawmuse\.com\/zh\/plugins\/#device-preview/u);
    assert.equal(
      officialDirectorySchema.safeParse({ registry: { url: "https://other.example" }, plugins: [] })
        .success,
      false,
    );
    assert.equal(
      officialDirectorySchema.safeParse({
        registry: { url: "https://clawmuse.com/registry" },
        plugins: [
          {
            ...entry,
            artifact: { ...entry.artifact, remote: "https://github.com/endvin/repo;whoami" },
          },
        ],
      }).success,
      false,
    );
  });
});
