import { useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { Card, CardSkeleton } from "./components/app/card.js";
import { CopyField } from "./components/app/copy-field.js";
import { FailureAlert } from "./components/app/failure-alert.js";
import { PageHeader } from "./components/app/page.js";
import { Button } from "./components/ui/button.js";

export const PLUGIN_DIRECTORY = "https://clawmuse.com/registry/index.json";
const safePath = z.string().regex(/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_.-]+)*$/);
const artifact = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("git"),
    remote: z.string().regex(/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    commit: z.string().regex(/^[a-f0-9]{40}$/),
    pluginPath: safePath.optional(),
  }),
  z.object({
    kind: z.literal("npm"),
    package: z.string().regex(/^(?:@[a-z0-9-]+\/)?[a-z0-9_.-]+$/),
    version: z.string().regex(/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/),
  }),
]);
const plugin = z.object({
  id: z.string().regex(/^clawmuse\/[a-z0-9]+(?:-[a-z0-9]+)*$/),
  name: z.string().min(1).max(200),
  description: z.string().min(1).max(4000),
  translations: z
    .record(
      z.string(),
      z.object({ name: z.string().optional(), description: z.string().optional() }),
    )
    .optional(),
  artifact,
});
export const officialDirectorySchema = z.object({
  registry: z.object({ url: z.literal("https://clawmuse.com/registry") }),
  plugins: z.array(plugin).max(100),
});
type OfficialPlugin = z.infer<typeof plugin>;

export function pluginCommands(entry: OfficialPlugin) {
  const runtimeId = entry.id.replace("/", "-");
  const source =
    entry.artifact.kind === "git"
      ? `git:${entry.artifact.remote}${entry.artifact.pluginPath ? `:${entry.artifact.pluginPath}` : ""}`
      : `npm:${entry.artifact.package}@${entry.artifact.version}`;
  const revision = entry.artifact.kind === "git" ? ` --ref ${entry.artifact.commit}` : "";
  return {
    install: `paseo plugin install ${source}${revision} --id ${runtimeId}`,
    update: `paseo plugin update ${runtimeId}${entry.artifact.kind === "git" ? revision : ` --version ${entry.artifact.version}`}`,
  };
}

export function OfficialPluginCard({ entry }: { entry: OfficialPlugin }) {
  const commands = pluginCommands(entry);
  const localized = entry.translations?.["zh-CN"];
  return (
    <Card
      title={localized?.name ?? entry.name}
      description={localized?.description ?? entry.description}
    >
      <CopyField label="在运行模拟器的主机上安装" value={commands.install} />
      <CopyField label="更新至目录中的固定版本" value={commands.update} />
      <p className="text-muted-foreground">
        安装前请阅读官网的环境要求和权限说明；若有同名内置版，先将它停用。安装插件表示信任其代码，插件在主机上以你的权限运行。
      </p>
      <Button asChild variant="outline" size="sm">
        <a
          href={`https://clawmuse.com/zh/plugins/#${entry.id.split("/")[1]}`}
          target="_blank"
          rel="noreferrer"
        >
          查看使用说明
        </a>
      </Button>
    </Card>
  );
}

export function OfficialPluginsPanel() {
  const directory = useQuery({
    queryKey: ["official-plugins", PLUGIN_DIRECTORY],
    staleTime: 60_000,
    queryFn: async ({ signal }) => {
      const response = await fetch(PLUGIN_DIRECTORY, {
        signal,
        credentials: "omit",
        redirect: "error",
      });
      if (!response.ok) throw new Error("插件目录暂时无法读取，请稍后刷新。");
      return officialDirectorySchema.parse(await response.json());
    },
  });
  let body;
  if (directory.isPending) body = <CardSkeleton />;
  else if (directory.isError)
    body = (
      <FailureAlert
        title="插件目录不可用"
        error={directory.error}
        fallback="请稍后刷新，或到官网查看安装说明。"
      />
    );
  else
    body = (
      <div className="grid gap-4">
        {directory.data.plugins.map((entry) => (
          <OfficialPluginCard key={entry.id} entry={entry} />
        ))}
        {directory.data.plugins.length === 0 ? (
          <p className="text-muted-foreground">暂无独立发布的官方插件。</p>
        ) : null}
      </div>
    );
  return (
    <>
      <PageHeader
        id="official-plugins"
        title="官方插件"
        description="按需安装和更新，无需重新安装 ClawMuse。插件运行在所选主机，手机远程使用。"
      />
      {body}
    </>
  );
}
