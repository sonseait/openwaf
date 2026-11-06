import { useState } from "react";
import {
  Alert,
  Badge,
  Box,
  Button,
  Checkbox,
  Code,
  Group,
  Loader,
  Modal,
  Paper,
  SimpleGrid,
  ScrollArea,
  Stack,
  Tabs,
  Text,
  Title,
  Textarea,
  VisuallyHidden,
  rem,
} from "@mantine/core";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ModalTabs, ModalSection, ModalTabLayout } from "./ModalTabs";
import { DataTable } from "./DataTable";
import { Controller, FormProvider, useForm, useWatch } from "react-hook-form";
import {
  Globe,
  Network,
  Shield,
  Check,
  FilePenLine,
  GitCompareArrows,
  History,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldCheck,
} from "lucide-react";
import toast from "react-hot-toast";
import { useSearchParams } from "react-router-dom";
import { api, queryClient } from "./api";
import { AccessEditor } from "./configuration/AccessEditor";
import { RoutesEditor } from "./configuration/RoutesEditor";
import { ErrorPagesEditor } from "./configuration/ErrorPagesEditor";
import { UpstreamsEditor } from "./configuration/UpstreamsEditor";
import { ConfigurationWarnings } from "./TrafficProfiles";
import { normalizeDocument } from "./configuration-document";
import { Difference, Failure } from "./shared";
import { time } from "./format";
import type { Config, Document, Version } from "./types";

export function Configuration() {
  const [params, setParams] = useSearchParams();
  const view = ["draft", "review", "history"].includes(params.get("view") ?? "")
    ? params.get("view")!
    : "draft";
  const config = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api<Config>("/config", { signal }),
  });
  const versions = useQuery({
    queryKey: ["versions", params.get("version")],
    queryFn: ({ signal }) =>
      api<Version[]>(
        `/config/versions${params.get("version") ? `?version=${encodeURIComponent(params.get("version")!)}` : ""}`,
        { signal },
      ),
  });
  const [review, setReview] = useState<{
    config: Config;
    version?: Version;
  } | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [reloadRequired, setReloadRequired] = useState(false);
  const commit = useMutation({
    mutationFn: async () => {
      if (!review) throw new Error("No configuration selected.");
      const body = {
        expected_draft_revision: review.config.draft_revision,
        expected_active_version: review.config.active_version,
        ...(review.version ? { version: review.version.version } : {}),
      };
      await api(`/config/${review.version ? "rollback" : "apply"}`, {
        method: "POST",
        body,
      });
    },
    onSuccess: () => {
      toast.success("Configuration committed and activated.");
      setReview(null);
      void queryClient.invalidateQueries({ queryKey: ["config"] });
      void queryClient.invalidateQueries({ queryKey: ["versions"] });
    },
    onError: () => setReloadRequired(true),
  });
  const reload = async () => {
    setReview(null);
    commit.reset();
    const result = await config.refetch();
    void versions.refetch();
    if (result.isSuccess) setReloadRequired(false);
  };
  const data = config.data;
  const changes = data
    ? [data.diff.routes, data.diff.upstreams].reduce(
        (sum, group) =>
          sum +
          group.added.length +
          group.changed.length +
          group.removed.length,
        Number(data.diff.trusted_proxies_changed) +
          Number(!!data.diff.error_pages_changed) +
          Number(!!data.diff.global_rules_changed),
      )
    : 0;
  const reviewDraft = () => {
    if (!data) return;
    commit.reset();
    setAcknowledged(false);
    setReview({ config: structuredClone(data) });
  };
  return (
    <Stack gap="md" maw={rem(1400)} mx="auto">
      <Group
        justify="space-between"
        align="flex-start"
        gap="md"
        mb="xs"
        className="page-heading"
      >
        <div>
          <Text className="eyebrow">GATEWAY / CONFIGURATION</Text>
          <Title order={1}>Configuration</Title>
          <Text c="dimmed" mt="xs">
            Shape your traffic. Review changes before they go live.
          </Text>
        </div>
        <Group gap="sm">
          <Button
            variant="default"
            leftSection={<RefreshCw size={rem(15)} />}
            onClick={() => void reload()}
            loading={config.isFetching}
          >
            Reload server state
          </Button>
          {data && (
            <Button
              leftSection={<Check size={rem(16)} />}
              disabled={
                data.degraded ||
                config.isError ||
                config.isFetching ||
                reloadRequired
              }
              onClick={reviewDraft}
            >
              Review apply
            </Button>
          )}
        </Group>
      </Group>
      {config.isPending && (
        <Group role="status">
          <Loader size="sm" />
          Reading configuration…
        </Group>
      )}
      {config.isError && <Failure error={config.error} />}
      {data && (
        <>
          <Paper withBorder p="md" radius="md" aria-label="Configuration state">
            <SimpleGrid cols={{ base: 2, lg: 4 }} spacing="md">
              <Group gap="sm" wrap="nowrap">
                <Box
                  component="span"
                  w={rem(9)}
                  h={rem(9)}
                  miw={rem(9)}
                  m={rem(5)}
                  bdrs="50%"
                  bg={data.degraded ? "orange.7" : "teal.8"}
                />
                <Stack gap={0}>
                  <Text size="xs" c="dimmed">
                    Active snapshot
                  </Text>
                  <Text fw={600}>Active v{data.active_version}</Text>
                </Stack>
              </Group>
              <Group gap="sm" wrap="nowrap">
                <ShieldCheck
                  size={rem(18)}
                  color="var(--mantine-color-dimmed)"
                />
                <Stack gap={0}>
                  <Text size="xs" c="dimmed">
                    Last committed
                  </Text>
                  <Text fw={600}>Committed v{data.committed_version}</Text>
                </Stack>
              </Group>
              <Group gap="sm" wrap="nowrap">
                <FilePenLine
                  size={rem(18)}
                  color="var(--mantine-color-dimmed)"
                />
                <Stack gap={0}>
                  <Text size="xs" c="dimmed">
                    Saved workspace
                  </Text>
                  <Text fw={600}>Draft r{data.draft_revision}</Text>
                </Stack>
              </Group>
              <Group gap="sm" wrap="nowrap">
                <Badge color={changes ? "orange" : "gray"} variant="light">
                  {changes
                    ? `${changes} pending ${changes === 1 ? "change" : "changes"}`
                    : "In sync"}
                </Badge>
              </Group>
            </SimpleGrid>
          </Paper>
          {data.degraded && (
            <Alert color="orange" title="Committed and active state differ">
              Apply and rollback are unavailable until the gateway reconciles
              its state.
            </Alert>
          )}
        </>
      )}
      {reloadRequired && (
        <Alert color="orange">
          Last commit was not acknowledged. Reload server state before retrying;
          it may already have completed.
        </Alert>
      )}
      <Tabs
        value={view}
        onChange={(value) =>
          setParams(
            () => {
              const next = new URLSearchParams(params);
              if (value && value !== "draft") next.set("view", value);
              else next.delete("view");
              return next;
            },
            {
              replace: true,
            },
          )
        }
        keepMounted
      >
        <Tabs.List className="workspace-tabs">
          <Tabs.Tab value="draft" leftSection={<FilePenLine size={rem(16)} />}>
            Draft editor
          </Tabs.Tab>
          <Tabs.Tab
            value="review"
            leftSection={<GitCompareArrows size={rem(16)} />}
          >
            Review & apply{" "}
            {changes > 0 && <span className="tab-count">{changes}</span>}
          </Tabs.Tab>
          <Tabs.Tab value="history" leftSection={<History size={rem(16)} />}>
            Version history
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="draft" pt="md">
          {data && (
            <Paper withBorder className="config-workbench">
              <DraftEditor
                key={`${data.draft_revision}:${config.dataUpdatedAt}`}
                config={data}
                unavailable={config.isError || config.isFetching}
              />
            </Paper>
          )}
        </Tabs.Panel>
        <Tabs.Panel value="review" pt="md">
          {data && (
            <Paper withBorder p="md">
              <Stack gap="md">
                <div>
                  <Text className="eyebrow">SAVED DRAFT → ACTIVE GATEWAY</Text>
                  <Title order={2}>Pending changes</Title>
                  <Text size="sm" c="dimmed" mt="xs">
                    Compare active v{data.active_version} with saved draft r
                    {data.draft_revision}. Unsaved edits are excluded.
                  </Text>
                </div>
                {!changes && (
                  <Text c="dimmed">
                    The saved draft matches the active configuration.
                  </Text>
                )}
                <Difference diff={data.diff} />
                <details className="editor-group">
                  <summary>Inspect saved draft</summary>
                  <ScrollArea.Autosize
                    mah={rem(300)}
                    offsetScrollbars="present"
                    viewportProps={{
                      tabIndex: 0,
                      role: "region",
                      "aria-label": "Configuration document",
                    }}
                  >
                    <Code block className="document-preview">
                      {JSON.stringify(data.draft, null, 2)}
                    </Code>
                  </ScrollArea.Autosize>
                </details>
                <details className="editor-group">
                  <summary>Inspect active configuration</summary>
                  <ScrollArea.Autosize
                    mah={rem(300)}
                    offsetScrollbars="present"
                    viewportProps={{
                      tabIndex: 0,
                      role: "region",
                      "aria-label": "Configuration document",
                    }}
                  >
                    <Code block className="document-preview">
                      {JSON.stringify(data.active, null, 2)}
                    </Code>
                  </ScrollArea.Autosize>
                </details>
                <Text size="sm" c="dimmed">
                  Review apply opens the final confirmation for this saved
                  revision.
                </Text>
              </Stack>
            </Paper>
          )}
        </Tabs.Panel>
        <Tabs.Panel value="history" pt="md">
          <Paper withBorder p="md">
            <Stack>
              <Group>
                <History size={rem(20)} />
                <Title order={2}>Version history</Title>
              </Group>
              <Text size="sm" c="dimmed">
                {params.has("version")
                  ? `Selected version ${params.get("version")}.`
                  : "Latest 100 commits."}{" "}
                Rollback validates an earlier document and creates a new
                version; it also replaces the saved draft.
              </Text>
              {versions.isError && <Failure error={versions.error} />}
              <DataTable
                idAccessor="version"
                minHeight={rem(160)}
                fetching={versions.isPending || versions.isFetching}
                records={versions.data ?? []}
                noRecordsText="No configuration versions available."
                columns={[
                  {
                    accessor: "version",
                    title: "Version",
                    width: rem(100),
                    render: (v) => <Badge variant="light">v{v.version}</Badge>,
                  },
                  {
                    accessor: "created_at",
                    title: "Committed at",
                    width: rem(230),
                    render: (v) => time(v.created_at),
                  },
                  {
                    accessor: "rollback_from",
                    title: "Origin",
                    width: rem(130),
                    render: (v) =>
                      v.rollback_from === null
                        ? "Apply / bootstrap"
                        : `Rollback to v${v.rollback_from}`,
                  },
                  {
                    accessor: "created_by",
                    title: "Actor",
                    width: rem(90),
                    render: (v) => v.created_by ?? "System",
                  },
                  {
                    accessor: "diff",
                    title: "Commit diff",
                    render: (v) => (
                      <details>
                        <summary>Inspect original diff</summary>
                        <Difference diff={v.diff} />
                      </details>
                    ),
                  },
                  {
                    accessor: "actions",
                    title: "Recovery",
                    width: rem(160),
                    render: (v) => (
                      <Button
                        size="compact-xs"
                        variant="light"
                        leftSection={<RotateCcw size={rem(14)} />}
                        disabled={
                          !data ||
                          config.isError ||
                          config.isFetching ||
                          versions.isError ||
                          data.degraded ||
                          reloadRequired ||
                          v.version === data.active_version
                        }
                        onClick={() => {
                          if (data) {
                            commit.reset();
                            setAcknowledged(false);
                            setReview({
                              config: structuredClone(data),
                              version: v,
                            });
                          }
                        }}
                      >
                        Review rollback
                      </Button>
                    ),
                  },
                ]}
              />
            </Stack>
          </Paper>{" "}
        </Tabs.Panel>
      </Tabs>
      <Modal
        opened={!!review}
        scrollAreaComponent={review?.version ? undefined : ModalTabLayout}
        closeButtonProps={{ "aria-label": "Close" }}
        onClose={() => {
          if (!commit.isPending) setReview(null);
        }}
        title={
          review?.version
            ? `Rollback to document v${review.version.version}`
            : "Apply saved draft"
        }
        size={rem(1100)}
        closeOnClickOutside={!commit.isPending}
        closeOnEscape={!commit.isPending}
        withCloseButton={!commit.isPending}
      >
        {review && (
          <Stack>
            <Text size="sm">
              Based on active v{review.config.active_version} and draft r
              {review.config.draft_revision}. Concurrent changes are rejected.
            </Text>
            {review.version ? (
              <>
                <Alert color="orange">
                  Rollback replaces the draft and activates the selected
                  historical document as a new version. The server revalidates
                  it against current listeners and limits.
                </Alert>
                <Text fw={600} size="sm">
                  Original commit diff for v{review.version.version} (not a
                  rollback preview)
                </Text>
                <Difference diff={review.version.diff} />
              </>
            ) : (
              <>
                <ModalTabs
                  label="Configuration apply review"
                  defaultValue="changes"
                >
                  <ModalSection value="changes" label="Changes">
                    <Difference diff={review.config.diff} />
                  </ModalSection>
                  <ModalSection value="document" label="Saved document">
                    <Code
                      block
                      className="document-preview"
                      aria-label="Configuration document"
                    >
                      {JSON.stringify(review.config.draft, null, 2)}
                    </Code>
                  </ModalSection>
                </ModalTabs>
              </>
            )}
            <Checkbox
              label={
                review.version
                  ? "I reviewed the target version and draft replacement."
                  : "I reviewed the saved draft and its changes."
              }
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.currentTarget.checked)}
              disabled={commit.isPending}
            />
            {commit.isError && <Failure error={commit.error} />}
            <Button
              color={review.version ? "orange" : "teal"}
              disabled={!acknowledged || reloadRequired}
              loading={commit.isPending}
              onClick={() => commit.mutate()}
            >
              {review.version ? "Validate & rollback" : "Apply saved draft"}
            </Button>
            {reloadRequired && (
              <Button variant="default" onClick={() => void reload()}>
                Reload server state
              </Button>
            )}
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
function DraftEditor({
  config,
  unavailable,
}: {
  config: Config;
  unavailable: boolean;
}) {
  const [editorParams] = useSearchParams();
  const [editorTab, setEditorTab] = useState<string | null>(
    editorParams.get("section") === "global" ? "global" : "routes",
  );
  const form = useForm<Document>({
    defaultValues: structuredClone(config.draft),
    shouldFocusError: false,
  });
  const values = useWatch({ control: form.control });
  const { control } = form;
  const dirty = Object.keys(form.formState.dirtyFields).length > 0;
  const [reloadRequired, setReloadRequired] = useState(false);
  const save = useMutation({
    mutationFn: async (input: Document) => {
      const document = normalizeDocument(input);
      if (new TextEncoder().encode(JSON.stringify(document)).byteLength > 65536)
        throw new Error("Configuration exceeds 64 KiB.");
      const validation = await api<{ valid: boolean; error: string | null }>(
        "/config/validate",
        { method: "POST", body: { document } },
      );
      if (!validation.valid)
        throw new Error(
          `Configuration rejected: ${validation.error ?? "invalid document"}`,
        );
      try {
        await api("/config/draft", {
          method: "PUT",
          body: { expected_revision: config.draft_revision, document },
        });
      } catch (error) {
        setReloadRequired(true);
        throw error;
      }
    },
    onSuccess: () => {
      toast.success("Draft validated and saved.");
      void queryClient.invalidateQueries({ queryKey: ["config"] });
    },
  });
  return (
    <FormProvider {...form}>
      <form
        noValidate
        onSubmit={form.handleSubmit(
          (v) => save.mutate(v),
          (errors) => {
            setEditorTab(
              errors.global_rules
                ? "global"
                : errors.routes
                  ? "routes"
                  : errors.upstreams
                    ? "upstreams"
                    : errors.error_pages
                      ? "errors"
                      : "trust",
            );
            requestAnimationFrame(() => {
              const input = document.querySelector<HTMLElement>(
                '.config-workbench [aria-invalid="true"]',
              );
              let ancestor = input?.parentElement;
              while (ancestor) {
                if (ancestor instanceof HTMLDetailsElement)
                  ancestor.open = true;
                ancestor = ancestor.parentElement;
              }
              input?.focus();
              input?.scrollIntoView({ block: "center" });
            });
          },
        )}
      >
        <Stack>
          <Box pt="md" px={{ base: "sm", sm: "md" }}>
            <Group justify="space-between" mb="md" gap="sm">
              <div>
                <Title order={2}>Edit draft</Title>
                <Text size="sm" c="dimmed" mt={rem(4)}>
                  Routes, upstream pools and the proxies you trust.
                </Text>
              </div>
              <Badge color={dirty ? "orange" : "gray"} variant="light">
                {dirty ? "Unsaved edits" : "Saved draft"}
              </Badge>
            </Group>
            <fieldset
              disabled={save.isPending || unavailable || reloadRequired}
              style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}
            >
              <VisuallyHidden component="legend">
                Draft configuration
              </VisuallyHidden>
              <Tabs value={editorTab} onChange={setEditorTab} keepMounted>
                <Tabs.List className="config-tabs">
                  <Tabs.Tab
                    value="routes"
                    leftSection={<Globe size={rem(16)} />}
                  >
                    Routes ({values.routes?.length ?? 0})
                  </Tabs.Tab>
                  <Tabs.Tab
                    value="upstreams"
                    leftSection={<Network size={rem(16)} />}
                  >
                    Upstreams ({values.upstreams?.length ?? 0})
                  </Tabs.Tab>
                  <Tabs.Tab
                    value="global"
                    leftSection={<Shield size={rem(16)} />}
                  >
                    Global rules
                  </Tabs.Tab>
                  <Tabs.Tab
                    value="trust"
                    leftSection={<Shield size={rem(16)} />}
                  >
                    Trusted proxies
                  </Tabs.Tab>
                  <Tabs.Tab
                    value="errors"
                    leftSection={<FilePenLine size={rem(16)} />}
                  >
                    Error pages
                  </Tabs.Tab>
                </Tabs.List>
                <Tabs.Panel value="routes" pt="md">
                  <RoutesEditor
                    disabled={save.isPending || unavailable || reloadRequired}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="upstreams" pt="md">
                  <UpstreamsEditor
                    disabled={save.isPending || unavailable || reloadRequired}
                  />
                </Tabs.Panel>
                <Tabs.Panel value="errors" pt="md">
                  <ErrorPagesEditor />
                </Tabs.Panel>
                <Tabs.Panel value="global" pt="md">
                  <Stack>
                    <Title order={3}>Global security rules</Title>
                    <Text size="sm" c="dimmed">
                      Applied before each route’s access policy. Both policies
                      must allow the request; allow never bypasses CrowdSec or
                      WAF. Browser challenge requires HTTPS, JavaScript and
                      cookies; route challenges cannot disable it. Rate limits
                      share one per-client budget across routes. DDoS protection
                      shares a total budget across all clients. GeoIP filtering
                      returns 503 when its database is unavailable.
                    </Text>
                    <AccessEditor base="global_rules" />
                  </Stack>
                </Tabs.Panel>
                <Tabs.Panel value="trust" pt="md">
                  <Controller
                    control={control}
                    name="trusted_proxies"
                    render={({ field, fieldState }) => (
                      <Textarea
                        {...field}
                        label="Trusted proxy CIDRs"
                        description="One IP network per line. Forwarded headers are trusted only from these proxies. Leave empty to trust no proxies."
                        error={fieldState.error?.message}
                        autosize
                        minRows={2}
                        value={field.value?.join("\n") ?? ""}
                        onChange={(event) =>
                          field.onChange(event.currentTarget.value.split("\n"))
                        }
                      />
                    )}
                  />
                </Tabs.Panel>
              </Tabs>
              <div className="editor-diagnostics">
                <ConfigurationWarnings />
              </div>
            </fieldset>
          </Box>
          {Object.keys(form.formState.errors).length > 0 && (
            <Alert color="red" title="Complete the required fields">
              Check the highlighted fields before saving. The relevant editor
              tab has been opened.
            </Alert>
          )}
          {save.isError && <Failure error={save.error} />}
          <Group
            className="draft-savebar"
            justify="space-between"
            px={{ base: "sm", sm: "md" }}
            py="md"
          >
            <Text size="xs" c="dimmed">
              {dirty ? "Your edits have not been saved. " : ""}
              Saving alone does not affect traffic.
            </Text>
            <Button
              leftSection={<Save size={rem(16)} />}
              type="submit"
              loading={save.isPending}
              disabled={unavailable || reloadRequired}
            >
              Validate & save draft
            </Button>
            {reloadRequired && (
              <Text size="xs" c="orange">
                Reload server state above before saving again.
              </Text>
            )}
          </Group>
        </Stack>
      </form>
    </FormProvider>
  );
}
