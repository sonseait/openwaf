import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { useReducedMotion } from "@mantine/hooks";
import { Link } from "react-router-dom";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Group,
  Loader,
  Modal,
  NativeSelect,
  Paper,
  Progress,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  Title,
  type ModalProps,
  rem,
} from "@mantine/core";
import {
  ArrowRight,
  Boxes,
  ExternalLink,
  Globe,
  Plus,
  ShieldCheck,
  Upload,
} from "lucide-react";
import dayjs from "dayjs";
import toast from "react-hot-toast";
import { api, ApiError, forgetSession, queryClient } from "./api";
import { ModalTabs, ModalSection, ModalTabLayout } from "./ModalTabs";
import { DataTable } from "./DataTable";
import { Failure } from "./shared";
import type { Config, Diff, Session } from "./types";

type Tls = { state: string; reason?: string; expires_at_unix_s?: number };
type Release = {
  id: string;
  checksum: string;
  bytes: number;
  file_count: number;
  created_at: string;
  preview: null | { url: string; expires_at_unix_ms: number; tls: Tls };
};
type Application = {
  id: string;
  name: string;
  domain: string;
  mode: "static" | "spa";
  active_release: string | null;
  active_domain: string | null;
  tls: Tls;
  releases: Release[];
};
type Inventory = {
  auto_tls_configured?: boolean;
  auto_tls_health?: { state: string; reason?: string | null };
  certificate_jobs?: {
    hostname: string;
    state: string;
    covered_by_hostname?: string | null;
    attempts: number;
    updated_at: string;
  }[];
  enabled: boolean;
  applications: Application[];
  preview_base_domain: string | null;
  limits: {
    zip_bytes: number;
    expanded_bytes: number;
    total_bytes: number;
    retained_releases: number;
  };
};
type Action = {
  kind: "deploy" | "rollback" | "preview" | "disable_preview" | "disable";
  release_id?: string;
  expected_active_version: number;
  expected_draft_revision: number;
};
type Review = {
  diff: Diff;
  routes: {
    domain: string;
    target: { release_id: string; preview_expires_at_unix_ms?: number };
    tls: Tls;
  }[];
  more_specific_routes: { id: string; hostname: string; path: string }[];
};
const size = (bytes: number) => `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
async function refresh() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ["applications"] }),
    queryClient.invalidateQueries({ queryKey: ["config"] }),
  ]);
}

function uploadZip(
  id: string,
  file: File,
  progress: (value: number) => void,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const abort = () => xhr.abort();
    const done = () => signal.removeEventListener("abort", abort);
    xhr.open("POST", `/api/v1/applications/${id}/releases`);
    xhr.timeout = 180000;
    const session = queryClient.getQueryData<Session | null>(["session"]);
    if (session) xhr.setRequestHeader("X-CSRF-Token", session.csrf_token);
    xhr.setRequestHeader("Accept", "application/json");
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable)
        progress(Math.round((event.loaded / event.total) * 100));
    };
    xhr.onload = () => {
      done();
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve();
        return;
      }
      if (xhr.status === 401) forgetSession();
      reject(
        new ApiError(
          xhr.status,
          xhr.status === 422
            ? "ZIP rejected. Check its build root, paths, size, and available disk quota."
            : xhr.status === 413
              ? "ZIP exceeds the upload limit."
              : "Upload failed. Reload release history before retrying.",
        ),
      );
    };
    xhr.onerror = xhr.ontimeout = () => {
      done();
      reject(
        new ApiError(
          0,
          "Upload acknowledgement missing. Reload release history before retrying.",
        ),
      );
    };
    xhr.onabort = () => {
      done();
      reject(
        new Error(
          "Upload cancelled. Reload release history to check its outcome.",
        ),
      );
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) {
      done();
      reject(new Error("Upload cancelled."));
      return;
    }
    const body = new FormData();
    body.append("file", file);
    xhr.send(body);
  });
}

export function Applications() {
  const inventory = useQuery({
    queryKey: ["applications"],
    queryFn: ({ signal }) => api<Inventory>("/applications", { signal }),
    refetchInterval: 30000,
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [editor, setEditor] = useState<Application | "new" | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [progress, setProgress] = useState(0);
  const [pending, setPending] = useState<{
    app: Application;
    action: Action;
    review: Review;
  } | null>(null);
  const [deleteItem, setDeleteItem] = useState<{
    app: string;
    release: string;
  } | null>(null);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  const form = useForm<{ file: FileList }>();
  const app = inventory.data?.applications.find((a) => a.id === selected);
  const upload = useMutation({
    mutationFn: async ({ id, file }: { id: string; file: File }) => {
      controller.current = new AbortController();
      setProgress(0);
      await uploadZip(id, file, setProgress, controller.current.signal);
    },
    onSuccess: async () => {
      form.reset();
      toast.success("Release ready. Preview or review Deploy to publish it.");
      await refresh();
    },
    onSettled: () => {
      controller.current = null;
    },
  });
  const review = useMutation({
    mutationFn: async ({
      app,
      kind,
      release,
    }: {
      app: Application;
      kind: Action["kind"];
      release?: string;
    }) => {
      const config = await api<Config>("/config");
      const action: Action = {
        kind,
        release_id: release,
        expected_active_version: config.active_version,
        expected_draft_revision: config.draft_revision,
      };
      const result = await api<Review>(`/applications/${app.id}/review`, {
        method: "POST",
        body: action,
      });
      return { app, action, review: result };
    },
    onSuccess: setPending,
  });
  const apply = useMutation({
    mutationFn: async () => {
      if (!pending) return;
      await api(`/applications/${pending.app.id}/actions`, {
        method: "POST",
        body: pending.action,
      });
    },
    onSuccess: async () => {
      setPending(null);
      toast.success("Application routing applied.");
      await refresh();
    },
  });
  const remove = useMutation({
    mutationFn: async () => {
      if (deleteItem)
        await api(
          `/applications/${deleteItem.app}/releases/${deleteItem.release}`,
          { method: "DELETE" },
        );
    },
    onSuccess: async () => {
      setDeleteItem(null);
      await refresh();
    },
  });
  const retryTls = useMutation({
    mutationFn: () =>
      api("/applications/certificates/retry", { method: "POST" }),
    onSuccess: refresh,
  });
  const busy =
    upload.isPending || review.isPending || apply.isPending || remove.isPending;
  const closeManager = () => {
    if (!busy) {
      setSelected(null);
      form.reset();
      upload.reset();
    }
  };
  if (inventory.isPending)
    return (
      <Group role="status">
        <Loader size="sm" />
        Loading applications…
      </Group>
    );
  if (inventory.isError)
    return (
      <Stack>
        <Failure error={inventory.error} />
        <Button onClick={() => void inventory.refetch()}>Retry</Button>
      </Stack>
    );
  const data = inventory.data;
  return (
    <Stack gap="md">
      <Group justify="space-between">
        <div>
          <Text className="eyebrow">GATEWAY / FRONTEND HOSTING</Text>
          <Title order={1}>Applications</Title>
          <Text c="dimmed">
            Upload a built website, preview it, then deploy to your domain.
          </Text>
        </div>
        <Group>
          <Button
            variant="default"
            loading={inventory.isFetching}
            disabled={busy}
            onClick={() => {
              void inventory.refetch();
              void queryClient.invalidateQueries({
                queryKey: ["certificate-requests"],
              });
            }}
          >
            Refresh
          </Button>
          <Button
            leftSection={<Plus size={rem(16)} />}
            onClick={() => setEditor("new")}
            disabled={!data.enabled || busy}
          >
            Create app
          </Button>
        </Group>
      </Group>
      {!data.enabled ? (
        <Alert color="blue">
          Set OPENWAF_APPLICATIONS_ROOT to an absolute persistent directory and
          restart the managed gateway to enable frontend hosting.
        </Alert>
      ) : (
        <>
          <Paper
            withBorder
            radius="md"
            component="section"
            aria-label="Application library"
            className="application-block"
          >
            <Group
              justify="space-between"
              p="md"
              className="application-block-heading"
            >
              <div>
                <Title order={2}>Application library</Title>
                <Text size="sm" c="dimmed">
                  Select an app to upload, preview or deploy a release.
                </Text>
              </div>
              <Badge variant="light" color="gray">
                {data.applications.length} / 64 apps
              </Badge>
            </Group>
            <DataTable
              withTableBorder={false}
              aria-label="Applications"
              records={data.applications}
              styles={{ table: { minWidth: rem(1100) } }}
              minHeight={rem(140)}
              noRecordsText="No applications yet. Create an app and upload your build ZIP."
              columns={[
                {
                  accessor: "name",
                  title: "Application",
                  render: (a) => (
                    <Button
                      variant={a.id === selected ? "light" : "subtle"}
                      leftSection={<Boxes size={rem(15)} />}
                      disabled={busy}
                      onClick={() => {
                        setSelected(a.id);
                        form.reset();
                        upload.reset();
                      }}
                    >
                      <Text component="span" truncate maw={rem(220)}>
                        {a.name}
                      </Text>
                    </Button>
                  ),
                },
                {
                  accessor: "domain",
                  width: rem(240),
                  render: (a) => (
                    <Stack gap={rem(3)}>
                      <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                        {a.domain}
                      </Text>
                      {a.active_release && a.tls.state === "ready" && (
                        <Anchor
                          href={`https://${a.active_domain ?? a.domain}`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Open website <ExternalLink size={rem(12)} />
                        </Anchor>
                      )}
                    </Stack>
                  ),
                },
                { accessor: "mode", title: "Mode" },
                {
                  accessor: "active_release",
                  title: "Active release",
                  render: (a) =>
                    a.active_release ? (
                      <Text size="sm">{a.active_release.slice(0, 12)}</Text>
                    ) : (
                      <Badge color="gray">Disabled</Badge>
                    ),
                },
                {
                  accessor: "tls",
                  title: "TLS",
                  width: rem(190),
                  render: (a) => (
                    <Badge
                      aria-label={
                        a.tls.state === "ready"
                          ? "Certificate loaded"
                          : "Certificate unavailable"
                      }
                      color={a.tls.state === "ready" ? "teal" : "yellow"}
                    >
                      {a.tls.state === "ready" ? "Loaded" : "Unavailable"}
                    </Badge>
                  ),
                },
                {
                  accessor: "actions",
                  title: "Actions",
                  width: rem(220),
                  render: (a) => (
                    <Group
                      className="application-actions"
                      gap={rem(4)}
                      wrap="nowrap"
                      preventGrowOverflow={false}
                    >
                      <Button
                        size="compact-xs"
                        variant="light"
                        disabled={busy}
                        onClick={() => {
                          setSelected(a.id);
                          form.reset();
                          upload.reset();
                        }}
                      >
                        Manage
                      </Button>
                      <Button
                        size="compact-xs"
                        variant="subtle"
                        disabled={
                          busy ||
                          !!a.active_release ||
                          a.releases.some((r) => r.preview)
                        }
                        onClick={() => setEditor(a)}
                      >
                        Edit
                      </Button>
                      <Button
                        size="compact-xs"
                        color="red"
                        variant="subtle"
                        disabled={busy || !a.active_release}
                        onClick={() =>
                          review.mutate({ app: a, kind: "disable" })
                        }
                      >
                        Disable
                      </Button>
                    </Group>
                  ),
                },
              ]}
            />
            {review.isError && !app && <Failure error={review.error} />}
            <Text
              size="sm"
              c="dimmed"
              p="md"
              className="application-block-footer"
            >
              If routing conflicts, review existing root routes. Save/apply or
              discard unrelated Configuration drafts before deploying. More
              specific routes such as /api keep their existing destination.
            </Text>
          </Paper>
          <Paper
            withBorder
            radius="md"
            p="md"
            component="section"
            aria-label="Domains and HTTPS"
            className="application-block"
          >
            <Stack>
              <Group justify="space-between">
                <Group gap="xs">
                  <Globe size={rem(18)} aria-hidden="true" />
                  <Title order={2}>Domains & HTTPS</Title>
                </Group>
                <Button
                  component={Link}
                  to="/certificates"
                  variant="default"
                  size="xs"
                >
                  Manage certificates
                </Button>
              </Group>
              <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
                <Stack gap="xs">
                  <Group justify="space-between">
                    <Text fw={600} size="sm">
                      Preview domain
                    </Text>
                    <Button
                      variant="subtle"
                      size="compact-xs"
                      onClick={() => setSettingsOpen(true)}
                      disabled={busy}
                    >
                      {data.preview_base_domain
                        ? "Edit preview domain"
                        : "Set preview domain"}
                    </Button>
                  </Group>
                  <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                    {data.preview_base_domain ?? "No preview domain configured"}
                  </Text>
                  <Text size="sm" c="dimmed">
                    Point production DNS to the public gateway. Previews require
                    wildcard DNS and TLS for{" "}
                    {data.preview_base_domain
                      ? `*.${data.preview_base_domain}`
                      : "a dedicated preview base domain"}
                    . Preview URLs are public.
                  </Text>
                </Stack>
                <Stack gap="xs">
                  <Text fw={600} size="sm">
                    Certificate management
                  </Text>
                  {data.auto_tls_configured ? (
                    <Text size="sm">
                      Automatic TLS is configured. Matching loaded wildcard
                      certificates are reused; other certificate requests run in
                      the background.
                    </Text>
                  ) : (
                    <ApplicationCertificates />
                  )}
                  <Text size="sm" c="dimmed">
                    Each TLS badge reports the certificate actually loaded by
                    the gateway. DNS and public reachability require separate
                    verification.
                  </Text>
                </Stack>
              </SimpleGrid>
              {data.auto_tls_health?.state === "degraded" && (
                <Alert color="red">
                  Automatic TLS worker is degraded.{" "}
                  {data.auto_tls_health.reason}
                </Alert>
              )}
            </Stack>
          </Paper>
          {!!data.certificate_jobs?.length && (
            <Paper
              withBorder
              radius="md"
              p="md"
              component="section"
              aria-label="Certificate provisioning"
              className="application-block"
            >
              <Stack>
                <Group justify="space-between">
                  <Title order={2}>Certificate provisioning</Title>
                  <Button
                    variant="default"
                    size="xs"
                    loading={retryTls.isPending}
                    disabled={!data.auto_tls_configured}
                    onClick={() => retryTls.mutate()}
                  >
                    Retry failed certificates
                  </Button>
                </Group>
                {data.certificate_jobs.map((job) => (
                  <Text
                    key={job.hostname}
                    size="sm"
                    style={{ overflowWrap: "anywhere" }}
                  >
                    {job.hostname} ·{" "}
                    {job.state === "covered"
                      ? `Using wildcard ${job.covered_by_hostname} · No separate certificate request`
                      : `${job.state} · attempts ${job.attempts}/5`}{" "}
                    · {dayjs(job.updated_at).format("MMM D HH:mm")}
                  </Text>
                ))}
                {retryTls.isError && <Failure error={retryTls.error} />}
              </Stack>
            </Paper>
          )}
          <Paper
            withBorder
            radius="md"
            p="md"
            component="section"
            aria-label="Storage limits"
            className="application-block"
          >
            <Stack gap="sm">
              <Title order={2}>Storage limits</Title>
              <SimpleGrid cols={{ base: 2, sm: 4 }}>
                {[
                  ["ZIP upload", size(data.limits.zip_bytes)],
                  ["Extracted release", size(data.limits.expanded_bytes)],
                  ["Storage budget", size(data.limits.total_bytes)],
                  [
                    "Retained releases",
                    `${data.limits.retained_releases} recent + protected`,
                  ],
                ].map(([label, value]) => (
                  <div key={label}>
                    <Text size="xs" c="dimmed">
                      {label}
                    </Text>
                    <Text size="sm" fw={600}>
                      {value}
                    </Text>
                  </div>
                ))}
              </SimpleGrid>
            </Stack>
          </Paper>
          <ApplicationModal
            opened={!!app && !pending && !deleteItem}
            onClose={closeManager}
            title={app ? `Manage ${app.name}` : "Manage application"}
            size={rem(1100)}
            scrollAreaComponent={ModalTabLayout}
            closeOnClickOutside={!busy}
            closeOnEscape={!busy}
            withCloseButton={!busy}
            transitionProps={{ duration: 0 }}
            returnFocus={!pending && !deleteItem}
          >
            {app && (
              <Stack>
                <Group justify="space-between">
                  <Badge color={app.active_release ? "teal" : "gray"}>
                    {app.active_release ? "Production active" : "Not deployed"}
                  </Badge>
                  <Text
                    size="sm"
                    c="dimmed"
                    style={{ overflowWrap: "anywhere" }}
                  >
                    {app.domain} · {app.mode.toUpperCase()}
                  </Text>
                </Group>
                <ModalTabs
                  key={app.id}
                  label="Application management"
                  defaultValue={app.releases.length ? "releases" : "upload"}
                >
                  <ModalSection value="upload" label="Upload release">
                    <Paper
                      withBorder
                      radius="md"
                      p="md"
                      component="section"
                      aria-label="Upload a release"
                    >
                      <Stack gap="sm">
                        <Title order={3}>Upload a release</Title>
                        <Text size="sm">
                          ZIP must contain index.html at its root, or in one
                          enclosing build folder. Choose SPA for client-side
                          navigation; missing JS/CSS still returns 404.
                        </Text>
                        <form
                          onSubmit={form.handleSubmit(({ file }) => {
                            const selectedFile = file?.[0];
                            if (!selectedFile) return;
                            if (selectedFile.size > data.limits.zip_bytes) {
                              form.setError("file", {
                                message: "ZIP exceeds the upload limit.",
                              });
                              return;
                            }
                            upload.mutate({ id: app.id, file: selectedFile });
                          })}
                        >
                          <Group align="end">
                            <Stack
                              gap={rem(4)}
                              style={{
                                minWidth: 0,
                                flex: `1 1 ${rem(280)}`,
                                maxWidth: "100%",
                              }}
                            >
                              <label htmlFor="application-zip">
                                Built frontend ZIP
                              </label>
                              <input
                                id="application-zip"
                                type="file"
                                accept=".zip,application/zip"
                                className="application-file-input"
                                disabled={busy}
                                {...form.register("file", {
                                  required: "Choose a build ZIP.",
                                })}
                              />
                              {form.formState.errors.file && (
                                <Text c="red" size="sm">
                                  {form.formState.errors.file.message}
                                </Text>
                              )}
                            </Stack>
                            <Button
                              type="submit"
                              leftSection={<Upload size={rem(15)} />}
                              loading={upload.isPending}
                              disabled={busy && !upload.isPending}
                            >
                              Upload release
                            </Button>
                            {upload.isPending && (
                              <Button
                                color="red"
                                variant="subtle"
                                onClick={() => controller.current?.abort()}
                              >
                                Cancel
                              </Button>
                            )}
                          </Group>
                        </form>
                        {upload.isPending && (
                          <Stack gap={rem(4)}>
                            <Progress
                              value={progress}
                              aria-label="ZIP upload progress"
                            />
                            <Text size="sm" role="status">
                              {progress < 100
                                ? `Uploading ${progress}%`
                                : "Checking and extracting ZIP…"}
                            </Text>
                          </Stack>
                        )}
                        {upload.isError && <Failure error={upload.error} />}
                      </Stack>
                    </Paper>
                  </ModalSection>
                  <ModalSection value="releases" label="Release history">
                    <Paper
                      withBorder
                      radius="md"
                      component="section"
                      aria-label="Release history"
                      className="application-block"
                    >
                      <Title
                        order={3}
                        p="md"
                        className="application-block-heading"
                      >
                        Release history
                      </Title>
                      <DataTable
                        withTableBorder={false}
                        aria-label="Application releases"
                        styles={{ table: { minWidth: rem(960) } }}
                        verticalAlign="top"
                        records={app.releases}
                        minHeight={rem(120)}
                        noRecordsText="No releases uploaded. Upload your build ZIP to begin."
                        columns={[
                          {
                            accessor: "id",
                            title: "Release",
                            render: (r) => (
                              <Stack gap={rem(3)}>
                                <Text size="sm">{r.id.slice(0, 12)}</Text>
                                {app.active_release === r.id && (
                                  <Badge size="xs" color="teal">
                                    Active
                                  </Badge>
                                )}
                                <Text size="xs" c="dimmed" title={r.checksum}>
                                  SHA-256 {r.checksum.slice(0, 12)}
                                </Text>
                              </Stack>
                            ),
                          },
                          {
                            accessor: "created_at",
                            title: "Uploaded",
                            render: (r) =>
                              dayjs(r.created_at).format("YYYY-MM-DD HH:mm:ss"),
                          },
                          {
                            accessor: "bytes",
                            title: "Build",
                            render: (r) =>
                              `${size(r.bytes)} · ${r.file_count} files`,
                          },
                          {
                            accessor: "preview",
                            title: "Preview",
                            width: rem(220),
                            render: (r) => <ReleasePreview release={r} />,
                          },
                          {
                            accessor: "actions",
                            title: "Actions",
                            width: rem(280),
                            render: (r, index) => (
                              <Group gap={rem(4)}>
                                <Button
                                  size="compact-xs"
                                  disabled={busy || app.active_release === r.id}
                                  onClick={() =>
                                    review.mutate({
                                      app,
                                      kind: index === 0 ? "deploy" : "rollback",
                                      release: r.id,
                                    })
                                  }
                                >
                                  {index === 0 ? "Deploy" : "Rollback"}
                                </Button>
                                <Button
                                  size="compact-xs"
                                  variant={r.preview ? "subtle" : "light"}
                                  color={r.preview ? "red" : undefined}
                                  disabled={
                                    busy ||
                                    (!r.preview && !data.preview_base_domain)
                                  }
                                  onClick={() =>
                                    review.mutate({
                                      app,
                                      kind: r.preview
                                        ? "disable_preview"
                                        : "preview",
                                      release: r.id,
                                    })
                                  }
                                >
                                  {r.preview
                                    ? "Disable preview"
                                    : "Create preview"}
                                </Button>
                                <Button
                                  size="compact-xs"
                                  variant="subtle"
                                  color="red"
                                  disabled={
                                    busy ||
                                    app.active_release === r.id ||
                                    !!r.preview
                                  }
                                  onClick={() =>
                                    setDeleteItem({
                                      app: app.id,
                                      release: r.id,
                                    })
                                  }
                                >
                                  Delete
                                </Button>
                              </Group>
                            ),
                          },
                        ]}
                      />
                    </Paper>
                  </ModalSection>
                </ModalTabs>
                {review.isError && <Failure error={review.error} />}
                <Group justify="flex-end">
                  <Button
                    variant="default"
                    disabled={busy}
                    onClick={closeManager}
                  >
                    Close
                  </Button>
                </Group>
              </Stack>
            )}
          </ApplicationModal>
        </>
      )}
      <AppEditor
        opened={!!editor}
        app={editor && editor !== "new" ? editor : undefined}
        onClose={() => setEditor(null)}
        onSaved={(id) => {
          setSelected(editor === "new" ? id : null);
          setEditor(null);
          void refresh();
        }}
      />
      {settingsOpen && (
        <PreviewSettings
          initial={data.preview_base_domain}
          onClose={() => setSettingsOpen(false)}
        />
      )}
      <ApplicationModal
        opened={!!pending}
        onClose={() => {
          if (!apply.isPending) {
            setPending(null);
            apply.reset();
          }
        }}
        title="Review application routing"
        scrollAreaComponent={ModalTabLayout}
        size={rem(720)}
        closeOnClickOutside={!apply.isPending}
        closeOnEscape={!apply.isPending}
        withCloseButton={!apply.isPending}
      >
        {pending && (
          <Stack gap="md" className="application-review">
            <ModalTabs
              label="Application routing review"
              defaultValue="summary"
            >
              <ModalSection value="summary" label="Summary">
                <Paper
                  withBorder
                  radius="md"
                  p="md"
                  className="application-review-summary"
                >
                  <Group justify="space-between" align="start" wrap="nowrap">
                    <Stack gap={rem(4)} style={{ minWidth: 0 }}>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={600}>
                        Application
                      </Text>
                      <Text fw={650} className="application-wrap">
                        {pending.app.name}
                      </Text>
                      <Text size="sm" c="dimmed" className="application-wrap">
                        {pending.app.domain}
                      </Text>
                    </Stack>
                    <Badge variant="light" size="lg">
                      {actionNames[pending.action.kind]}
                    </Badge>
                  </Group>
                  <Text size="sm" mt="md">
                    {actionDescriptions[pending.action.kind]}
                  </Text>
                </Paper>
                <Stack gap="xs">
                  <Text size="sm" fw={600}>
                    Routing changes
                  </Text>
                  <SimpleGrid cols={3} spacing="xs">
                    {(
                      [
                        ["added", "Added", "teal"],
                        ["changed", "Updated", "blue"],
                        ["removed", "Removed", "red"],
                      ] as const
                    ).map(([key, label, color]) => (
                      <Paper key={key} withBorder radius="md" p="sm">
                        <Text size="xs" c="dimmed">
                          {label}
                        </Text>
                        <Text size="xl" fw={650} c={color}>
                          {pending.review.diff.routes[key]?.length ?? 0}
                        </Text>
                      </Paper>
                    ))}
                  </SimpleGrid>
                </Stack>
              </ModalSection>
              <ModalSection value="routes" label="Routes after apply">
                <Stack gap="xs">
                  <Text size="sm" fw={600}>
                    Routes after apply
                  </Text>
                  {pending.review.routes.length === 0 && (
                    <Text size="sm" c="dimmed">
                      No application routes will remain active.
                    </Text>
                  )}
                  {pending.review.routes.map((r) => (
                    <Paper key={r.domain} withBorder radius="md" p="md">
                      <Stack gap="sm">
                        <Group justify="space-between" align="start">
                          <Text fw={600} size="sm" className="application-wrap">
                            {r.domain}
                          </Text>
                          <Badge
                            variant="light"
                            color={r.tls.state === "ready" ? "teal" : "yellow"}
                            leftSection={
                              r.tls.state === "ready" ? (
                                <ShieldCheck size={rem(12)} />
                              ) : undefined
                            }
                          >
                            TLS {r.tls.state}
                          </Badge>
                        </Group>
                        <Group gap="xs">
                          <Badge color="gray" variant="light">
                            {r.target.preview_expires_at_unix_ms
                              ? "Public preview"
                              : "Production"}
                          </Badge>
                          <ArrowRight size={rem(14)} aria-hidden="true" />
                          <Text size="xs" c="dimmed" ff="monospace">
                            Release {r.target.release_id.slice(0, 12)}
                          </Text>
                        </Group>
                        {r.tls.state !== "ready" && (
                          <Alert color="yellow" p="xs">
                            HTTPS cannot serve this domain until a valid
                            certificate is issued and loaded.
                          </Alert>
                        )}
                      </Stack>
                    </Paper>
                  ))}
                </Stack>
                {!!pending.review.more_specific_routes.length && (
                  <Alert
                    color="yellow"
                    title="Existing routes retain precedence"
                  >
                    <Stack gap={rem(4)}>
                      {pending.review.more_specific_routes.map((r) => (
                        <Text key={r.id} size="sm" className="application-wrap">
                          {r.hostname}
                          {r.path}{" "}
                          <Text span c="dimmed">
                            · {r.id}
                          </Text>
                        </Text>
                      ))}
                    </Stack>
                  </Alert>
                )}
              </ModalSection>
              <ModalSection value="changes" label="Change details">
                <Stack gap="sm">
                  {(["added", "changed", "removed"] as const).map((kind) => (
                    <div key={kind}>
                      <Text size="xs" c="dimmed" tt="capitalize">
                        {kind}
                      </Text>
                      <Text
                        size="sm"
                        ff="monospace"
                        className="application-wrap"
                      >
                        {pending.review.diff.routes[kind]?.join(", ") || "None"}
                      </Text>
                    </div>
                  ))}
                </Stack>
              </ModalSection>
            </ModalTabs>
            {apply.isError && <Failure error={apply.error} />}
            <Group
              justify="space-between"
              className="application-review-footer"
            >
              <Button
                variant="default"
                disabled={apply.isPending}
                onClick={() => {
                  setPending(null);
                  apply.reset();
                }}
              >
                Cancel
              </Button>
              <Button
                loading={apply.isPending}
                onClick={() => apply.mutate()}
                rightSection={<ArrowRight size={rem(15)} />}
              >
                Confirm {pending.action.kind.replaceAll("_", " ")}
              </Button>
            </Group>
          </Stack>
        )}
      </ApplicationModal>
      <ApplicationModal
        opened={!!deleteItem}
        onClose={() => {
          if (!remove.isPending) {
            setDeleteItem(null);
            remove.reset();
          }
        }}
        title="Delete release"
      >
        <Stack>
          <Text>
            This removes the release from history and disables future rollback
            to it. Content is reclaimed after existing requests finish.
          </Text>
          {remove.isError && <Failure error={remove.error} />}
          <Button
            color="red"
            loading={remove.isPending}
            onClick={() => remove.mutate()}
          >
            Delete release
          </Button>
        </Stack>
      </ApplicationModal>
    </Stack>
  );
}
const actionNames: Record<Action["kind"], string> = {
  deploy: "Deploy",
  rollback: "Rollback",
  preview: "Create preview",
  disable_preview: "Disable preview",
  disable: "Disable production",
};
const actionDescriptions: Record<Action["kind"], string> = {
  deploy:
    "Publish this release to the production domain. Traffic switches after you confirm.",
  rollback: "Switch production traffic to the selected earlier release.",
  preview:
    "Publish a separate, public preview for this release. It expires after seven days.",
  disable_preview:
    "Remove this preview route. Its URL will stop serving the release.",
  disable:
    "Remove the production route. Uploaded releases remain available for a later deployment.",
};
function ReleasePreview({ release }: { release: Release }) {
  const preview = release.preview;
  if (!preview)
    return (
      <Text size="xs" c="dimmed">
        No public preview
      </Text>
    );
  return (
    <Stack gap="xs" className="application-preview-cell">
      <Group gap="xs" wrap="nowrap" align="start">
        <Anchor
          href={preview.url}
          target="_blank"
          rel="noopener noreferrer"
          aria-label="Open preview"
          title={preview.url}
          className="application-preview-link"
          p={0}
        >
          <Text span size="xs" ff="monospace">
            {preview.url.replace(/^https?:\/\//, "").split(".")[0]}
          </Text>
          <ExternalLink size={rem(14)} aria-hidden="true" />
        </Anchor>
      </Group>
      <Badge
        size="xs"
        variant="light"
        color={preview.tls.state === "ready" ? "teal" : "yellow"}
      >
        TLS {preview.tls.state}
      </Badge>
      <Text size="xs" c="dimmed">
        Public · expires{" "}
        {dayjs(preview.expires_at_unix_ms).format("MMM D HH:mm")}
      </Text>
    </Stack>
  );
}
function ApplicationModal(props: ModalProps) {
  const reducedMotion = useReducedMotion();
  return (
    <Modal
      {...props}
      title={
        typeof props.title === "string" ? (
          <Title order={2} size="h3">
            {props.title}
          </Title>
        ) : (
          props.title
        )
      }
      closeButtonProps={{
        "aria-label": "Close dialog",
        ...props.closeButtonProps,
      }}
      transitionProps={{
        ...props.transitionProps,
        ...(reducedMotion ? { duration: 0 } : {}),
      }}
    />
  );
}
function ApplicationCertificates() {
  const certificates = useQuery({
    queryKey: ["certificate-requests"],
    queryFn: ({ signal }) =>
      api<{
        enabled: boolean;
        providers: { id: string }[];
        unavailable_reason: string | null;
        worker: { state: string };
        observed_at_unix_ms: number;
      }>("/certificates", { signal }),
    refetchInterval: 30000,
  });
  if (certificates.isPending)
    return (
      <Group gap="xs" role="status">
        <Loader size="xs" />
        <Text size="sm">Checking certificate management…</Text>
      </Group>
    );
  if (certificates.isError)
    return (
      <Stack gap="xs">
        <Alert color="yellow">
          Certificate management status is unavailable. Application TLS badges
          still show the last observed loaded certificate state.
        </Alert>
        <Button
          variant="default"
          size="xs"
          onClick={() => void certificates.refetch()}
        >
          Retry certificate status
        </Button>
      </Stack>
    );
  const data = certificates.data;
  return (
    <Stack gap="xs">
      <Text size="sm">
        {data.enabled
          ? data.providers.length
            ? "Request certificates in Certificates; managed requests are renewed there. Applications reuse matching certificates loaded by the gateway. New application domains require a certificate request."
            : "Add a DNS provider in Certificates, then request a certificate for your application domain or preview wildcard."
          : "Applications use certificates loaded by the gateway. Certificate requests are unavailable on this server; review setup in Certificates."}
      </Text>
      {!data.enabled && data.unavailable_reason && (
        <Text size="sm" c="dimmed">
          {data.unavailable_reason}
        </Text>
      )}
      {data.worker.state === "degraded" && (
        <Alert color="yellow">
          The certificate worker is degraded. Review affected requests in
          Certificates.
        </Alert>
      )}
      <Text size="xs" c="dimmed">
        Last certificate service observation:{" "}
        {dayjs(data.observed_at_unix_ms).format("MMM D HH:mm:ss")}
      </Text>
    </Stack>
  );
}
function AppEditor({
  opened,
  app,
  onClose,
  onSaved,
}: {
  opened: boolean;
  app?: Application;
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const form = useForm<{
    name: string;
    domain: string;
    mode: "static" | "spa";
  }>({
    defaultValues: {
      name: app?.name ?? "",
      domain: app?.domain ?? "",
      mode: app?.mode ?? "static",
    },
  });
  const resetForm = form.reset;
  useEffect(() => {
    if (opened)
      resetForm({
        name: app?.name ?? "",
        domain: app?.domain ?? "",
        mode: app?.mode ?? "static",
      });
  }, [app, opened, resetForm]);
  const save = useMutation({
    mutationFn: (body: { name: string; domain: string; mode: string }) =>
      api<{ id: string }>(app ? `/applications/${app.id}` : "/applications", {
        method: app ? "PUT" : "POST",
        body,
      }),
    onSuccess: (result) => onSaved(result.id),
  });
  return (
    <ApplicationModal
      opened={opened}
      onClose={() => {
        if (!save.isPending) onClose();
      }}
      title={app ? "Edit application" : "Create application"}
      closeOnClickOutside={!save.isPending}
      closeOnEscape={!save.isPending}
      withCloseButton={!save.isPending}
      onExitTransitionEnd={() => save.reset()}
    >
      <form onSubmit={form.handleSubmit((body) => save.mutate(body))}>
        <Stack>
          <TextInput
            label="Application name"
            required
            maxLength={100}
            data-autofocus
            disabled={save.isPending}
            {...form.register("name", { required: true })}
          />
          <TextInput
            label="Production domain"
            placeholder="app.example.com"
            required
            disabled={save.isPending}
            {...form.register("domain", { required: true })}
          />
          <NativeSelect
            label="Website type"
            disabled={save.isPending}
            data={[
              { value: "static", label: "Static HTML" },
              { value: "spa", label: "SPA (React / Vite)" },
            ]}
            {...form.register("mode")}
          />
          <Text size="sm" c="dimmed">
            Use a dedicated domain, separate from the admin dashboard. DNS must
            point to the gateway. Disable production and previews before editing
            app metadata.
          </Text>
          {save.isError && <Failure error={save.error} />}
          <Group justify="flex-end">
            <Button
              variant="default"
              disabled={save.isPending}
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              {app ? "Save" : "Create app"}
            </Button>
          </Group>
        </Stack>
      </form>
    </ApplicationModal>
  );
}
function PreviewSettings({
  initial,
  onClose,
}: {
  initial: string | null;
  onClose: () => void;
}) {
  const form = useForm({ defaultValues: { domain: initial ?? "" } });
  const save = useMutation({
    mutationFn: (domain: string) =>
      api("/applications/settings", {
        method: "PUT",
        body: { preview_base_domain: domain.trim() || null },
      }),
    onSuccess: async () => {
      await refresh();
      onClose();
    },
  });
  return (
    <ApplicationModal
      opened
      onClose={() => {
        if (!save.isPending) onClose();
      }}
      title="Preview domain"
    >
      <form onSubmit={form.handleSubmit(({ domain }) => save.mutate(domain))}>
        <Stack>
          <TextInput
            label="Preview base domain"
            placeholder="preview.example.com"
            {...form.register("domain")}
          />
          <Text size="sm">
            Create wildcard DNS *.preview.example.com pointing to the gateway
            and configure wildcard TLS using Cloudflare DNS-01. URLs are public
            and expire after 7 days. Disable existing previews before changing
            this setting.
          </Text>
          {save.isError && <Failure error={save.error} />}
          <Button type="submit" loading={save.isPending}>
            Save preview domain
          </Button>
        </Stack>
      </form>
    </ApplicationModal>
  );
}
