import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm, useWatch } from "react-hook-form";
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Group,
  Loader,
  NativeSelect,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { Plus } from "lucide-react";
import toast from "react-hot-toast";
import dayjs from "dayjs";
import { api, queryClient } from "./api";
import { DataTable } from "./DataTable";
import { Failure } from "./shared";
import { CloudflareModal as Modal } from "./CloudflareModal";
import { CloudflareDns } from "./CloudflareDns";

export type CloudflareProvider = {
  id: string;
  name: string;
  zone_name: string;
  zone_id?: string;
  environment: "staging" | "production";
  source: "dashboard";
  revision: number;
  request_count: number;
};
type Inventory = {
  enabled: boolean;
  unavailable_reason: string | null;
  providers: CloudflareProvider[];
  observed_at_unix_ms: number;
  capacity: number;
};
function refreshProviders() {
  void queryClient.invalidateQueries({ queryKey: ["certificate-providers"] });
  void queryClient.invalidateQueries({ queryKey: ["certificate-requests"] });
}
export function CloudflareProviders({ paused }: { paused: boolean }) {
  const [editing, setEditing] = useState<CloudflareProvider | "new" | null>(
    null,
  );
  const [deleting, setDeleting] = useState<CloudflareProvider | null>(null);
  const [dns, setDns] = useState<CloudflareProvider | null>(null);
  const [tested, setTested] = useState<{
    id: string;
    observed_at_unix_ms: number;
  } | null>(null);
  const inventory = useQuery({
    queryKey: ["certificate-providers"],
    queryFn: ({ signal }) =>
      api<Inventory>("/certificate-providers", { signal }),
    refetchInterval: paused ? false : 10000,
  });
  const test = useMutation({
    mutationFn: (p: CloudflareProvider) =>
      api<{ observed_at_unix_ms: number }>(
        `/certificate-providers/${p.id}/test`,
        { method: "POST" },
      ),
    onSuccess: (result, p) =>
      setTested({ id: p.id, observed_at_unix_ms: result.observed_at_unix_ms }),
  });
  const remove = useMutation({
    mutationFn: (p: CloudflareProvider) =>
      api(`/certificate-providers/${p.id}`, {
        method: "DELETE",
        body: { expected_revision: p.revision },
      }),
    onSuccess: () => {
      setDeleting(null);
      refreshProviders();
      toast.success("Provider deleted");
    },
  });
  const data = inventory.data;
  return (
    <Paper
      withBorder
      p="md"
      component="section"
      aria-label="Cloudflare providers"
    >
      <Stack>
        <Group justify="space-between">
          <Stack gap={rem(4)}>
            <Title order={2}>DNS providers</Title>
            <Text size="sm" c="dimmed">
              Manage Cloudflare connections here. Each provider is one DNS zone
              and CA environment.
            </Text>
          </Stack>
          <Button
            leftSection={<Plus size={rem(16)} />}
            disabled={!data?.enabled || inventory.isError}
            onClick={() => setEditing("new")}
          >
            Add provider
          </Button>
        </Group>
        {inventory.isPending && (
          <Group role="status">
            <Loader size="sm" />
            Loading providers…
          </Group>
        )}
        {inventory.isError && (
          <>
            <Alert color="yellow">Provider observations may be stale.</Alert>
            <Failure error={inventory.error} />
            <Button onClick={() => void inventory.refetch()} variant="default">
              Retry providers
            </Button>
          </>
        )}
        {data && (
          <>
            {!data.enabled && (
              <Alert color="yellow">
                {data.unavailable_reason ??
                  "Provider management is unavailable on this server."}
              </Alert>
            )}
            <Text size="sm" c="dimmed">
              {paused ? "Provider refresh paused" : "Last provider observation"}
              : {dayjs(data.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")}
            </Text>
            <DataTable
              records={data.providers}
              idAccessor="id"
              minHeight={rem(140)}
              noRecordsText="No DNS providers yet. Add a Cloudflare connection to get started."
              columns={[
                {
                  accessor: "name",
                  title: "Provider",
                  render: (p) => (
                    <Stack gap={rem(4)}>
                      <Text size="sm">{p.name}</Text>
                      <Badge variant="light">Application managed</Badge>
                    </Stack>
                  ),
                },
                { accessor: "zone_name", title: "Zone" },
                {
                  accessor: "environment",
                  title: "CA",
                  render: (p) => (
                    <Badge
                      color={p.environment === "staging" ? "yellow" : "blue"}
                    >
                      {p.environment}
                    </Badge>
                  ),
                },
                {
                  accessor: "actions",
                  title: "Actions",
                  render: (p) => (
                    <Group gap="xs">
                      <Button
                        size="xs"
                        variant="default"
                        disabled={!data.enabled}
                        onClick={() => {
                          test.reset();
                          setTested(null);
                          test.mutate(p);
                        }}
                        loading={test.isPending && test.variables?.id === p.id}
                        aria-label={`Test provider ${p.name}`}
                      >
                        Test
                      </Button>
                      <Button
                        size="xs"
                        variant="default"
                        disabled={!data.enabled}
                        onClick={() => setEditing(p)}
                        aria-label={`Edit provider ${p.name}`}
                      >
                        Edit
                      </Button>
                      <Button
                        size="xs"
                        variant="default"
                        disabled={!data.enabled}
                        onClick={() => setDns(p)}
                        aria-label={`Manage DNS ${p.zone_name}`}
                      >
                        DNS records
                      </Button>
                      <Button
                        size="xs"
                        variant="subtle"
                        color="red"
                        disabled={!data.enabled || (p.request_count ?? 0) > 0}
                        onClick={() => {
                          remove.reset();
                          setDeleting(p);
                        }}
                        aria-label={`Delete provider ${p.name}`}
                      >
                        Delete
                      </Button>
                    </Group>
                  ),
                },
              ]}
            />
          </>
        )}
        {test.isError && <Failure error={test.error} />}
        {tested && (
          <Alert color="green">
            Zone and DNS read access verified at{" "}
            {dayjs(tested.observed_at_unix_ms).format("HH:mm:ss")}. DNS write
            access was not tested.
          </Alert>
        )}
      </Stack>
      <Modal
        opened={editing !== null}
        onClose={() => setEditing(null)}
        title={
          editing === "new"
            ? "Add Cloudflare provider"
            : "Edit Cloudflare provider"
        }
        size="lg"
      >
        {editing && (
          <ProviderForm
            provider={editing === "new" ? undefined : editing}
            done={() => setEditing(null)}
          />
        )}
      </Modal>
      <Modal
        opened={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete provider"
        size="md"
      >
        {deleting && (
          <Stack>
            <Text>
              Delete {deleting.name}? Its saved credentials will be removed.
              Providers used by certificate requests cannot be deleted.
            </Text>
            {remove.isError && <Failure error={remove.error} />}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setDeleting(null)}>
                Cancel
              </Button>
              <Button
                color="red"
                loading={remove.isPending}
                onClick={() => remove.mutate(deleting)}
              >
                Delete provider
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
      <Modal
        opened={dns !== null}
        onClose={() => setDns(null)}
        title={`Cloudflare DNS · ${dns?.zone_name ?? ""}`}
        size="xl"
      >
        {dns && <CloudflareDns provider={dns} paused={paused} />}
      </Modal>
    </Paper>
  );
}
type Form = {
  name: string;
  environment: "production" | "staging";
  auth_type: "api_token" | "global_api_key";
  secret: string;
  email: string;
  zone_id: string;
  replace: boolean;
};
type Zone = { id: string; name: string };
function ProviderForm({
  provider,
  done,
}: {
  provider?: CloudflareProvider;
  done: () => void;
}) {
  const {
    register,
    control,
    getValues,
    setValue,
    handleSubmit,
    resetField,
    formState: { errors },
  } = useForm<Form>({
    defaultValues: {
      name: provider?.name ?? "",
      environment: provider?.environment ?? "production",
      auth_type: "api_token",
      secret: "",
      email: "",
      zone_id: provider?.zone_id ?? "",
      replace: !provider,
    },
  });
  const authType = useWatch({ control, name: "auth_type" });
  const replace = useWatch({ control, name: "replace" });
  const [zone, setZone] = useState<Zone | null>(null);
  const [zonePage, setZonePage] = useState(1);
  function credentials() {
    const v = getValues();
    return {
      auth_type: v.auth_type,
      secret: v.secret,
      email: v.auth_type === "global_api_key" ? v.email : null,
    };
  }
  const discover = useMutation({
    mutationFn: (page: number) =>
      api<{ zones: Zone[]; page: number; has_more: boolean }>(
        "/certificate-providers/discover",
        { method: "POST", body: { credentials: credentials(), page } },
      ),
  });
  const save = useMutation({
    mutationFn: async () => {
      const v = getValues();
      try {
        return await api(
          provider
            ? `/certificate-providers/${provider.id}`
            : "/certificate-providers",
          {
            method: provider ? "PUT" : "POST",
            body: provider
              ? {
                  name: v.name,
                  expected_revision: provider.revision,
                  credentials: v.replace ? credentials() : null,
                }
              : {
                  name: v.name,
                  environment: v.environment,
                  zone_id: zone?.id,
                  zone_name: zone?.name,
                  credentials: credentials(),
                },
          },
        );
      } finally {
        resetField("secret");
      }
    },
    onSuccess: () => {
      refreshProviders();
      toast.success(provider ? "Provider updated" : "Provider added");
      done();
    },
  });
  const needSecret = !provider || replace;
  return (
    <form onSubmit={handleSubmit(() => save.mutate())} autoComplete="off">
      <Stack>
        <TextInput
          label="Provider name"
          required
          maxLength={100}
          {...register("name", {
            required: "Enter a provider name",
            validate: (v) => !!v.trim() || "Enter a provider name",
          })}
          error={errors.name?.message}
        />
        {provider ? (
          <Text size="sm">
            Zone: {provider.zone_name} · {provider.environment}. Create another
            provider to use a different zone or CA environment.
          </Text>
        ) : (
          <NativeSelect
            label="Certificate environment"
            data={[
              { value: "production", label: "Let's Encrypt · Production" },
              {
                value: "staging",
                label: "Let's Encrypt · Staging (test certificates)",
              },
            ]}
            {...register("environment")}
          />
        )}
        {provider && (
          <Checkbox
            label="Replace saved credentials"
            {...register("replace")}
          />
        )}
        {needSecret && (
          <>
            <NativeSelect
              label="Cloudflare authentication"
              data={[
                { value: "api_token", label: "API Token (recommended)" },
                { value: "global_api_key", label: "Global API Key + email" },
              ]}
              {...register("auth_type", {
                onChange: () => {
                  setZone(null);
                  discover.reset();
                },
              })}
            />
            {authType === "global_api_key" && (
              <TextInput
                label="Cloudflare account email"
                type="email"
                autoComplete="off"
                required
                maxLength={254}
                {...register("email", {
                  required: authType === "global_api_key" && needSecret,
                })}
              />
            )}
            <PasswordInput
              label={
                authType === "api_token"
                  ? "Cloudflare API Token"
                  : "Cloudflare Global API Key"
              }
              autoComplete="new-password"
              required
              minLength={16}
              maxLength={512}
              {...register("secret", {
                required: needSecret && "Enter credentials",
                minLength: { value: 16, message: "Enter valid credentials" },
                onChange: () => {
                  setZone(null);
                  discover.reset();
                },
              })}
              error={errors.secret?.message}
            />
            <Text size="sm" c="dimmed">
              For API Tokens, grant Zone Read, DNS Read and DNS Edit for the
              zones you want to manage. Credentials are encrypted on the server
              and are never returned to the browser.
            </Text>
          </>
        )}
        {!provider && (
          <>
            <Group>
              <Button
                variant="default"
                type="button"
                disabled={!needSecret}
                loading={discover.isPending}
                onClick={() => {
                  setZonePage(1);
                  discover.mutate(1);
                }}
              >
                Connect and load zones
              </Button>
            </Group>
            {discover.isError && <Failure error={discover.error} />}
            {discover.data && (
              <>
                <NativeSelect
                  label="Cloudflare zone"
                  value={zone?.id ?? ""}
                  data={[
                    { value: "", label: "Choose a zone" },
                    ...discover.data.zones.map((z) => ({
                      value: z.id,
                      label: z.name,
                    })),
                  ]}
                  onChange={(e) => {
                    const selected =
                      discover.data.zones.find(
                        (z) => z.id === e.currentTarget.value,
                      ) ?? null;
                    setZone(selected);
                    setValue("zone_id", selected?.id ?? "");
                  }}
                />
                <Group>
                  <Button
                    size="xs"
                    variant="default"
                    disabled={zonePage <= 1 || discover.isPending}
                    onClick={() => {
                      setZone(null);
                      setZonePage(zonePage - 1);
                      discover.mutate(zonePage - 1);
                    }}
                  >
                    Previous zones
                  </Button>
                  <Text size="sm">Page {discover.data.page}</Text>
                  <Button
                    size="xs"
                    variant="default"
                    disabled={!discover.data.has_more || discover.isPending}
                    onClick={() => {
                      setZone(null);
                      setZonePage(zonePage + 1);
                      discover.mutate(zonePage + 1);
                    }}
                  >
                    Next zones
                  </Button>
                </Group>
                {discover.data.zones.length === 0 && (
                  <Alert color="yellow">
                    No zones are visible to these credentials. Check the token's
                    zone scope.
                  </Alert>
                )}
              </>
            )}
          </>
        )}
        {save.isError && <Failure error={save.error} />}
        <Group justify="flex-end">
          <Button variant="default" onClick={done}>
            Cancel
          </Button>
          <Button
            type="submit"
            loading={save.isPending}
            disabled={!provider && !zone}
          >
            Save provider
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
