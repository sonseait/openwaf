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
  Modal,
  NativeSelect,
  Paper,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import { Plus, RotateCw } from "lucide-react";
import dayjs from "dayjs";
import toast from "react-hot-toast";
import { api, ApiError, queryClient } from "./api";
import { DataTable } from "./DataTable";
import { Failure } from "./shared";
import { CloudflareProviders } from "./CloudflareProviders";

type Provider = {
  id: string;
  name: string;
  zone_name: string;
  environment: "staging" | "production";
};
type CertificateRequest = {
  hostname: string;
  provider_id: string;
  state: "pending" | "running" | "current" | "covered" | "degraded";
  attempts: number;
  covered_by_hostname: string | null;
  last_error_code: string | null;
  next_attempt: string;
  updated_at: string;
  loaded_certificate: {
    hostname: string;
    dns_names: string[];
    valid_until_unix_s: number;
  } | null;
};
type Inventory = {
  enabled: boolean;
  unavailable_reason: string | null;
  providers: Provider[];
  requests: CertificateRequest[];
  worker: { state: string; observed_at_unix_ms: number };
  observed_at_unix_ms: number;
};
function invalidate() {
  void queryClient.invalidateQueries({ queryKey: ["certificate-requests"] });
  void queryClient.invalidateQueries({ queryKey: ["dependencies"] });
  void queryClient.invalidateQueries({ queryKey: ["applications"] });
}
const errors: Record<string, string> = {
  provider_changed:
    "The saved provider is unavailable or its issuance configuration changed. Restore the original provider used for this request before retrying.",
  interrupted:
    "The worker was interrupted. Check pending DNS cleanup before retrying.",
  worker_failed:
    "The ACME worker failed. Check provider credentials, DNS propagation and private worker state before retrying.",
};
export function CertificateRequests({ paused }: { paused: boolean }) {
  const [opened, setOpened] = useState(false);
  const inventory = useQuery({
    queryKey: ["certificate-requests"],
    queryFn: ({ signal }) => api<Inventory>("/certificates", { signal }),
    refetchInterval: paused ? false : 5000,
  });
  const retry = useMutation({
    mutationFn: (hostname: string) =>
      api("/certificates/retry", { method: "POST", body: { hostname } }),
    onSuccess: () => {
      invalidate();
      toast.success("Certificate retry queued");
    },
  });
  const data = inventory.data;
  return (
    <>
      <CloudflareProviders paused={paused} />
      <Paper
        withBorder
        p="md"
        component="section"
        aria-label="Certificate requests"
      >
        <Stack>
          <Group justify="space-between">
            <Stack gap={rem(4)}>
              <Title order={2}>Certificate requests</Title>
              <Text size="sm" c="dimmed">
                Request an exact domain or wildcard using Cloudflare DNS-01.
                Managed certificates are checked automatically for renewal.
              </Text>
            </Stack>
            <Button
              leftSection={<Plus size={rem(16)} />}
              disabled={
                !data?.enabled || inventory.isError || !data.providers.length
              }
              onClick={() => setOpened(true)}
            >
              Request certificate
            </Button>
          </Group>
          {inventory.isPending && (
            <Group role="status">
              <Loader size="sm" />
              Loading certificate requests…
            </Group>
          )}
          {inventory.isError && (
            <>
              <Alert color="yellow">
                Certificate request status is unavailable; displayed
                observations may be stale.
              </Alert>
              <Failure error={inventory.error} />
              <Button
                variant="default"
                onClick={() => void inventory.refetch()}
              >
                Retry certificate status
              </Button>
            </>
          )}
          {data && (
            <>
              {!data.enabled && (
                <Alert color="yellow">
                  {data.unavailable_reason ??
                    "Certificate requests are unavailable on this server."}{" "}
                  Existing loaded certificates continue to serve traffic.
                </Alert>
              )}
              {data.worker.state === "degraded" && (
                <Alert color="yellow">
                  The certificate worker reported a failure. Review the affected
                  request before retrying.
                </Alert>
              )}
              <Text size="sm" c="dimmed">
                {paused ? "Paused observation" : "Last request observation"}:{" "}
                {dayjs(data.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")}{" "}
                · Worker: {data.worker.state}
              </Text>
              <Text size="sm">
                A completed worker check does not confirm HTTPS is ready.
                “Loaded” means a valid certificate is present in the gateway;
                DNS and public reachability require separate verification.
              </Text>
              <DataTable
                records={data.requests}
                idAccessor="hostname"
                minHeight={rem(140)}
                noRecordsText="No certificate requests yet."
                columns={[
                  {
                    accessor: "hostname",
                    title: "Domain",
                    render: (r) => (
                      <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                        {r.hostname}
                      </Text>
                    ),
                  },
                  {
                    accessor: "provider_id",
                    title: "Provider",
                    render: (r) => {
                      const provider = data.providers.find(
                        (p) => p.id === r.provider_id,
                      );
                      return (
                        <Stack gap={rem(4)}>
                          <Text size="sm">
                            {provider?.name ?? "Provider unavailable"}
                          </Text>
                          {provider && (
                            <Badge
                              color={
                                provider.environment === "staging"
                                  ? "yellow"
                                  : "blue"
                              }
                            >
                              {provider.environment}
                            </Badge>
                          )}
                        </Stack>
                      );
                    },
                  },
                  {
                    accessor: "state",
                    title: "Provisioning",
                    render: (r) => (
                      <Stack gap={rem(4)}>
                        <Badge
                          color={
                            r.state === "degraded"
                              ? "red"
                              : r.state === "covered" || r.state === "current"
                                ? "green"
                                : "blue"
                          }
                        >
                          {r.state === "current"
                            ? "Worker check complete"
                            : r.state === "covered"
                              ? "Using existing wildcard"
                              : r.state}
                        </Badge>
                        {r.covered_by_hostname && (
                          <Text size="xs">{r.covered_by_hostname}</Text>
                        )}
                        {r.last_error_code && (
                          <Text size="xs" c="red">
                            {errors[r.last_error_code] ??
                              "Certificate request failed."}
                          </Text>
                        )}
                        <Text size="xs" c="dimmed">
                          Attempts {r.attempts}/5 · Updated{" "}
                          {dayjs(r.updated_at).format("MMM D HH:mm:ss")}
                        </Text>
                        {r.state !== "covered" &&
                          r.state !== "running" &&
                          r.attempts < 5 && (
                            <Text size="xs" c="dimmed">
                              Next check{" "}
                              {dayjs(r.next_attempt).format("MMM D HH:mm")}
                            </Text>
                          )}
                      </Stack>
                    ),
                  },
                  {
                    accessor: "loaded_certificate",
                    title: "Gateway TLS",
                    render: (r) =>
                      r.loaded_certificate ? (
                        <Stack gap={rem(4)}>
                          <Badge color="green">Loaded</Badge>
                          <Text size="xs">{r.loaded_certificate.hostname}</Text>
                          <Text size="xs">
                            Expires{" "}
                            {dayjs
                              .unix(r.loaded_certificate.valid_until_unix_s)
                              .format("YYYY-MM-DD HH:mm")}
                          </Text>
                        </Stack>
                      ) : (
                        <Badge color="yellow">Not loaded</Badge>
                      ),
                  },
                  {
                    accessor: "retry",
                    title: "Action",
                    render: (r) => (
                      <Button
                        size="xs"
                        variant="default"
                        leftSection={<RotateCw size={rem(14)} />}
                        disabled={
                          !data.enabled ||
                          r.state !== "degraded" ||
                          r.last_error_code === "provider_changed"
                        }
                        loading={
                          retry.isPending && retry.variables === r.hostname
                        }
                        onClick={() => retry.mutate(r.hostname)}
                        aria-label={`Retry certificate ${r.hostname}`}
                      >
                        Retry
                      </Button>
                    ),
                  },
                ]}
              />
            </>
          )}
          {retry.isError && <Failure error={retry.error} />}
        </Stack>
        <Modal
          opened={opened}
          onClose={() => setOpened(false)}
          title="Request certificate"
          size="lg"
        >
          {opened && data && (
            <RequestForm
              providers={data.providers}
              done={() => setOpened(false)}
            />
          )}
        </Modal>
      </Paper>
    </>
  );
}
type Input = {
  hostname: string;
  provider_id: string;
  terms_of_service_agreed: boolean;
};
function RequestForm({
  providers,
  done,
}: {
  providers: Provider[];
  done: () => void;
}) {
  const {
    register,
    handleSubmit,
    control,
    formState: { errors: formErrors },
  } = useForm<Input>({
    defaultValues: {
      hostname: "",
      provider_id: providers[0]?.id ?? "",
      terms_of_service_agreed: false,
    },
  });
  const providerId = useWatch({ control, name: "provider_id" });
  const provider = providers.find((p) => p.id === providerId);
  const request = useMutation({
    mutationFn: (body: Input) => api("/certificates", { method: "POST", body }),
    onSuccess: () => {
      invalidate();
      toast.success("Certificate request queued");
      done();
    },
  });
  return (
    <form onSubmit={handleSubmit((input) => request.mutate(input))}>
      <Stack>
        <NativeSelect
          label="DNS provider"
          description="The provider controls the DNS zone and certificate authority used for this request."
          data={providers.map((p) => ({
            value: p.id,
            label: `${p.name} · ${p.zone_name} · ${p.environment}`,
          }))}
          {...register("provider_id", { required: true })}
        />
        {provider?.environment === "staging" && (
          <Alert color="yellow">
            Staging issues test certificates that browsers do not trust. These
            certificates are kept outside the live gateway TLS snapshot.
          </Alert>
        )}
        <TextInput
          label="Certificate domain"
          placeholder="*.sub.example.com"
          description="Use an ASCII domain or punycode. Wildcards cover one level of subdomains; they do not include the base domain."
          required
          maxLength={253}
          {...register("hostname", {
            required: "Enter a domain",
            validate: (value) => {
              const normalized = value.trim().toLowerCase().replace(/\.$/, "");
              const base = normalized.replace(/^\*\./, "");
              const valid =
                base.includes(".") &&
                !/^\d+(\.\d+){3}$/.test(base) &&
                base
                  .split(".")
                  .every(
                    (label) =>
                      label.length <= 63 &&
                      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
                  );
              if (!valid)
                return "Enter a valid domain, optionally starting with *.";
              if (
                provider &&
                base !== provider.zone_name &&
                !base.endsWith(`.${provider.zone_name}`)
              )
                return `Choose a domain inside ${provider.zone_name}`;
              return true;
            },
          })}
          error={formErrors.hostname?.message}
        />
        <Checkbox
          label="I agree to the certificate authority’s terms of service"
          {...register("terms_of_service_agreed", {
            validate: (value) =>
              value || "Accept the CA terms to request a certificate",
          })}
          error={formErrors.terms_of_service_agreed?.message}
        />
        <Text size="sm" c="dimmed">
          For Let’s Encrypt, review{" "}
          <a
            href="https://letsencrypt.org/repository/"
            target="_blank"
            rel="noreferrer"
          >
            the subscriber agreement
          </a>
          . Cloudflare TXT challenge records are created and cleaned up
          automatically. Requests with existing exact certificates stay with
          their current renewal manager.
        </Text>
        {request.isError &&
          (request.error instanceof ApiError && request.error.status === 409 ? (
            <Alert color="yellow">
              This domain already has a request, a loaded certificate or an
              active renewal owner, or the request limit has been reached.
              Refresh the inventory before requesting again.
            </Alert>
          ) : (
            <Failure error={request.error} />
          ))}
        <Group justify="flex-end">
          <Button variant="default" onClick={done} disabled={request.isPending}>
            Cancel
          </Button>
          <Button type="submit" loading={request.isPending}>
            Queue certificate request
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
