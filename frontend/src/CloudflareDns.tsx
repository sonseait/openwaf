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
  Stack,
  Text,
  Textarea,
  TextInput,
  rem,
} from "@mantine/core";
import dayjs from "dayjs";
import toast from "react-hot-toast";
import { api, queryClient } from "./api";
import { DataTable } from "./DataTable";
import { Failure } from "./shared";
import { CloudflareModal as Modal } from "./CloudflareModal";
import type { CloudflareProvider } from "./CloudflareProviders";

type Record = {
  id: string;
  name: string;
  type: string;
  content: string;
  ttl: number;
  proxied: boolean;
  priority: number | null;
  version: string;
  editable: boolean;
  protected: boolean;
};
type Inventory = {
  records: Record[];
  page: number;
  has_more: boolean;
  provider_revision: number;
  zone_name: string;
  source: string;
  observed_at_unix_ms: number;
};
export function CloudflareDns({
  provider,
  paused,
}: {
  provider: CloudflareProvider;
  paused: boolean;
}) {
  const [page, setPage] = useState(1);
  const [name, setName] = useState("");
  const [filter, setFilter] = useState("");
  const [editing, setEditing] = useState<Record | "new" | null>(null);
  const [deleting, setDeleting] = useState<Record | null>(null);
  const path = `/certificate-providers/${provider.id}/dns`;
  const query = useQuery({
    queryKey: ["cloudflare-dns", provider.id, page, filter],
    queryFn: ({ signal }) =>
      api<Inventory>(
        `${path}?page=${page}&name=${encodeURIComponent(filter)}`,
        { signal },
      ),
    refetchInterval: paused ? false : 30000,
  });
  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: ["cloudflare-dns", provider.id],
    });
  const remove = useMutation({
    mutationFn: () =>
      api(`${path}/${deleting?.id}`, {
        method: "DELETE",
        body: {
          expected_provider_revision: query.data?.provider_revision,
          expected_record: deleting?.version,
        },
      }),
    onSuccess: () => {
      setDeleting(null);
      invalidate();
      toast.success("DNS record deleted");
    },
  });
  const data = query.data;
  return (
    <Stack>
      <Alert color="blue">
        Changes are sent directly to Cloudflare. ACME challenge records and
        unsupported record types are view-only.
      </Alert>
      <Group align="flex-end">
        <TextInput
          label="Filter by full DNS name"
          placeholder={`www.${provider.zone_name}`}
          value={name}
          onChange={(e) => setName(e.currentTarget.value)}
          maxLength={253}
        />
        <Button
          variant="default"
          onClick={() => {
            setPage(1);
            setFilter(name.trim());
          }}
        >
          Filter records
        </Button>
        <Button variant="default" onClick={() => void query.refetch()}>
          Refresh DNS
        </Button>
        <Button
          disabled={!data || query.isError}
          onClick={() => setEditing("new")}
        >
          Add DNS record
        </Button>
      </Group>
      {query.isPending && (
        <Group role="status">
          <Loader size="sm" />
          Loading Cloudflare DNS…
        </Group>
      )}
      {query.isError && (
        <>
          <Alert color="yellow">
            DNS observations may be stale. Reload records before retrying any
            change that was not acknowledged.
          </Alert>
          <Failure error={query.error} />
        </>
      )}
      {data && (
        <>
          <Text size="sm" c="dimmed">
            Source: Cloudflare · {paused ? "DNS refresh paused" : "Observed"}:{" "}
            {dayjs(data.observed_at_unix_ms).format("YYYY-MM-DD HH:mm:ss")}
          </Text>
          <DataTable
            records={data.records}
            idAccessor="id"
            noRecordsText="No DNS records match this page."
            minHeight={rem(160)}
            columns={[
              { accessor: "type", title: "Type" },
              {
                accessor: "name",
                title: "Name",
                render: (r) => (
                  <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                    {r.name}
                  </Text>
                ),
              },
              {
                accessor: "content",
                title: "Content",
                render: (r) => (
                  <Text
                    size="xs"
                    lineClamp={3}
                    style={{ overflowWrap: "anywhere", maxWidth: rem(280) }}
                  >
                    {r.content}
                  </Text>
                ),
              },
              {
                accessor: "ttl",
                title: "TTL",
                render: (r) => (r.ttl === 1 ? "Auto" : `${r.ttl}s`),
              },
              {
                accessor: "proxied",
                title: "Proxy",
                render: (r) => (
                  <Badge color={r.proxied ? "orange" : "gray"}>
                    {r.proxied ? "Proxied" : "DNS only"}
                  </Badge>
                ),
              },
              {
                accessor: "actions",
                title: "Actions",
                render: (r) =>
                  r.editable ? (
                    <Group gap="xs">
                      <Button
                        size="xs"
                        variant="default"
                        disabled={query.isError}
                        onClick={() => setEditing(r)}
                        aria-label={`Edit DNS ${r.name}`}
                      >
                        Edit
                      </Button>
                      <Button
                        size="xs"
                        variant="subtle"
                        color="red"
                        disabled={query.isError}
                        onClick={() => {
                          remove.reset();
                          setDeleting(r);
                        }}
                        aria-label={`Delete DNS ${r.name}`}
                      >
                        Delete
                      </Button>
                    </Group>
                  ) : (
                    <Badge color="gray">
                      {r.protected ? "ACME protected" : "View only"}
                    </Badge>
                  ),
              },
            ]}
          />
          <Group justify="space-between">
            <Button
              variant="default"
              disabled={page <= 1 || query.isFetching}
              onClick={() => setPage(page - 1)}
            >
              Previous records
            </Button>
            <Text size="sm">Page {data.page}</Text>
            <Button
              variant="default"
              disabled={!data.has_more || query.isFetching}
              onClick={() => setPage(page + 1)}
            >
              Next records
            </Button>
          </Group>
        </>
      )}
      <Modal
        opened={editing !== null}
        onClose={() => setEditing(null)}
        title={editing === "new" ? "Add DNS record" : "Edit DNS record"}
        size="lg"
      >
        {editing && data && (
          <RecordForm
            record={editing === "new" ? undefined : editing}
            providerRevision={data.provider_revision}
            path={path}
            zone={provider.zone_name}
            done={() => {
              setEditing(null);
              invalidate();
            }}
          />
        )}
      </Modal>
      <Modal
        opened={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete DNS record"
      >
        {deleting && (
          <Stack>
            <Text>
              Delete {deleting.type} {deleting.name} from Cloudflare? This can
              affect services using the record.
            </Text>
            {remove.isError && <Failure error={remove.error} />}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setDeleting(null)}>
                Cancel
              </Button>
              <Button
                color="red"
                loading={remove.isPending}
                onClick={() => remove.mutate()}
              >
                Delete DNS record
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
type Form = {
  type: string;
  name: string;
  content: string;
  ttl: string;
  proxied: boolean;
  priority: string;
};
function RecordForm({
  record,
  providerRevision,
  path,
  zone,
  done,
}: {
  record?: Record;
  providerRevision: number;
  path: string;
  zone: string;
  done: () => void;
}) {
  const {
    register,
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<Form>({
    defaultValues: {
      type: record?.type ?? "A",
      name: record?.name ?? "@",
      content: record?.content ?? "",
      ttl: String(record?.ttl ?? 1),
      proxied: record?.proxied ?? false,
      priority: String(record?.priority ?? 10),
    },
  });
  const type = useWatch({ control, name: "type" });
  const proxied = useWatch({ control, name: "proxied" });
  const canProxy = ["A", "AAAA", "CNAME"].includes(type);
  const save = useMutation({
    mutationFn: (v: Form) =>
      api(record ? `${path}/${record.id}` : path, {
        method: record ? "PUT" : "POST",
        body: {
          expected_provider_revision: providerRevision,
          expected_record: record?.version ?? null,
          record: {
            type: record?.type ?? v.type,
            name: v.name,
            content: v.content,
            ttl: canProxy && v.proxied ? 1 : Number(v.ttl),
            proxied: canProxy && v.proxied,
            priority: v.type === "MX" ? Number(v.priority) : null,
          },
        },
      }),
    onSuccess: () => {
      toast.success(record ? "DNS record updated" : "DNS record created");
      done();
    },
  });
  return (
    <form onSubmit={handleSubmit((v) => save.mutate(v))}>
      <Stack>
        <NativeSelect
          label="Record type"
          disabled={!!record}
          data={["A", "AAAA", "CNAME", "TXT", "MX", "NS"]}
          {...register("type")}
        />
        <TextInput
          label="DNS name"
          description={`Use @ for ${zone}, a relative name, or a full name in this zone.`}
          required
          maxLength={253}
          {...register("name", { required: "Enter a DNS name" })}
          error={errors.name?.message}
        />
        <Textarea
          label="Record content"
          required
          minRows={2}
          maxLength={2048}
          {...register("content", { required: "Enter record content" })}
          error={errors.content?.message}
        />
        {type === "MX" && (
          <TextInput
            type="number"
            label="MX priority"
            min={0}
            max={65535}
            required
            {...register("priority", { min: 0, max: 65535 })}
          />
        )}
        {canProxy && (
          <Checkbox
            label="Proxy traffic through Cloudflare"
            {...register("proxied")}
          />
        )}
        {canProxy && proxied ? (
          <Text size="sm">Proxied records use automatic TTL.</Text>
        ) : (
          <TextInput
            label="TTL in seconds"
            description="1 means automatic; otherwise 60–86400 seconds."
            type="number"
            min={1}
            max={86400}
            required
            {...register("ttl", {
              validate: (v) =>
                v === "1" ||
                (Number(v) >= 60 && Number(v) <= 86400) ||
                "Use 1 or a TTL between 60 and 86400",
            })}
            error={errors.ttl?.message}
          />
        )}
        {save.isError && (
          <>
            <Failure error={save.error} />
            <Alert color="yellow">
              Reload DNS records before retrying if Cloudflare did not
              acknowledge this change.
            </Alert>
          </>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={done}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            {record ? "Save DNS record" : "Create DNS record"}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
