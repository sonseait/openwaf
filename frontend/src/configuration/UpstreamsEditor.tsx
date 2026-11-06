import { ModalTabLayout } from "../ModalTabs";
import { useState } from "react";
import { Badge, Button, Group, Modal, Stack, Text, rem } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import {
  FormProvider,
  useFieldArray,
  useForm,
  useFormContext,
  useWatch,
} from "react-hook-form";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { focusModalError } from "../modal-focus";
import { DataTable } from "../DataTable";
import type { Document, Upstream } from "../types";
import { UpstreamEditor } from "./UpstreamEditor";

export function UpstreamsEditor({ disabled }: { disabled: boolean }) {
  const { control, getValues } = useFormContext<Document>();
  const upstreams = useFieldArray({
    control,
    name: "upstreams",
    keyName: "formKey",
  });
  const values = useWatch({ control, name: "upstreams" });
  const routeValues = useWatch({ control, name: "routes" });
  const references = (id: string) =>
    routeValues.filter(
      (route) =>
        route.upstream === id ||
        route.middleware?.forward_auth?.upstream === id,
    );
  const [editing, setEditing] = useState<{
    index: number;
    document: Document;
    adding: boolean;
  } | null>(null);
  const [removing, setRemoving] = useState<number | null>(null);
  const records = upstreams.fields.map((field, index) => ({
    ...(values[index] ?? field),
    formKey: field.formKey,
    index,
  }));
  const focusUpstream = (index?: number) => {
    requestAnimationFrame(() => {
      const button =
        index === undefined
          ? null
          : document.querySelector<HTMLButtonElement>(
              `[data-upstream-edit="${index}"]`,
            );
      (
        button ??
        document.querySelector<HTMLButtonElement>("[data-add-upstream]")
      )?.focus();
    });
  };
  const closeEditor = () => {
    const index = editing?.adding ? undefined : editing?.index;
    setEditing(null);
    focusUpstream(index);
  };
  const open = (index: number, adding = false) => {
    const document = structuredClone(getValues());
    if (adding)
      document.upstreams.push({
        id: "",
        endpoints: [{ address: "", protocol: "http", tls_server_name: null }],
      });
    setEditing({ index, document, adding });
  };
  return (
    <Stack>
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Upstream pools in the current draft. Edit endpoints, TLS, health
          checks and balancing.
        </Text>
        <Button
          type="button"
          data-add-upstream
          leftSection={<Plus size={rem(16)} />}
          disabled={disabled}
          onClick={() => open(upstreams.fields.length, true)}
        >
          Add upstream
        </Button>
      </Group>
      <DataTable
        aria-label="Draft upstreams"
        idAccessor="formKey"
        records={records}
        minHeight={rem(160)}
        styles={{ table: { minWidth: rem(820) } }}
        pinLastColumn
        noRecordsText="No upstream pools. Add endpoints manually or choose them in discovery."
        columns={[
          {
            accessor: "id",
            title: "Pool",
            width: "21%",
            render: (pool) => (
              <Stack gap={rem(3)}>
                <Text size="sm" fw={600} style={{ overflowWrap: "anywhere" }}>
                  {pool.id || "Unnamed upstream"}
                </Text>
                <Text size="xs" c="dimmed">
                  {references(pool.id).length} routes · {pool.endpoints.length}{" "}
                  endpoints
                </Text>
              </Stack>
            ),
          },
          {
            accessor: "endpoints",
            title: "Endpoints",
            width: "31%",
            render: (pool) => (
              <Stack gap={rem(3)}>
                {pool.endpoints.slice(0, 2).map((endpoint, i) => (
                  <Text key={i} size="sm" style={{ overflowWrap: "anywhere" }}>
                    {endpoint.protocol.toUpperCase()} ·{" "}
                    {endpoint.address || "Unassigned"}
                  </Text>
                ))}
                {pool.endpoints.length === 0 && (
                  <Text size="sm" c="dimmed">
                    No endpoints
                  </Text>
                )}
                {pool.endpoints.length > 2 && (
                  <Text size="xs" c="dimmed">
                    +{pool.endpoints.length - 2} more
                  </Text>
                )}
              </Stack>
            ),
          },
          {
            accessor: "settings",
            title: "Policy",
            render: (pool) => (
              <Stack gap={rem(4)}>
                <Text size="sm">
                  {
                    {
                      round_robin: "Round robin",
                      weighted_round_robin: "Weighted round robin",
                      least_active_requests: "Least active requests",
                    }[pool.balancing?.algorithm ?? "round_robin"]
                  }
                </Text>
                <Text size="xs" c="dimmed">
                  Health check: {pool.health?.method ?? "HEAD"}{" "}
                  {pool.health?.path ?? "/"}
                </Text>
                <Group gap={rem(4)}>
                  {pool.affinity && <Badge size="xs">Sticky sessions</Badge>}
                  {pool.endpoints.some(
                    (endpoint) =>
                      endpoint.protocol === "https" &&
                      endpoint.tls_verify === false,
                  ) && (
                    <Badge size="xs" color="orange">
                      TLS verification disabled
                    </Badge>
                  )}
                </Group>
              </Stack>
            ),
          },
          {
            accessor: "source",
            title: "Source",
            width: rem(110),
            render: (pool) => (
              <Group gap={rem(4)}>
                {pool.endpoints.some((endpoint) => endpoint.source) && (
                  <Badge size="xs">Discovery</Badge>
                )}
                {pool.endpoints.some((endpoint) => !endpoint.source) && (
                  <Badge size="xs" color="gray">
                    Manual
                  </Badge>
                )}
              </Group>
            ),
          },
          {
            accessor: "actions",
            title: "Actions",
            width: rem(140),
            render: (r) => (
              <Group gap={rem(4)} wrap="nowrap">
                <Button
                  type="button"
                  size="compact-xs"
                  variant="subtle"
                  data-upstream-edit={r.index}
                  aria-label={`Edit upstream ${r.id || "Unnamed upstream"}`}
                  disabled={disabled}
                  leftSection={<Pencil size={rem(14)} />}
                  onClick={() => open(r.index)}
                >
                  Edit
                </Button>
                <Button
                  type="button"
                  size="compact-xs"
                  color="red"
                  variant="subtle"
                  aria-label={`Remove upstream ${r.id || "Unnamed upstream"}`}
                  disabled={disabled}
                  onClick={() => setRemoving(r.index)}
                >
                  <Trash2 size={rem(14)} />
                </Button>
              </Group>
            ),
          },
        ]}
      />
      {editing && (
        <UpstreamModal
          initial={editing.document}
          index={editing.index}
          adding={editing.adding}
          disabled={disabled}
          onClose={closeEditor}
          onSave={(upstream) => {
            if (editing.adding)
              upstreams.append(upstream, { shouldFocus: false });
            else upstreams.update(editing.index, upstream);
            setEditing(null);
            focusUpstream(editing.index);
          }}
        />
      )}
      <Modal
        opened={removing !== null}
        onClose={() => setRemoving(null)}
        title="Remove upstream?"
        closeButtonProps={{ "aria-label": "Close remove upstream" }}
      >
        <Stack>
          <Text>
            Remove {removing !== null ? values[removing]?.id : ""} from this
            draft? Live traffic changes only after you save and apply.
          </Text>
          {removing !== null && references(values[removing]?.id).length > 0 && (
            <Text size="sm" c="orange">
              Referenced by{" "}
              {references(values[removing]?.id)
                .map((route) => route.id)
                .join(", ")}
              . Update these routes before saving the draft.
            </Text>
          )}
          <Group justify="flex-end">
            <Button
              type="button"
              variant="default"
              onClick={() => setRemoving(null)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              color="red"
              disabled={disabled}
              onClick={() => {
                if (removing !== null) upstreams.remove(removing);
                const index = removing;
                setRemoving(null);
                focusUpstream(index ?? undefined);
              }}
            >
              Remove upstream
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

function UpstreamModal({
  initial,
  index,
  adding,
  disabled,
  onSave,
  onClose,
}: {
  initial: Document;
  index: number;
  adding: boolean;
  disabled: boolean;
  onSave: (upstream: Upstream) => void;
  onClose: () => void;
}) {
  const form = useForm<Document>({
    defaultValues: initial,
    shouldFocusError: false,
  });
  const mobile = useMediaQuery("(max-width: 48em)");
  return (
    <Modal
      opened
      onClose={onClose}
      title={
        adding ? "Add upstream" : `Edit upstream ${initial.upstreams[index].id}`
      }
      size={rem(1100)}
      fullScreen={mobile}
      scrollAreaComponent={ModalTabLayout}
      returnFocus={false}
      closeOnClickOutside={false}
      closeButtonProps={{ "aria-label": "Cancel upstream editing" }}
      classNames={{ body: "upstream-modal-body" }}
    >
      <FormProvider {...form}>
        <form
          noValidate
          onSubmit={(event) => {
            event.stopPropagation();
            void form.handleSubmit(
              (document) => onSave(document.upstreams[index]),
              () =>
                focusModalError(".upstream-modal-body", "[data-add-endpoint]"),
            )(event);
          }}
        >
          <Stack>
            <Text size="sm" c="dimmed">
              Changes are added to your local draft. Save and apply the draft to
              change live traffic.
            </Text>
            <fieldset
              disabled={disabled}
              style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}
            >
              <UpstreamEditor index={index} />
            </fieldset>
            <Group
              justify="flex-end"
              className="upstream-modal-actions"
              py="md"
            >
              <Button type="button" variant="default" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={disabled}>
                {adding ? "Add to draft" : "Update draft upstream"}
              </Button>
            </Group>
          </Stack>
        </form>
      </FormProvider>
    </Modal>
  );
}
