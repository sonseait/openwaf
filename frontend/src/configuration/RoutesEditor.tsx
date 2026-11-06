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
import type { Document, Route } from "../types";
import { RouteEditor } from "./RouteEditor";

export function RoutesEditor({ disabled }: { disabled: boolean }) {
  const { control, getValues } = useFormContext<Document>();
  const routes = useFieldArray({ control, name: "routes", keyName: "formKey" });
  const values = useWatch({ control, name: "routes" });
  const [editing, setEditing] = useState<{
    index: number;
    document: Document;
    adding: boolean;
  } | null>(null);
  const [removing, setRemoving] = useState<number | null>(null);
  const records = routes.fields.map((field, index) => ({
    ...values[index],
    formKey: field.formKey,
    index,
  }));
  const focusRoute = (index?: number) => {
    requestAnimationFrame(() => {
      const button =
        index === undefined
          ? null
          : document.querySelector<HTMLButtonElement>(
              `[data-route-edit="${index}"]`,
            );
      (
        button ?? document.querySelector<HTMLButtonElement>("[data-add-route]")
      )?.focus();
    });
  };
  const closeEditor = () => {
    const index = editing?.adding ? undefined : editing?.index;
    setEditing(null);
    focusRoute(index);
  };
  const open = (index: number, adding = false) => {
    const document = structuredClone(getValues());
    if (adding)
      document.routes.push({
        id: "",
        hostname: "",
        path: "/",
        path_match: "prefix",
        methods: [],
        upstream: "",
      });
    setEditing({ index, document, adding });
  };
  return (
    <Stack>
      <Group justify="space-between">
        <Text size="sm" c="dimmed">
          Routes in the current draft. Edit a route to configure matching,
          destination and protection.
        </Text>
        <Button
          type="button"
          data-add-route
          leftSection={<Plus size={rem(16)} />}
          disabled={disabled}
          onClick={() => open(routes.fields.length, true)}
        >
          Add route
        </Button>
      </Group>
      <DataTable
        aria-label="Draft routes"
        idAccessor="formKey"
        records={records}
        minHeight={rem(160)}
        styles={{ table: { minWidth: rem(760) } }}
        pinLastColumn
        noRecordsText="No routes in this draft. Add a route to forward or redirect requests."
        columns={[
          {
            accessor: "hostname",
            title: "Route",
            width: "28%",
            render: (r) => (
              <Stack gap={rem(3)}>
                <Text size="sm" fw={600} style={{ overflowWrap: "anywhere" }}>
                  {r.hostname || "Unnamed host"}
                </Text>
                <Text size="xs" c="dimmed">
                  {r.id || "Unnamed route"}
                </Text>
              </Stack>
            ),
          },
          {
            accessor: "path",
            title: "Match",
            width: "22%",
            render: (r) => (
              <Stack gap={rem(3)}>
                <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                  {r.path || "/"}{" "}
                  <Text span size="xs" c="dimmed">
                    ({r.path_match})
                  </Text>
                </Text>
                <Text size="xs" c="dimmed">
                  {r.methods?.length ? r.methods.join(", ") : "All methods"}
                </Text>
              </Stack>
            ),
          },
          {
            accessor: "upstream",
            title: "Destination",
            width: "22%",
            render: (r) => (
              <Text size="sm" style={{ overflowWrap: "anywhere" }}>
                {r.application
                  ? `Application · ${r.application.release_id.slice(0, 12)}`
                  : r.redirect
                    ? `Redirect · ${r.redirect.status}`
                    : r.upstream || "Unassigned"}
              </Text>
            ),
          },
          {
            accessor: "protection",
            title: "Protection",
            render: (r) => (
              <Group gap={rem(4)}>
                {r.maintenance && (
                  <Badge size="xs" color="yellow">
                    Maintenance · 503
                  </Badge>
                )}
                <Badge
                  size="xs"
                  variant="light"
                  color={r.waf?.mode === "Off" ? "gray" : "teal"}
                >
                  WAF: {r.waf?.mode ?? "Inherited"}
                </Badge>
                {r.access?.challenge && <Badge size="xs">Challenge</Badge>}
                {r.access?.ddos && <Badge size="xs">HTTP flood</Badge>}
                {r.access?.rate_limit && <Badge size="xs">IP rate limit</Badge>}
                {r.password_protect && <Badge size="xs">Password</Badge>}
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
                  data-route-edit={r.index}
                  aria-label={`Edit route ${r.id || r.hostname}`}
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
                  aria-label={`Remove route ${r.id || r.hostname}`}
                  disabled={disabled || !!r.application}
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
        <RouteModal
          initial={editing.document}
          index={editing.index}
          adding={editing.adding}
          disabled={disabled}
          onClose={closeEditor}
          onSave={(route) => {
            if (editing.adding) routes.append(route, { shouldFocus: false });
            else routes.update(editing.index, route);
            setEditing(null);
            focusRoute(editing.index);
          }}
        />
      )}
      <Modal
        opened={removing !== null}
        onClose={() => setRemoving(null)}
        title="Remove route?"
        closeButtonProps={{ "aria-label": "Close remove route" }}
      >
        <Stack>
          <Text>
            Remove {removing !== null ? values[removing]?.id : ""} from this
            draft? Live traffic changes only after you save and apply.
          </Text>
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
                if (removing !== null) routes.remove(removing);
                setRemoving(null);
              }}
            >
              Remove route
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}

function RouteModal({
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
  onSave: (route: Route) => void;
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
      title={adding ? "Add route" : `Edit route ${initial.routes[index].id}`}
      size={rem(1100)}
      fullScreen={mobile}
      scrollAreaComponent={ModalTabLayout}
      returnFocus={false}
      closeOnClickOutside={false}
      closeButtonProps={{ "aria-label": "Cancel route editing" }}
      classNames={{ body: "route-modal-body" }}
    >
      <FormProvider {...form}>
        <form
          noValidate
          onSubmit={(event) => {
            event.stopPropagation();
            void form.handleSubmit(
              (document) => onSave(document.routes[index]),
              () => focusModalError(".route-modal-body"),
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
              <RouteEditor index={index} />
            </fieldset>
            <Group justify="flex-end" className="route-modal-actions" py="md">
              <Button type="button" variant="default" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" disabled={disabled}>
                {adding ? "Add to draft" : "Update draft route"}
              </Button>
            </Group>
          </Stack>
        </form>
      </FormProvider>
    </Modal>
  );
}
