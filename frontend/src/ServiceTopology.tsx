import { useMemo, useState } from "react";
import {
  Badge,
  Button,
  Group,
  NativeSelect,
  Stack,
  Text,
  TextInput,
  Title,
  rem,
} from "@mantine/core";
import {
  ArrowRight,
  ArrowUpRight,
  Box,
  CornerDownRight,
  Globe,
  LockKeyhole,
  Search,
  Server,
  ShieldCheck,
  Waypoints,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Controller, useForm, useWatch } from "react-hook-form";
import { sourceLabel, time } from "./format";
import { DetailsGrid, StatusBadge } from "./shared";
import type { Document, Endpoint, Route } from "./types";

function wafLabel(route: Route) {
  if (!route.waf) return "Inherits startup mode";
  return route.waf.mode === "On"
    ? "Blocking"
    : route.waf.mode === "Off"
      ? "Off"
      : "Detection only";
}

function EndpointNode({ endpoint }: { endpoint: Endpoint }) {
  return (
    <div className="service-map-endpoint">
      <Group gap="xs" wrap="nowrap" align="flex-start">
        <Server
          size={rem(15)}
          className="service-map-muted-icon"
          aria-hidden="true"
        />
        <div className="service-map-node-content">
          <Text fw={600} ff="monospace" size="xs">
            {endpoint.address}
          </Text>
          <Group gap={rem(5)} mt={rem(6)}>
            <StatusBadge
              color={
                endpoint.protocol === "https" && endpoint.tls_verify !== false
                  ? "teal"
                  : endpoint.tls_verify === false &&
                      endpoint.protocol === "https"
                    ? "orange"
                    : "gray"
              }
            >
              {endpoint.protocol === "http"
                ? "HTTP"
                : endpoint.tls_verify === false
                  ? "TLS verification off"
                  : "TLS verification on"}
            </StatusBadge>
            <Text size="xs" c="dimmed">
              {endpoint.source?.kind === "host_port"
                ? "Host listener"
                : endpoint.source
                  ? "Docker"
                  : "Manual"}
            </Text>
          </Group>
          {(endpoint.source || endpoint.tls_server_name) && (
            <details className="service-map-source">
              <summary>Endpoint details</summary>
              {endpoint.tls_server_name && (
                <Text size="xs">SNI: {endpoint.tls_server_name}</Text>
              )}
              {endpoint.source && (
                <>
                  <Text size="xs">{sourceLabel(endpoint.source)}</Text>
                  <Text size="xs" c="dimmed">
                    Source observed {time(endpoint.source.observed_at_unix_ms)}
                  </Text>
                </>
              )}
            </details>
          )}
        </div>
      </Group>
    </div>
  );
}

function RouteProtection({
  route,
  globalRules,
}: {
  route: Route;
  globalRules: Document["global_rules"];
}) {
  return (
    <section
      className="service-map-protection"
      aria-label={`Protection for route ${route.id}`}
    >
      <Group justify="space-between" gap="xs" mb="md">
        <Group gap="xs">
          <ShieldCheck size={rem(16)} aria-hidden="true" />
          <Title order={3}>Route protection</Title>
        </Group>
        <Text size="xs" c="dimmed">
          <Link to={`/routes/${encodeURIComponent(route.id)}`}>{route.id}</Link>
        </Text>
      </Group>
      <DetailsGrid
        items={[
          {
            label: "WAF policy",
            value: (
              <StatusBadge
                color={
                  route.waf?.mode === "On"
                    ? "teal"
                    : route.waf?.mode === "Off"
                      ? "orange"
                      : "blue"
                }
              >
                {wafLabel(route)}
              </StatusBadge>
            ),
          },
          {
            label: "Authentication",
            value:
              route.password_protect && route.middleware?.forward_auth
                ? "Password + ForwardAuth"
                : route.password_protect
                  ? "Password login"
                  : route.middleware?.forward_auth
                    ? "ForwardAuth"
                    : "No route authentication gate",
          },
          {
            label: "Body inspection",
            value:
              route.body?.inspection === "headers-query-only"
                ? "Headers / query only"
                : `Full-body eligible · up to ${Math.min(65536, route.waf?.body_limit_bytes ?? 65536, route.body?.max_body_bytes ?? 65536).toLocaleString()} B; multipart skipped`,
          },
          {
            label: "Route access rules",
            value:
              [
                route.access?.allow?.length || route.access?.deny?.length
                  ? "IP ACL"
                  : "",
                route.access?.geo ? "GeoIP" : "",
                route.access?.rate_limit ? "IP rate limit" : "",
                route.access?.ddos ? "HTTP flood limit" : "",
              ]
                .filter(Boolean)
                .join(" · ") || "None configured",
          },
          {
            label: "Global access rules",
            value:
              globalRules &&
              (globalRules.allow?.length ||
                globalRules.deny?.length ||
                globalRules.geo ||
                globalRules.rate_limit ||
                globalRules.ddos)
                ? "Also apply before route rules"
                : "None configured",
          },
          {
            label: "Route behavior",
            value: route.maintenance
              ? "Maintenance response enabled"
              : route.redirect
                ? `Redirect ${route.redirect.status}${route.redirect.http_only ? " for HTTP" : ""}`
                : route.application
                  ? `Hosted application · ${route.application.mode}`
                  : "Proxy to upstream",
          },
        ]}
      />
      {route.middleware?.forward_auth && (
        <Text size="xs" c="dimmed" mt="md">
          Authentication upstream: {route.middleware.forward_auth.upstream}
        </Text>
      )}
      <Text size="xs" c="dimmed" mt="md">
        Policies describe configuration. Runtime inspection and client TLS
        certificates are not verified by this map.
      </Text>
    </section>
  );
}

export function ServiceTopology({ document }: { document: Document }) {
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [selectedRoute, setSelectedRoute] = useState<string | null>(null);
  const form = useForm({ defaultValues: { search: "" } });
  const search = useWatch({ control: form.control, name: "search" })
    .trim()
    .toLowerCase();
  const services = useMemo(() => {
    const upstreams = document.upstreams.map((upstream) => ({
      key: `upstream:${upstream.id}`,
      name: upstream.id,
      upstream,
      routes: document.routes.filter((route) => route.upstream === upstream.id),
      authRoutes: document.routes.filter(
        (route) => route.middleware?.forward_auth?.upstream === upstream.id,
      ),
    }));
    const localRoutes = document.routes.filter((route) => !route.upstream);
    return [
      ...upstreams,
      ...(localRoutes.length
        ? [
            {
              key: "local",
              name: "Local handlers",
              upstream: null,
              routes: localRoutes,
              authRoutes: [],
            },
          ]
        : []),
    ];
  }, [document]);
  const filtered = services.filter((service) =>
    [
      service.name,
      ...service.routes.flatMap((route) => [
        route.id,
        route.hostname,
        route.path,
      ]),
      ...service.authRoutes.map((route) => route.id),
      ...(service.upstream?.endpoints.map((endpoint) => endpoint.address) ??
        []),
    ].some((value) => value.toLowerCase().includes(search)),
  );
  const service =
    filtered.find((item) => item.key === selectedService) ?? filtered[0];
  const route =
    service?.routes.find((item) => item.id === selectedRoute) ??
    service?.routes[0];
  return (
    <div className="service-map-workspace">
      <aside className="service-map-services" aria-label="Configured services">
        <div className="service-map-service-heading">
          <Group justify="space-between" mb="sm">
            <Text fw={600}>Services</Text>
            <Text size="xs" c="dimmed">
              {filtered.length} / {services.length}
            </Text>
          </Group>
          <Controller
            name="search"
            control={form.control}
            render={({ field }) => (
              <TextInput
                {...field}
                type="search"
                aria-label="Find a service, route or endpoint"
                placeholder="Find a service…"
                maxLength={253}
                leftSection={<Search size={rem(14)} aria-hidden="true" />}
              />
            )}
          />
        </div>
        {!!filtered.length && (
          <div className="service-map-mobile-service">
            <NativeSelect
              label="Selected service"
              data={filtered.map((item) => ({
                value: item.key,
                label: item.name,
              }))}
              value={service?.key ?? ""}
              onChange={(event) => {
                setSelectedService(event.currentTarget.value);
                setSelectedRoute(null);
              }}
            />
          </div>
        )}
        <div className="service-map-service-list">
          {filtered.map((item) => (
            <button
              type="button"
              key={item.key}
              className="service-map-service"
              data-selected={service?.key === item.key || undefined}
              aria-pressed={service?.key === item.key}
              onClick={() => {
                setSelectedService(item.key);
                setSelectedRoute(null);
              }}
            >
              {item.upstream ? (
                <Box size={rem(17)} aria-hidden="true" />
              ) : (
                <CornerDownRight size={rem(17)} aria-hidden="true" />
              )}
              <span className="service-map-node-content">
                <span className="service-map-service-name">{item.name}</span>
                <span className="service-map-service-meta">
                  {item.routes.length}{" "}
                  {item.routes.length === 1 ? "route" : "routes"} ·{" "}
                  {item.upstream
                    ? `${item.upstream.endpoints.length} ${item.upstream.endpoints.length === 1 ? "endpoint" : "endpoints"}`
                    : "Gateway response"}
                </span>
              </span>
              <ArrowRight size={rem(14)} aria-hidden="true" />
            </button>
          ))}
        </div>
        {!filtered.length && (
          <Stack p="md" gap="sm">
            <Text c="dimmed">
              {search
                ? "No services match your search."
                : "No services configured yet."}
            </Text>
            {search ? (
              <Button variant="subtle" onClick={() => form.reset()}>
                Clear search
              </Button>
            ) : (
              <Button component={Link} to="/configuration" variant="light">
                Add configuration
              </Button>
            )}
          </Stack>
        )}
      </aside>
      <div className="service-map-detail">
        {service ? (
          <>
            <div className="service-map-detail-heading">
              <div>
                <Title order={2}>{service.name}</Title>
                <Text size="xs" c="dimmed" mt={rem(4)}>
                  {service.upstream
                    ? "Configured request paths"
                    : "Routes handled directly by the gateway"}
                </Text>
              </div>
              <Badge color="gray" variant="outline">
                Active configuration
              </Badge>
            </div>
            <div
              className="service-map-flow"
              aria-label={`Configured traffic paths for ${service.name}`}
            >
              <section
                className="service-map-lane"
                aria-label="Incoming routes"
              >
                <div className="service-map-lane-label">
                  <Globe size={rem(14)} aria-hidden="true" />
                  <span>Incoming routes</span>
                  <span>{service.routes.length}</span>
                </div>
                <div className="service-map-route-list">
                  {service.routes.map((item) => (
                    <button
                      type="button"
                      key={item.id}
                      className="service-map-route"
                      data-selected={route?.id === item.id || undefined}
                      aria-pressed={route?.id === item.id}
                      onClick={() => setSelectedRoute(item.id)}
                    >
                      <span className="service-map-route-host">
                        {item.hostname}
                      </span>
                      <span className="service-map-route-path">
                        {item.path}
                        <span className="service-map-match">
                          {item.path_match}
                        </span>
                      </span>
                      <span className="service-map-route-meta">
                        {item.methods.length
                          ? item.methods.join(", ")
                          : "All methods"}
                        {item.password_protect ||
                        item.middleware?.forward_auth ? (
                          <LockKeyhole
                            size={rem(12)}
                            aria-label="Route authentication configured"
                          />
                        ) : null}
                      </span>
                    </button>
                  ))}
                  {!service.routes.length && (
                    <Text size="sm" c="dimmed" p="sm">
                      No incoming proxy routes.
                    </Text>
                  )}
                </div>
              </section>
              <div className="service-map-connector" aria-hidden="true">
                <ArrowRight size={rem(20)} />
              </div>
              <section
                className="service-map-lane service-map-upstream-lane"
                aria-label={
                  service.upstream ? "Selected upstream" : "Local handling"
                }
              >
                <div className="service-map-lane-label">
                  <Waypoints size={rem(14)} aria-hidden="true" />
                  <span>{service.upstream ? "Upstream" : "OpenWAF"}</span>
                </div>
                <div className="service-map-upstream-node">
                  <span className="service-map-upstream-icon">
                    <Waypoints size={rem(23)} aria-hidden="true" />
                  </span>
                  <Text fw={600}>{service.name}</Text>
                  <Text size="xs" c="dimmed">
                    {service.upstream
                      ? (
                          service.upstream.balancing?.algorithm ?? "round_robin"
                        ).replaceAll("_", " ")
                      : "Local response"}
                  </Text>
                  {service.upstream?.affinity && (
                    <Badge size="xs" variant="light">
                      Session affinity
                    </Badge>
                  )}
                  {service.upstream?.health && (
                    <Text size="xs" c="dimmed">
                      Health checks configured
                    </Text>
                  )}
                </div>
              </section>
              <div className="service-map-connector" aria-hidden="true">
                <ArrowRight size={rem(20)} />
              </div>
              <section
                className="service-map-lane"
                aria-label={
                  service.upstream ? "Backend endpoints" : "Response targets"
                }
              >
                <div className="service-map-lane-label">
                  <Server size={rem(14)} aria-hidden="true" />
                  <span>
                    {service.upstream
                      ? "Backend endpoints"
                      : "Selected response"}
                  </span>
                  {service.upstream && (
                    <span>{service.upstream.endpoints.length}</span>
                  )}
                </div>
                <div className="service-map-endpoint-list">
                  {service.upstream
                    ? service.upstream.endpoints.map((endpoint, index) => (
                        <EndpointNode
                          key={`${endpoint.address}:${index}`}
                          endpoint={endpoint}
                        />
                      ))
                    : route && (
                        <div className="service-map-endpoint">
                          <Text fw={600}>
                            {route.application
                              ? "Hosted application"
                              : route.redirect
                                ? `HTTP ${route.redirect.status} redirect`
                                : "Local response"}
                          </Text>
                          <Text size="xs" c="dimmed" mt="xs">
                            {route.application
                              ? `${route.application.application_id} · release ${route.application.release_id} · ${route.application.mode}`
                              : (route.redirect?.url ?? "Handled by OpenWAF")}
                          </Text>
                        </div>
                      )}
                  {service.upstream && !service.upstream.endpoints.length && (
                    <Text c="dimmed">No endpoints configured.</Text>
                  )}
                </div>
              </section>
            </div>
            {!!service.authRoutes.length && (
              <div className="service-map-auth-dependencies">
                <LockKeyhole size={rem(15)} aria-hidden="true" />
                <Text size="xs">
                  Also used for ForwardAuth by:{" "}
                  {service.authRoutes.map((item) => item.id).join(", ")}.
                  Authentication calls are separate from proxy forwarding.
                </Text>
              </div>
            )}
            {route ? (
              <RouteProtection
                route={route}
                globalRules={document.global_rules}
              />
            ) : (
              <div className="service-map-protection">
                <Text c="dimmed">
                  {service.authRoutes.length
                    ? "This upstream serves authentication requests only."
                    : "This upstream is not referenced by an active route."}
                </Text>
              </div>
            )}
          </>
        ) : (
          <Stack className="service-map-empty" align="center" gap="sm">
            <Waypoints size={rem(32)} strokeWidth={1.4} aria-hidden="true" />
            <Title order={2}>
              {search ? "No matching paths" : "Your service map starts here"}
            </Title>
            <Text c="dimmed" ta="center">
              {search
                ? "Search by service, hostname, route or endpoint address."
                : "Configure an upstream and a route to see how requests reach your services."}
            </Text>
            {!search && (
              <Button
                component={Link}
                to="/configuration"
                rightSection={<ArrowUpRight size={rem(14)} />}
              >
                Open configuration
              </Button>
            )}
          </Stack>
        )}
      </div>
    </div>
  );
}
