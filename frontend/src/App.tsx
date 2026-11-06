import {
  ActionIcon,
  AppShell,
  Burger,
  CloseButton,
  FocusTrap,
  NavLink as MantineNavLink,
  useComputedColorScheme,
  useMantineTheme,
  Alert,
  Badge,
  Button,
  Container,
  Group,
  Loader,
  Paper,
  PasswordInput,
  ScrollArea,
  Stack,
  Text,
  TextInput,
  Title,
  useMantineColorScheme,
  rem,
} from "@mantine/core";
import { useFocusReturn, useMediaQuery } from "@mantine/hooks";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import {
  Boxes,
  Activity,
  ChartNoAxesCombined,
  ArrowRight,
  Bell,
  Gauge,
  GitBranch,
  LogOut,
  Moon,
  Network,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  KeyRound,
} from "lucide-react";
import { api, ApiError, forgetSession, queryClient } from "./api";
import type { Session } from "./types";
import { Failure } from "./shared";
import { lazy, Suspense, useState, Fragment } from "react";
import toast from "react-hot-toast";
const AntiAbuse = lazy(() =>
  import("./AntiAbuse").then((m) => ({ default: m.AntiAbuse })),
);
const SecuritySimulator = lazy(() =>
  import("./SecuritySimulator").then((m) => ({ default: m.SecuritySimulator })),
);
const Applications = lazy(() =>
  import("./Applications").then((m) => ({ default: m.Applications })),
);
const RouteDetail = lazy(() =>
  import("./Investigation").then((m) => ({ default: m.RouteDetail })),
);
const RequestReferencePage = lazy(() =>
  import("./Investigation").then((m) => ({ default: m.RequestReferencePage })),
);
const ServiceMap = lazy(() =>
  import("./ServiceMap").then((m) => ({ default: m.ServiceMap })),
);
const RoutePlayground = lazy(() =>
  import("./RoutePlayground").then((m) => ({ default: m.RoutePlayground })),
);
const Discovery = lazy(() =>
  import("./Discovery").then((module) => ({ default: module.Discovery })),
);
const Configuration = lazy(() =>
  import("./Configuration").then((module) => ({
    default: module.Configuration,
  })),
);

const Telemetry = lazy(() =>
  import("./Telemetry").then((module) => ({ default: module.Telemetry })),
);

const SystemHealth = lazy(() =>
  import("./SystemHealth").then((m) => ({ default: m.SystemHealth })),
);

const Operations = lazy(() =>
  import("./Operations").then((module) => ({ default: module.Operations })),
);

function FirstAccess() {
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: async ({ signal }) => {
      const status = await api<{ setup_required: boolean }>("/auth/setup", {
        signal,
      });
      if (typeof status.setup_required !== "boolean")
        throw new Error("Invalid setup status. Retry the setup check.");
      return status;
    },
  });
  if (setup.isPending)
    return (
      <Container py="md">
        <Group role="status">
          <Loader size="sm" />
          Checking administrator setup…
        </Group>
      </Container>
    );
  if (setup.isError)
    return (
      <Container size="sm" py="md">
        <Stack>
          <Failure error={setup.error} />
          <Button onClick={() => void setup.refetch()}>
            Retry setup check
          </Button>
        </Stack>
      </Container>
    );
  return (
    <Login
      key={String(setup.data.setup_required)}
      setupRequired={setup.data.setup_required}
    />
  );
}

function Login({ setupRequired }: { setupRequired: boolean }) {
  const {
    register,
    handleSubmit,
    resetField,
    getValues,
    formState: { errors },
  } = useForm<{ username: string; password: string; confirmation: string }>();
  const login = useMutation({
    mutationFn: async (body: { username: string; password: string }) => {
      if (setupRequired) {
        await api<void>("/auth/setup", { method: "POST", body });
        return null;
      }
      return api<Session>("/auth/login", { method: "POST", body });
    },
    onSuccess: (session) => {
      if (setupRequired) {
        toast.success("Administrator created. Sign in to continue.");
        queryClient.setQueryData(["setup"], { setup_required: false });
      } else {
        forgetSession();
        queryClient.setQueryData(["session"], session);
      }
    },
    onError: (error) => {
      if (!setupRequired) return;
      if (error instanceof ApiError && error.status === 409) {
        toast("An administrator already exists. Sign in to continue.");
        queryClient.setQueryData(["setup"], { setup_required: false });
      } else if (error instanceof ApiError && [0, 503].includes(error.status)) {
        void queryClient.invalidateQueries({ queryKey: ["setup"] });
      }
    },
    onSettled: () => {
      resetField("password");
      resetField("confirmation");
    },
  });
  return (
    <Container size={rem(1100)} className="login">
      <div className="login-story">
        <Badge variant="outline" color="teal">
          SINGLE NODE / CONTROL PLANE
        </Badge>
        <Title order={1}>
          A clear view.
          <br />A deliberate change.
        </Title>
        <Text size="lg" c="dimmed">
          Discover services, verify their reachability, and review every
          configuration before it reaches your gateway.
        </Text>
        <Group mt="md">
          <ShieldCheck size={rem(20)} />
          <Text size="sm">OpenWAF · Operator workspace</Text>
        </Group>
      </div>
      <Paper withBorder p="md">
        <Stack gap="md">
          <div>
            <Title order={2}>
              {setupRequired ? "Create your administrator" : "Welcome back"}
            </Title>
            <Text c="dimmed" size="sm">
              {setupRequired
                ? "Set up the first administrator for this OpenWAF instance."
                : "Sign in with your local administrator account."}
            </Text>
          </div>
          <form
            onSubmit={handleSubmit(({ username, password }) =>
              login.mutate({ username, password }),
            )}
          >
            <Stack>
              <TextInput
                label="Username"
                autoComplete="username"
                {...register("username", {
                  required: "Enter your username",
                  maxLength: {
                    value: 64,
                    message: "Use at most 64 characters",
                  },
                  pattern: {
                    value: /^[a-z0-9_-]+$/,
                    message: "Use lowercase letters, numbers, _ or -",
                  },
                })}
                error={errors.username?.message}
              />
              <PasswordInput
                label="Password"
                autoComplete={
                  setupRequired ? "new-password" : "current-password"
                }
                {...register("password", {
                  required: "Enter your password",
                  validate: (value) => {
                    const length = new TextEncoder().encode(value).length;
                    return (
                      (length <= 128 && (!setupRequired || length >= 12)) ||
                      (setupRequired
                        ? "Use 12–128 bytes"
                        : "Use at most 128 bytes")
                    );
                  },
                })}
                error={errors.password?.message}
              />
              {setupRequired && (
                <PasswordInput
                  label="Confirm password"
                  autoComplete="new-password"
                  {...register("confirmation", {
                    required: "Confirm your password",
                    validate: (value) =>
                      value === getValues("password") ||
                      "Passwords do not match",
                  })}
                  error={errors.confirmation?.message}
                />
              )}
              {login.isError && <Failure error={login.error} />}
              <Button
                type="submit"
                loading={login.isPending}
                rightSection={<ArrowRight size={rem(16)} />}
              >
                {setupRequired ? "Create administrator" : "Sign in"}
              </Button>
            </Stack>
          </form>
          <Text c="dimmed" size="xs">
            Your session uses a secure, HttpOnly cookie. Use the HTTPS Admin
            origin.
          </Text>
        </Stack>
      </Paper>
    </Container>
  );
}
export function App() {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const { toggleColorScheme } = useMantineColorScheme();
  const colorScheme = useComputedColorScheme("light");
  const theme = useMantineTheme();
  const mobile = useMediaQuery(`(max-width: ${theme.breakpoints.sm})`);
  useFocusReturn({ opened: Boolean(mobile && navigationOpen) });
  const session = useQuery({
    queryKey: ["session"],
    queryFn: async ({ signal }) => {
      try {
        return await api<Session>("/auth/session", { signal });
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null;
        throw error;
      }
    },
    staleTime: Infinity,
  });
  const logout = useMutation({
    mutationFn: () => api("/auth/logout", { method: "POST" }),
    onSuccess: forgetSession,
  });
  if (session.isPending)
    return (
      <Container py="md">
        <Group role="status">
          <Loader size="sm" />
          Checking your session…
        </Group>
      </Container>
    );
  if (session.isError)
    return (
      <Container size="sm" py="md">
        <Stack>
          <Failure error={session.error} />
          <Button onClick={() => void session.refetch()}>
            Retry session check
          </Button>
        </Stack>
      </Container>
    );
  if (!session.data) return <FirstAccess />;
  return (
    <AppShell
      key={session.data.csrf_token}
      header={{ height: { base: rem(48), sm: rem(44) } }}
      navbar={{
        width: rem(224),
        breakpoint: "sm",
        collapsed: { mobile: !navigationOpen },
      }}
      padding={0}
      className="workspace"
      transitionDuration={0}
    >
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <AppShell.Header className="topbar">
        <Group gap="sm" wrap="nowrap">
          <Burger
            hiddenFrom="sm"
            opened={navigationOpen}
            aria-label="Toggle navigation"
            aria-expanded={navigationOpen}
            aria-controls="workspace-navigation"
            onClick={() => setNavigationOpen(!navigationOpen)}
          />
          <div className="brand-mark">
            <ShieldCheck size={rem(24)} />
          </div>
          <Text fw={800} size="lg">
            OpenWAF<span className="brand-divider"> / </span>
            <span className="brand-caption">Gateway console</span>
          </Text>
        </Group>
        <Group gap="xs" wrap="nowrap" className="session-actions">
          <Badge variant="light" color="gray">
            {session.data.username}
          </Badge>
          <ActionIcon
            variant="subtle"
            color="gray"
            aria-label="Toggle color scheme"
            onClick={toggleColorScheme}
          >
            {colorScheme === "dark" ? (
              <Sun size={rem(19)} />
            ) : (
              <Moon size={rem(19)} />
            )}
          </ActionIcon>
          <Button
            className="session-signout"
            aria-label="Sign out"
            variant="subtle"
            color="gray"
            size="compact-xs"
            leftSection={<LogOut size={rem(16)} />}
            loading={logout.isPending}
            onClick={() => logout.mutate()}
          >
            Sign out
          </Button>
        </Group>
      </AppShell.Header>
      <AppShell.Navbar
        id="workspace-navigation"
        className="sidebar"
        p="xs"
        inert={Boolean(mobile && !navigationOpen)}
        onKeyDown={(event) => {
          if (event.key === "Escape") setNavigationOpen(false);
        }}
      >
        <FocusTrap active={Boolean(mobile && navigationOpen)}>
          <Stack gap="sm" h="100%" mih={0}>
            <Group justify="space-between" hiddenFrom="sm">
              <Text fw={600}>Navigation</Text>
              <CloseButton
                aria-label="Close navigation"
                onClick={() => setNavigationOpen(false)}
              />
            </Group>
            <div className="workspace-label">
              <span className="node-symbol">01</span>
              <span>
                Operator workspace<small>Single-node gateway</small>
              </span>
            </div>
            <ScrollArea
              flex={1}
              mih={0}
              type="hover"
              scrollbars="y"
              scrollbarSize={rem(6)}
              offsetScrollbars="present"
              overscrollBehavior="contain"
              viewportProps={{
                tabIndex: 0,
                role: "region",
                "aria-label": "Scrollable navigation",
              }}
            >
              <nav aria-label="Main navigation">
                {[
                  {
                    to: "/overview",
                    label: "Overview",
                    icon: Gauge,
                    group: "MONITOR",
                  },
                  { to: "/traffic", label: "Live traffic", icon: Activity },
                  {
                    to: "/statistics",
                    label: "Request statistics",
                    icon: ChartNoAxesCombined,
                  },
                  {
                    label: "Applications",
                    to: "/applications",
                    icon: Boxes,
                  },
                  {
                    to: "/configuration",
                    label: "Configuration",
                    icon: SlidersHorizontal,
                    group: "GATEWAY",
                  },
                  {
                    to: "/discovery",
                    label: "Upstreams & discovery",
                    icon: Network,
                  },
                  { to: "/service-map", label: "Service map", icon: Network },
                  { to: "/abuse", label: "Abuse incidents", icon: ShieldCheck },
                  {
                    to: "/security-simulator",
                    label: "Security simulator",
                    icon: Shield,
                  },
                  {
                    to: "/playground",
                    label: "Route playground",
                    icon: GitBranch,
                  },
                  { to: "/security", label: "Security", icon: Shield },
                  {
                    to: "/certificates",
                    label: "Certificates",
                    icon: KeyRound,
                  },
                  {
                    to: "/uptime",
                    label: "Uptime",
                    icon: GitBranch,
                    group: "OPERATIONS",
                  },
                  { to: "/alerts", label: "Alerts", icon: Bell },
                  { to: "/health", label: "System health", icon: Activity },
                  { to: "/settings", label: "Settings", icon: Settings },
                ].map(({ to, label, icon: Icon, group }) => (
                  <Fragment key={to}>
                    {group && <div className="nav-group-label">{group}</div>}
                    <MantineNavLink
                      component={NavLink}
                      to={to}
                      label={label}
                      leftSection={
                        <Icon
                          size={rem(18)}
                          strokeWidth={1.7}
                          aria-hidden="true"
                        />
                      }
                      onClick={() => setNavigationOpen(false)}
                    />
                  </Fragment>
                ))}
              </nav>
            </ScrollArea>
            <Stack
              component="footer"
              className="sidebar-note"
              gap={rem(4)}
              pt="sm"
              mx="xs"
              flex="0 0 auto"
            >
              <Group gap="xs" wrap="nowrap">
                <ShieldCheck size={rem(18)} aria-hidden="true" />
                <Text size="sm">OpenWAF control plane</Text>
              </Group>
              <Text size="xs" c="dimmed">
                Draft → Validate → Apply
              </Text>
            </Stack>
          </Stack>
        </FocusTrap>
      </AppShell.Navbar>
      <AppShell.Main id="main" tabIndex={-1} className="workspace-main">
        <ScrollArea
          flex={1}
          mih={0}
          type="auto"
          scrollbars="y"
          offsetScrollbars="present"
          overscrollBehavior="contain"
          viewportProps={{
            tabIndex: 0,
            role: "region",
            "aria-label": "Page content",
          }}
        >
          <div className="workspace-content">
            {logout.isError && (
              <Alert color="red" mb="md">
                <Failure error={logout.error} />
              </Alert>
            )}
            <Suspense
              fallback={
                <Group role="status">
                  <Loader size="sm" />
                  Loading workspace…
                </Group>
              }
            >
              <Routes>
                <Route
                  path="/security-simulator"
                  element={<SecuritySimulator />}
                />
                <Route path="/abuse" element={<AntiAbuse />} />
                {(
                  [
                    "Security",
                    "Certificates",
                    "Uptime",
                    "Alerts",
                    "Settings",
                  ] as const
                ).map((name) => (
                  <Route
                    key={name}
                    path={`/${name.toLowerCase()}`}
                    element={<Operations page={name} />}
                  />
                ))}
                <Route path="/overview" element={<Telemetry />} />
                <Route path="/traffic" element={<Telemetry traffic />} />
                <Route path="/statistics" element={<Telemetry statistics />} />
                <Route path="/discovery" element={<Discovery />} />
                <Route path="/routes/:id" element={<RouteDetail />} />
                <Route
                  path="/requests/:id"
                  element={<RequestReferencePage />}
                />
                <Route path="/service-map" element={<ServiceMap />} />
                <Route path="/playground" element={<RoutePlayground />} />
                <Route path="/health" element={<SystemHealth />} />
                <Route path="/configuration" element={<Configuration />} />
                <Route path="/applications" element={<Applications />} />
                <Route
                  path="*"
                  element={<Navigate replace to="/discovery" />}
                />
              </Routes>
            </Suspense>
          </div>
        </ScrollArea>
      </AppShell.Main>
    </AppShell>
  );
}
