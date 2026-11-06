import {
  ActionIcon,
  Alert,
  Anchor,
  Badge,
  Button,
  Checkbox,
  CloseButton,
  Grid,
  Group,
  Input,
  InputBase,
  Modal,
  NativeSelect,
  NavLink,
  NumberInput,
  Paper,
  PasswordInput,
  ScrollArea,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Tabs,
  Text,
  Textarea,
  TextInput,
  Title,
  createTheme,
  rem,
} from "@mantine/core";

// Density comes from component sizes and spacing. Keep scale available for
// proportional resizing, including custom CSS and Lucide icons using rem().
export const theme = createTheme({
  scale: 1,
  fontFamily: "'IBM Plex Sans', 'Segoe UI', sans-serif",
  fontSizes: {
    xs: rem(12),
    sm: rem(13),
    md: rem(14),
    lg: rem(16),
    xl: rem(18),
  },
  spacing: { xs: rem(8), sm: rem(10), md: rem(12), lg: rem(16), xl: rem(20) },
  lineHeights: { xs: "1.4", sm: "1.45", md: "1.45", lg: "1.5", xl: "1.5" },
  fontFamilyMonospace: "'IBM Plex Mono', monospace",
  headings: {
    fontFamily: "'IBM Plex Sans', 'Segoe UI', sans-serif",
    fontWeight: "600",
    sizes: {
      h1: { fontSize: rem(20), lineHeight: "1.3" },
      h2: { fontSize: rem(16), lineHeight: "1.4" },
      h3: { fontSize: rem(14), lineHeight: "1.4" },
    },
  },
  colors: {
    app: [
      "#ecf4ff",
      "#dce4f5",
      "#b9c7e2",
      "#94a8d0",
      "#748dc0",
      "#5f7cb7",
      "#5474b4",
      "#44639f",
      "#3a5890",
      "#2c4b80",
    ],
  },
  primaryColor: "app",
  defaultRadius: "sm",
  components: {
    ActionIcon: ActionIcon.extend({ defaultProps: { size: "md" } }),
    CloseButton: CloseButton.extend({ defaultProps: { size: "md" } }),
    Text: Text.extend({ defaultProps: { size: "sm" } }),
    Anchor: Anchor.extend({ defaultProps: { size: "sm" } }),
    Button: Button.extend({ defaultProps: { size: "xs", fw: 600 } }),
    Badge: Badge.extend({ defaultProps: { size: "sm", radius: "sm" } }),
    Input: Input.extend({ defaultProps: { size: "xs" } }),
    InputBase: InputBase.extend({ defaultProps: { size: "xs" } }),
    TextInput: TextInput.extend({ defaultProps: { size: "xs" } }),
    PasswordInput: PasswordInput.extend({ defaultProps: { size: "xs" } }),
    NumberInput: NumberInput.extend({ defaultProps: { size: "xs" } }),
    Select: Select.extend({ defaultProps: { size: "xs" } }),
    NativeSelect: NativeSelect.extend({ defaultProps: { size: "xs" } }),
    Textarea: Textarea.extend({ defaultProps: { size: "xs" } }),
    Checkbox: Checkbox.extend({ defaultProps: { size: "xs" } }),
    Switch: Switch.extend({ defaultProps: { size: "xs" } }),
    Group: Group.extend({ defaultProps: { gap: "sm" } }),
    Stack: Stack.extend({ defaultProps: { gap: "sm" } }),
    Grid: Grid.extend({ defaultProps: { gutter: "sm" } }),
    SimpleGrid: SimpleGrid.extend({
      defaultProps: { spacing: "sm", verticalSpacing: "sm" },
    }),
    Alert: Alert.extend({ defaultProps: { p: "sm" } }),
    Paper: Paper.extend({
      defaultProps: { radius: "sm", bg: "var(--console-surface)" },
    }),
    NavLink: NavLink.extend({
      defaultProps: { variant: "light" },
      styles: {
        root: { fontSize: "var(--mantine-font-size-sm)", lineHeight: 1.4 },
      },
    }),
    Tabs: Tabs.extend({
      styles: {
        tab: {
          fontSize: "var(--mantine-font-size-sm)",
          padding: "var(--mantine-spacing-xs) var(--mantine-spacing-sm)",
        },
      },
    }),
    Title: Title.extend({
      defaultProps: { textWrap: "pretty" },
      styles: { root: { letterSpacing: "-0.02em" } },
    }),
    ScrollArea: ScrollArea.extend({
      defaultProps: {
        scrollbarSize: rem(8),
        type: "auto",
        overscrollBehavior: "contain",
        viewportProps: { tabIndex: 0 },
      },
    }),
    Modal: Modal.extend({
      defaultProps: {
        radius: "sm",
        padding: "md",
        scrollAreaComponent: ScrollArea.Autosize,
      },
      styles: {
        header: {
          minHeight: rem(44),
          borderBottom: "1px solid var(--console-border)",
          marginBottom: "var(--mantine-spacing-sm)",
        },
        title: { fontWeight: 600, fontSize: "var(--mantine-font-size-lg)" },
      },
    }),
    InputWrapper: Input.Wrapper.extend({
      defaultProps: {
        inputWrapperOrder: ["label", "input", "description", "error"],
      },
    }),
  },
});
