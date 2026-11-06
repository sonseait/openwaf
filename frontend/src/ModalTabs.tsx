import { Children, type ReactElement, type ReactNode } from "react";
import { Box, Stack, Tabs, type ScrollAreaAutosizeProps } from "@mantine/core";

type SectionProps = { value: string; label: string; children: ReactNode };

export function ModalSection({ children }: SectionProps) {
  return <Stack gap="md">{children}</Stack>;
}

export function ModalTabs({
  children,
  label,
  defaultValue,
}: {
  children: ReactElement<SectionProps>[];
  label: string;
  defaultValue: string;
}) {
  const sections = Children.toArray(children) as ReactElement<SectionProps>[];
  return (
    <Tabs
      defaultValue={defaultValue}
      keepMounted
      className="modal-section-tabs"
    >
      <Tabs.List aria-label={label} className="modal-section-tab-list">
        {sections.map(({ props }) => (
          <Tabs.Tab key={props.value} value={props.value}>
            {props.label}
          </Tabs.Tab>
        ))}
      </Tabs.List>
      {sections.map((section) => (
        <Tabs.Panel
          key={section.props.value}
          value={section.props.value}
          tabIndex={0}
          className="modal-section-panel"
          pt="md"
        >
          {section}
        </Tabs.Panel>
      ))}
    </Tabs>
  );
}

// Mantine passes the available viewport height here. Keep the header and body
// in one flex layout; the active tab panel owns vertical scrolling.
export function ModalTabLayout({ children, style }: ScrollAreaAutosizeProps) {
  return (
    <Box className="modal-tab-layout" style={style}>
      {children}
    </Box>
  );
}
