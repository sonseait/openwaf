import { Modal, ScrollArea, Title, type ModalProps } from "@mantine/core";

export function CloudflareModal({
  title,
  children,
  ...props
}: Omit<ModalProps, "title"> & { title: string }) {
  return (
    <Modal.Root {...props} scrollAreaComponent={ScrollArea.Autosize}>
      <Modal.Overlay />
      <Modal.Content aria-label={title}>
        <Modal.Header>
          <Title order={2} size="h3">
            {title}
          </Title>
          <Modal.CloseButton aria-label="Close dialog" />
        </Modal.Header>
        <Modal.Body>{children}</Modal.Body>
      </Modal.Content>
    </Modal.Root>
  );
}
