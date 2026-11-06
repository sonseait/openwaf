// All panels stay mounted so RHF retains values and validates hidden fields.
// Reveal the containing tab before focusing an invalid control.
export function focusModalError(scope: string, fallback?: string) {
  requestAnimationFrame(() => {
    const container = document.querySelector(scope);
    const input =
      container?.querySelector<HTMLElement>('[aria-invalid="true"]') ??
      (fallback ? container?.querySelector<HTMLElement>(fallback) : null);
    const panel = input?.closest('[role="tabpanel"]');
    const tabId = panel?.getAttribute("aria-labelledby");
    if (tabId) {
      const tab = document.getElementById(tabId);
      tab?.click();
      tab?.scrollIntoView({ block: "nearest", inline: "nearest" });
    }
    let ancestor = input?.parentElement;
    while (ancestor) {
      if (ancestor instanceof HTMLDetailsElement) ancestor.open = true;
      ancestor = ancestor.parentElement;
    }
    requestAnimationFrame(() => {
      input?.focus();
      input?.scrollIntoView({ block: "nearest", inline: "nearest" });
    });
  });
}
