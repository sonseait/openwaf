import type { QueryClient } from "@tanstack/react-query";
import type { Config } from "./types";

// Only configuration gets a short cache across navigation. Request bodies and
// other protected queries retain their existing zero-retention defaults.
export const configCacheOptions = { staleTime: 30_000, gcTime: 60_000 };

export function observeConfigVersion(client: QueryClient, version: number) {
  const state = client.getQueryState<Config>(["config"]);
  if (
    state?.data &&
    state.data.active_version !== version &&
    !state.isInvalidated
  )
    return client.invalidateQueries({ queryKey: ["config"] });
}
