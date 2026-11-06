export function matchesLivePathPrefix(path: string, prefix: string): boolean {
  return !prefix || path.split("?", 1)[0].startsWith(prefix);
}
