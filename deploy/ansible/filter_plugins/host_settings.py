"""Resolve host facts without network lookups or changing operator choices."""
import ipaddress

from ansible.errors import AnsibleFilterError


def host_settings(facts, capacities, profile="auto", ipv4="auto", ipv6="auto",
                  postgres="auto", database_url_file=""):
    """Select a fitting tier and primary global addresses, not private/NAT IPs.

    Capacities are generated from backend/runtime/vps_profiles.py. MemTotal can
    be slightly below the advertised size due to kernel/firmware reservations;
    the generated minimum permits at most 5% below nominal RAM, never swap.
    Empty IP overrides disable that address family. Explicit origins are checked
    by the existing literal/native validators, not treated as discovery hints.
    """
    try:
        cpus = int(facts["processor_vcpus"])
        memory = int(facts["memtotal_mb"])
    except (KeyError, TypeError, ValueError) as error:
        raise AnsibleFilterError("Cannot size OpenWAF: CPU/MemTotal host facts are unavailable") from error
    fitting = [tier["name"] for tier in capacities
               if cpus >= tier["cpus"] and memory >= tier["minimum_memory_mib"]]
    if not fitting:
        minimum = capacities[0]
        raise AnsibleFilterError(
            f"No supported OpenWAF profile fits {cpus} vCPUs / {memory} MiB RAM; "
            f"minimum is {minimum['cpus']} vCPUs and {minimum['minimum_memory_mib']} MiB usable RAM "
            f"(nominal {minimum['memory_mib'] // 1024} GiB); swap does not count")
    if profile != "auto" and profile not in fitting:
        raise AnsibleFilterError(
            f"OpenWAF profile {profile!r} is unknown or exceeds {cpus} vCPUs / {memory} MiB RAM; "
            f"fitting profiles: {', '.join(fitting)}")

    def origin(requested, family):
        if requested != "auto":
            return requested
        address = facts.get(f"default_ipv{family}", {}).get("address", "")
        try:
            parsed = ipaddress.ip_address(address)
            return str(parsed) if parsed.version == family and parsed.is_global else ""
        except ValueError:
            return ""

    resolved_ipv4, resolved_ipv6 = origin(ipv4, 4), origin(ipv6, 6)
    if not resolved_ipv4 and not resolved_ipv6:
        raise AnsibleFilterError(
            "No global origin IP detected on default interfaces. For NAT/multiple interfaces, "
            "set openwaf_origin_ipv4/openwaf_origin_ipv6 to the reachable public origin; "
            "SSH addresses and third-party IP services are not used")
    if postgres != "auto" and not isinstance(postgres, bool):
        raise AnsibleFilterError("openwaf_postgres_create must be auto or a boolean")
    return {"profile": fitting[-1] if profile == "auto" else profile,
            "ipv4": resolved_ipv4, "ipv6": resolved_ipv6,
            "postgres_create": not bool(database_url_file) if postgres == "auto" else postgres,
            "cpus": cpus, "memory_mib": memory}


class FilterModule:
    def filters(self):
        return {"openwaf_host_settings": host_settings}
