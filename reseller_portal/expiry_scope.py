def interface_groups(interface_ids, subscription_interfaces):
    parents = {int(i): int(i) for i in interface_ids}

    def root(i):
        parents.setdefault(i, i)
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    seen = {}
    for sid, iid in subscription_interfaces:
        iid = int(iid)
        first = seen.setdefault(sid, iid)
        parents[root(iid)] = root(first)
    groups = {}
    for iid in parents:
        groups.setdefault(root(iid), set()).add(iid)
    return sorted((tuple(sorted(group)) for group in groups.values()))


def scope_is_closed(interface_ids, subscription_interfaces):
    ids = set(interface_ids)
    subscription_interfaces = tuple(subscription_interfaces)
    touched = {sid for sid, iid in subscription_interfaces if iid in ids}
    return all(iid in ids for sid, iid in subscription_interfaces if sid in touched)
