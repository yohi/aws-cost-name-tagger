"""Seven EC2-family Kinds: one ``ec2.create_tags`` Name request per resource (Design 4.2)."""
from __future__ import annotations

from types import MappingProxyType

from name_tag_kind_adapters import (
    AdapterSpec, _Unknown, name_tag, one, resource_part, same)

_ID = lambda t: resource_part(t).split("/", 1)[1]  # noqa: E731


def _spec(kind, describe, id_kwarg, list_key, id_key, tags_key="Tags", owner_key=None):
    proof = owner_key is not None
    def reads(t):
        return (("ec2", describe, {id_kwarg: [_ID(t)]}),)

    def extract(t, responses):
        item = one(responses[0][list_key])
        same(item[id_key], _ID(t))
        if owner_key:
            same(item.get(owner_key), t.owner_account)  # accountless ARN: owner from OwnerId
        if tags_key not in item:
            raise _Unknown()
        return item[tags_key]

    def write(t, name):
        return {"Resources": [_ID(t)], "Tags": name_tag(name)}

    return AdapterSpec(kind, "ec2", "create_tags", reads, extract, write,
                       required_ops=(("ec2", describe),), needs_ownership_proof=proof)


def _instance_extract(t, responses):
    reservation = one(responses[0]["Reservations"])
    item = one(reservation["Instances"])
    same(item["InstanceId"], _ID(t))
    if "Tags" not in item:
        raise _Unknown()
    return item["Tags"]


_instance = _spec("instance", "describe_instances", "InstanceIds", "Reservations", "InstanceId")
_instance = AdapterSpec(_instance.kind, "ec2", "create_tags", _instance.reads,
                        _instance_extract, _instance.write_kwargs,
                        required_ops=_instance.required_ops)

EC2_SPECS = MappingProxyType({
    "instance": _instance,
    "volume": _spec("volume", "describe_volumes", "VolumeIds", "Volumes", "VolumeId"),
    "snapshot": _spec("snapshot", "describe_snapshots", "SnapshotIds", "Snapshots",
                      "SnapshotId", owner_key="OwnerId"),
    "eni": _spec("eni", "describe_network_interfaces", "NetworkInterfaceIds",
                 "NetworkInterfaces", "NetworkInterfaceId", tags_key="TagSet"),
    "eip": _spec("eip", "describe_addresses", "AllocationIds", "Addresses", "AllocationId"),
    "nat": _spec("nat", "describe_nat_gateways", "NatGatewayIds", "NatGateways", "NatGatewayId"),
    "endpoint": _spec("endpoint", "describe_vpc_endpoints", "VpcEndpointIds", "VpcEndpoints",
                      "VpcEndpointId"),
})
