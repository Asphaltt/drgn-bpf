#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# Copyright Leon Hwang
# SPDX-License-Identifier: LGPL-2.1-or-later

import argparse

import drgn
from drgn import container_of
from drgn.helpers.common.type import enum_type_to_class
from drgn.helpers.linux import (
    bpf_map_for_each,
    bpf_prog_for_each,
    bpf_link_for_each,
    hlist_for_each_entry,
)

BpfMapType = enum_type_to_class(prog.type("enum bpf_map_type"), "BpfMapType")
BpfProgType = enum_type_to_class(prog.type("enum bpf_prog_type"), "BpfProgType")
BpfAttachType = enum_type_to_class(prog.type("enum bpf_attach_type"), "BpfAttachType")
BpfLinkType = enum_type_to_class(prog.type("enum bpf_link_type"), "BpfLinkType")


def is_version_ge_0_0_23():
    """Check if drgn version is 0.0.23 or greater."""
    version = drgn.internal.version.__version__.split("+")[0]
    version_nums = [int(x) for x in version.split(".")]
    major, minor, patch = version_nums
    return major > 0 or minor > 0 or patch >= 23


def __run_interactive(args):
    if not is_version_ge_0_0_23():
        print("Interactive mode requires drgn 0.0.23+")
        exit(1)

    from drgn.cli import run_interactive

    run_interactive(prog)


def get_btf_name(btf, btf_id):
    type_ = btf.types[btf_id]
    if type_.name_off < btf.hdr.str_len:
        return btf.strings[type_.name_off].address_of_().string_().decode()
    return ""


def get_prog_btf_name(bpf_prog):
    aux = bpf_prog.aux
    if aux.btf:
        # func_info[0] points to BPF program function itself.
        return get_btf_name(aux.btf, aux.func_info[0].type_id)
    return ""


def get_prog_name(bpf_prog):
    return get_prog_btf_name(bpf_prog) or bpf_prog.aux.name.string_().decode()


def attach_type_to_tramp(attach_type):
    # bpf_tramp_prog_type is available since linux kernel 5.5, this code should
    # be called only after checking for bpf_prog.aux.trampoline to be present
    # though so no error checking here.
    BpfProgTrampType = enum_type_to_class(
        prog.type("enum bpf_tramp_prog_type"), "BpfProgTrampType"
    )

    at = BpfAttachType(attach_type)

    if at == BpfAttachType.BPF_TRACE_FENTRY:
        return BpfProgTrampType.BPF_TRAMP_FENTRY

    if at == BpfAttachType.BPF_TRACE_FEXIT:
        return BpfProgTrampType.BPF_TRAMP_FEXIT

    return BpfProgTrampType.BPF_TRAMP_REPLACE


def get_linked_func(bpf_prog):
    kind = attach_type_to_tramp(bpf_prog.expected_attach_type)

    linked_prog = bpf_prog.aux.linked_prog
    linked_prog_id = linked_prog.aux.id.value_()
    linked_btf_id = bpf_prog.aux.attach_btf_id.value_()
    linked_name = (
        f"{get_prog_name(linked_prog)}->"
        f"{get_btf_name(linked_prog.aux.btf, linked_btf_id)}()"
    )

    return f"{linked_prog_id}->{linked_btf_id}: {kind.name} {linked_name}"


def get_tramp_progs(bpf_prog):
    try:
        tr = bpf_prog.aux.member_("trampoline")
    except LookupError:
        # Trampoline is available since Linux kernel commit
        # fec56f5890d9 ("bpf: Introduce BPF trampoline") (in v5.5).
        # Skip trampoline if current kernel doesn't support it.
        return

    if not tr:
        return

    if tr.extension_prog:
        yield tr.extension_prog
    else:
        for head in tr.progs_hlist:
            for tramp_aux in hlist_for_each_entry(
                "struct bpf_prog_aux", head, "tramp_hlist"
            ):
                yield tramp_aux.prog


def get_trampoline_flags(flags):
    tramp_flags = [
        "BPF_TRAMP_F_RESTORE_REGS",
        "BPF_TRAMP_F_CALL_ORIG",
        "BPF_TRAMP_F_SKIP_FRAME",
        "BPF_TRAMP_F_IP_ARG",
        "BPF_TRAMP_F_RET_FENTRY_RET",
        "BPF_TRAMP_F_ORIG_STACK",
        "BPF_TRAMP_F_SHARE_IPMODIFY",
        "BPF_TRAMP_F_TAIL_CALL_CTX",
    ]

    f = list()
    for i in range(0, len(tramp_flags)):
        if flags & (1 << i):
            f.append(tramp_flags[i])

    return "|".join(f)


def show_attach_func_name(bpf_prog, prefix):
    func_ = bpf_prog.aux.attach_func_name
    if func_:
        func_ = func_.string_().decode()
        print(f"\t{prefix}: {func_}")


def show_prog(bpf_prog, prefix):
    type_ = BpfProgType(bpf_prog.type).name
    name = get_prog_name(bpf_prog)
    ksym = bpf_prog.aux.ksym.name.string_().decode()
    ptr = bpf_prog.aux.ksym.start.value_()
    tail_call_reachable = bpf_prog.aux.tail_call_reachable.value_()

    ksym_desc = f" {ksym} {ptr:#x}" if ptr else ""
    tail_call_desc = " tail_call_reachable" if tail_call_reachable else ""
    print(f"\t{prefix:>3}: {type_:16} {name:16}{ksym_desc}{tail_call_desc}")

    if type_ == "BPF_PROG_TYPE_EXT":
        dst_prog = bpf_prog.aux.dst_prog
        if dst_prog:
            show_prog(dst_prog, "\ttarget prog")
        show_attach_func_name(bpf_prog, "\ttarget func")


def list_bpf_progs(args):
    for bpf_prog in bpf_prog_for_each(prog):
        id_ = bpf_prog.aux.id.value_()
        type_ = BpfProgType(bpf_prog.type).name
        name = get_prog_name(bpf_prog)
        ksym = bpf_prog.aux.ksym.name.string_().decode()
        ptr = bpf_prog.aux.ksym.start.value_()
        dst_prog = bpf_prog.aux.dst_prog
        dst_tramp = bpf_prog.aux.dst_trampoline
        tail_call_reachable = bpf_prog.aux.tail_call_reachable.value_()

        linked = ", ".join([get_linked_func(p) for p in get_tramp_progs(bpf_prog)])
        if linked:
            linked = f" linked:[{linked}]"

        ksym_desc = f" {ksym} {ptr:#x}" if ptr else ""
        tail_call_desc = " tail_call_reachable" if tail_call_reachable else ""
        print(f"{id_:>6}: {type_:32} {name:32}{ksym_desc}{linked}{tail_call_desc}")

        if dst_prog:
            show_prog(dst_prog, "target prog")
        if type_ == "BPF_PROG_TYPE_EXT":
            show_attach_func_name(bpf_prog, "target func")
        if dst_tramp:
            tramp_flags = dst_tramp.flags.value_()
            print(f"\ttarget trampoline: {get_trampoline_flags(tramp_flags)}")

        func_info_cnt = bpf_prog.aux.func_info_cnt
        if func_info_cnt > 1:
            for i in range(0, func_info_cnt):
                show_prog(bpf_prog.aux.func[i], i)


def show_prog_array_map(map_):
    array = container_of(map_, prog.type("struct bpf_array"), "map")
    for i in range(0, map_.max_entries):
        prog_ = array.ptrs[i]
        if prog_:
            bpf_prog = drgn.cast("struct bpf_prog *", prog_)
            show_prog(bpf_prog, f"progs[{i}]")


def get_owner_info(map_):
    try:
        type_ = BpfProgType(map_.owner.type).name
        jited = map_.owner.jited.value_()
        return f"{type_} jited:{jited}"
    except AttributeError:
        pass

    array = container_of(map_, prog.type("struct bpf_array"), "map")
    try:
        type_ = BpfProgType(array.aux.owner.type).name
        jited = array.aux.owner.jited.value_()
        return f"{type_} jited:{jited}"
    except AttributeError:
        pass

    return ""


def show_map_internals(map_):
    type_ = BpfMapType(map_.map_type).name

    if type_ == "BPF_MAP_TYPE_PROG_ARRAY":
        owner = get_owner_info(map_)
        if owner:
            print(f"\towner bpf prog: {owner}")
        show_prog_array_map(map_)


def list_bpf_maps(args):
    show_internals = args.D

    for map_ in bpf_map_for_each(prog):
        id_ = map_.id.value_()
        type_ = BpfMapType(map_.map_type).name
        name = map_.name.string_().decode()

        print(f"{id_:>6}: {type_:32} {name}")

        if show_internals:
            show_map_internals(map_)


def list_bpf_links(args):
    for link_ in bpf_link_for_each(prog):
        id_ = link_.id.value_()
        type_ = BpfLinkType(link_.type).name
        linked_prog = link_.prog

        print(f"{id_:>6}: {type_:32}")
        if linked_prog:
            show_prog(linked_prog, "linked prog")

        if type_ == "BPF_LINK_TYPE_TRACING":
            tracing_link = container_of(
                link_, prog.type("struct bpf_tracing_link"), "link"
            )
            tgt_prog = tracing_link.tgt_prog
            if tgt_prog:
                show_prog(tgt_prog, "target prog")
            show_attach_func_name(linked_prog, "target func")
            ext_prog = tracing_link.trampoline.extension_prog
            if ext_prog:
                show_prog(ext_prog, "extend prog")
            tramp_flags = tracing_link.trampoline.flags.value_()
            print(f"\ttrampoline flags: {get_trampoline_flags(tramp_flags)}")


def main():
    parser = argparse.ArgumentParser(
        description="drgn script to list BPF programs or maps or links and their properties unavailable via kernel API"
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")
    subparsers.required = True

    prog_parser = subparsers.add_parser("prog", aliases=["p"], help="list BPF programs")
    prog_parser.set_defaults(func=list_bpf_progs)

    map_parser = subparsers.add_parser("map", aliases=["m"], help="list BPF maps")
    map_parser.set_defaults(func=list_bpf_maps)
    map_parser.add_argument("-D", action="store_true", help="show map internal details")

    link_parser = subparsers.add_parser("link", aliases=["l"], help="list BPF links")
    link_parser.set_defaults(func=list_bpf_links)

    interact_parser = subparsers.add_parser(
        "interact", aliases=["i"], help="start interactive shell, requires 0.0.23+ drgn"
    )
    interact_parser.set_defaults(func=__run_interactive)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
