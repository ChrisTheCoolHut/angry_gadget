#!/usr/bin/env python
import angr
from termcolor import colored
from tqdm import tqdm
import argparse

# angr please be quiet
import logging
log_things = ["angr", "pyvex", "claripy", "cle"]
for log in log_things:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

rebased_bin_sh = 0


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("binary")

    args = parser.parse_args()

    p = angr.Project(args.binary, auto_load_libs=False)

    print("Building CFG, this will take a moment")

    # Build CFG for xrefs
    cfg = p.analyses.CFG(data_references=True,
                         cross_references=True,
                         resolve_indirect_jumps=True,
                         normalize=True,
                         show_progressbar=True)

    # There is only 1 /bin/sh in libc
    binary_base = p.loader.main_object.image_base_delta
    bin_sh_loc = list(p.loader.main_object.memory.find(b"/bin/sh"))[0]

    # Rebase it since that find is relative
    global rebased_bin_sh
    rebased_bin_sh = binary_base + bin_sh_loc

    # Two way to find gadgets:
    # xrefs to /bin/sh and step forward to execve
    # xrefs to execve and step backwards to /bin/sh
    # ultimately we want execve("/bin/sh",NULL,NULL)
    bin_sh_xrefs = p.kb.xrefs.get_xrefs_by_dst(rebased_bin_sh)

    sym_execve = p.loader.main_object.get_symbol('execve')
    execve_xrefs = p.kb.xrefs.get_xrefs_by_dst(sym_execve.rebased_addr)

    # Hook with our execve checker
    p.hook_symbol("execve", check_execve)

    # Try up back_ins_count instructions
    # before the xref
    back_ins_count = 10

    gadgets = []
    gadget_addrs = []

    potential_xrefs = bin_sh_xrefs.union(execve_xrefs)

    print("Iterating over XREFs looking for gadget")

    # Progress bars
    pbar = tqdm(total=len(potential_xrefs), ascii=True)
    pbar_ins = tqdm(total=0, ascii=True)

    for xref in potential_xrefs:

        # Get block and node since the instruction_addrs
        # aren't the same in both.
        node = cfg.model.get_node(xref.block_addr)
        block = p.factory.block(xref.block_addr)

        # Build up to back_ins_count starting points
        # for analysis. We'll go from these addrs to
        # execve and see if we match the right constraints
        block_ins = list(block.instruction_addrs)

        # Remove values after the /bin/sh or execve call
        xref_index = block_ins.index(xref.ins_addr)
        node_ins = block_ins[:xref_index]

        # At least try up to back_ins_count instructions
        # before our given xref
        while (len(node_ins) < back_ins_count):
            predecessor_nodes = cfg.model.get_predecessors(node)

            if not predecessor_nodes:
                break

            for p_node in predecessor_nodes:
                p_node_ins = list(node.instruction_addrs)
                node_ins.extend(p_node_ins)

        pbar_ins.reset(total=len(node_ins))
        # run from start_addr to execve and check constraints
        for start_addr in node_ins:

            # Setup state
            state = p.factory.blank_state(addr=start_addr)
            state.globals["gadget_addr"] = start_addr

            # Setup simulation manager
            simgr = p.factory.simgr(state)

            # max 5 steps, could probably do fewer...
            pbar.set_description("Trying {}".format(hex(start_addr)))
            for _ in range(5):
                simgr.step()
                found = []
                for stash in simgr.stashes:
                    for path in simgr.stashes[stash]:

                        if "valid" in path.globals.keys():

                            found.append(path)
                            if path.globals[
                                    "valid"] and start_addr not in gadget_addrs:
                                gadget_addrs.append(start_addr)
                                gadgets.append((start_addr - binary_base,
                                                path.solver.constraints))

                for path in found:
                    simgr.stashes['found'].append(path)
            pbar_ins.update(1)
        pbar_ins.clear()
        
        pbar.update(1)
    pbar_ins.close()
    pbar.close()

    # Show fewest constraints at bottom
    gadgets.sort(key = lambda x: len(x[1]), reverse=True)

    pretty_print(gadgets)


def check_execve(state):
    # execve("/bin/sh",NULL,NULL)
    # or execve("/bin/sh",ptr->NULL,NULL)
    rsi_val = state.memory.load(state.regs.rsi)
    constraints = [
        state.regs.rdi == rebased_bin_sh, rsi_val == 0, state.regs.rdx == 0
    ]

    state.globals["valid"] = state.solver.satisfiable(constraints)


def pretty_print(gadgets):
    for addr, constraints in gadgets:
        print("{} :".format(
            colored("libc_base + " + str(hex(addr)), 'cyan', attrs=['bold'])))
        for constraint in constraints:
            print("\t{}".format(colored(constraint, 'red', attrs=['bold'])))


if __name__ == "__main__":
    main()
