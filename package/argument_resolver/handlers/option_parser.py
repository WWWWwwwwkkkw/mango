"""Account for the command-line parser's externally visible index update."""

from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation

from argument_resolver.handlers.base import HandlerBase


def _calls_import(obj, function):
    binding = obj.imports.get(function.name)
    if binding is None or binding.resolvedby is None:
        return False
    target = binding.resolvedby.rebased_addr
    if function.addr == target or getattr(obj, "plt", {}).get(function.name) == function.addr:
        return True
    # Some loaders resolve the relocation but omit its trampoline from plt.
    # Require a single-block forwarding edge to the exact imported symbol.
    edges = function.transition_graph.edges(data=True)
    return len(edges) == 1 and any(
        src.addr == function.addr and dst.addr == target and data.get("type") == "transition"
        for src, dst, data in edges
    )


class OptionParserEffects(HandlerBase):
    def handle_function(self, state, data):
        obj = self._project.loader.main_object
        function = data.function
        if function is None and data.function_codeloc.block_addr is not None:
            function = self._project.kb.functions.get(data.function_codeloc.block_addr)
        if (function is not None and function.name in ("getopt", "getopt_long", "getopt_long_only")
                and _calls_import(obj, function)):
            symbol = obj.get_symbol("optind")
            if symbol is not None and symbol.is_import:
                symbol = symbol.resolvedby
            if symbol is not None and symbol.is_export and symbol.size > 0:
                slot = MemoryLocation(symbol.rebased_addr, symbol.size, endness=state.arch.memory_endness)
                # Option consumption depends on runtime argv and prior parser
                # state. Record a call-site definition without assuming a step.
                sources = {slot}
                for group in data.args_atoms or ():
                    sources.update(group)
                data.depends(slot, *sources, value=state.top(slot.size * state.arch.byte_width),
                             apply_at_callsite=True)
        return super().handle_function(state, data)
