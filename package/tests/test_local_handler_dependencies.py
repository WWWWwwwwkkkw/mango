"""Dependency selection must retain order without repeated whitelist scans."""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

import networkx as nx
from angr.analyses.reaching_definitions.dep_graph import DepGraph
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Register
from angr.knowledge_plugins.key_definitions.definition import Definition

from argument_resolver.handlers.local_handler import LocalHandler
from argument_resolver.utils.stored_function import StoredFunction


def definition(index):
    return Definition(Register(index * 4, 4), CodeLocation(0x400000 + index * 4, 0))


def function(key, definitions=(), returns=()):
    # This method only reads cached identity, definition sets and function presence.
    func = StoredFunction.__new__(StoredFunction)
    func._hash = key
    func.definitions = set(definitions)
    func.return_definitions = set(returns)
    func._data = SimpleNamespace(
        function=SimpleNamespace(addr=key), function_codeloc=CodeLocation(key, 0)
    )
    return func


def select(trace, stored, targets, graph, parent=None, in_subject=True):
    handler = SimpleNamespace(current_parent=parent, call_trace=trace)
    return LocalHandler.get_dependent_definitions(
        handler, DepGraph(graph), stored, set(targets), in_subject
    )


class TestLocalHandlerDependencies(TestCase):
    def assert_identity_order(self, result, expected):
        self.assertEqual([id(func) for func in result], [id(func) for func in expected])

    def test_dependency_chain_avoids_cubic_equality_work(self):
        size = 100
        nodes = [definition(i) for i in range(size + 1)]
        stored = function(1000, [nodes[0]])
        chain = [function(1001 + i, [nodes[i + 1]], [nodes[i]]) for i in range(size)]
        comparisons = 0
        original_eq = StoredFunction.__eq__

        def counted_eq(left, right):
            nonlocal comparisons
            comparisons += 1
            return original_eq(left, right)

        with patch.object(StoredFunction, "__eq__", counted_eq):
            graph = nx.empty_graph(nodes, create_using=nx.DiGraph)
            result = select([stored] + chain, stored, [nodes[0]], graph)

        self.assert_identity_order(result, [stored] + chain)
        self.assertLess(comparisons, 4 * size * size,
                        f"Dependency selection performed {comparisons} equality checks")

    def test_preserves_trace_order_and_excludes_unrelated_functions(self):
        root, middle, target, unrelated = [definition(i) for i in range(4)]
        stored = function(1000, [target])
        second = function(1002, [middle])
        first = function(1001, [root])
        excluded = function(1003, [unrelated])
        graph = nx.DiGraph([(root, middle), (middle, target)])
        graph.add_node(unrelated)
        result = select([stored, second, excluded, first], stored, [target], graph)
        self.assert_identity_order(result, [stored, second, first])

    def test_parent_boundary_and_out_of_subject_targets(self):
        root = definition(0)
        earlier = function(1001, [root])
        parent = function(1002, [root])
        stored = function(1000)
        later = function(1003, [root])
        graph = nx.empty_graph([root], create_using=nx.DiGraph)
        result = select([earlier, parent, stored, later], stored, [root], graph,
                        parent=parent, in_subject=False)
        self.assert_identity_order(result, [stored, parent, later])

    def test_equal_distinct_object_is_skipped_like_existing_whitelist(self):
        root = definition(0)
        stored = function(1000, [root])
        equal_object = function(1000, [root])
        other = function(1001, [root])
        graph = nx.empty_graph([root], create_using=nx.DiGraph)
        result = select([equal_object, other], stored, [root], graph)
        self.assert_identity_order(result, [stored, other])

    def test_equal_objects_already_queued_are_both_preserved(self):
        root = definition(0)
        stored = function(1000, [root])
        first = function(1001, [root])
        second = function(1001, [root])
        graph = nx.empty_graph([root], create_using=nx.DiGraph)
        result = select([stored, first, second], stored, [root], graph)
        self.assert_identity_order(result, [stored, first, second])
