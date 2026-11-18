from conftest import ids, run


def test_chat_residue_and_elisions(make_repo):
    root = make_repo({
        "a.js": """
            // Certainly! Here is the updated code with the changes:
            function f() {
              // ... rest of the code remains the same
            }
        """,
        "b.py": "def g():\n    # your code here\n    return 1\n",
    })
    found = ids(run(root))
    assert "SLOP001" in found and found.count("SLOP002") == 2


def test_hallucinated_python_and_js_dependencies(make_repo):
    root = make_repo({
        "requirements.txt": "requests==2.32.3\npyyaml>=6\n",
        "app.py": """
            import os
            import requests
            import yaml
            import helpers
            import totally_real_sdk
            try:
                import ujson
            except ImportError:
                ujson = None
        """,
        "helpers.py": "X = 1\n",
        "web/package.json": '{"dependencies": {"express": "^4"}}',
        "web/index.js": """
            const express = require("express");
            const fs = require("node:fs");
            const path = require("path");
            const local = require("./local");
            import magic from "@acme/magic-sdk";
        """,
    })
    hits = {f.message.split("`")[1] for f in run(root) if f.rule_id == "SLOP004"}
    assert hits == {"totally_real_sdk", "@acme/magic-sdk"}


def test_python_ast_rules(make_repo):
    root = make_repo({
        "m.py": """
            import json
            import sys


            def risky(items=[]):
                try:
                    return items[0]
                except:
                    pass


            def dead():
                return 1
                print("never")


            def todo_later():
                pass


            print(sys.argv)
        """,
    })
    found = ids(run(root))
    for rule in ("GAP002", "GAP003", "GAP011", "LOOSE004", "LOOSE006", "LOOSE007"):
        assert rule in found, rule


def test_abstract_methods_are_not_stubs(make_repo):
    root = make_repo({
        "base.py": """
            from abc import ABC, abstractmethod


            class Store(ABC):
                @abstractmethod
                def save(self, item):
                    raise NotImplementedError


                def hook(self):
                    pass
        """,
    })
    assert not {"LOOSE003", "LOOSE007"} & set(ids(run(root)))


def test_swallowed_errors_in_other_languages(make_repo):
    root = make_repo({
        "a.ts": "try { go(); } catch (e) {}\npromise.catch(() => {});\n",
        "b.java": "try {\n  run();\n} catch (Exception e) {\n  // ignore\n}\n",
        "c.go": "if err := f(); err != nil {\n}\n",
    })
    assert ids(run(root)).count("GAP001") == 4


def test_todo_severity_and_ticket_links(make_repo):
    root = make_repo({"a.py": "x = 1  # TODO: tidy\n# FIXME: broken on leap years\n# TODO(#123): tracked\n"})
    todos = {f.line: f.severity.value for f in run(root) if f.rule_id == "LOOSE001"}
    assert todos == {1: "low", 2: "medium", 3: "info"}


def test_commented_out_code_but_not_prose(make_repo):
    root = make_repo({
        "a.py": """
            # if the user is an admin we skip the quota check because
            # admins are billed separately from regular accounts
            x = 1
            # result = compute(x)
            # if result > 3:
            #     notify(result)
        """,
    })
    hits = [f.line for f in run(root) if f.rule_id == "LOOSE002"]
    assert hits == [4]


def test_duplicate_blocks_across_files(make_repo):
    block = "".join(f"    total_value_{i} = compute_something_long(argument_{i}, scale={i})\n" for i in range(8))
    root = make_repo({"a.py": f"def a():\n{block}", "b.py": f"def b():\n{block}"})
    dupes = [f for f in run(root) if f.rule_id == "SLOP005"]
    assert len(dupes) == 1 and dupes[0].path == "b.py"


def test_repo_level_gaps(make_repo):
    body = "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(60))
    root = make_repo({"src/lib.py": body})
    found = ids(run(root))
    assert "GAP004" in found and "GAP005" in found


def test_comment_markers_inside_strings_are_not_comments(make_repo):
    root = make_repo({
        "a.py": 'COLOR = "#fff"  # TODO: theme\nURL = "http://localhost:8000/#TODO"\n',
        "b.js": 'const u = "https://x.io//TODO"; // FIXME: retry\n',
    })
    todos = {(f.path, f.line) for f in run(root) if f.rule_id == "LOOSE001"}
    assert todos == {("a.py", 1), ("b.js", 1)}
