from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "github-awareness-history.py"
SPEC = importlib.util.spec_from_file_location("github_awareness_history", TOOL)
HISTORY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(HISTORY)


class GithubAwarenessHistoryTests(unittest.TestCase):
    def test_collects_all_issue_pr_comment_and_review_source_instances(self) -> None:
        def api(args: list[str]):
            if args == ["repos/acme/vault"]:
                return {"has_discussions": False}
            endpoint = args[-1]
            pages = {
                "repos/acme/vault/issues?state=all&per_page=100": [[
                    {"number": 1, "html_url": "https://github/acme/vault/issues/1"},
                    {"number": 2, "html_url": "https://github/acme/vault/pull/2", "pull_request": {}},
                ]],
                "repos/acme/vault/issues/1/comments?per_page=100": [[
                    {"id": 11, "html_url": "https://github/acme/vault/issues/1#comment-11"},
                ]],
                "repos/acme/vault/issues/2/comments?per_page=100": [[]],
                "repos/acme/vault/pulls/2/reviews?per_page=100": [[
                    {"id": 21, "html_url": "https://github/acme/vault/pull/2#review-21"},
                ]],
                "repos/acme/vault/pulls/2/comments?per_page=100": [[
                    {"id": 22, "html_url": "https://github/acme/vault/pull/2#comment-22"},
                ]],
            }
            return pages[endpoint]

        result = HISTORY.collect("acme/vault", "a" * 40, api=api)
        self.assertEqual(result["schema"], HISTORY.SCHEMA)
        self.assertEqual(result["coverage"]["issue"]["count"], 1)
        self.assertEqual(result["coverage"]["pull_request"]["count"], 1)
        self.assertEqual(result["coverage"]["discussion"]["count"], 1)
        self.assertEqual(result["coverage"]["review_comment"]["count"], 2)
        self.assertEqual(result["discussion_threads"]["status"], "not_applicable")
        self.assertEqual(len(result["sources"]), 5)
        self.assertTrue(all(row["pin_binding"] == "a" * 40 for row in result["sources"]))

    def test_malformed_paginated_response_fails_closed(self) -> None:
        def api(args: list[str]):
            if args == ["repos/acme/vault"]:
                return {"has_discussions": False}
            return {"not": "pages"}

        with self.assertRaisesRegex(HISTORY.HistoryError, "github_api_pages_malformed"):
            HISTORY.collect("acme/vault", "b" * 40, api=api)

    def test_discussions_are_paginated_when_repository_enables_them(self) -> None:
        calls: list[list[str]] = []

        def api(args: list[str]):
            calls.append(args)
            if args == ["repos/acme/vault"]:
                return {"has_discussions": True}
            if args[:2] == ["--paginate", "--slurp"]:
                return [[]]
            if args[0] == "graphql":
                query = next(value for value in args if value.startswith("query="))
                if "replies(first:100" in query:
                    cursor = next((value for value in args if value.startswith("cursor=")), "")
                    if cursor == "cursor=NEXT":
                        return {"data": {"node": {"replies": {
                            "nodes": [{"id": "DR_2", "url": "https://github/acme/vault/discussions/1#reply-2"}],
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                        }}}}
                    return {"data": {"node": {"replies": {
                        "nodes": [{"id": "DR_1", "url": "https://github/acme/vault/discussions/1#reply-1"}],
                        "pageInfo": {"hasNextPage": True, "endCursor": "NEXT"},
                    }}}}
                if "comments(first:100" in query:
                    return {"data": {"repository": {"discussion": {"comments": {
                        "nodes": [{"id": "DC_1", "url": "https://github/acme/vault/discussions/1#comment-1"}],
                        "pageInfo": {"hasNextPage": False, "endCursor": None},
                    }}}}}
                return {"data": {"repository": {"discussions": {
                    "nodes": [{"id": "D_1", "number": 1, "url": "https://github/acme/vault/discussions/1"}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }}}}
            raise AssertionError(args)

        result = HISTORY.collect("acme/vault", "c" * 40, api=api)
        self.assertEqual(result["coverage"]["discussion"]["count"], 4)
        self.assertIn("github:acme/vault:discussion:discussion-comment-DC_1", {row["source_id"] for row in result["sources"]})
        self.assertIn("github:acme/vault:discussion:discussion-reply-DR_2", {row["source_id"] for row in result["sources"]})
        self.assertEqual(result["sources"][0]["source_kind"], "discussion")
        self.assertTrue(any(call[0] == "graphql" for call in calls))


if __name__ == "__main__":
    unittest.main()
