"""
Copyright (c) 2026 Stefan Kumarasinghe

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import unittest

try:
    from ._env import ensure_test_env
except ImportError:
    from tests._env import ensure_test_env

ensure_test_env()

from routers.observability.alerts import router as alerts_router


class RulesRouterRegistrationTests(unittest.TestCase):
    def test_delete_rule_route_is_registered(self):
        has_delete_route = any(
            route.path == "/api/alertmanager/rules/{rule_id}" and "DELETE" in route.methods
            for route in alerts_router.routes
        )
        self.assertTrue(has_delete_route, "Expected DELETE /api/alertmanager/rules/{rule_id} route to be registered")


if __name__ == "__main__":
    unittest.main()
