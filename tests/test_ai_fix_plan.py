import unittest

from services.ai_analyzer import _apply_fix_threshold, _reconcile_upgrade_components


class FixPlanGroundingTests(unittest.TestCase):
    def test_upgrade_plan_contains_every_grounded_path(self):
        plan = {
            "plan_type": "upgrade",
            "summary": "Upgrade Teams",
            "components": [{
                "name": "Microsoft Teams",
                "current_version": "1.4.0.7174",
                "path": "C:\\Users\\admin.acn\\Teams.exe",
                "affected": "受影响",
                "affected_reason": "old",
                "fixed_version": "old",
            }],
        }
        grounded = [
            {"name": "Microsoft Teams", "version": "1.4.0.7174", "path": "C:\\Users\\admin.acn\\Teams.exe"},
            {"name": "Microsoft Teams", "version": "1.4.0.7174", "path": "C:\\Users\\Administrator\\Teams.exe"},
            {"name": "Microsoft Teams", "version": "1.4.0.7174", "path": "C:\\Users\\APAC_TVM_WIN_SRV\\Teams.exe"},
        ]

        result = _reconcile_upgrade_components(plan, grounded)
        result = _apply_fix_threshold(result, "1.6.00.27573")

        self.assertEqual(len(result["components"]), 3)
        self.assertTrue(all(item["affected"] == "受影响" for item in result["components"]))
        self.assertTrue(all(item["fixed_version"] == "1.6.00.27573 或更高" for item in result["components"]))


if __name__ == "__main__":
    unittest.main()
