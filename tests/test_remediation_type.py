import json
import unittest

from services.vul_service import classify_remediation_type


class RemediationTypeTests(unittest.TestCase):
    def classify(self, plan):
        return classify_remediation_type(json.dumps(plan, ensure_ascii=False))

    def test_regular_component_upgrade_is_software_upgrade(self):
        self.assertEqual(
            self.classify({
                "plan_type": "upgrade",
                "summary": "将 Microsoft Teams 升级到安全版本",
                "components": [{"name": "Microsoft Teams", "fixed_version": "1.6.00.27573"}],
            }),
            "software_upgrade",
        )

    def test_windows_kb_upgrade_is_system_patch(self):
        self.assertEqual(
            self.classify({
                "plan_type": "upgrade",
                "summary": "通过 Windows Update 安装累计更新 KB5030219",
            }),
            "system_patch",
        )

    def test_linux_kernel_upgrade_is_system_patch(self):
        self.assertEqual(
            self.classify({
                "plan_type": "upgrade",
                "components": [{"name": "linux-image-5.15.0-91-generic"}],
            }),
            "system_patch",
        )

    def test_registry_runbook_is_configuration(self):
        self.assertEqual(
            self.classify({
                "plan_type": "runbook",
                "fix_steps": [{"action": "修改注册表并禁用易受攻击的协议"}],
            }),
            "configuration",
        )

    def test_generic_runbook_is_operational(self):
        self.assertEqual(
            self.classify({
                "plan_type": "runbook",
                "fix_steps": [{"action": "停止服务，替换文件并完成验证"}],
            }),
            "operational",
        )

    def test_missing_plan_is_pending(self):
        self.assertEqual(classify_remediation_type(None), "pending")


if __name__ == "__main__":
    unittest.main()
