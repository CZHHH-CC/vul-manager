import unittest

from services.detection_parser import merge_grounded_components, parse_detection_logic


class DetectionParserTests(unittest.TestCase):
    def test_pairs_concatenated_teams_versions_and_paths(self):
        text = (
            "▶Check if the version of Teams.exe is less than 1.6.00.27573"
            "Checks(product_version less than 1.6.00.27573)RequiredAll comparisons must pass"
            "Foundproduct_version: 1.4.0.4167"
            "product_version: 1.6.0.16472"
            "product_version: 1.4.0.29469"
            "Evidence"
            "filepath: C:\\Users\\APAC_TVM_WIN_SRV\\Teams.exe"
            "filepath: C:\\Users\\bruce.zhang\\Teams.exe"
            "filepath: C:\\Users\\FNOperator\\Teams.exe"
        )

        self.assertEqual(
            parse_detection_logic(text),
            [
                {
                    "name": "Teams.exe",
                    "version": "1.4.0.4167",
                    "path": "C:\\Users\\APAC_TVM_WIN_SRV\\Teams.exe",
                },
                {
                    "name": "Teams.exe",
                    "version": "1.6.0.16472",
                    "path": "C:\\Users\\bruce.zhang\\Teams.exe",
                },
                {
                    "name": "Teams.exe",
                    "version": "1.4.0.29469",
                    "path": "C:\\Users\\FNOperator\\Teams.exe",
                },
            ],
        )

    def test_merges_missing_scanner_paths_for_related_ai_component(self):
        ai = [{
            "name": "Microsoft Teams",
            "version": "1.4.0.7174",
            "path": "C:\\Users\\admin.acn\\Teams.exe",
        }]
        regex = [
            {"name": "Teams.exe", "version": "1.4.0.7174", "path": "C:\\Users\\admin.acn\\Teams.exe"},
            {"name": "Teams.exe", "version": "1.4.0.7174", "path": "C:\\Users\\Administrator\\Teams.exe"},
            {"name": "Teams.exe", "version": "1.4.0.7174", "path": "C:\\Users\\APAC_TVM_WIN_SRV\\Teams.exe"},
            {"name": "jammy", "version": "", "path": "/etc/lsb-release"},
        ]

        merged = merge_grounded_components(ai, regex)

        self.assertEqual(len(merged), 3)
        self.assertTrue(all(item["name"] == "Microsoft Teams" for item in merged))
        self.assertEqual(
            [item["path"] for item in merged],
            [
                "C:\\Users\\admin.acn\\Teams.exe",
                "C:\\Users\\Administrator\\Teams.exe",
                "C:\\Users\\APAC_TVM_WIN_SRV\\Teams.exe",
            ],
        )


if __name__ == "__main__":
    unittest.main()
