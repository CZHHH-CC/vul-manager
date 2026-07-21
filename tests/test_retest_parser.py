import unittest

from services.retest_parser import parse_retest_components, parse_work_notes


class RetestParserTests(unittest.TestCase):
    def test_parses_reopened_event_with_version_and_path(self):
        notes = """2026-07-21 07:10:04 - Integration ServiceNow (Work notes)
VIT automatically reviewed. Crowdstrike status: open (via entities_api).
Status changed from Resolved to Open. Reopened because Simplified Evaluation Logic (CVE-2023-5217):
▶ Check if the version of Teams.exe is less than 1.6.00.27573 Checks : (product_version less than 1.6.00.27573)
Found :
- product_version: 1.3.0.28779
- product_version: 1.2.0.34161
Evidence:
- filepath: C:\\Users\\one\\Teams.exe
- filepath: C:\\Users\\two\\Teams.exe
Vendor Advisory: https://example.com"""

        events = parse_work_notes(notes)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["result"], "reopened")
        self.assertEqual(events[0]["previous_state"], "Resolved")
        self.assertEqual(events[0]["new_state"], "Open")
        self.assertEqual(
            events[0]["detected_components"],
            [
                {"name": "Teams.exe", "version": "1.3.0.28779", "path": "C:\\Users\\one\\Teams.exe"},
                {"name": "Teams.exe", "version": "1.2.0.34161", "path": "C:\\Users\\two\\Teams.exe"},
            ],
        )

    def test_parses_concise_still_detected_result(self):
        text = "nodejs 18.19.1+dfsg-6ubuntu5 v18.19.1 at C:\\Program Files\\nodejs\\node.exe is still detected"

        self.assertEqual(
            parse_retest_components(text),
            [{
                "name": "nodejs 18.19.1+dfsg-6ubuntu5",
                "version": "18.19.1",
                "path": "C:\\Program Files\\nodejs\\node.exe",
            }],
        )

    def test_keeps_closed_retest_without_detection_path(self):
        notes = """2026-06-05 08:32:40 - Integration ServiceNow (Work notes)
VIT automatically closed. Crowdstrike status: closed (via entities_api).
Vulnerability was patched on: 2026-06-05T08:00:00Z"""

        events = parse_work_notes(notes)

        self.assertEqual(events[0]["result"], "closed")
        self.assertEqual(events[0]["detected_components"], [])

    def test_prefers_versioned_file_system_paths_over_duplicate_zip_evidence(self):
        text = """▶ Check if version of Tomcat is less than or equal to 9.0.97 Checks : match
Found :
- captured_content: [9.0.73], file_system_path: /opt/tomcat/lib/catalina.jar
Evidence:
- zipfile Path: /opt/tomcat/lib/catalina.jar (qualified_path: :META-INF/MANIFEST.MF)"""

        self.assertEqual(
            parse_retest_components(text),
            [{"name": "Tomcat", "version": "9.0.73", "path": "/opt/tomcat/lib/catalina.jar"}],
        )

    def test_parses_display_version_with_registry_detection_location(self):
        text = r"""Simplified Evaluation Logic (CVE-2023-48795):
▶ Check if filezilla is installed [inventory]
   Evidence found on host:
   - registry_item SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\filezilla Client\DisplayVersion = 3.62.2 (not evaluated)
▶ Check if the lower version of FileZilla is less than 3.66.4
Checks : (value less than 3.66.4)
Required: All comparisons must pass
Found :
  - DisplayVersion:: value: [3.62.2]
Evidence:
  - registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\filezilla Client\DisplayVersion"""

        self.assertEqual(
            parse_retest_components(text),
            [{
                "name": "FileZilla",
                "version": "3.62.2",
                "path": r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\filezilla Client\DisplayVersion",
            }],
        )

    def test_ignores_manual_work_notes(self):
        notes = "2026-07-20 14:26:31 - User Name (Work notes) Resolution reason: patched"
        self.assertEqual(parse_work_notes(notes), [])


if __name__ == "__main__":
    unittest.main()
