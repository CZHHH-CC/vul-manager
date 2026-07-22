import json
import unittest
from datetime import datetime
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.database import Base
from db.models import (
    Settings,
    UploadLog,
    Vulnerability,
    VulnAnalysis,
    VulnHistory,
    VulnRetest,
)
from services.excel_parser import process_excel_upload
from services.vul_service import export_vulns_for_report, get_vuln_list, get_vuln_list_metadata


class ExportAndReplaceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.db = sessionmaker(bind=self.engine)()

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_export_uses_latest_retest_time_result_and_components(self):
        vulnerability = Vulnerability(
            vit_number="VIT-EXPORT",
            severity="High",
            severity_level=2,
            state="Open",
        )
        self.db.add(vulnerability)
        self.db.flush()
        self.db.add(VulnAnalysis(
            vulnerability_id=vulnerability.id,
            detected_components=json.dumps([
                {"name": "Teams.exe", "version": "1.4.0", "path": "C:\\initial\\Teams.exe"}
            ]),
            ai_fix_plan=json.dumps({
                "plan_type": "upgrade",
                "summary": "Upgrade Microsoft Teams",
                "components": [],
            }),
        ))
        self.db.add_all([
            VulnRetest(
                vulnerability_id=vulnerability.id,
                event_key="old",
                retested_at=datetime(2026, 7, 1, 9, 0, 0),
                result="reopened",
                detected_components=json.dumps([
                    {"name": "Teams.exe", "version": "1.5.0", "path": "C:\\old\\Teams.exe"}
                ]),
            ),
            VulnRetest(
                vulnerability_id=vulnerability.id,
                event_key="latest",
                retested_at=datetime(2026, 7, 20, 10, 30, 45),
                result="still_detected",
                detected_components=json.dumps([
                    {"name": "Teams.exe", "version": "1.6.0", "path": "C:\\latest\\Teams.exe"}
                ]),
            ),
        ])
        self.db.commit()

        row = export_vulns_for_report(self.db)[0]

        self.assertEqual(row["处置类型"], "软件升级")
        self.assertIn("1.4.0", row["检测到的组件"])
        self.assertEqual(row["最新复测时间"], "2026-07-20 10:30:45")
        self.assertEqual(row["最新复测结果"], "still_detected")
        self.assertIn("C:\\latest\\Teams.exe", row["最新复测组件"])
        self.assertNotIn("C:\\old\\Teams.exe", row["最新复测组件"])

    def test_list_metadata_prefers_latest_retest_components(self):
        vulnerability = Vulnerability(vit_number="VIT-LIST")
        self.db.add(vulnerability)
        self.db.flush()
        self.db.add(VulnAnalysis(
            vulnerability_id=vulnerability.id,
            detected_components=json.dumps([
                {"name": "Initial", "version": "1.0", "path": "C:\\initial.exe"}
            ]),
        ))
        self.db.add(VulnRetest(
            vulnerability_id=vulnerability.id,
            event_key="latest-list",
            retested_at=datetime(2026, 7, 21, 7, 17, 33),
            result="reopened",
            detected_components=json.dumps([
                {"name": "FileZilla", "version": "3.62.2", "path": "HKEY_LOCAL_MACHINE\\DisplayVersion"}
            ]),
        ))
        self.db.commit()

        metadata = get_vuln_list_metadata(self.db, [vulnerability])[vulnerability.id]

        self.assertEqual(metadata["component_source"], "retest")
        self.assertEqual(metadata["components"][0]["name"], "FileZilla")
        self.assertEqual(metadata["latest_retest"].retested_at, datetime(2026, 7, 21, 7, 17, 33))
        self.assertIn("HKEY_LOCAL_MACHINE", metadata["component_tooltip"])

    def test_mismatched_retest_does_not_replace_initial_components_or_export(self):
        vulnerability = Vulnerability(
            vit_number="VIT-MISMATCH",
            cve_id="CVE-2025-39973",
        )
        self.db.add(vulnerability)
        self.db.flush()
        self.db.add(VulnAnalysis(
            vulnerability_id=vulnerability.id,
            detected_components=json.dumps([
                {"name": "linux-image", "version": "5.15.0", "path": "/boot/vmlinuz"}
            ]),
        ))
        self.db.add(VulnRetest(
            vulnerability_id=vulnerability.id,
            event_key="mismatched-cve",
            retested_at=datetime(2026, 7, 21, 7, 16, 15),
            result="reopened",
            detection_logic="Simplified Evaluation Logic (CVE-2021-1636)",
            detected_components=json.dumps([
                {"name": "sqlservr.exe", "version": "2019.150.2000.5", "path": "D:\\SQL\\sqlservr.exe"}
            ]),
        ))
        self.db.commit()

        metadata = get_vuln_list_metadata(self.db, [vulnerability])[vulnerability.id]
        exported = export_vulns_for_report(self.db)[0]

        self.assertEqual(metadata["component_source"], "initial")
        self.assertEqual(metadata["components"][0]["name"], "linux-image")
        self.assertEqual(exported["最新复测组件"], "")
        self.assertIn("CVE-2021-1636", exported["最新复测数据校验"])

    def test_component_fuzzy_search_matches_initial_and_retest_components(self):
        initial = Vulnerability(vit_number="VIT-INITIAL", severity_level=2)
        retested = Vulnerability(vit_number="VIT-RETEST", severity_level=2)
        self.db.add_all([initial, retested])
        self.db.flush()
        self.db.add(VulnAnalysis(
            vulnerability_id=initial.id,
            detected_components=json.dumps([
                {"name": "Apache Tomcat", "version": "9.0.73", "path": "/opt/tomcat"}
            ]),
        ))
        self.db.add(VulnRetest(
            vulnerability_id=retested.id,
            event_key="component-search",
            retested_at=datetime(2026, 7, 21),
            result="reopened",
            detected_components=json.dumps([
                {"name": "FileZilla", "version": "3.62.2", "path": "HKEY_LOCAL_MACHINE\\DisplayVersion"}
            ]),
        ))
        self.db.commit()

        by_name = get_vuln_list(self.db, component="filez")["items"]
        by_version = get_vuln_list(self.db, component="9.0.7")["items"]
        by_path = get_vuln_list(self.db, search="displayversion")["items"]

        self.assertEqual([v.vit_number for v in by_name], ["VIT-RETEST"])
        self.assertEqual([v.vit_number for v in by_version], ["VIT-INITIAL"])
        self.assertEqual([v.vit_number for v in by_path], ["VIT-RETEST"])

    def test_replace_deletes_only_vulnerabilities_and_related_records(self):
        old = Vulnerability(vit_number="VIT-OLD", severity="High", severity_level=2)
        self.db.add(old)
        self.db.flush()
        self.db.add_all([
            VulnAnalysis(vulnerability_id=old.id),
            VulnHistory(vulnerability_id=old.id, field_changed="state"),
            VulnRetest(
                vulnerability_id=old.id,
                event_key="old-retest",
                retested_at=datetime(2026, 7, 1),
                result="reopened",
            ),
            Settings(key="ai_provider", value="openai"),
            UploadLog(filename="old.xlsx", total_rows=1),
        ])
        self.db.commit()

        new_record = {
            "vit_number": "VIT-NEW",
            "cve_id": "CVE-2026-0001",
            "hostname": "host-new",
            "server_class": "Server",
            "severity": "High",
            "severity_level": 2,
            "state": "Open",
            "short_description": "new record",
            "assignment_group": "Security",
            "raw_description": "",
            "raw_recommendation": "",
            "work_notes": "",
        }
        with patch("services.excel_parser.parse_excel_to_records", return_value=[new_record]):
            result = process_excel_upload(
                self.db, "unused.xlsx", "new.xlsx", replace_existing=True
            )

        self.assertEqual(result["deleted"], 1)
        self.assertEqual(result["new"], 1)
        self.assertEqual(
            [v.vit_number for v in self.db.query(Vulnerability).all()], ["VIT-NEW"]
        )
        self.assertEqual(self.db.query(VulnRetest).count(), 0)
        self.assertEqual(self.db.query(VulnHistory).count(), 0)
        self.assertEqual(self.db.query(Settings).count(), 1)
        self.assertEqual(self.db.query(UploadLog).count(), 2)

    def test_empty_replacement_file_does_not_delete_existing_data(self):
        self.db.add(Vulnerability(vit_number="VIT-KEEP"))
        self.db.commit()

        with patch("services.excel_parser.parse_excel_to_records", return_value=[]):
            with self.assertRaisesRegex(ValueError, "未找到有效"):
                process_excel_upload(
                    self.db, "unused.xlsx", "empty.xlsx", replace_existing=True
                )

        self.assertEqual(self.db.query(Vulnerability).count(), 1)


if __name__ == "__main__":
    unittest.main()
