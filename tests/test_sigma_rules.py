import yaml
import unittest
import subprocess
import os

class TestSigmaRules(unittest.TestCase):
    
    def setUp(self):
        """Load all Sigma rule files"""
        self.rules_dir = 'rules'
        self.rule_files = []
        for root, dirs, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yml'):
                    self.rule_files.append(os.path.join(root, file))
    
    def test_rule_syntax_valid(self):
        """Test that all rules are valid YAML"""
        for rule_file in self.rule_files:
            with self.subTest(rule=rule_file):
                with open(rule_file, 'r') as f:
                    try:
                        yaml.safe_load(f)
                    except yaml.YAMLError as e:
                        self.fail(f"Invalid YAML in {rule_file}: {e}")
    
    def test_rule_required_fields(self):
        """Test that all rules have required fields"""
        required_fields = ['title', 'id', 'logsource', 'detection', 'level']
        for rule_file in self.rule_files:
            with self.subTest(rule=rule_file):
                with open(rule_file, 'r') as f:
                    rule = yaml.safe_load(f)
                    for field in required_fields:
                        self.assertIn(field, rule, f"Missing {field} in {rule_file}")
    
    def test_rule_unique_ids(self):
        """Test that all rules have unique IDs"""
        ids = []
        for rule_file in self.rule_files:
            with open(rule_file, 'r') as f:
                rule = yaml.safe_load(f)
                rule_id = rule.get('id')
                self.assertNotIn(rule_id, ids, f"Duplicate ID {rule_id} in {rule_file}")
                ids.append(rule_id)
    
    def test_mitre_mapping(self):
        """Test that rules have MITRE ATT&CK mappings"""
        for rule_file in self.rule_files:
            with self.subTest(rule=rule_file):
                with open(rule_file, 'r') as f:
                    rule = yaml.safe_load(f)
                    self.assertIn('mitre', rule, f"Missing MITRE mapping in {rule_file}")
    
    def test_rule_sigma_conversion(self):
        """Test that rules can be converted to other formats"""
        for rule_file in self.rule_files:
            with self.subTest(rule=rule_file):
                try:
                    result = subprocess.run(
                        ['sigma', 'convert', '-t', 'splunk', rule_file],
                        capture_output=True,
                        timeout=5
                    )
                    self.assertEqual(result.returncode, 0, f"Failed to convert {rule_file}")
                except Exception as e:
                    self.fail(f"Conversion test failed for {rule_file}: {e}")

if __name__ == '__main__':
    unittest.main()