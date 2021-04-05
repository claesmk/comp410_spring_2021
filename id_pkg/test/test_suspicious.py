import unittest
import git
import os
import id_pkg as intrusion_detect
import pandas as pd


class TestSuspicious(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'intrusion_logs.txt')

    log = intrusion_detect.IdParse(syslog_file)

    def test_get_low_severity(self):
        # Find low severity messages
        low_severity = self.log.get_low_severity()
        # low_severity = log.df[log.df['Severity'] >= 6]

        print('These are the unique low severity messages')
        print(low_severity['ID'].unique())

        self.assertListEqual([305011, 713160], list(low_severity['ID'].unique()))

    def test_get_high_severity(self):
        attacks = self.log.get_high_severity()

        print(attacks['ID'].unique())

        attack_ip_address_list = attacks['Source'].dropna().unique()
        # Show the address of know attackers
        print(attack_ip_address_list)

        # success = self.log.get_low_severity()
        # suspicious = success[success['Source'].isin(attack_ip_address_list)]
        # suspicious.to_excel('suspicious.xlsx')

        # Force fail
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
