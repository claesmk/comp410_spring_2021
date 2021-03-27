import unittest
import git
import os
import id_pkg as intrusion_detect


class TestScanning(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'scan_log.txt')

    def test_scanning_stub(self):
        self.assertEqual(True, True)

    scan_msg = {'Date': 'Mar 24 2021 21:02:33',
                'Host': 'HOST',
                'ID': '%ASA-4-733101'}

    def test_scanning_create_sample_log(self):
        # %ASA-4-733101: Host 175.0.0.1 is attacking. Current burst rate is 200 per second, max configured rate is 0;
        # Current average rate is 0 per second, max configured rate is 0; Cumulative total count is 2024
        scan_msg = {'Date': 'Mar 24 2021 21:02:33',
                'Host': 'HOST',
                'ID': '%ASA-4-733101'}

    with open(syslog_file, 'w') as f:
        for scans in range(1, 255, 4):
            log_str = scan_msg['Date'] + ' ' + scan_msg['Host'] + ' : ' + scan_msg['ID'] + ': '
            log_str = log_str + '192.168.3.10 is attacking. Current burst rate is 200 per second, max configured rate is 0; ' \
                                'Current average rate is 0 per second, max configured rate is 0; Cumulative total count is 2024\n'
            f.write(log_str)

    def test_has_scanning(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # Check to make sure the ip spoofing information got added to the dataframe
        # Get a subset of the whole dataframe
        # s=spoof df=dataframe
        sdf = id_syslog.df[id_syslog.df['ID'] == 733101]

        # Expecting 1 source address
        self.assertTrue((sdf['Source'] == '192.168.3.10').all())

        self.assertTrue(id_syslog.has_scanning())


if __name__ == '__main__':
    unittest.main()
