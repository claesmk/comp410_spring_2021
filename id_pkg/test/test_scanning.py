import unittest
import git
import os


class TestScanning(unittest.TestCase):
    def test_scanning_stub(self):
        self.assertEqual(True, True)

    def test_scanning_create_sample_log(self):
        # %ASA-4-733101: Host 175.0.0.1 is attacking. Current burst rate is 200 per second, max configured rate is 0; Current average rate is 0 per second, max configured rate is 0; Cumulative total count is 2024
        line = {'Date': 'Mar 24 2021 21:02:33',
                'ID': '%ASA-4-733101',
                'Host': 'Host'}
        git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
        log_path = os.path.join(git_root, 'data')

        with open(os.path.join(log_path, 'scan_log.txt'), 'w') as f:
            for dest_ip in range(1, 255, 1):
                log_str = line['Date'] + ' ' + line['ID'] + ': ' + line['Host'] + ' '
                log_str = log_str + '192.168.3.' + str(dest_ip) +\
                          ' is attacking. Current burst rate is 200 per second, max configured rate is 0; Current average rate is 0 per second, max configured rate is 0; Cumulative total count is 2024\n'
                f.write(log_str)

    def test_has_scanning(self):
        pass


if __name__ == '__main__':
    unittest.main()
