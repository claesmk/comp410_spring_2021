import unittest
import git
import os
import id_pkg as intrusion_detect

class TestIcmpCommand(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'icmp_command.txt')

    def test_icmp_command_stub(self):
        self.assertEqual(True, True)

    info = {'Date': 'Oct 20 2020 06:20:53',
            'Host': 'HOST',
            'ID': '%ASA-3-313008',
            'Interface': 'TestInterface'}

    def test_icmp_command_create_sample_log(self):
        # %ASA-3-313008: Denied ICMPv6 type=number , code=code from IP_address on interface interface_name
        # Oct 20 2020 06:20:53 HOST : %ASA-3-313008: Denied ICMPv6 type=number , code=code from 10.1.1.1 on
        #   interface TestInterface
        info = {'Date': 'Oct 20 2020 06:20:53',
                'Host': 'HOST',
                'ID': '%ASA-3-313008',
                'Interface': 'TestInterface'}

        # Get the path to the data directory in the git repo

        # Create a sample log file
        # https://docs.python.org/3/tutorial/inputoutput.html
    with open(syslog_file, 'w') as f:
        for ip_address_d in range(1, 256, 1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add the source IP address message
            log_string = log_string + 'Denied ICMPv6 type=8, code=5 from 10.1.1.1'

            # Terminate the message with the interface name
            log_string = log_string + ' on interface ' + info['Interface'] + '\n'
            f.write(log_string)


    def test_icmp_command_parse_log(self):

        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # Check to make sure the icmp information got added to the dataframe
        # Get a subset of the whole dataframe
        # s=spoof df=dataframe
        sdf = id_syslog.df[id_syslog.df['ID'] == 313008]

        # Expecting 255 total records
        self.assertEqual(255, len(sdf))

        # Expecting 1 source address
        self.assertTrue((sdf['Source'] == '10.1.1.1').all())

        # Expecting 1 source address
        self.assertTrue((sdf['Interface'] == 'TestInterface').all())

    def test_has_icmp_command(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)
        # self.assertEqual(True, id_syslog.has_icmp())
        self.assertTrue(id_syslog.has_icmp())


if __name__ == '__main__':
    unittest.main()
