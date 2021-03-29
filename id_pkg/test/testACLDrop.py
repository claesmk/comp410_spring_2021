import unittest
import os
import git
import id_pkg as intrusion_detect


class MyTestCase(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'ACLDrop.txt')

    # Rather than get into ordering test cases work around the problem by making sure
    # the test log file gets generated whenever this class is created.

    # %ASA-3-710003: {TCP|UDP} access denied by ACL from source_IP/source_port to interface_name:dest_IP/service
    # Sep 12 2014 06:50:53 HOST : %ASA-3-710003: {TCP|UDP} access denied by ACL from source_IP/source_port to interface_name:dest_IP/service
    info = {'Date': 'Sep 12 2014 06:50:53',
            'Host': 'HOST',
            'ID': '%ASA-3-710003',
            'Interface': 'TestInterface'}

    # Create a sample log file
    # https://docs.python.org/3/tutorial/inputoutput.html
    with open(syslog_file, 'w') as f:
        for ip_address_d in range(1,256,1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add the source IP address message
            log_string = log_string + 'UDP access denied by ACL from '
            # Now add the destination IP
            log_string = log_string + '10.1.1.1 port 80 '
            # Terminate the message with the interface name
            log_string = log_string + 'to interface_name:' + info['Interface'] + '\n'
            f.write(log_string)

    def test_ACLDrop_stub(self):
        self.assertEqual(True, True)

    def test_ACLDrop_parse_log(self):
        # Create an IdParse object
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # Check to make sure the ip spoofing information got added to the dataframe
        # Get a subset of the whole dataframe
        # s=spoof df=dataframe
        sdf = id_syslog.df[id_syslog.df['ID'] == 710003]

        # Expecting 255 total records
        self.assertEqual(255, len(sdf))

        # Expecting 1 source address
        self.assertTrue((sdf['Source'] == '10.1.1.1').all())

        # Expecting 255 unique destination addresses
        # self.assertEqual(255, sdf['Destination'].nunique())

    def test_has_ACLDrop(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # The test file generated has ip spoofing present
        # so expect this to return true
        self.assertTrue(id_syslog.has_ACLDrop())

if __name__ == '__main__':
    unittest.main()
