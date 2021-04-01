import unittest
import os
import git
import id_pkg as intrusion_detect

class MyTestCase(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'bad_packets.txt')

    # Rather than get into ordering test cases work around the problem by making sure
    # the test log file gets generated whenever this class is created.

    # %ASA-3-324301: Radius Accounting Request has a bad header length hdr_len, packet length pkt_len
    # Sep 12 2014 06:50:53 HOST : %ASA-3-324301: Radius Accounting Request has a bad header length hdr_len, packet length pkt_len
    #   interface TestInterface
    info = {'Date': 'Sep 12 2014 06:50:53',
            'Host': 'HOST',
            'ID': '%ASA-3-324301',
            'Packet Length': 'Packet Length'}

    # Create a sample log file
    # https://docs.python.org/3/tutorial/inputoutput.html
    with open(syslog_file, 'w') as f:
        for header_length_d in range(1,100,1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add the source IP address message
            log_string = log_string + 'Radius Accounting Request has a bad header length '
            # Now add the header length
            log_string = log_string + str(header_length_d)
            # Terminate the message with the interface name
            log_string = log_string + ', packet length ' + info['Packet Length'] + '\n'
            f.write(log_string)

    def test_bad_packets_stub(self):
        self.assertEqual(True, True)

    def test_bad_packets_parse_log(self):
        # Create an IdParse object
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # Check to make sure the bad packet information got added to the dataframe
        # Get a subset of the whole dataframe
        # s=spoof df=dataframe
        sdf = id_syslog.df[id_syslog.df['ID'] == 324301]

        # Expecting 99 total records
        self.assertEqual(99, len(sdf))

        # Expecting 1 source address
        # self.assertTrue((sdf['Source'] == '10.1.1.1').all())

        # Expecting 99 unique destination addresses
        # self.assertEqual(100, sdf['Packets'].nunique())

    def test_has_bad_packets(self):
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # The test file generated has bad packets present
        # so expect this to return true
        self.assertTrue(id_syslog.has_bad_packets())

if __name__ == '__main__':
    unittest.main()
