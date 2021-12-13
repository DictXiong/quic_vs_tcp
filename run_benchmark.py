#!/usr/bin/python
import argparse
import os
import os.path
import subprocess
import sys
import threading
import time
import collections

# Loopback interface mtu must be set to 1500
# sudo ifconfig lo mtu 1500
#
# IPv6 disabling on loopback:
# sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1

# global variables definition

# misc
tests = 5
devnull = open(os.devnull, 'wb')

# testfile stuff
testFile = "100M.html"
testFilePath = "/var/www/html/" + testFile
tmpFilePath = "./testfile"
testFileQuicEssentials = "\"HTTP/1.1 200 OK\nX-Original-Url: https://www.example.org/\n\n\""
testFileGenerationCommand = "dd if=/dev/urandom of=" + \
	tmpFilePath + " bs=2M count=16 > /dev/null 2>&1"
testFileQuicIntroCommand = "echo " + testFileQuicEssentials + " | sudo tee " + testFilePath + \
	" > /dev/null && cat " + tmpFilePath + \
	" | sudo tee --append " + testFilePath + " >/dev/null"

testFileSize = 33554491

# client commands
tcpHost = "12.12.12.101:50443"
quicHost = "12.12.12.101"
quicPort = "60443"
certHostName = "pc1.ibd.ink"
tcpClientCommand = "wget -O /dev/null https://{}/{} --no-check-certificate".format(tcpHost, testFile)
quicClientCommand = "/home2/root/src/src/out/Default/quic_client --host={} --disable-certificate-verification --port={} https://{}/{} > /dev/null".format(quicHost, quicPort, certHostName, testFile)
quicChromiumDownloadFilepath = "/dev/null"

# tcpdump commands
pcapTouch = "touch /tmp/test.pcap"
tcpdumpCapture = ["/usr/bin/sudo", "/usr/sbin/tcpdump",
				  "-i", "eth2", "-w", "/tmp/test.pcap"]
tcpdumpCaptureKill = "sudo kill "
tcpdumpAnalyze = "tcpdump -r /tmp/test.pcap -tttttnnqv > xxx 2>/dev/null"
#tcpdumpSpikeFile = "/tmp/tcpdump.tmp"
#tcpdumpSpikeAnalyze = "tcpdump -r /tmp/test.pcap -ttnnqv > " + \
#	tcpdumpSpikeFile + " 2>/dev/null"


def main():
	parser = argparse.ArgumentParser(
		description="Execute a test file transfer on lo, with either QUIC or TCP+TLSv1.2, producing a packet dump. Network conditions can be specified.")
	parser.add_argument("-p", "--protocol", nargs="+", choices=[
		"TCP", "QUIC"], help="Protocol used in the transfer.", required="true")
	parser.add_argument("-b", "--bandwidth", nargs="+", type=int,
						choices=range(1, 101), help="Bandwidth (in Mbps)", default="100")
	parser.add_argument("-t", "--tag", type=str, help="Output file tag", default="")
	parser.add_argument(
		"--verbose", help="Generate more messages in the output.", action="store_true")
	parser.add_argument(
		"--vverbose", help="Generate even more messages in the output.", action="store_true")
	# parse arguments and create a params object for all possible combinations
	args = parser.parse_args()

	class params:
		def __init__(self, protocol, bandwidth, tag):
			self.protocol = protocol
			self.bandwidth = bandwidth
			self.tag = tag

	paramsQueue = collections.deque()

	if not isinstance(args.protocol, collections.Iterable):
		args.protocol = [args.protocol]
	if not isinstance(args.bandwidth, collections.Iterable):
		args.bandwidth = [args.bandwidth]

	for protocol in args.protocol:
		for bandwidth in args.bandwidth:
			paramsQueue.append(params(protocol, bandwidth, args.tag))

	# function definitions

	# DX: although we dont need this here but it is important
	# create the test file
	# def generateTestFile():
	# 	if args.verbose or args.vverbose:
	# 		print ("Generating test file...")
	# 	retCode = os.system(testFileGenerationCommand)
	# 	retCode2 = os.system(testFileQuicIntroCommand)

	# 	if (retCode != 0) or (retCode2 != 0) or (not checkTestFile()):
	# 		print >>sys.stderr, "Test file generation error (" + str(
	# 			retCode) + ")."
	# 		exit()

	# 	#os.system("sudo cp -f " + testFilePath + " /var/www/html/");

	# 	if args.verbose or args.vverbose:
	# 		print( "Test file created.")
	# 	return

	# generate output filename
	def getOutputFilename(testIndex, params):
		ret = ""
		if len(str(params.tag)) != 0:
			ret += str(params.tag) + "_"
		ret += str(params.protocol).lower()
		ret += "_" + str(params.bandwidth)
		ret += "_" + str(testIndex + 1)
		return ret

	# start tcpdump capture
	def startCapture():
		global captureProcess
		os.system(pcapTouch)
		captureProcess = subprocess.Popen(
			tcpdumpCapture, stdout=devnull, stderr=devnull, shell=False)
		if args.vverbose:
			print ("Capture started (" + str(captureProcess.pid) + ")")
		return

	# stop tcpdump capture and run tcpdump analysis
	def stopCaptureAndAnalyze(testIndex, params):
		os.system(tcpdumpCaptureKill + str(captureProcess.pid))
		if args.vverbose:
			print( "Analyzing pcap file...")
		outputName = getOutputFilename(testIndex, params)
		os.system(tcpdumpAnalyze.replace("xxx", "./raw/"+ str(outputName)))
		return

	# create the test file if it does not already exist
	# DX: here our server and client are not co-located.

	# run the tests for all params files
	while paramsQueue:
		params = paramsQueue.pop()

		if args.verbose:
			print ("Running tests for: protocol=" + str(params.protocol) + ", bandwidth=" + str(params.bandwidth) + ".")

		# double the number of tests if a spike is present
		# DX: but here test is always == curTests
		curTests = tests
		for i in range(curTests):
			startCapture()
			if args.vverbose:
				print ("Starting test #" + str(i + 1) + "...")

			# run the transfer
			if params.protocol == "TCP":
				os.system(tcpClientCommand)
			else:
				if os.path.isfile(quicChromiumDownloadFilepath):
					os.remove(quicChromiumDownloadFilepath)
				os.system(quicClientCommand)
				# DX: ?
				# while (True):
				#     if (not os.path.isfile(quicChromiumDownloadFilepath)):
				#         time.sleep(0.1)
				#         continue
				#     print os.path.getsize(quicChromiumDownloadFilepath);
				#     os.remove(quicChromiumDownloadFilepath)
				#     break

			stopCaptureAndAnalyze(i, params)

			if args.verbose or args.vverbose:
				outputName = getOutputFilename(i, params)
				print ("Test #" + str(i + 1) + " finished, output in " + str(outputName))

main()
