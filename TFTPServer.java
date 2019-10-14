/*
 * TFTPServer.java
 * The TFTP server is based on the RFC1350 protocol
 * and is able to handle read and write requests in "octet" mode.
 * The server operates in some predefined directory/directories 
 * from where it is able to read from and/or write to files. 
 * Files outside the predefined directory/directories and their
 * sub-folders are considered forbidden to clients. Files within the
 * server's directory/directories of operation ending with the character
 * '~' are also considered forbidden. 
 * 
 * Most errors, both internal and according to the TFTP standard, are
 * tried to be handled in as reasonable ways as possible.
 * 
 * Author: Robin Wassbjer
 * Last edited: 2015-03-07 (YYYY-MM-DD)
 */

package Assignment3;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;

public class TFTPServer {
	public static final int TFTPPORT = 69;
	public static final int BUFSIZE = 516;

	/* Directories for Windows */
	public static final String READDIR = "C:\\Users\\read\\";
	public static final String WRITEDIR = "C:\\Users\\write\\";

	/* Directories for Ubuntu */
	// public static final String READDIR = "/home/username/read/";
	// public static final String WRITEDIR = "/home/username/write/";

	/* Operation codes */
	public static final int OP_RRQ = 1;
	public static final int OP_WRQ = 2;
	public static final int OP_DAT = 3;
	public static final int OP_ACK = 4;
	public static final int OP_ERR = 5;

	/* Error codes */
	public static final int UNDEFINED_ERR = 0;
	public static final int FNF_ERR = 1;
	public static final int ACCVIO_ERR = 2;
	public static final int DISKALLO_ERR = 3;
	public static final int ILLTFTP_ERR = 4;
	public static final int UNKNTID_ERR = 5;
	public static final int FILEEXISTS_ERR = 6;
	public static final int NOSUCHUSER_ERR = 7; // Never used - "Mail" mode not implemented

	public static void main(String[] args) {

		try {
			TFTPServer server = new TFTPServer();
			server.start();
		} catch (SocketException e) {
			System.err.println("Socket on port " + TFTPPORT + " could not be created.");
		}
	}

	private void start() throws SocketException {
		byte[] buf = new byte[BUFSIZE];

		System.out.println("------------------------------");
		System.out.println("      Running TFTPServer      ");
		System.out.println("------------------------------\n");

		/* Create socket */
		DatagramSocket socket = new DatagramSocket(null);

		/* Create local bind point */
		SocketAddress localBindPoint = new InetSocketAddress(TFTPPORT);
		socket.bind(localBindPoint);

		System.out.println("Listening at port " + TFTPPORT + " for new requests.");

		/* Loop to handle various requests */
		while (true) {
			InetSocketAddress clientAddress;

			clientAddress = receiveFrom(socket, buf);
			if (clientAddress == null) /* If clientAddress is null, an error occurred in receiveFrom() */
				continue;

			String[] parsedRQ = ParseRQ(buf); // Parse request - [Operation, File, Mode]

			new Thread() {
				public void run() {

					/* Create handler socket on a free port */
					/*
					 * TFTP uses connectionless UDP, so the socket is not "connected" to some
					 * specific client.
					 */
					try (DatagramSocket sendSocket = new DatagramSocket(0);) {

						final int opType = Integer.parseInt(parsedRQ[0]); // Get operation
						String requestedFile = parsedRQ[1]; // Get file name
						String mode = parsedRQ[2]; // Get mode

						System.out.println(((opType == OP_RRQ) ? "Read" : "Write") + " request for \"" + requestedFile + "\" in \""
								+ mode + "\" mode from " + clientAddress.getAddress().getHostAddress() + " on port "
								+ clientAddress.getPort() + ".");

						/* Read request */
						if (opType == OP_RRQ) {
							requestedFile = READDIR + requestedFile;
							HandleRQ(sendSocket, clientAddress, OP_RRQ, requestedFile, mode);
						}
						/* Write request */
						else {
							requestedFile = WRITEDIR + requestedFile;
							HandleRQ(sendSocket, clientAddress, OP_WRQ, requestedFile, mode);
						}

					} catch (SocketException e) {
						System.err.println("Could not create handler socket. Terminating session.");
					} catch (NumberFormatException e) {
						System.out
								.println("Invalid operation type requested by client " + clientAddress.getAddress().getHostAddress()
										+ " on port " + clientAddress.getPort() + ". Terminating session.");
					}
				}
			}.start();
		}
	}

	/**
	 * Tries to receive a packet from datagram socket <code>socket</code>, store its
	 * data in buffer <code>buf</code> and return the packet's source address.
	 * 
	 * @param socket - The socket to listen on.
	 * @param buf    - The buffer to store the packet's data.
	 * @return The packet's source address if receipt was successful, otherwise
	 *         <code>null</code>.
	 */
	private InetSocketAddress receiveFrom(DatagramSocket socket, byte[] buf) {
		DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
		try {
			socket.receive(receivePacket);
		} catch (Exception e) {
			System.err.println("Error receiving packet.");
			return null;
		}
		return new InetSocketAddress(receivePacket.getAddress(), receivePacket.getPort());
	}

	/**
	 * Parses the information in a standard TFTP request.
	 * 
	 * @param buf - The buffer containing the request.
	 * @return A <code>String</code> array containing the parsed request as
	 *         follows:</br>
	 *         [Opcode | Filename | Mode]
	 */
	private String[] ParseRQ(byte[] buf) {

		/*
		 * 2 bytes string 1 byte string 1 byte
		 * ------------------------------------------------ | Opcode | Filename | 0 |
		 * Mode | 0 | ------------------------------------------------ Standard TFTP
		 * request
		 */

		ByteBuffer wrap = ByteBuffer.wrap(buf);
		short opcode = wrap.getShort(); // Get opcode.
		String requestedFile = "";
		String mode = "";
		int index = 0;

		/* Get filename and mode */
		for (int i = 2; i <= buf.length - 1; i++) {
			/* Get mode */
			if (buf[i] == 0 && requestedFile.length() != 0) {
				mode = new String(buf, index, i - index);
				break;
			}
			/* Get fileName */
			if (buf[i] == 0 && requestedFile.length() == 0) {
				requestedFile = new String(buf, 2, i - 2);
				index = i + 1; // Skip zero-byte after filename
			}
		}
		String[] parsedRQ = { Short.toString(opcode), requestedFile, mode };
		return parsedRQ;
	}

	/**
	 * Handles a TFTP request by sending/receiving DATA-, ACK-, and ERROR-packets to
	 * an assigned, specific client according to the RFC1350 protocol.</br>
	 * <b>Note:</b> Currently, only requests in "octet" mode can be handled.
	 * 
	 * @param sendSocket - The socket to send from/listen on.
	 * @param clientAddr - The client address of whom the handler should be assigned
	 *                   to serve.
	 * @param opReq      - The operation to handle (READ/WRITE).
	 * @param filePath   - The path of the file to be read/written to.
	 * @param mode       - The mode in which the request should be handled.
	 */
	private void HandleRQ(DatagramSocket sendSocket, InetSocketAddress clientAddr, int opReq, String filePath,
			String mode) {
		/* Only "octet" mode is handled */
		if (!mode.toUpperCase().equals("OCTET")) {
			sendError(ILLTFTP_ERR, "TFTP operation \"" + mode + "\" not supported.", sendSocket, clientAddr);
			System.out.println("Client " + clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort()
					+ " requested an unsupported operation mode (\"" + mode + "\").");
			return;
		}

		File file = new File(filePath);

		/* Handle a write request */
		if (opReq == OP_WRQ) {
			handleWriteRQ(file, sendSocket, clientAddr);
		}

		/* Handle a read request */
		else if (opReq == OP_RRQ) {
			handleReadRQ(file, sendSocket, clientAddr);
		}

	}

	/**
	 * Handles a TFTP Write request in "octet" mode according to the RFC1350
	 * protocol.
	 * 
	 * @param reqFile    - The file to be created and filled with data.
	 * @param sendSocket - The socket to send from/listen on.
	 * @param clientAddr - The client address of whom the handler should be assigned
	 *                   to serve.
	 */
	private void handleWriteRQ(File reqFile, DatagramSocket sendSocket, InetSocketAddress clientAddr) {

		/* Access to file denied */
		if (!fileAccess(reqFile, new File(WRITEDIR))) {
			sendError(ACCVIO_ERR, "Creation access denied.", sendSocket, clientAddr);
			System.out.println("Client " + clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort()
					+ "'s request was denied due to access violation.");
			return;
		}

		/* File exists */
		if (reqFile.exists()) {
			sendError(FILEEXISTS_ERR, "File already exists.", sendSocket, clientAddr);
			System.out.println("File \"" + reqFile.getName() + "\" in write request from client "
					+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + " already exists.");
			return;
		}

		/* Various handler data */
		final int TIMEOUTTIME = 2000;
		final int MAXRETRANSMITS = 5;

		byte[] buf = new byte[BUFSIZE];
		DatagramPacket packet = new DatagramPacket(buf, buf.length, clientAddr);
		InetSocketAddress sender;
		ByteBuffer wrap = ByteBuffer.wrap(buf);

		short block = 0;
		short expectedBlock = 1;
		short opcode = 0;
		boolean badOP = false; // Checks if whatever is received is something expected.
		int retransmits = 0;

		sendAck(block, sendSocket, clientAddr); // Send write request ACK.

		try (FileOutputStream fOut = new FileOutputStream(reqFile)) {

			System.out.println("Receiving file \"" + reqFile.getName() + "\" from client "
					+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");

			while (packet.getLength() == BUFSIZE || badOP) {

				sendSocket.setSoTimeout(TIMEOUTTIME);
				try {
					sendSocket.receive(packet);
					sender = new InetSocketAddress(packet.getAddress(), packet.getPort());

					/* Received packet from non-expected client */
					if (!clientAddr.equals(sender)) {
						// Send error to sender.
						sendError(UNKNTID_ERR, "Unknown transfer ID.", sendSocket, sender);
						System.out.println("Sent TID error to client " + sender.getAddress().getHostAddress() + " on port "
								+ sender.getPort() + ".");
						continue; // Don't terminate session.
					}

					opcode = wrap.getShort(0); // Get opcode
					block = wrap.getShort(2); // Get block number.

					/* Received packet was of type DATA and contained expected block number */
					if (opcode == OP_DAT && block == expectedBlock) {

						/* Try to create file only when first data packet has arrived. */
						if (block == 1) {
							try {
								reqFile.createNewFile();
							} catch (Exception e) {
								System.err.println("Could not create file " + reqFile + ".");
								sendError(UNDEFINED_ERR,
										"Internal server error. Could not create requested file" + reqFile.getName() + ".", sendSocket,
										clientAddr);
								System.out.println("A file creation error occured. Session with client "
										+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + " terminated.");
								return;
							}
						}
						try {
							fOut.write(buf, 4, buf.length - 4); // Write received data to file.
						} catch (IOException e) {

							/*
							 * Due to no specific exception for "Disk full", this error may be sent for
							 * other reasons as well.
							 */
							sendError(DISKALLO_ERR, "Server disk full or allocation exceeded.", sendSocket, clientAddr);
							System.out.println("Server disk full or allocation exceeded. Session with client "
									+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + " terminated.");
							try {
								fOut.close();
								reqFile.delete(); // Delete file. No point in keeping an incomplete file?
								System.out.println(reqFile.getName() + " deleted!");
							} catch (Exception e2) {
								System.out.println("File " + reqFile.getName() + " could not be deleted.");
							}
							return;
						}

						expectedBlock++; // Start expecting the next block number.
						retransmits = 0; // Reset number of retransmits.
						badOP = false;
					}

					/* Received packet was an error packet */
					else if (opcode == OP_ERR) {
						System.out.println("Client error occured. Terminating session with client "
								+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");
						try {
							fOut.close();
							reqFile.delete(); // Delete file. No point in keeping an incomplete file?
							System.out.println(reqFile.getName() + " deleted!");
						} catch (Exception e) {
							System.out.println("File " + reqFile.getName() + " could not be deleted.");
						}
						return;
					}

					/* Received packet was something else. */
					else
						badOP = true;
				}

				catch (SocketTimeoutException e) {
					/* Only retransmit a few times, then terminate. */
					if (retransmits >= MAXRETRANSMITS) {
						System.out.println("Response timeout. Terminating session with client "
								+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");

						try {
							fOut.close();
							reqFile.delete(); // Delete file. No point in keeping an incomplete file?
							System.out.println(reqFile.getName() + " deleted!");
						}

						catch (Exception e2) {
							System.out.println("File " + reqFile.getName() + " could not be deleted.");
						}
						return;
					}

					retransmits++;
				}
				sendAck(block, sendSocket, clientAddr);
			}

			System.out.println("Request from " + clientAddr.getAddress().getHostAddress() + " using port "
					+ clientAddr.getPort() + " finished!"); // Request finished!

		} catch (IOException e) {
			sendError(UNDEFINED_ERR, "Internal server error.", sendSocket, clientAddr);
			System.out.println("Writing to file " + reqFile.getName() + " failed. Terminating session " + "with client "
					+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");
		}

	}

	/**
	 * Handles a TFTP read request in "octet" mode according to the RFC1350
	 * protocol.
	 * 
	 * @param reqFile    - The file from which data should be read.
	 * @param sendSocket - The socket to send from/listen on.
	 * @param clientAddr - The client address of whom the handler should be assigned
	 *                   to serve.
	 */
	private void handleReadRQ(File reqFile, DatagramSocket sendSocket, InetSocketAddress clientAddr) {

		System.out.println("My port: " + sendSocket.getLocalPort());

		/* Access to file denied */
		if (!fileAccess(reqFile, new File(READDIR))) {
			sendError(ACCVIO_ERR, "Access to file denied.", sendSocket, clientAddr);
			System.out.println("Client " + clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort()
					+ "'s requeset was denied due to access violation.");
			return;
		}

		/* Various handler data */
		final int TIMEOUTTIME = 2000;
		final int MAXRETRANSMITS = 5;

		byte[] buf = new byte[BUFSIZE];
		DatagramPacket packet = new DatagramPacket(buf, buf.length, clientAddr);
		InetSocketAddress sender = null;
		ByteBuffer wrap = ByteBuffer.wrap(buf);

		char blockAck = 0;
		char expectedBlockAck = 1;
		short opcode = 0;
		boolean badOP = false;
		int retransmits = 0;
		int b = 0;

		try (FileInputStream fIn = new FileInputStream(reqFile)) {

			System.out.println("Sending file \"" + reqFile.getName() + "\" to client "
					+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");

			/* Loop until end of file */
			while (b > -1) {

				b = fIn.read(buf, 4, buf.length - 4); // Read from file.

				/* Create first four bytes in DATA packet */
				buf[0] = 0;
				buf[1] = 3;
				buf[2] = (byte) (expectedBlockAck >> 8); // Most significant byte of expectedBlockAck.
				buf[3] = (byte) expectedBlockAck; // Least significant byte of expectedBlockAck.

				if (b > -1)
					packet = new DatagramPacket(buf, b + 4, clientAddr);

				/*
				 * DATA packet without data. In case a file consists of an exact multiple of 512
				 * bytes.
				 */
				else
					packet = new DatagramPacket(buf, 4, clientAddr);

				sendSocket.send(packet);

				/* Loop until correct acknowledgement is received */
				do {

					sendSocket.setSoTimeout(TIMEOUTTIME);
					try {
						sendSocket.receive(packet);
						sender = new InetSocketAddress(packet.getAddress(), packet.getPort());
					} catch (SocketTimeoutException e) {
						/* Only retransmit a few times, then terminate. */
						if (retransmits >= MAXRETRANSMITS) {
							System.out.println("Response timeout. Terminating session with client "
									+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");
							return;
						}
						sendSocket.send(packet); // Re-send DATA-packet.
						retransmits++;
						continue;
					}

					/* Packet received from non-expected client */
					if (!sender.equals(clientAddr)) {
						sendError(UNKNTID_ERR, "Unknown transfer ID.", sendSocket, sender);
						System.out.println("Sent TID error to client " + sender.getAddress().getHostAddress() + " on port "
								+ sender.getPort() + ".");
						continue; // Don't terminate.
					}

					opcode = wrap.getShort(0);
					blockAck = wrap.getChar(2);

					retransmits = 0; // Received something from client, so reset retransmits.

					/* Error packet received */
					if (opcode == OP_ERR) {
						System.out.println("Client error occured. Terminating session with client "
								+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + ".");
						return;
					}

					/* Packet received was as expected */
					else if (opcode == OP_ACK && blockAck == expectedBlockAck)
						badOP = false;

					/* Some non-expected packet from expected client */
					else {
						badOP = true;
						sendSocket.send(packet); // Re-send packet.
					}
				} while (!clientAddr.equals(sender) || badOP);

				expectedBlockAck++;
			}

			System.out.println("Request from " + clientAddr.getAddress().getHostAddress() + " using port "
					+ clientAddr.getPort() + " finished!"); // Request finished!

		} catch (FileNotFoundException e) {
			sendError(FNF_ERR, "File not found.", sendSocket, clientAddr);
			System.out.println("File \"" + reqFile.getName() + "\" requested by client "
					+ clientAddr.getAddress().getHostAddress() + " on port " + clientAddr.getPort() + " could not be found.");
		} catch (Exception e) {
			sendError(UNDEFINED_ERR, "Internal server error.", sendSocket, clientAddr);
			System.out.println("Some error occured. Session with client " + clientAddr.getAddress().getHostAddress()
					+ " on port " + clientAddr.getPort() + " terminated.");
		}

	}

	/**
	 * Sends an acknowledgement for data block <code>block</code> to a client from
	 * socket <code>sendSocket</code>.
	 * 
	 * @param block      - The block number to be acknowledged.
	 * @param sendSocket - The socket from which the packet should be sent.
	 * @param clientAddr - The address to which the acknowledgement should be sent.
	 */
	private void sendAck(short block, DatagramSocket sendSocket, InetSocketAddress clientAddr) {

		/*
		 * 2 bytes 2 bytes ------------------ | Opcode | Block # | ------------------
		 * Standard TFTP acknowledgement
		 */

		byte lsByte = (byte) block; // Get least significant byte of block number.
		byte msByte = (byte) (block >> 8); // Get most significant byte of block number.

		/* Create the acknowledgement */
		byte[] ack = { 0, 4, msByte, lsByte };
		DatagramPacket ackPacket = new DatagramPacket(ack, ack.length, clientAddr);

		try {
			sendSocket.send(ackPacket);
		} catch (IOException e) {
			System.err.println("Acknowledgement to client " + clientAddr.getAddress().getHostAddress() + " on port "
					+ clientAddr.getPort() + " could not be sent.");
		}

	}

	/**
	 * Sends an error packet with error code <code>errorCode</code> and error
	 * message <code>errorMessage</code> to a client from socket
	 * <code>sendSocket</code>.
	 * 
	 * @param errorCode  - The error code of the packet.
	 * @param message    - The error message of the packet.
	 * @param sendSocket - The socket from which the packet should be sent.
	 * @param clientAddr - The address to which the error should be sent.
	 */
	private void sendError(int errorCode, String message, DatagramSocket sendSocket, InetSocketAddress clientAddr) {

		/*
		 * 2 bytes 2 bytes string 1 byte ------------------------------------- | Opcode
		 * | ErrorCode | ErrMsg | 0 | ------------------------------------- Standard
		 * TFTP error
		 */

		/* Create error packet */
		String error = (char) 0 + "" + (char) 5 + "" + (char) 0 + "" + (char) errorCode + "" + message + (char) 0;
		DatagramPacket errorPacket = new DatagramPacket(error.getBytes(), error.length(), clientAddr);

		try {
			sendSocket.send(errorPacket);
		} catch (Exception e) {
			System.err.println("Could not send error to client " + clientAddr.getAddress().getHostAddress() + " on port "
					+ clientAddr.getPort());
		}
	}

	/**
	 * Checks if access to a requested file should be allowed. Only files not ending
	 * with the character '~' that lies within a given root path <code>root</code>
	 * are considered accessible.
	 * 
	 * @param reqFile - The requested file/directory.
	 * @param root    - The file/directory in which the requested file/directory
	 *                should reside.
	 * @return - <code>True</code>, if the requested file is accessible,
	 *         <code>false</code> otherwise.
	 */
	private boolean fileAccess(File reqFile, File root) {
		try {
			String reqPath = reqFile.getCanonicalPath(); // Get canonical path of requested file/directory.
			String rootPath = root.getCanonicalPath(); // Get canonical path of root file/directory.
			if (reqPath.startsWith(rootPath) && !reqFile.getName().endsWith("~"))
				return true;
		} catch (Exception e) {
		}
		return false;
	}
}
