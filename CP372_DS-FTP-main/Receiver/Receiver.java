import java.io.*;
import java.net.*;

/**
 * DS-FTP Receiver (Earth Station)
 * 
 * CP372 Assignment 2 - Deep Space File Transfer Protocol
 * 
 * Implements both Stop-and-Wait and Go-Back-N protocols with buffering
 * 
 * Command line:
 *   Receiver <sender_ip> <sender_ack_port> <rcv_data_port> <output_file> <RN>
 * 
 * Example:
 *   java Receiver localhost 9876 8888 received_file.txt 5
 */
public class Receiver {
    
    // Protocol constants
    private static final int MAX_PAYLOAD = 124;  // Maximum payload size per packet
    private static final int MAX_SEQ = 128;      // Maximum sequence number (modulo 128)
    private static final int INACTIVITY_TIMEOUT = 5000; // 5 seconds inactivity timeout
    private static final int SOCKET_TIMEOUT = 3000;     // 3 seconds socket timeout
    
    // Connection parameters
    private InetAddress senderIp;
    private int senderAckPort;
    private int rcvDataPort;
    private String outputFile;
    private int rn; // Reliability Number for ACK loss
    
    // Protocol state
    private DatagramSocket dataSocket;
    private DatagramSocket ackSocket;
    private int expectedSeq = 0;           // Next expected sequence number (0 = SOT, then 1+ for DATA)
    private int lastAckSent = -1;           // Last ACK sent (to avoid resending duplicates)
    private long lastAckTime = 0;           // When the last ACK was sent
    
    // GBN buffering
    private byte[][] packetBuffer;          // Buffer for out-of-order packets
    private boolean[] received;              // Track received packets
    private int windowSize = 20;              // Will be dynamically set based on sender's window
    private int highestReceived = -1;         // Highest sequence number received
    
    // File output
    private FileOutputStream fileOut;
    private int bytesWritten = 0;
    private int packetsWritten = 0;
    
    // ACK counting for ChaosEngine
    private int ackCount = 0;
    
    // Protocol detection
    private boolean isGBN = false;           // Will be detected from packet patterns
    private int lastSeq = -1;
    private int seqJumpCount = 0;
    
    // Duplicate packet detection
    private int lastProcessedSeq = -1;
    private long lastPacketTime = 0;
    
    public static void main(String[] args) {
        if (args.length != 5) {
            System.err.println("Usage: java Receiver <sender_ip> <sender_ack_port> " +
                              "<rcv_data_port> <output_file> <RN>");
            System.err.println("  RN = Reliability Number (0 = no drops, X = drop every Xth ACK)");
            System.exit(1);
        }
        
        Receiver receiver = new Receiver();
        receiver.parseArgs(args);
        
        try {
            receiver.run();
        } catch (Exception e) {
            System.err.println("Receiver error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private void parseArgs(String[] args) {
        try {
            senderIp = InetAddress.getByName(args[0]);
            senderAckPort = Integer.parseInt(args[1]);
            rcvDataPort = Integer.parseInt(args[2]);
            outputFile = args[3];
            rn = Integer.parseInt(args[4]);
            
            if (rn < 0) {
                throw new IllegalArgumentException("RN must be >= 0");
            }
        } catch (Exception e) {
            System.err.println("Invalid arguments: " + e.getMessage());
            System.exit(1);
        }
    }
    
    private void run() throws Exception {
        // Create sockets
        dataSocket = new DatagramSocket(rcvDataPort);
        ackSocket = new DatagramSocket(); // Ephemeral port for sending ACKs
        
        System.out.println("\n=== DS-FTP Receiver Starting ===");
        System.out.println("Listening on data port: " + rcvDataPort);
        System.out.println("Sending ACKs to: " + senderIp + ":" + senderAckPort);
        System.out.println("Output file: " + outputFile);
        System.out.println("Reliability Number (RN): " + rn + 
                          (rn > 0 ? " (every " + rn + "th ACK dropped)" : " (no ACK drops)"));
        System.out.println("Maximum payload per packet: " + MAX_PAYLOAD + " bytes");
        System.out.println("===============================\n");
        
        // Initialize buffer (size MAX_SEQ)
        packetBuffer = new byte[MAX_SEQ][];
        received = new boolean[MAX_SEQ];
        
        // Wait for handshake
        if (!waitForHandshake()) {
            System.err.println("Handshake failed - no connection established");
            return;
        }
        
        // Prepare output file
        fileOut = new FileOutputStream(outputFile);
        
        // Main receive loop
        boolean transferComplete = false;
        long lastActivity = System.currentTimeMillis();
        
        System.out.println("\n--- Waiting for data transfer ---");
        
        while (!transferComplete) {
            try {
                // Receive packet with timeout to detect end
                dataSocket.setSoTimeout(SOCKET_TIMEOUT);
                DatagramPacket recvPacket = new DatagramPacket(
                    new byte[DSPacket.MAX_PACKET_SIZE], DSPacket.MAX_PACKET_SIZE);
                dataSocket.receive(recvPacket);
                
                lastActivity = System.currentTimeMillis();
                DSPacket packet = new DSPacket(recvPacket.getData());
                
                // Validate payload size (using MAX_PAYLOAD constant)
                if (packet.getLength() > MAX_PAYLOAD) {
                    System.out.println("Warning: Packet " + packet.getSeqNum() + 
                                      " has payload size " + packet.getLength() + 
                                      " which exceeds maximum " + MAX_PAYLOAD);
                }
                
                // Process based on type
                switch (packet.getType()) {
                    case DSPacket.TYPE_DATA:
                        processDataPacket(packet);
                        break;
                    case DSPacket.TYPE_EOT:
                        transferComplete = processEotPacket(packet);
                        break;
                    default:
                        System.out.println("Unexpected packet type: " + packet.getType());
                }
                
            } catch (SocketTimeoutException e) {
                // Check if we've been inactive for too long after EOT expectation
                if (System.currentTimeMillis() - lastActivity > INACTIVITY_TIMEOUT) {
                    System.out.println("\nInactivity timeout (" + INACTIVITY_TIMEOUT + 
                                      "ms) - assuming transfer complete");
                    break;
                }
            } catch (Exception e) {
                System.err.println("Receive error: " + e.getMessage());
            }
        }
        
        // Cleanup
        fileOut.close();
        dataSocket.close();
        ackSocket.close();
        
        System.out.println("\n=== Transfer Summary ===");
        System.out.println("Total bytes written: " + bytesWritten);
        System.out.println("Total packets written: " + packetsWritten);
        System.out.println("Average payload size: " + 
                          (packetsWritten > 0 ? bytesWritten / packetsWritten : 0) + " bytes");
        System.out.println("ACKs sent (including drops): " + ackCount);
        System.out.println("Last ACK sent: " + lastAckSent);
        System.out.println("Receiver finished.");
    }
    
    private boolean waitForHandshake() throws Exception {
        System.out.println("[HANDSHAKE] Waiting for SOT packet...");
        
        while (true) {
            DatagramPacket recvPacket = new DatagramPacket(
                new byte[DSPacket.MAX_PACKET_SIZE], DSPacket.MAX_PACKET_SIZE);
            dataSocket.receive(recvPacket);
            
            DSPacket packet = new DSPacket(recvPacket.getData());
            
            if (packet.getType() == DSPacket.TYPE_SOT && packet.getSeqNum() == 0) {
                System.out.println("[HANDSHAKE] ✓ Received SOT (Seq 0)");
                
                // Send ACK for SOT
                sendAck(0);
                System.out.println("[HANDSHAKE] Sent ACK for SOT");
                
                // Set expected sequence for first DATA packet
                expectedSeq = 1;
                lastAckSent = 0;
                lastAckTime = System.currentTimeMillis();
                return true;
            } else {
                System.out.println("[HANDSHAKE] Ignoring unexpected packet (type=" + 
                                  packet.getType() + ", seq=" + packet.getSeqNum() + ")");
            }
        }
    }
    
    private void processDataPacket(DSPacket packet) throws Exception {
        int seqNum = packet.getSeqNum();
        byte[] payload = packet.getPayload();
        long currentTime = System.currentTimeMillis();
        
        // Detect duplicate packets (using lastProcessedSeq)
        if (seqNum == lastProcessedSeq && currentTime - lastPacketTime < 100) {
            System.out.println("[DATA] Possible duplicate packet Seq=" + seqNum + 
                              " (ignoring)");
            return;
        }
        
        // Validate payload size against MAX_PAYLOAD
        if (payload.length > MAX_PAYLOAD) {
            System.err.println("Error: Received packet " + seqNum + 
                             " has payload size " + payload.length + 
                             " which exceeds maximum " + MAX_PAYLOAD);
            return;
        }
        
        // Update last processed packet info
        lastProcessedSeq = seqNum;
        lastPacketTime = currentTime;
        
        // Detect protocol based on packet patterns
        detectProtocol(seqNum);
        
        System.out.println("[DATA] Received packet Seq=" + seqNum + 
                          " (len=" + payload.length + "/" + MAX_PAYLOAD + " bytes)");
        
        // Check if this is the expected in-order packet
        if (seqNum == expectedSeq) {
            // Deliver immediately
            deliverPacket(seqNum, payload);
            
            // Update expected sequence
            expectedSeq = (expectedSeq + 1) % MAX_SEQ;
            
            // Check buffer for next packets
            deliverFromBuffer();
            
            // Send cumulative ACK
            int ackSeq = (expectedSeq - 1 + MAX_SEQ) % MAX_SEQ;
            
            // Only send ACK if it's different from the last one or enough time has passed
            if (ackSeq != lastAckSent || currentTime - lastAckTime > 50) {
                sendAck(ackSeq);
                System.out.println("  → Delivered in-order, buffer checked, sent ACK " + ackSeq);
            } else {
                System.out.println("  → Delivered in-order, buffer checked, ACK " + ackSeq + 
                                  " already sent recently (skipping)");
            }
            
        } else if (isWithinWindow(seqNum)) {
            // Out-of-order but within window - buffer it
            if (!received[seqNum]) {
                System.out.println("  → Buffering out-of-order packet " + seqNum);
                packetBuffer[seqNum] = payload;
                received[seqNum] = true;
                
                if (seqNum > highestReceived) {
                    highestReceived = seqNum;
                }
            } else {
                System.out.println("  → Duplicate packet " + seqNum + " (already buffered)");
            }
            
            // Send ACK for last in-order packet
            int ackSeq = (expectedSeq - 1 + MAX_SEQ) % MAX_SEQ;
            
            // Only send ACK if it's different from the last one or enough time has passed
            if (ackSeq != lastAckSent || currentTime - lastAckTime > 50) {
                sendAck(ackSeq);
                System.out.println("  → Sent cumulative ACK " + ackSeq);
            } else {
                System.out.println("  → Cumulative ACK " + ackSeq + 
                                  " already sent recently (skipping)");
            }
            
        } else {
            // Outside window - discard and resend last ACK
            System.out.println("  → Packet " + seqNum + " outside window, discarding");
            int ackSeq = (expectedSeq - 1 + MAX_SEQ) % MAX_SEQ;
            
            // Always resend last ACK for out-of-window packets (as per protocol)
            if (lastAckSent != -1) {
                sendAck(lastAckSent);
                System.out.println("  → Resent last ACK " + lastAckSent);
            } else {
                sendAck(ackSeq);
                System.out.println("  → Sent cumulative ACK " + ackSeq);
            }
        }
    }
    
    private void deliverPacket(int seqNum, byte[] payload) throws IOException {
        fileOut.write(payload);
        bytesWritten += payload.length;
        packetsWritten++;
        
        // Clear from buffer if it was there
        if (received[seqNum]) {
            packetBuffer[seqNum] = null;
            received[seqNum] = false;
        }
        
        System.out.println("  ✓ Delivered packet " + seqNum + 
                          " (total: " + packetsWritten + " packets, " + 
                          bytesWritten + " bytes)");
    }
    
    private void deliverFromBuffer() throws IOException {
        while (received[expectedSeq]) {
            deliverPacket(expectedSeq, packetBuffer[expectedSeq]);
            expectedSeq = (expectedSeq + 1) % MAX_SEQ;
        }
    }
    
    private boolean processEotPacket(DSPacket packet) throws Exception {
        int seqNum = packet.getSeqNum();
        System.out.println("\n[TEARDOWN] Received EOT (Seq " + seqNum + ")");
        
        // Send ACK for EOT
        sendAck(seqNum);
        System.out.println("[TEARDOWN] Sent ACK for EOT");
        lastAckSent = seqNum;
        lastAckTime = System.currentTimeMillis();
        
        // Check if any packets still in buffer
        int bufferedCount = 0;
        for (int i = 0; i < MAX_SEQ; i++) {
            if (received[i]) bufferedCount++;
        }
        
        if (bufferedCount > 0) {
            System.out.println("[TEARDOWN] Warning: " + bufferedCount + 
                              " packets still in buffer at EOT");
        }
        
        return true;
    }
    
    private void sendAck(int seqNum) throws Exception {
        ackCount++;
        
        // Check if this ACK should be dropped (ChaosEngine)
        if (ChaosEngine.shouldDrop(ackCount, rn)) {
            System.out.println("  [DROPPED] ACK " + seqNum + " (#" + ackCount + 
                              ", RN=" + rn + ") - simulating loss");
            return;
        }
        
        DSPacket ackPacket = new DSPacket(DSPacket.TYPE_ACK, seqNum, null);
        byte[] data = ackPacket.toBytes();
        DatagramPacket datagram = new DatagramPacket(data, data.length, 
                                                     senderIp, senderAckPort);
        ackSocket.send(datagram);
        
        System.out.println("  [SENT] ACK " + seqNum + " (#" + ackCount + ")");
        lastAckSent = seqNum;
        lastAckTime = System.currentTimeMillis();
    }
    
    private void detectProtocol(int currentSeq) {
        if (isGBN) return; // Already detected
        
        if (lastSeq != -1) {
            int diff = (currentSeq - lastSeq + MAX_SEQ) % MAX_SEQ;
            
            // In GBN, we might see jumps due to permutation
            if (diff > 1 && diff < 10) {
                seqJumpCount++;
            }
            
            // After 3 jumps, assume GBN
            if (seqJumpCount >= 3) {
                isGBN = true;
                windowSize = 20; // Default GBN window
                System.out.println("\n[PROTOCOL DETECTION] Detected Go-Back-N protocol");
                System.out.println("  (based on " + seqJumpCount + " sequence jumps)\n");
            }
        }
        
        lastSeq = currentSeq;
    }
    
    private boolean isWithinWindow(int seqNum) {
        if (!isGBN) {
            // In Stop-and-Wait, only expect exactly expectedSeq
            return seqNum == expectedSeq;
        }
        
        // For GBN, check if within window (simplified)
        int diff;
        if (seqNum >= expectedSeq) {
            diff = seqNum - expectedSeq;
        } else {
            diff = (seqNum + MAX_SEQ) - expectedSeq;
        }
        
        return diff >= 0 && diff < windowSize;
    }
}